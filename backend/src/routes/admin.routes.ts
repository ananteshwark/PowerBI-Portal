import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { requireAuth, requireAdmin } from '../middleware/auth.middleware.js';
import { hashPassword } from '../auth/password.js';
import { badRequest, forbidden } from '../utils/errors.js';
import { recordAudit, type AuditAction } from '../services/audit.service.js';
import { validateRlsMappings, summarise } from '../services/rlsValidator.service.js';
import * as admin from '../services/admin.service.js';

export const adminRouter = Router();

// Order matters: authenticate, then check the admin flag. requireAdmin reads
// req.user, which requireAuth populates from the database rather than the JWT,
// so a revoked admin role takes effect on the next request.
adminRouter.use(requireAuth);
adminRouter.use(requireAdmin);

/**
 * Admin actions are the ones most worth having a record of: they are how the
 * answer to "who could see what" changes over time.
 */
function audit(req: Request, action: AuditAction, detail: Record<string, unknown>): void {
  recordAudit({
    userId: req.user!.id,
    action,
    detail,
    ipAddress: req.ip,
    userAgent: req.get('user-agent') ?? null,
  });
}

const uuid = z.string().uuid();
const roleNames = z.array(z.string().regex(/^[a-z][a-z0-9_]{1,63}$/)).max(64);

// ------------------------------------------------------------------ users --
adminRouter.get('/users', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    res.json({ users: await admin.listUsers() });
  } catch (err) {
    next(err);
  }
});

const createUserSchema = z.object({
  email: z.string().email().max(320),
  displayName: z.string().min(1).max(200),
  // Minimum length only. Enforcing composition rules here would be security
  // theatre; length is what actually matters.
  password: z.string().min(12).max(1024),
  department: z.string().max(200).optional(),
  effectiveUsername: z.string().max(320).optional(),
  roles: roleNames.optional(),
});

adminRouter.post('/users', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const input = createUserSchema.parse(req.body);
    const user = await admin.createUser({
      email: input.email,
      displayName: input.displayName,
      passwordHash: await hashPassword(input.password),
      department: input.department,
      effectiveUsername: input.effectiveUsername,
      roles: input.roles,
    });
    audit(req, 'admin_user_created', { targetUserId: user.id, roles: user.roles });
    res.status(201).json(user);
  } catch (err) {
    next(err);
  }
});

const updateUserSchema = z.object({
  displayName: z.string().min(1).max(200).optional(),
  department: z.string().max(200).nullable().optional(),
  effectiveUsername: z.string().max(320).optional(),
  isActive: z.boolean().optional(),
});

adminRouter.patch('/users/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = uuid.parse(req.params.id);
    const input = updateUserSchema.parse(req.body);

    // Locking yourself out is recoverable only via direct database access.
    if (input.isActive === false && id === req.user!.id) {
      throw badRequest('You cannot deactivate your own account');
    }

    const user = await admin.updateUser(id, input);
    audit(req, 'admin_user_updated', { targetUserId: id, changed: Object.keys(input) });
    res.json(user);
  } catch (err) {
    next(err);
  }
});

adminRouter.put('/users/:id/roles', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = uuid.parse(req.params.id);
    const { roles } = z.object({ roles: roleNames }).parse(req.body);

    // Same reasoning as self-deactivation: if this is the last admin, removing
    // their own admin role leaves nobody able to grant it back.
    if (id === req.user!.id) {
      const adminRoles = (await admin.listRoles()).filter((r) => r.isAdmin).map((r) => r.name);
      const keepsAdmin = roles.some((r) => adminRoles.includes(r));
      if (!keepsAdmin) {
        throw forbidden('You cannot remove your own administrator role');
      }
    }

    const user = await admin.setUserRoles(id, roles);
    audit(req, 'admin_user_roles_replaced', { targetUserId: id, roles });
    res.json(user);
  } catch (err) {
    next(err);
  }
});

// ------------------------------------------------------------------ roles --
adminRouter.get('/roles', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    res.json({ roles: await admin.listRoles() });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------- reports --
adminRouter.get('/reports', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    res.json({ reports: await admin.listReports() });
  } catch (err) {
    next(err);
  }
});

adminRouter.put('/reports/:id/access', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = uuid.parse(req.params.id);
    const { roles } = z.object({ roles: roleNames }).parse(req.body);
    const report = await admin.setReportRoleAccess(id, roles);
    audit(req, 'admin_report_access_replaced', { reportId: id, roles });
    res.json(report);
  } catch (err) {
    next(err);
  }
});

// ----------------------------------------------------------- RLS mappings --
adminRouter.get('/rls-mappings', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    res.json({ mappings: await admin.listRlsMappings() });
  } catch (err) {
    next(err);
  }
});

const createMappingSchema = z.object({
  roleName: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/),
  pbiDatasetId: z.string().uuid(),
  // Deliberately not lower-cased or trimmed beyond whitespace: Power BI role
  // names are case-sensitive and normalising here would silently break RLS.
  pbiRoleName: z.string().min(1).max(200),
});

adminRouter.post('/rls-mappings', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const input = createMappingSchema.parse(req.body);
    const mapping = await admin.createRlsMapping(input);
    audit(req, 'admin_rls_mapping_created', { ...input });
    res.status(201).json(mapping);
  } catch (err) {
    next(err);
  }
});

adminRouter.delete('/rls-mappings/:id', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const id = uuid.parse(req.params.id);
    await admin.deleteRlsMapping(id);
    audit(req, 'admin_rls_mapping_deleted', { mappingId: id });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

/**
 * On-demand drift check. Same result the CLI prints, so an admin UI and the
 * scheduled job cannot disagree about what is wrong.
 */
adminRouter.get('/rls-validation', async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const issues = await validateRlsMappings();
    res.json({ ...summarise(issues), issues });
  } catch (err) {
    next(err);
  }
});
