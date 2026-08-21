import { Router, type Request, type Response, type NextFunction } from 'express';
import { requireAuth } from '../middleware/auth.middleware.js';
import { listAccessibleReports, findAccessibleReport } from '../services/reports.service.js';
import { notFound } from '../utils/errors.js';

export const reportsRouter = Router();

reportsRouter.use(requireAuth);

/**
 * GET /api/reports — the report catalogue for the signed-in user.
 *
 * Returns display metadata only. Workspace and Power BI report IDs are
 * deliberately withheld: the browser never needs them (the embed endpoint
 * returns the embedUrl already built), and not shipping them means a compromised
 * frontend cannot enumerate the workspace's contents.
 */
reportsRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const reports = await listAccessibleReports(req.user!.id);
    res.json({
      reports: reports.map((r) => ({
        id: r.reportId,
        slug: r.slug,
        name: r.name,
        description: r.description,
        category: r.category,
        rlsEnabled: r.rlsRequired,
      })),
    });
  } catch (err) {
    next(err);
  }
});

/**
 * GET /api/reports/:slugOrId — metadata for one report.
 *
 * Exists so the report page does not have to pull the whole catalogue to
 * render one title. Same authorization path as the embed endpoint, and the
 * same withheld fields: no workspace or Power BI identifiers.
 */
reportsRouter.get('/:slugOrId', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const report = await findAccessibleReport(req.user!.id, req.params.slugOrId!);
    // 404 rather than 403: for a caller with no grant, "does not exist" and
    // "not yours" must be indistinguishable, or this becomes a way to
    // enumerate the workspace.
    if (!report) throw notFound('Report not found');

    res.json({
      id: report.reportId,
      slug: report.slug,
      name: report.name,
      description: report.description,
      category: report.category,
      rlsEnabled: report.rlsRequired,
    });
  } catch (err) {
    next(err);
  }
});
