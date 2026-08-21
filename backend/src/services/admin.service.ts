import { query, withTransaction } from '../db/pool.js';
import { badRequest, notFound } from '../utils/errors.js';
import { logger } from '../utils/logger.js';
import { invalidateUser } from './tokenCache.js';
import { revokeAllForUser } from '../auth/refreshTokens.js';

/**
 * Administrative mutations.
 *
 * The rule that governs this whole file: **any change to what a user may see
 * must take effect immediately.** `applyAccessChange` is how that is enforced,
 * and every mutation below that touches roles, grants or account state calls
 * it. Forgetting to is how a demoted user keeps reading data for another hour,
 * so it lives in one place rather than being repeated at each call site.
 */
async function applyAccessChange(userIds: string[], reason: string): Promise<void> {
  const unique = [...new Set(userIds)];
  await Promise.all(
    unique.map(async (id) => {
      // The one that actually matters. An embed token is a Power BI credential
      // with the OLD RLS identity baked into it, valid for up to an hour, and
      // nothing revokes it server-side — dropping it from the cache is the only
      // way to stop it being handed out again.
      await invalidateUser(id);

      // Belt and braces. Roles are NOT trusted from the JWT — requireAuth
      // re-reads them from the database on every request — so a stale access
      // token cannot grant permissions that were just removed. Revoking the
      // refresh tokens ends the session outright, which is what deactivation
      // needs, and forces a clean re-login after a role change.
      await revokeAllForUser(id);
    }),
  );
  if (unique.length) {
    logger.info({ userIds: unique, reason }, 'Access change applied — sessions and cache cleared');
  }
}

// ------------------------------------------------------------------ users --
export interface AdminUser {
  id: string;
  email: string;
  displayName: string;
  department: string | null;
  effectiveUsername: string;
  isActive: boolean;
  lastLoginAt: string | null;
  roles: string[];
}

const USER_SELECT = `
  SELECT u.id,
         u.email::text        AS "email",
         u.display_name       AS "displayName",
         u.department,
         u.effective_username AS "effectiveUsername",
         u.is_active          AS "isActive",
         u.last_login_at      AS "lastLoginAt",
         array_remove(array_agg(r.name ORDER BY r.name), NULL) AS roles
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r       ON r.id = ur.role_id
`;

export async function listUsers(): Promise<AdminUser[]> {
  const { rows } = await query<AdminUser>(
    `${USER_SELECT} GROUP BY u.id ORDER BY u.email`,
  );
  return rows;
}

export async function getUser(userId: string): Promise<AdminUser | null> {
  const { rows } = await query<AdminUser>(
    `${USER_SELECT} WHERE u.id = $1 GROUP BY u.id`,
    [userId],
  );
  return rows[0] ?? null;
}

export interface CreateUserInput {
  email: string;
  displayName: string;
  passwordHash: string;
  department?: string | undefined;
  effectiveUsername?: string | undefined;
  roles?: string[] | undefined;
}

export async function createUser(input: CreateUserInput): Promise<AdminUser> {
  const id = await withTransaction(async (client) => {
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO users (email, display_name, password_hash, department, effective_username)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [
        input.email,
        input.displayName,
        input.passwordHash,
        input.department ?? null,
        // NULL lets the trigger default it to the email address.
        input.effectiveUsername ?? null,
      ],
    );
    const userId = rows[0]!.id;

    if (input.roles?.length) {
      await assignRoles(client, userId, input.roles);
    }
    return userId;
  }).catch((err: { code?: string }) => {
    if (err.code === '23505') throw badRequest('A user with that email already exists');
    throw err;
  });

  return (await getUser(id))!;
}

export interface UpdateUserInput {
  displayName?: string | undefined;
  department?: string | null | undefined;
  effectiveUsername?: string | undefined;
  isActive?: boolean | undefined;
}

export async function updateUser(userId: string, input: UpdateUserInput): Promise<AdminUser> {
  const sets: string[] = [];
  const values: unknown[] = [userId];

  const push = (col: string, value: unknown) => {
    values.push(value);
    sets.push(`${col} = $${values.length}`);
  };

  if (input.displayName !== undefined) push('display_name', input.displayName);
  if (input.department !== undefined) push('department', input.department);
  if (input.effectiveUsername !== undefined) push('effective_username', input.effectiveUsername);
  if (input.isActive !== undefined) push('is_active', input.isActive);

  if (sets.length === 0) throw badRequest('No fields to update');

  const { rowCount } = await query(
    `UPDATE users SET ${sets.join(', ')} WHERE id = $1`,
    values,
  );
  if (!rowCount) throw notFound('User not found');

  // effective_username is what USERPRINCIPALNAME() returns inside the dataset's
  // DAX, so changing it changes which rows the user sees. Deactivation must cut
  // access now, not when the token expires. Either way, clear both caches.
  if (input.effectiveUsername !== undefined || input.isActive !== undefined) {
    await applyAccessChange([userId], 'user updated');
  }

  return (await getUser(userId))!;
}

async function assignRoles(
  client: { query: (sql: string, params?: unknown[]) => Promise<{ rows: unknown[]; rowCount: number | null }> },
  userId: string,
  roleNames: string[],
): Promise<void> {
  const res = await client.query(
    `INSERT INTO user_roles (user_id, role_id)
     SELECT $1, r.id FROM roles r WHERE r.name = ANY($2::text[])`,
    [userId, roleNames],
  );
  if ((res.rowCount ?? 0) !== roleNames.length) {
    // Silently granting a subset would leave the caller believing a role was
    // applied when it was not.
    throw badRequest(`One or more roles do not exist: ${roleNames.join(', ')}`);
  }
}

/** Replace a user's role set wholesale. Returns the updated user. */
export async function setUserRoles(userId: string, roleNames: string[]): Promise<AdminUser> {
  const exists = await getUser(userId);
  if (!exists) throw notFound('User not found');

  await withTransaction(async (client) => {
    await client.query(`DELETE FROM user_roles WHERE user_id = $1`, [userId]);
    if (roleNames.length) await assignRoles(client, userId, roleNames);
  });

  await applyAccessChange([userId], 'roles replaced');
  return (await getUser(userId))!;
}

// ------------------------------------------------------------------ roles --
export interface AdminRole {
  id: string;
  name: string;
  description: string | null;
  isAdmin: boolean;
  userCount: number;
}

export async function listRoles(): Promise<AdminRole[]> {
  const { rows } = await query<AdminRole>(
    `SELECT r.id, r.name, r.description, r.is_admin AS "isAdmin",
            count(ur.user_id)::int AS "userCount"
       FROM roles r
       LEFT JOIN user_roles ur ON ur.role_id = r.id
      GROUP BY r.id
      ORDER BY r.name`,
  );
  return rows;
}

// ---------------------------------------------------------------- reports --
export interface AdminReport {
  id: string;
  slug: string;
  name: string;
  category: string | null;
  workspaceId: string;
  pbiReportId: string;
  pbiDatasetId: string | null;
  rlsRequired: boolean;
  isActive: boolean;
  grantedRoles: string[];
}

export async function listReports(): Promise<AdminReport[]> {
  const { rows } = await query<AdminReport>(
    `SELECT rep.id, rep.slug, rep.name, rep.category,
            rep.workspace_id   AS "workspaceId",
            rep.pbi_report_id  AS "pbiReportId",
            rep.pbi_dataset_id AS "pbiDatasetId",
            rep.rls_required   AS "rlsRequired",
            rep.is_active      AS "isActive",
            array_remove(array_agg(r.name ORDER BY r.name), NULL) AS "grantedRoles"
       FROM reports rep
       LEFT JOIN report_role_access ra ON ra.report_id = rep.id
       LEFT JOIN roles r               ON r.id = ra.role_id
      GROUP BY rep.id
      ORDER BY rep.name`,
  );
  return rows;
}

/**
 * Replace which roles may see a report.
 *
 * Invalidates every user whose access changes in EITHER direction — the union
 * of the old and new role memberships. Only clearing the newly-granted users
 * would leave a revoked user with a working cached token.
 */
export async function setReportRoleAccess(
  reportId: string,
  roleNames: string[],
): Promise<AdminReport> {
  const affected = await withTransaction(async (client) => {
    const report = await client.query(`SELECT 1 FROM reports WHERE id = $1`, [reportId]);
    if (!report.rowCount) throw notFound('Report not found');

    // Capture the before-set while the old rows still exist.
    const before = await client.query<{ user_id: string }>(
      `SELECT DISTINCT ur.user_id
         FROM report_role_access ra
         JOIN user_roles ur ON ur.role_id = ra.role_id
        WHERE ra.report_id = $1`,
      [reportId],
    );

    await client.query(`DELETE FROM report_role_access WHERE report_id = $1`, [reportId]);

    if (roleNames.length) {
      const res = await client.query(
        `INSERT INTO report_role_access (report_id, role_id)
         SELECT $1, r.id FROM roles r WHERE r.name = ANY($2::text[])`,
        [reportId, roleNames],
      );
      if ((res.rowCount ?? 0) !== roleNames.length) {
        throw badRequest(`One or more roles do not exist: ${roleNames.join(', ')}`);
      }
    }

    const after = await client.query<{ user_id: string }>(
      `SELECT DISTINCT ur.user_id
         FROM report_role_access ra
         JOIN user_roles ur ON ur.role_id = ra.role_id
        WHERE ra.report_id = $1`,
      [reportId],
    );

    return [...before.rows, ...after.rows].map((r) => r.user_id);
  });

  await applyAccessChange(affected, 'report access changed');

  const reports = await listReports();
  return reports.find((r) => r.id === reportId)!;
}

// ----------------------------------------------------------- RLS mappings --
export interface AdminRlsMapping {
  id: string;
  roleName: string;
  pbiDatasetId: string;
  pbiRoleName: string;
}

export async function listRlsMappings(): Promise<AdminRlsMapping[]> {
  const { rows } = await query<AdminRlsMapping>(
    `SELECT m.id, r.name AS "roleName",
            m.pbi_dataset_id AS "pbiDatasetId",
            m.pbi_role_name  AS "pbiRoleName"
       FROM rls_role_mappings m
       JOIN roles r ON r.id = m.role_id
      ORDER BY r.name, m.pbi_role_name`,
  );
  return rows;
}

export async function createRlsMapping(input: {
  roleName: string;
  pbiDatasetId: string;
  pbiRoleName: string;
}): Promise<AdminRlsMapping> {
  const { rows } = await query<{ id: string }>(
    `INSERT INTO rls_role_mappings (role_id, pbi_dataset_id, pbi_role_name)
     SELECT r.id, $2::uuid, $3 FROM roles r WHERE r.name = $1
     ON CONFLICT DO NOTHING
     RETURNING id`,
    [input.roleName, input.pbiDatasetId, input.pbiRoleName],
  );

  if (!rows[0]) {
    const roleExists = await query(`SELECT 1 FROM roles WHERE name = $1`, [input.roleName]);
    throw badRequest(
      roleExists.rowCount ? 'That mapping already exists' : `Role "${input.roleName}" does not exist`,
    );
  }

  // A new mapping changes which RLS roles resolve, so every holder of that
  // portal role has a stale identity fingerprint cached.
  const { rows: affected } = await query<{ user_id: string }>(
    `SELECT ur.user_id FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE r.name = $1`,
    [input.roleName],
  );
  await applyAccessChange(affected.map((a) => a.user_id), 'rls mapping created');

  return (await listRlsMappings()).find((m) => m.id === rows[0]!.id)!;
}

export async function deleteRlsMapping(mappingId: string): Promise<void> {
  const { rows } = await query<{ role_id: string }>(
    `DELETE FROM rls_role_mappings WHERE id = $1 RETURNING role_id`,
    [mappingId],
  );
  if (!rows[0]) throw notFound('Mapping not found');

  const { rows: affected } = await query<{ user_id: string }>(
    `SELECT user_id FROM user_roles WHERE role_id = $1`,
    [rows[0].role_id],
  );
  await applyAccessChange(affected.map((a) => a.user_id), 'rls mapping deleted');
}
