import { query } from '../db/pool.js';
import type { EffectiveIdentity } from '../types/domain.js';
import { unauthorized } from '../utils/errors.js';

/**
 * Resolves the effective identity we assert to Power BI for a given
 * (user, dataset) pair.
 *
 * The RLS role names come from `rls_role_mappings`, scoped to the dataset,
 * because the same portal role commonly maps to differently named Power BI
 * roles across models. Resolution is done per-dataset, per-request, from the
 * database — never from the JWT. A JWT is issued for up to 15 minutes; roles
 * revoked in that window must take effect on the next embed, and reading the
 * live tables is what guarantees that.
 */
export async function resolveEffectiveIdentity(
  userId: string,
  datasetId: string,
): Promise<EffectiveIdentity> {
  const [userRes, rolesRes, attrsRes] = await Promise.all([
    query<{ effective_username: string }>(
      `SELECT effective_username FROM users WHERE id = $1 AND is_active`,
      [userId],
    ),
    query<{ pbi_role_name: string }>(
      `SELECT DISTINCT m.pbi_role_name
         FROM rls_role_mappings m
         JOIN user_roles ur ON ur.role_id = m.role_id
        WHERE ur.user_id = $1
          AND m.pbi_dataset_id = $2
        ORDER BY m.pbi_role_name`,
      [userId, datasetId],
    ),
    query<{ attr_key: string; attr_value: string }>(
      `SELECT attr_key, attr_value FROM user_rls_attributes WHERE user_id = $1`,
      [userId],
    ),
  ]);

  const user = userRes.rows[0];
  if (!user) {
    // Deactivated between JWT issuance and this call. A bare Error here became
    // a 500; this is an auth outcome, not a server fault.
    throw unauthorized('Account is inactive');
  }

  return {
    username: user.effective_username,
    roles: rolesRes.rows.map((r) => r.pbi_role_name),
    datasets: [datasetId],
    attributes: Object.fromEntries(attrsRes.rows.map((r) => [r.attr_key, r.attr_value])),
  };
}
