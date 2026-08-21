import { query } from '../db/pool.js';
import type { AccessibleReport } from '../types/domain.js';

const SELECT_COLUMNS = `
    report_id              AS "reportId",
    slug,
    name,
    description,
    category,
    workspace_id           AS "workspaceId",
    pbi_report_id          AS "pbiReportId",
    pbi_dataset_id         AS "pbiDatasetId",
    rls_required           AS "rlsRequired",
    token_lifetime_minutes AS "tokenLifetimeMinutes"
`;

/** Every active report this user can reach, via role grant or direct grant. */
export async function listAccessibleReports(userId: string): Promise<AccessibleReport[]> {
  const { rows } = await query<AccessibleReport>(
    `SELECT ${SELECT_COLUMNS}
       FROM user_report_access
      WHERE user_id = $1
      ORDER BY category NULLS LAST, name`,
    [userId],
  );
  return rows;
}

/**
 * The authorization check. Returns null when the user has no grant for the
 * report — the caller turns that into a 403.
 *
 * Deliberately reads the same `user_report_access` view as the list endpoint,
 * so the set of reports a user can see listed and the set they can embed can
 * never drift apart.
 */
export async function findAccessibleReport(
  userId: string,
  reportIdOrSlug: string,
): Promise<AccessibleReport | null> {
  const isUuid =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(reportIdOrSlug);

  const { rows } = await query<AccessibleReport>(
    `SELECT ${SELECT_COLUMNS}
       FROM user_report_access
      WHERE user_id = $1
        AND (${isUuid ? 'report_id = $2::uuid' : 'slug = $2'})
      LIMIT 1`,
    [userId, reportIdOrSlug],
  );
  return rows[0] ?? null;
}

/** Cache the datasetId resolved from Power BI so later embeds skip a REST call. */
export async function cacheDatasetId(reportId: string, datasetId: string): Promise<void> {
  await query(
    `UPDATE reports SET pbi_dataset_id = $2 WHERE id = $1 AND pbi_dataset_id IS DISTINCT FROM $2`,
    [reportId, datasetId],
  );
}
