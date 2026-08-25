import { query } from '../db/pool.js';
import { getDatasetRoles } from '../powerbi/client.js';
import { logger } from '../utils/logger.js';

/**
 * Detects drift between `rls_role_mappings` and the roles actually defined in
 * each Power BI dataset.
 *
 * This exists because the failure mode is silent. Power BI role names are
 * case-sensitive strings we assert at token time; nothing validates them when a
 * mapping row is written. Get one wrong and there is no error anywhere — the
 * user just sees a dashboard with no rows, or worse, a report is left with no
 * resolvable roles and the fail-closed guard starts denying access to people
 * who should have it. Both look like "the dashboard is broken", days after the
 * dataset was republished by someone else.
 *
 * Run it on a schedule and alert on anything non-empty.
 */

export type RlsIssueKind =
  /** Mapping names a role the dataset does not define. Users get denied (fail-closed). */
  | 'mapping_references_unknown_role'
  /** Dataset defines a role nothing maps to. Probably an unfinished onboarding. */
  | 'dataset_role_unmapped'
  /** Report requires RLS but the dataset defines no roles at all. Nobody can view it. */
  | 'rls_required_but_dataset_has_no_roles'
  /** Dataset has no roles and the report agrees — but then identities must be omitted. */
  | 'rls_not_required_but_dataset_has_roles'
  /** Could not reach Power BI for this dataset. Not drift; unknown. */
  | 'dataset_unreadable';

export interface RlsIssue {
  kind: RlsIssueKind;
  severity: 'error' | 'warning';
  datasetId: string;
  workspaceId: string;
  reportSlugs: string[];
  detail: string;
  /** Role names involved, where relevant. */
  roles?: string[];
}

interface DatasetRow {
  pbi_dataset_id: string;
  workspace_id: string;
  slugs: string[];
  rls_required: boolean;
}

/**
 * Case-insensitive comparison used only to produce a *better error message*
 * when a mapping differs from a real role by case alone — which is the single
 * most common way this breaks. Matching itself stays case-sensitive, because
 * that is what Power BI does.
 */
const findCaseInsensitiveMatch = (name: string, candidates: string[]): string | undefined =>
  candidates.find((c) => c.toLowerCase() === name.toLowerCase() && c !== name);

/**
 * How the validator reads a dataset's roles. Injectable so tests can exercise
 * the drift logic without a Power BI tenant — ESM module namespaces are
 * non-configurable, so an export cannot be stubbed in place.
 */
export type RoleFetcher = (workspaceId: string, datasetId: string) => Promise<string[]>;

export async function validateRlsMappings(
  fetchRoles: RoleFetcher = getDatasetRoles,
): Promise<RlsIssue[]> {
  const { rows: datasets } = await query<DatasetRow>(
    `SELECT r.pbi_dataset_id,
            -- One dataset can back several reports, possibly across workspaces.
            -- Any workspace the SP can read works for the roles lookup.
            min(r.workspace_id::text)::uuid       AS workspace_id,
            array_agg(r.slug ORDER BY r.slug)     AS slugs,
            bool_or(r.rls_required)               AS rls_required
       FROM reports r
      WHERE r.is_active AND r.pbi_dataset_id IS NOT NULL
      GROUP BY r.pbi_dataset_id`,
  );

  const issues: RlsIssue[] = [];

  for (const ds of datasets) {
    let actualRoles: string[];
    try {
      actualRoles = await fetchRoles(ds.workspace_id, ds.pbi_dataset_id);
    } catch (err) {
      issues.push({
        kind: 'dataset_unreadable',
        severity: 'warning',
        datasetId: ds.pbi_dataset_id,
        workspaceId: ds.workspace_id,
        reportSlugs: ds.slugs,
        detail:
          'Could not read roles from Power BI. Check the service principal still has ' +
          'Member or Contributor on this workspace.',
      });
      logger.warn({ err, datasetId: ds.pbi_dataset_id }, 'RLS validation: dataset unreadable');
      continue;
    }

    const { rows: mapped } = await query<{ pbi_role_name: string; role_names: string[] }>(
      `SELECT m.pbi_role_name,
              array_agg(ro.name ORDER BY ro.name) AS role_names
         FROM rls_role_mappings m
         JOIN roles ro ON ro.id = m.role_id
        WHERE m.pbi_dataset_id = $1
        GROUP BY m.pbi_role_name`,
      [ds.pbi_dataset_id],
    );
    const mappedNames = mapped.map((m) => m.pbi_role_name);

    // --- mapping points at a role that does not exist -----------------------
    for (const { pbi_role_name, role_names } of mapped) {
      if (actualRoles.includes(pbi_role_name)) continue;

      const nearMiss = findCaseInsensitiveMatch(pbi_role_name, actualRoles);
      issues.push({
        kind: 'mapping_references_unknown_role',
        severity: 'error',
        datasetId: ds.pbi_dataset_id,
        workspaceId: ds.workspace_id,
        reportSlugs: ds.slugs,
        roles: [pbi_role_name],
        detail: nearMiss
          ? `Portal role(s) ${role_names.join(', ')} map to "${pbi_role_name}", but the dataset ` +
            `defines "${nearMiss}". Power BI role names are case-sensitive — fix the casing.`
          : `Portal role(s) ${role_names.join(', ')} map to "${pbi_role_name}", which this ` +
            `dataset does not define. Defined roles: ${actualRoles.join(', ') || '(none)'}. ` +
            'Users relying on this mapping are being denied access.',
      });
    }

    // --- dataset role nobody maps to ---------------------------------------
    for (const role of actualRoles) {
      if (mappedNames.includes(role)) continue;
      issues.push({
        kind: 'dataset_role_unmapped',
        severity: 'warning',
        datasetId: ds.pbi_dataset_id,
        workspaceId: ds.workspace_id,
        reportSlugs: ds.slugs,
        roles: [role],
        detail:
          `The dataset defines RLS role "${role}", but no portal role maps to it, so it can ` +
          'never be applied. Usually an unfinished onboarding.',
      });
    }

    // --- the two fail-closed mismatches -------------------------------------
    if (ds.rls_required && actualRoles.length === 0) {
      issues.push({
        kind: 'rls_required_but_dataset_has_no_roles',
        severity: 'error',
        datasetId: ds.pbi_dataset_id,
        workspaceId: ds.workspace_id,
        reportSlugs: ds.slugs,
        detail:
          'Report(s) are marked rls_required but the dataset defines no RLS roles, so every ' +
          'embed request fails closed and nobody can view them. Either define roles in Power BI ' +
          'Desktop or set reports.rls_required = false.',
      });
    }

    if (!ds.rls_required && actualRoles.length > 0) {
      issues.push({
        kind: 'rls_not_required_but_dataset_has_roles',
        severity: 'error',
        datasetId: ds.pbi_dataset_id,
        workspaceId: ds.workspace_id,
        reportSlugs: ds.slugs,
        roles: actualRoles,
        detail:
          'The dataset defines RLS roles but report(s) are marked rls_required = false, so ' +
          'tokens are minted WITHOUT an effective identity — which returns every row to every ' +
          'user. Set rls_required = true.',
      });
    }
  }

  return issues;
}

/** Convenience for the CLI and any future admin endpoint. */
export const summarise = (issues: RlsIssue[]) => ({
  total: issues.length,
  errors: issues.filter((i) => i.severity === 'error').length,
  warnings: issues.filter((i) => i.severity === 'warning').length,
});
