/**
 * End-to-end check of the Azure / Power BI configuration.
 *
 * Each step maps to a step in docs/AZURE_SETUP.md, so a failure tells you which
 * part of the setup is wrong rather than just "401".
 *
 *   npm run verify:powerbi -- <workspaceId> <reportId>
 *   (falls back to POWERBI_WORKSPACE_ID and the first row in `reports`)
 */
import { config } from '../src/config/env.js';
import { getAadToken, remainingMinutes } from '../src/powerbi/aadToken.js';
import { getReport, getDatasetRoles, generateEmbedToken } from '../src/powerbi/client.js';
import { query, closePool } from '../src/db/pool.js';

const PASS = '\u001b[32m✔\u001b[0m';
const FAIL = '\u001b[31m\u2718\u001b[0m';

async function main(): Promise<void> {
  let [workspaceId, reportId] = process.argv.slice(2);

  if (!workspaceId || !reportId) {
    const { rows } = await query<{ workspace_id: string; pbi_report_id: string }>(
      `SELECT workspace_id, pbi_report_id FROM reports WHERE is_active ORDER BY created_at LIMIT 1`,
    );
    workspaceId ??= rows[0]?.workspace_id ?? config.powerbi.defaultWorkspaceId ?? '';
    reportId ??= rows[0]?.pbi_report_id ?? '';
  }

  if (!workspaceId || !reportId) {
    console.error('Provide a workspace id and report id, or seed the reports table first.');
    process.exit(1);
  }

  console.log(`\nVerifying workspace ${workspaceId}, report ${reportId}\n`);

  // -- 1. Entra ID (setup steps 1-2) --------------------------------------
  const token = await getAadToken();
  console.log(`${PASS} Entra ID token acquired (valid ${remainingMinutes(token)} more minutes)`);

  // -- 2/3. Workspace + report visibility (setup steps 5, 6, 9) -----------
  const report = await getReport(workspaceId, reportId);
  console.log(`${PASS} Service principal can read the workspace (steps 5-6 correct)`);
  console.log(`${PASS} Report metadata readable: "${report.name}"`);
  console.log(`     dataset: ${report.datasetId}`);

  // -- 4. RLS roles on the dataset (setup step 8) -------------------------
  const roles = await getDatasetRoles(workspaceId, report.datasetId);
  if (roles.length === 0) {
    console.log(
      `${FAIL} Dataset has NO RLS roles defined.\n` +
        `     Either add roles in Power BI Desktop (step 8), or set\n` +
        `     reports.rls_required = FALSE for this report — Power BI rejects\n` +
        `     an effective identity against a dataset with no roles.`,
    );
  } else {
    console.log(`${PASS} Dataset RLS roles present: ${roles.join(', ')}`);

    const { rows: mapped } = await query<{ pbi_role_name: string }>(
      `SELECT DISTINCT pbi_role_name FROM rls_role_mappings WHERE pbi_dataset_id = $1`,
      [report.datasetId],
    );
    const unmapped = mapped.map((m) => m.pbi_role_name).filter((n) => !roles.includes(n));
    if (unmapped.length) {
      console.log(
        `${FAIL} rls_role_mappings references role name(s) not in the dataset: ${unmapped.join(', ')}\n` +
          `     Role names are case-sensitive. Fix the mapping rows or the dataset.`,
      );
    }
  }

  // -- 5. The real thing (everything) -------------------------------------
  const testRole = roles[0];
  const embed = await generateEmbedToken({
    workspaceId,
    reportId,
    datasetId: report.datasetId,
    requestedLifetimeMinutes: 10,
    ...(testRole
      ? { identities: [{ username: 'verify@example.com', roles: [testRole], datasets: [report.datasetId] }] }
      : {}),
  });

  console.log(
    `${PASS} Embed token generated${testRole ? ` with RLS role "${testRole}"` : ' (no RLS)'}` +
      `, expires ${embed.expiration}`,
  );
  console.log('\nAll checks passed. Capacity (step 7) is not verifiable via API — confirm in the portal.\n');
}

main()
  .then(() => closePool())
  .catch(async (err) => {
    console.error(`\n${FAIL} ${err.message}\n`);
    if (err.internal) console.error('   detail:', JSON.stringify(err.internal));
    console.error('   See docs/AZURE_SETUP.md section 11 for the failure table.\n');
    await closePool().catch(() => undefined);
    process.exit(1);
  });
