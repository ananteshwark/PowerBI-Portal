/**
 * Report drift between rls_role_mappings and the roles Power BI actually
 * defines.
 *
 *   npm run validate:rls          # human-readable, exits 1 on any error
 *   npm run validate:rls -- --json  # machine-readable, for alerting
 *
 * Run this on a schedule. The failure it catches is silent: a mistyped or
 * re-cased Power BI role name produces no error anywhere, just users who see an
 * empty dashboard or a denial, days after someone else republished the dataset.
 */
import { validateRlsMappings, summarise, type RlsIssue } from '../src/services/rlsValidator.service.js';
import { closePool } from '../src/db/pool.js';

const RED = '\u001b[31m';
const YELLOW = '\u001b[33m';
const GREEN = '\u001b[32m';
const DIM = '\u001b[2m';
const RESET = '\u001b[0m';

function printHuman(issues: RlsIssue[]): void {
  if (issues.length === 0) {
    console.log(`\n${GREEN}✔${RESET} RLS mappings are consistent with every dataset.\n`);
    return;
  }

  console.log('');
  for (const issue of issues) {
    const colour = issue.severity === 'error' ? RED : YELLOW;
    const mark = issue.severity === 'error' ? '✘' : '!';
    console.log(`${colour}${mark} ${issue.kind}${RESET}`);
    console.log(`  ${issue.detail}`);
    console.log(`  ${DIM}dataset ${issue.datasetId}${RESET}`);
    console.log(`  ${DIM}affects: ${issue.reportSlugs.join(', ')}${RESET}\n`);
  }

  const { total, errors, warnings } = summarise(issues);
  console.log(`${total} issue(s): ${errors} error(s), ${warnings} warning(s)\n`);
}

async function main(): Promise<void> {
  const asJson = process.argv.includes('--json');
  const issues = await validateRlsMappings();

  if (asJson) {
    console.log(JSON.stringify({ ...summarise(issues), issues }, null, 2));
  } else {
    printHuman(issues);
  }

  // Warnings alone do not fail the run: an unmapped dataset role is usually a
  // half-finished onboarding, not an outage. Errors mean users are already
  // being denied, or — worse — served unfiltered data.
  if (issues.some((i) => i.severity === 'error')) process.exitCode = 1;
}

main()
  .then(() => closePool())
  .catch(async (err) => {
    console.error(`\n${RED}✘${RESET} ${err instanceof Error ? err.message : String(err)}\n`);
    await closePool().catch(() => undefined);
    process.exit(2);
  });
