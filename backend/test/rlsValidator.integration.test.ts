/**
 * The RLS mapping validator.
 *
 * Every case here is a real, silent production failure: Power BI reports no
 * error for any of them, so without this validator the first signal is a user
 * saying "my dashboard is empty" — or, in the rls_not_required case, nobody
 * saying anything while every row is served to everyone.
 *
 * The role fetcher is injected: the point is the drift logic, not the REST call.
 *
 * Requires TEST_DATABASE_URL pointing at a migrated, disposable database.
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';

const TEST_DB = process.env.TEST_DATABASE_URL;

process.env.DATABASE_URL = TEST_DB ?? 'postgresql://localhost:5432/unused';
process.env.JWT_SECRET ??= 'test-secret-that-is-at-least-32-characters-long';
process.env.AZURE_TENANT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_SECRET ??= 'test-secret';

describe('RLS mapping validator', { skip: TEST_DB ? false : 'TEST_DATABASE_URL not set' }, () => {
  let validateRlsMappings: typeof import('../src/services/rlsValidator.service.js').validateRlsMappings;
  let query: typeof import('../src/db/pool.js').query;
  let closePool: typeof import('../src/db/pool.js').closePool;

  const tag = `rv${Date.now()}`;
  const datasetId = '00000000-0000-4000-8000-000000000abc';
  let roleId: string;

  /** What the injected fetcher reports this dataset defines. */
  let datasetRoles: string[] = [];
  /** Set to make the fetcher throw, simulating an unreachable dataset. */
  let fetchThrows = false;

  const fetchRoles = async () => {
    if (fetchThrows) throw new Error('403 from Power BI');
    return datasetRoles;
  };

  before(async () => {
    ({ validateRlsMappings } = await import('../src/services/rlsValidator.service.js'));
    ({ query, closePool } = await import('../src/db/pool.js'));

    const role = await query<{ id: string }>(
      `INSERT INTO roles (name) VALUES ($1) RETURNING id`,
      [`${tag}_manager`],
    );
    roleId = role.rows[0]!.id;

    await query(
      `INSERT INTO reports (name, slug, workspace_id, pbi_report_id, pbi_dataset_id, rls_required)
       VALUES ('Validator fixture', $1, gen_random_uuid(), gen_random_uuid(), $2, TRUE)`,
      [`${tag}-report`, datasetId],
    );
  });

  after(async () => {
    await query(`DELETE FROM reports WHERE slug LIKE $1`, [`${tag}-%`]);
    await query(`DELETE FROM roles WHERE name LIKE $1`, [`${tag}_%`]);
    await closePool();
  });

  /** Issues for our fixture dataset only — the table may hold other rows. */
  const ours = async () =>
    (await validateRlsMappings(fetchRoles)).filter((i) => i.datasetId === datasetId);

  const setMapping = async (pbiRoleName: string | null) => {
    await query(`DELETE FROM rls_role_mappings WHERE pbi_dataset_id = $1`, [datasetId]);
    if (pbiRoleName !== null) {
      await query(
        `INSERT INTO rls_role_mappings (role_id, pbi_dataset_id, pbi_role_name)
         VALUES ($1, $2, $3)`,
        [roleId, datasetId, pbiRoleName],
      );
    }
  };

  const setRlsRequired = (v: boolean) =>
    query(`UPDATE reports SET rls_required = $2 WHERE slug = $1`, [`${tag}-report`, v]);

  test('a correct mapping produces no issues', async () => {
    datasetRoles = ['RegionalManager'];
    await setRlsRequired(true);
    await setMapping('RegionalManager');

    assert.deepEqual(await ours(), []);
  });

  /**
   * The most common way this breaks in practice, and the reason the validator
   * exists: role names are case-sensitive and nothing validates them on write.
   */
  test('catches a case mismatch and says so explicitly', async () => {
    datasetRoles = ['RegionalManager'];
    await setMapping('regionalmanager');

    const issues = await ours();
    const issue = issues.find((i) => i.kind === 'mapping_references_unknown_role');

    assert.ok(issue, 'a mapping naming a non-existent role must be reported');
    assert.equal(issue.severity, 'error');
    assert.match(issue.detail, /case-sensitive/i);
    assert.match(issue.detail, /RegionalManager/, 'should name the role it probably meant');
  });

  test('catches a mapping to a role that does not exist at all', async () => {
    datasetRoles = ['RegionalManager'];
    await setMapping('Typo');

    const issue = (await ours()).find((i) => i.kind === 'mapping_references_unknown_role');
    assert.ok(issue);
    assert.match(issue.detail, /being denied access/);
  });

  test('flags a dataset role nothing maps to, as a warning not an error', async () => {
    datasetRoles = ['RegionalManager', 'Auditor'];
    await setMapping('RegionalManager');

    const issue = (await ours()).find((i) => i.kind === 'dataset_role_unmapped');
    assert.ok(issue);
    assert.equal(issue.severity, 'warning', 'an unfinished onboarding is not an outage');
    assert.deepEqual(issue.roles, ['Auditor']);
  });

  /**
   * rls_required with no roles means the fail-closed guard denies everyone —
   * the report is simply unusable, and nothing else reports that.
   */
  test('catches rls_required against a dataset with no roles', async () => {
    datasetRoles = [];
    await setRlsRequired(true);
    await setMapping(null);

    const issue = (await ours()).find(
      (i) => i.kind === 'rls_required_but_dataset_has_no_roles',
    );
    assert.ok(issue);
    assert.equal(issue.severity, 'error');
  });

  /**
   * The dangerous direction. rls_required = false means we mint tokens with no
   * effective identity; against a dataset that HAS roles, that returns every
   * row to every user. Silent data exposure.
   */
  test('catches rls_required = false against a dataset that has roles', async () => {
    datasetRoles = ['RegionalManager'];
    await setRlsRequired(false);
    await setMapping('RegionalManager');

    const issue = (await ours()).find(
      (i) => i.kind === 'rls_not_required_but_dataset_has_roles',
    );
    assert.ok(issue, 'this is silent data exposure and must be an error');
    assert.equal(issue.severity, 'error');
    assert.match(issue.detail, /every row to every user/);
  });

  test('reports an unreadable dataset as a warning, not silent success', async () => {
    await setRlsRequired(true);
    await setMapping('RegionalManager');
    fetchThrows = true;
    try {
      const issue = (await ours()).find((i) => i.kind === 'dataset_unreadable');
      assert.ok(issue, 'an unreachable dataset must not look like a clean result');
      assert.equal(issue.severity, 'warning');
    } finally {
      fetchThrows = false;
    }
  });

  test('names the affected reports so the alert is actionable', async () => {
    datasetRoles = ['RegionalManager'];
    await setRlsRequired(true);
    await setMapping('Wrong');

    const issue = (await ours())[0];
    assert.ok(issue);
    assert.deepEqual(issue.reportSlugs, [`${tag}-report`]);
  });
});
