/**
 * Report access: the authorization layer that decides which reports a user may
 * open at all. RLS filters rows *within* a report; this decides whether they
 * reach the report in the first place, so a hole here is not mitigated by RLS.
 *
 * Two code paths answer that question, for measured performance reasons
 * (migration 003):
 *   - listAccessibleReports  -> accessible_reports(user_id)   [catalogue]
 *   - findAccessibleReport   -> user_report_access view       [point lookup]
 *
 * They must agree exactly. These tests assert that across a matrix of grant
 * shapes, so the two definitions cannot silently drift.
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

describe('report access', { skip: TEST_DB ? false : 'TEST_DATABASE_URL not set' }, () => {
  let listAccessibleReports: typeof import('../src/services/reports.service.js').listAccessibleReports;
  let findAccessibleReport: typeof import('../src/services/reports.service.js').findAccessibleReport;
  let query: typeof import('../src/db/pool.js').query;
  let closePool: typeof import('../src/db/pool.js').closePool;

  /** Fixture ids, keyed by the scenario they exercise. */
  const users: Record<string, string> = {};
  const reports: Record<string, string> = {};
  const tag = `ra${Date.now()}`;

  before(async () => {
    ({ listAccessibleReports, findAccessibleReport } = await import(
      '../src/services/reports.service.js'
    ));
    ({ query, closePool } = await import('../src/db/pool.js'));

    const roleRes = await query<{ id: string; name: string }>(
      `INSERT INTO roles (name) VALUES ($1), ($2) RETURNING id, name`,
      [`${tag}_granted`, `${tag}_other`],
    );
    const grantedRole = roleRes.rows.find((r) => r.name === `${tag}_granted`)!.id;
    const otherRole = roleRes.rows.find((r) => r.name === `${tag}_other`)!.id;

    const mkUser = async (key: string, active = true) => {
      const { rows } = await query<{ id: string }>(
        `INSERT INTO users (email, password_hash, display_name, is_active)
         VALUES ($1, 'x', $2, $3) RETURNING id`,
        [`${tag}-${key}@test.local`, key, active],
      );
      users[key] = rows[0]!.id;
      return rows[0]!.id;
    };

    const mkReport = async (key: string, active = true) => {
      const { rows } = await query<{ id: string }>(
        `INSERT INTO reports (name, slug, workspace_id, pbi_report_id, is_active)
         VALUES ($1, $2, gen_random_uuid(), gen_random_uuid(), $3) RETURNING id`,
        [key, `${tag}-${key}`, active],
      );
      reports[key] = rows[0]!.id;
      return rows[0]!.id;
    };

    await Promise.all([
      mkUser('viaRole'),
      mkUser('viaDirect'),
      mkUser('viaBoth'),
      mkUser('expiredGrant'),
      mkUser('noGrant'),
      mkUser('inactive', false),
    ]);
    await Promise.all([mkReport('shared'), mkReport('archived', false)]);

    // viaRole + viaBoth + inactive hold the granted role
    for (const key of ['viaRole', 'viaBoth', 'inactive']) {
      await query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [
        users[key],
        grantedRole,
      ]);
    }
    // noGrant holds a role with no report attached to it
    await query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [
      users.noGrant,
      otherRole,
    ]);

    await query(`INSERT INTO report_role_access (report_id, role_id) VALUES ($1, $2), ($3, $2)`, [
      reports.shared,
      grantedRole,
      reports.archived,
    ]);

    await query(`INSERT INTO report_user_access (report_id, user_id) VALUES ($1, $2), ($1, $3)`, [
      reports.shared,
      users.viaDirect,
      users.viaBoth,
    ]);
    await query(
      `INSERT INTO report_user_access (report_id, user_id, expires_at)
       VALUES ($1, $2, now() - INTERVAL '1 day')`,
      [reports.shared, users.expiredGrant],
    );
  });

  after(async () => {
    await query(`DELETE FROM users WHERE email LIKE $1`, [`${tag}-%`]);
    await query(`DELETE FROM reports WHERE slug LIKE $1`, [`${tag}-%`]);
    await query(`DELETE FROM roles WHERE name LIKE $1`, [`${tag}_%`]);
    await closePool();
  });

  // ------------------------------------------------------------ semantics --
  const cases: [string, boolean, string][] = [
    ['viaRole', true, 'a role grant gives access'],
    ['viaDirect', true, 'a direct grant gives access'],
    ['viaBoth', true, 'holding both grants still gives access'],
    ['expiredGrant', false, 'a lapsed direct grant does not'],
    ['noGrant', false, 'an unrelated role does not'],
    ['inactive', false, 'a deactivated user gets nothing, role or not'],
  ];

  for (const [key, expected, why] of cases) {
    test(why, async () => {
      const found = await findAccessibleReport(users[key]!, `${tag}-shared`);
      assert.equal(found !== null, expected);
    });
  }

  test('an inactive report is invisible even to users granted it', async () => {
    assert.equal(await findAccessibleReport(users.viaRole!, `${tag}-archived`), null);
    const listed = await listAccessibleReports(users.viaRole!);
    assert.ok(!listed.some((r) => r.slug === `${tag}-archived`));
  });

  test('holding both grant types yields one row, not two', async () => {
    const listed = await listAccessibleReports(users.viaBoth!);
    assert.equal(listed.filter((r) => r.slug === `${tag}-shared`).length, 1);
  });

  test('a report can be looked up by uuid as well as slug', async () => {
    const bySlug = await findAccessibleReport(users.viaRole!, `${tag}-shared`);
    const byId = await findAccessibleReport(users.viaRole!, reports.shared!);
    assert.deepEqual(byId, bySlug);
  });

  // -------------------------------------------------------- the drift guard --
  /**
   * The catalogue and the authorization check read different SQL objects, so
   * this is the assertion that keeps them honest. If they ever disagree, either
   * a user sees a report they cannot open (annoying) or — the dangerous
   * direction — can open one that was never listed for them.
   */
  test('accessible_reports() and user_report_access agree for every user', async () => {
    for (const [key, userId] of Object.entries(users)) {
      const listed = (await listAccessibleReports(userId)).map((r) => r.slug).sort();

      const probed: string[] = [];
      for (const slug of [`${tag}-shared`, `${tag}-archived`]) {
        if (await findAccessibleReport(userId, slug)) probed.push(slug);
      }

      assert.deepEqual(
        listed.filter((s) => s.startsWith(tag)),
        probed.sort(),
        `catalogue and authorization check disagree for "${key}"`,
      );
    }
  });

  test('the two paths return identical row shapes', async () => {
    const [fromList] = (await listAccessibleReports(users.viaRole!)).filter(
      (r) => r.slug === `${tag}-shared`,
    );
    const fromFind = await findAccessibleReport(users.viaRole!, `${tag}-shared`);
    assert.deepEqual(fromFind, fromList, 'column sets must match, not just the row count');
  });
});
