/**
 * Admin mutations.
 *
 * The property under test throughout is that a permission change takes effect
 * NOW. Two caches sit between a database row and what a browser can do — the
 * embed-token cache and the user's 15-minute access token — and if either
 * survives a demotion the user keeps reading data they no longer have rights
 * to. That is the whole reason applyAccessChange exists, so it is asserted on
 * every mutation rather than assumed.
 *
 * Requires TEST_DATABASE_URL pointing at a migrated, disposable database.
 */
import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const TEST_DB = process.env.TEST_DATABASE_URL;

process.env.DATABASE_URL = TEST_DB ?? 'postgresql://localhost:5432/unused';
process.env.JWT_SECRET ??= 'test-secret-that-is-at-least-32-characters-long';
process.env.AZURE_TENANT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_SECRET ??= 'test-secret';

describe('admin service', { skip: TEST_DB ? false : 'TEST_DATABASE_URL not set' }, () => {
  let admin: typeof import('../src/services/admin.service.js');
  let cache: typeof import('../src/services/tokenCache.js');
  let refresh: typeof import('../src/auth/refreshTokens.js');
  let query: typeof import('../src/db/pool.js').query;
  let closePool: typeof import('../src/db/pool.js').closePool;

  const tag = `ad${Date.now()}`;
  const datasetId = '00000000-0000-4000-8000-0000000000ad';
  let userId: string;
  let reportId: string;

  const makeToken = () => ({
    token: 'cached-under-old-identity',
    embedUrl: 'https://app.powerbi.com/embed',
    reportId: 'r1',
    expiresAtMs: Date.now() + 60 * 60 * 1000,
    rlsUsername: 'x@y.com',
    rlsRoles: ['Old'],
  });

  /** Seed a cached embed token and a live session for the fixture user. */
  async function primeCachesFor(id: string): Promise<void> {
    await cache.getOrCreateEmbedToken(
      { userId: id, reportId: 'r1', fingerprint: 'fp1' },
      async () => makeToken(),
    );
    await refresh.issueRefreshToken({ userId: id });
  }

  const cachedTokenExists = async (id: string): Promise<boolean> => {
    const hit = await cache.getOrCreateEmbedToken(
      { userId: id, reportId: 'r1', fingerprint: 'fp1' },
      async () => ({ ...makeToken(), token: 'freshly-minted' }),
    );
    return hit.value.token === 'cached-under-old-identity';
  };

  const liveSessions = async (id: string): Promise<number> => {
    const { rows } = await query<{ n: string }>(
      `SELECT count(*)::text AS n FROM refresh_tokens
        WHERE user_id = $1 AND revoked_at IS NULL`,
      [id],
    );
    return Number(rows[0]!.n);
  };

  before(async () => {
    admin = await import('../src/services/admin.service.js');
    cache = await import('../src/services/tokenCache.js');
    refresh = await import('../src/auth/refreshTokens.js');
    ({ query, closePool } = await import('../src/db/pool.js'));

    await query(`INSERT INTO roles (name) VALUES ($1), ($2), ($3)`, [
      `${tag}_alpha`,
      `${tag}_beta`,
      `${tag}_gamma`,
    ]);

    const report = await query<{ id: string }>(
      `INSERT INTO reports (name, slug, workspace_id, pbi_report_id, pbi_dataset_id)
       VALUES ('Admin fixture', $1, gen_random_uuid(), gen_random_uuid(), $2) RETURNING id`,
      [`${tag}-report`, datasetId],
    );
    reportId = report.rows[0]!.id;
  });

  beforeEach(async () => {
    await query(`DELETE FROM users WHERE email LIKE $1`, [`${tag}-%`]);
    const created = await admin.createUser({
      email: `${tag}-user@test.local`,
      displayName: 'Fixture User',
      passwordHash: 'x',
      roles: [`${tag}_alpha`],
    });
    userId = created.id;
    await primeCachesFor(userId);
  });

  after(async () => {
    await query(`DELETE FROM users WHERE email LIKE $1`, [`${tag}-%`]);
    await query(`DELETE FROM reports WHERE slug LIKE $1`, [`${tag}-%`]);
    await query(`DELETE FROM roles WHERE name LIKE $1`, [`${tag}_%`]);
    await closePool();
  });

  // ------------------------------------------------------------- creation --
  test('createUser assigns roles and defaults effectiveUsername to the email', async () => {
    const user = await admin.getUser(userId);
    assert.deepEqual(user?.roles, [`${tag}_alpha`]);
    assert.equal(user?.effectiveUsername, `${tag}-user@test.local`);
  });

  test('createUser rejects an unknown role rather than silently granting a subset', async () => {
    await assert.rejects(
      () =>
        admin.createUser({
          email: `${tag}-bogus@test.local`,
          displayName: 'X',
          passwordHash: 'x',
          roles: [`${tag}_alpha`, 'no_such_role'],
        }),
      (err: { status?: number }) => err.status === 400,
    );
    // And must not have created a half-configured account.
    const { rows } = await query(`SELECT 1 FROM users WHERE email = $1`, [`${tag}-bogus@test.local`]);
    assert.equal(rows.length, 0, 'the whole creation must roll back');
  });

  test('createUser rejects a duplicate email with 400, not a raw constraint error', async () => {
    await assert.rejects(
      () =>
        admin.createUser({
          email: `${tag}-user@test.local`,
          displayName: 'Dup',
          passwordHash: 'x',
        }),
      (err: { status?: number }) => err.status === 400,
    );
  });

  // ------------------------------------------- the invalidation property --
  test('replacing roles clears cached tokens AND live sessions', async () => {
    assert.ok(await cachedTokenExists(userId), 'precondition: token cached');
    assert.ok((await liveSessions(userId)) > 0, 'precondition: session live');

    await admin.setUserRoles(userId, [`${tag}_beta`]);

    assert.equal(
      await cachedTokenExists(userId),
      false,
      'a token minted under the old roles must not survive the change',
    );
    assert.equal(
      await liveSessions(userId),
      0,
      'the access token carries roles for up to 15 minutes; the session must be revoked',
    );
  });

  test('deactivating a user clears both caches', async () => {
    await admin.updateUser(userId, { isActive: false });
    assert.equal(await cachedTokenExists(userId), false);
    assert.equal(await liveSessions(userId), 0);
  });

  /**
   * effective_username is what USERPRINCIPALNAME() returns inside the dataset's
   * DAX, so changing it changes which rows the user sees.
   */
  test('changing effectiveUsername clears both caches', async () => {
    await admin.updateUser(userId, { effectiveUsername: 'someone.else@test.local' });
    assert.equal(await cachedTokenExists(userId), false);
    assert.equal(await liveSessions(userId), 0);
  });

  test('a cosmetic update does NOT sign the user out', async () => {
    await admin.updateUser(userId, { displayName: 'Renamed' });
    assert.ok(
      (await liveSessions(userId)) > 0,
      'renaming someone should not log them out',
    );
    assert.equal((await admin.getUser(userId))?.displayName, 'Renamed');
  });

  /**
   * The direction that is easy to get wrong: revoking access must invalidate
   * the users who are LOSING it, which means capturing the membership set
   * before the delete, not after.
   */
  test('revoking report access invalidates the users who lose it', async () => {
    await admin.setReportRoleAccess(reportId, [`${tag}_alpha`]);
    await primeCachesFor(userId);
    assert.ok(await cachedTokenExists(userId), 'precondition: token cached');

    // alpha no longer grants the report; our fixture user holds only alpha.
    await admin.setReportRoleAccess(reportId, [`${tag}_gamma`]);

    assert.equal(
      await cachedTokenExists(userId),
      false,
      'a user losing access must not keep a working cached token',
    );
  });

  test('granting report access invalidates the users who gain it', async () => {
    await admin.setReportRoleAccess(reportId, []);
    await primeCachesFor(userId);
    await admin.setReportRoleAccess(reportId, [`${tag}_alpha`]);
    assert.equal(await cachedTokenExists(userId), false);
  });

  // --------------------------------------------------------- RLS mappings --
  test('creating a mapping invalidates every holder of that portal role', async () => {
    await primeCachesFor(userId);
    const mapping = await admin.createRlsMapping({
      roleName: `${tag}_alpha`,
      pbiDatasetId: datasetId,
      pbiRoleName: 'RegionalManager',
    });

    assert.equal(
      await cachedTokenExists(userId),
      false,
      'the resolved RLS roles changed, so the cached identity is stale',
    );
    assert.equal(mapping.pbiRoleName, 'RegionalManager');
  });

  test('mapping preserves the exact casing of the Power BI role name', async () => {
    const mapping = await admin.createRlsMapping({
      roleName: `${tag}_beta`,
      pbiDatasetId: datasetId,
      pbiRoleName: 'MiXeDCaseRole',
    });
    assert.equal(
      mapping.pbiRoleName,
      'MiXeDCaseRole',
      'normalising case here would silently break RLS matching',
    );
  });

  test('a duplicate mapping is a 400, not a silent no-op', async () => {
    await admin.createRlsMapping({
      roleName: `${tag}_gamma`,
      pbiDatasetId: datasetId,
      pbiRoleName: 'Dup',
    });
    await assert.rejects(
      () =>
        admin.createRlsMapping({
          roleName: `${tag}_gamma`,
          pbiDatasetId: datasetId,
          pbiRoleName: 'Dup',
        }),
      (err: { status?: number }) => err.status === 400,
    );
  });

  test('deleting a mapping invalidates the affected users', async () => {
    const mapping = await admin.createRlsMapping({
      roleName: `${tag}_alpha`,
      pbiDatasetId: datasetId,
      pbiRoleName: 'ToDelete',
    });
    await primeCachesFor(userId);
    await admin.deleteRlsMapping(mapping.id);
    assert.equal(await cachedTokenExists(userId), false);
  });

  test('deleting an unknown mapping is a 404', async () => {
    await assert.rejects(
      () => admin.deleteRlsMapping('00000000-0000-4000-8000-000000000999'),
      (err: { status?: number }) => err.status === 404,
    );
  });
});
