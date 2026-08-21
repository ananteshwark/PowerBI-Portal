/**
 * Integration tests for refresh-token rotation and reuse detection.
 *
 * Requires a real PostgreSQL — reuse detection depends on transaction
 * semantics that cannot be exercised against a mock. Skipped unless
 * TEST_DATABASE_URL points at a migrated, disposable database:
 *
 *   createdb portal_test
 *   TEST_DATABASE_URL=postgres://…/portal_test npm run migrate
 *   TEST_DATABASE_URL=postgres://…/portal_test npm test
 */
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';

const TEST_DB = process.env.TEST_DATABASE_URL;

process.env.DATABASE_URL = TEST_DB ?? 'postgresql://localhost:5432/unused';
process.env.JWT_SECRET ??= 'test-secret-that-is-at-least-32-characters-long';
process.env.AZURE_TENANT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_SECRET ??= 'test-secret';

describe('refresh token rotation', { skip: TEST_DB ? false : 'TEST_DATABASE_URL not set' }, () => {
  let issueRefreshToken: typeof import('../src/auth/refreshTokens.js').issueRefreshToken;
  let rotateRefreshToken: typeof import('../src/auth/refreshTokens.js').rotateRefreshToken;
  let query: typeof import('../src/db/pool.js').query;
  let closePool: typeof import('../src/db/pool.js').closePool;
  let userId: string;

  before(async () => {
    ({ issueRefreshToken, rotateRefreshToken } = await import('../src/auth/refreshTokens.js'));
    ({ query, closePool } = await import('../src/db/pool.js'));

    const { rows } = await query<{ id: string }>(
      `INSERT INTO users (email, password_hash, display_name)
       VALUES ($1, 'x', 'Rotation Test') RETURNING id`,
      [`rotation-${Date.now()}@test.local`],
    );
    userId = rows[0]!.id;
  });

  after(async () => {
    if (userId) await query('DELETE FROM users WHERE id = $1', [userId]);
    await closePool();
  });

  /** Newest token row for this user — used to identify the family under test. */
  async function newestFamilyId(): Promise<string> {
    const { rows } = await query<{ family_id: string }>(
      `SELECT family_id FROM refresh_tokens
        WHERE user_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`,
      [userId],
    );
    return rows[0]!.family_id;
  }

  async function liveTokensInFamily(familyId: string): Promise<number> {
    const { rows } = await query<{ live: string }>(
      `SELECT count(*) FILTER (WHERE revoked_at IS NULL)::text AS live
         FROM refresh_tokens WHERE family_id = $1`,
      [familyId],
    );
    return Number(rows[0]!.live);
  }

  test('rotation issues a different token and leaves exactly one live', async () => {
    const first = await issueRefreshToken({ userId });
    const familyId = await newestFamilyId();

    const { token: second } = await rotateRefreshToken(first, {});
    assert.notEqual(first, second);

    // The successor replaces the predecessor rather than accumulating.
    assert.equal(await liveTokensInFamily(familyId), 1);

    const { rows } = await query<{ replaced: boolean }>(
      `SELECT (replaced_by IS NOT NULL) AS replaced
         FROM refresh_tokens
        WHERE family_id = $1 AND revoked_at IS NOT NULL`,
      [familyId],
    );
    assert.equal(rows[0]?.replaced, true, 'the rotated token should point at its successor');
  });

  /**
   * REGRESSION: the family revocation used to run inside the same transaction
   * as the 401 we throw, so ROLLBACK silently undid it — a stolen token was
   * detected but the victim's live session stayed usable. The revocation must
   * happen after the rollback.
   */
  test('replaying a rotated token revokes the whole family, surviving the rollback', async () => {
    const original = await issueRefreshToken({ userId });
    const familyId = await newestFamilyId();
    const { token: current } = await rotateRefreshToken(original, {});

    assert.equal(await liveTokensInFamily(familyId), 1, 'precondition: one live token');

    // Attacker replays the original.
    await assert.rejects(
      () => rotateRefreshToken(original, {}),
      (err: { status?: number }) => err.status === 401,
    );

    // The victim's still-current token must now be dead too.
    await assert.rejects(
      () => rotateRefreshToken(current, {}),
      (err: { status?: number }) => err.status === 401,
      'family revocation was rolled back — the stolen session is still live',
    );

    assert.equal(
      await liveTokensInFamily(familyId),
      0,
      'no token in a compromised family may remain live',
    );
  });

  test('an unknown token is rejected', async () => {
    await assert.rejects(
      () => rotateRefreshToken('not-a-real-token', {}),
      (err: { status?: number }) => err.status === 401,
    );
  });
});
