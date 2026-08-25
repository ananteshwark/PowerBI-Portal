/**
 * Tests for the two rules that actually protect data:
 *   1. cache keys change when the RLS identity changes
 *   2. concurrent misses collapse into one upstream call (single-flight)
 *
 * Run: npm test
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

process.env.DATABASE_URL ??= 'postgresql://localhost:5432/test';
process.env.JWT_SECRET ??= 'test-secret-that-is-at-least-32-characters-long';
process.env.AZURE_TENANT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_ID ??= '00000000-0000-0000-0000-000000000000';
process.env.AZURE_CLIENT_SECRET ??= 'test-secret';

const { identityFingerprint, getOrCreateEmbedToken, invalidateUser } = await import(
  '../src/services/tokenCache.js'
);

describe('identityFingerprint', () => {
  test('is stable regardless of role ordering', () => {
    assert.equal(
      identityFingerprint('a@b.com', ['Manager', 'Analyst']),
      identityFingerprint('a@b.com', ['Analyst', 'Manager']),
    );
  });

  test('changes when a role is added — the stale token can never be served', () => {
    assert.notEqual(
      identityFingerprint('a@b.com', ['Analyst']),
      identityFingerprint('a@b.com', ['Analyst', 'Manager']),
    );
  });

  test('changes when the effective username changes', () => {
    assert.notEqual(
      identityFingerprint('a@b.com', ['Analyst']),
      identityFingerprint('c@d.com', ['Analyst']),
    );
  });

  test('distinguishes "no RLS" from an empty-role identity', () => {
    assert.notEqual(identityFingerprint(null, []), identityFingerprint('a@b.com', []));
  });
});

describe('getOrCreateEmbedToken', () => {
  const makeToken = (token: string) => ({
    token,
    embedUrl: 'https://app.powerbi.com/embed',
    reportId: 'r1',
    expiresAtMs: Date.now() + 60 * 60 * 1000,
    rlsUsername: 'a@b.com',
    rlsRoles: ['Analyst'],
  });

  test('collapses concurrent misses into a single upstream call', async () => {
    let calls = 0;
    const factory = async () => {
      calls += 1;
      await new Promise((r) => setTimeout(r, 20));
      return makeToken('shared');
    };

    const args = { userId: 'u-singleflight', reportId: 'r1', fingerprint: 'fp1' };
    const results = await Promise.all(
      Array.from({ length: 8 }, () => getOrCreateEmbedToken(args, factory)),
    );

    assert.equal(calls, 1, 'factory must run exactly once for concurrent misses');
    assert.ok(results.every((r) => r.value.token === 'shared'));
  });

  test('serves a subsequent request from cache', async () => {
    let calls = 0;
    const factory = async () => {
      calls += 1;
      return makeToken('cached');
    };

    const args = { userId: 'u-cache', reportId: 'r1', fingerprint: 'fp1' };
    const first = await getOrCreateEmbedToken(args, factory);
    const second = await getOrCreateEmbedToken(args, factory);

    assert.equal(calls, 1);
    assert.equal(first.cached, false);
    assert.equal(second.cached, true);
  });

  test('a different fingerprint does not hit the cached entry', async () => {
    let calls = 0;
    const factory = async () => {
      calls += 1;
      return makeToken(`t${calls}`);
    };

    await getOrCreateEmbedToken({ userId: 'u-fp', reportId: 'r1', fingerprint: 'fp1' }, factory);
    await getOrCreateEmbedToken({ userId: 'u-fp', reportId: 'r1', fingerprint: 'fp2' }, factory);

    assert.equal(calls, 2, 'a changed RLS identity must force a new token');
  });

  /**
   * REGRESSION: when Power BI rejects the token the browser holds, re-serving
   * the cached copy hands back the same rejected value. The client then errors
   * again, asks again, and loops. bypassCache must evict, not just skip the
   * read — otherwise a concurrent reader keeps serving the bad token until it
   * expires.
   */
  test('bypassCache mints a new token and evicts the bad one', async () => {
    let calls = 0;
    const factory = async () => {
      calls += 1;
      return makeToken(`token-${calls}`);
    };

    const args = { userId: 'u-bypass', reportId: 'r1', fingerprint: 'fp1' };

    const first = await getOrCreateEmbedToken(args, factory);
    assert.equal(first.value.token, 'token-1');

    // Normal read still hits the cache.
    assert.equal((await getOrCreateEmbedToken(args, factory)).cached, true);
    assert.equal(calls, 1);

    // Power BI rejected token-1: force a fresh mint.
    const forced = await getOrCreateEmbedToken({ ...args, bypassCache: true }, factory);
    assert.equal(forced.value.token, 'token-2');
    assert.equal(forced.cached, false);
    assert.equal(calls, 2);

    // The bad token must be gone, not lingering for the next reader.
    const after = await getOrCreateEmbedToken(args, factory);
    assert.equal(after.value.token, 'token-2', 'the evicted token must not come back');
    assert.equal(calls, 2, 'the replacement should now be cached');
  });

  /**
   * REGRESSION: invalidateUser cleared the store, but a mint already in flight
   * resolved afterwards and wrote its result — silently re-populating the cache
   * that had just been cleared on logout or a role change, with a token derived
   * from the identity the user held *before* the change.
   */
  test('a mint in flight during invalidateUser does not repopulate the cache', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;

    const slowFactory = async () => {
      calls += 1;
      await gate; // still minting while invalidateUser runs
      return makeToken('stale-identity');
    };

    const args = { userId: 'u-epoch', reportId: 'r1', fingerprint: 'fp1' };
    const pending = getOrCreateEmbedToken(args, slowFactory);

    await invalidateUser('u-epoch');
    release();

    // The in-flight caller still gets its token: it was authorized when the
    // request began.
    assert.equal((await pending).value.token, 'stale-identity');

    // But nobody else may be served it.
    const next = await getOrCreateEmbedToken(args, async () => {
      calls += 1;
      return makeToken('fresh');
    });
    assert.equal(next.value.token, 'fresh', 'the invalidated token must not be served again');
    assert.equal(calls, 2);
  });

  test('does not cache a token that is already inside the refresh skew', async () => {
    let calls = 0;
    const factory = async () => {
      calls += 1;
      return { ...makeToken('short'), expiresAtMs: Date.now() + 10_000 };
    };

    const args = { userId: 'u-short', reportId: 'r1', fingerprint: 'fp1' };
    await getOrCreateEmbedToken(args, factory);
    await getOrCreateEmbedToken(args, factory);

    assert.equal(calls, 2, 'a near-expiry token must not be reused');
  });
});
