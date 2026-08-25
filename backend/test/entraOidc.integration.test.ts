/**
 * Entra ID sign-in.
 *
 * Runs the real flow against a stub issuer: a local HTTP server serving a
 * discovery document and JWKS, with ID tokens signed by a keypair generated
 * here. That covers everything the portal is responsible for — PKCE, state,
 * nonce, signature, issuer, audience, tenant, expiry, and the account-matching
 * rules. What it does not cover is Microsoft's own behaviour at the network
 * edge, which is configuration rather than logic.
 *
 * Most cases below are attacks. A sign-in flow that only gets tested on the
 * happy path is a sign-in flow whose checks are decorative.
 *
 * Requires TEST_DATABASE_URL pointing at a migrated, disposable database.
 */
import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

const TEST_DB = process.env.TEST_DATABASE_URL;

// ---- stub issuer -----------------------------------------------------------
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'test-key-1';
const TENANT = '11111111-2222-3333-4444-555555555555';
const CLIENT_ID = '99999999-8888-7777-6666-555555555555';

let issuerBase = '';
let server: http.Server;
/** What the stub's token endpoint will hand back next. */
let nextTokenResponse: Record<string, unknown> = {};

function signIdToken(claims: Record<string, unknown>, kid = KID): string {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const signingInput = `${enc(header)}.${enc(claims)}`;
  const sig = crypto
    .sign('RSA-SHA256', Buffer.from(signingInput), privateKey)
    .toString('base64url');
  return `${signingInput}.${sig}`;
}

const baseClaims = (over: Record<string, unknown> = {}) => ({
  iss: `${issuerBase}/v2.0`,
  aud: CLIENT_ID,
  tid: TENANT,
  oid: 'oid-alice',
  sub: 'sub-alice',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
  name: 'Alice Example',
  email: 'alice@contoso.com',
  ...over,
});

before(async () => {
  await new Promise<void>((resolve) => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url ?? '/', issuerBase || 'http://localhost');
      res.setHeader('content-type', 'application/json');

      if (url.pathname === '/.well-known/openid-configuration') {
        res.end(
          JSON.stringify({
            issuer: `${issuerBase}/v2.0`,
            authorization_endpoint: `${issuerBase}/authorize`,
            token_endpoint: `${issuerBase}/token`,
            jwks_uri: `${issuerBase}/keys`,
          }),
        );
        return;
      }
      if (url.pathname === '/keys') {
        const jwk = publicKey.export({ format: 'jwk' });
        res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, use: 'sig', alg: 'RS256' }] }));
        return;
      }
      if (url.pathname === '/token') {
        res.end(JSON.stringify(nextTokenResponse));
        return;
      }
      res.statusCode = 404;
      res.end('{}');
    });
    server.listen(0, '127.0.0.1', () => {
      issuerBase = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      resolve();
    });
  });

  // Config is read at import time, so every value must be set before the first
  // import of anything that pulls in config/env.
  process.env.DATABASE_URL = TEST_DB ?? 'postgresql://localhost:5432/unused';
  process.env.JWT_SECRET ??= 'test-secret-that-is-at-least-32-characters-long';
  process.env.AZURE_TENANT_ID ??= '00000000-0000-0000-0000-000000000000';
  process.env.AZURE_CLIENT_ID ??= '00000000-0000-0000-0000-000000000000';
  process.env.AZURE_CLIENT_SECRET ??= 'test-secret';
  process.env.AUTH_PROVIDER = 'both';
  process.env.ENTRA_OIDC_TENANT_ID = TENANT;
  process.env.ENTRA_OIDC_CLIENT_ID = CLIENT_ID;
  process.env.ENTRA_OIDC_CLIENT_SECRET = 'stub-secret';
  process.env.ENTRA_OIDC_REDIRECT_URI = 'http://localhost:4000/api/auth/entra/callback';
  process.env.ENTRA_OIDC_DISCOVERY_URL = `${issuerBase}/.well-known/openid-configuration`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe('Entra OIDC', { skip: TEST_DB ? false : 'TEST_DATABASE_URL not set' }, () => {
  let oidc: typeof import('../src/auth/entra/oidc.js');

  before(async () => {
    oidc = await import('../src/auth/entra/oidc.js');
    oidc.resetOidcCaches();
  });

  // ------------------------------------------------------------------ PKCE --
  test('PKCE challenge is the S256 hash of the verifier', () => {
    const { verifier, challenge } = oidc.createPkce();
    const expected = crypto.createHash('sha256').update(verifier).digest('base64url');
    assert.equal(challenge, expected);
    assert.ok(verifier.length >= 43, 'verifier must meet the RFC 7636 minimum length');
  });

  test('each sign-in gets a distinct verifier', () => {
    assert.notEqual(oidc.createPkce().verifier, oidc.createPkce().verifier);
  });

  test('authorization URL carries S256 PKCE, state and nonce', async () => {
    const url = new URL(
      await oidc.buildAuthorizationUrl({ state: 'st', nonce: 'no', codeChallenge: 'ch' }),
    );
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
    assert.equal(url.searchParams.get('code_challenge'), 'ch');
    assert.equal(url.searchParams.get('state'), 'st');
    assert.equal(url.searchParams.get('nonce'), 'no');
    assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
    assert.equal(url.searchParams.get('response_type'), 'code');
    // No Graph or Power BI scopes: a stolen code must buy identity and nothing more.
    assert.equal(url.searchParams.get('scope'), 'openid profile email');
  });

  // -------------------------------------------------------- happy path -----
  test('a well-formed ID token verifies and returns its claims', async () => {
    const token = signIdToken(baseClaims({ nonce: 'n-1' }));
    const claims = await oidc.verifyIdToken(token, 'n-1');
    assert.equal(claims.oid, 'oid-alice');
    assert.equal(claims.email, 'alice@contoso.com');
  });

  // ------------------------------------------------------------- attacks ---
  const rejects = (token: string, nonce = 'n-1', why = '') =>
    assert.rejects(
      () => oidc.verifyIdToken(token, nonce),
      (err: { status?: number }) => err.status === 401,
      why,
    );

  test('rejects a tampered payload', async () => {
    const token = signIdToken(baseClaims({ nonce: 'n-1' }));
    const [h, , s] = token.split('.');
    const forged = Buffer.from(
      JSON.stringify(baseClaims({ nonce: 'n-1', oid: 'oid-attacker' })),
    ).toString('base64url');
    await rejects(`${h}.${forged}.${s}`, 'n-1', 'a re-signed-over payload must fail');
  });

  test('rejects a token signed by a different key', async () => {
    const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const header = { alg: 'RS256', typ: 'JWT', kid: KID };
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const input = `${enc(header)}.${enc(baseClaims({ nonce: 'n-1' }))}`;
    const sig = crypto.sign('RSA-SHA256', Buffer.from(input), other.privateKey).toString('base64url');
    await rejects(`${input}.${sig}`, 'n-1', 'signature must be checked against the JWKS');
  });

  test('rejects alg:none', async () => {
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${enc({ alg: 'none', typ: 'JWT', kid: KID })}.${enc(baseClaims({ nonce: 'n-1' }))}.`;
    await rejects(token, 'n-1', 'the classic JWT bypass must not work');
  });

  test('rejects an HS256 token signed with the public key as the HMAC secret', async () => {
    // RS256/HS256 confusion: if the verifier trusted the token's own alg, the
    // public key (which the attacker has) doubles as the shared secret.
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const input = `${enc({ alg: 'HS256', typ: 'JWT', kid: KID })}.${enc(baseClaims({ nonce: 'n-1' }))}`;
    const pem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const sig = crypto.createHmac('sha256', pem).update(input).digest('base64url');
    await rejects(`${input}.${sig}`, 'n-1');
  });

  test('rejects a mismatched nonce — a token replayed from another session', async () => {
    const token = signIdToken(baseClaims({ nonce: 'n-other' }));
    await rejects(token, 'n-1');
  });

  test('rejects a token with no nonce at all', async () => {
    await rejects(signIdToken(baseClaims()), 'n-1');
  });

  test('rejects a token minted for a different application', async () => {
    await rejects(signIdToken(baseClaims({ nonce: 'n-1', aud: 'some-other-app' })), 'n-1');
  });

  test('rejects a token from a different issuer', async () => {
    await rejects(signIdToken(baseClaims({ nonce: 'n-1', iss: 'https://evil.example/v2.0' })), 'n-1');
  });

  test('rejects a token from a different tenant', async () => {
    await rejects(
      signIdToken(baseClaims({ nonce: 'n-1', tid: '00000000-dead-beef-0000-000000000000' })),
      'n-1',
    );
  });

  test('rejects an expired token', async () => {
    const past = Math.floor(Date.now() / 1000) - 7200;
    await rejects(signIdToken(baseClaims({ nonce: 'n-1', iat: past, exp: past + 60 })), 'n-1');
  });

  test('allows small clock skew rather than failing a valid sign-in', async () => {
    // Issued 30s in "the future" relative to us — routine between two hosts.
    const soon = Math.floor(Date.now() / 1000) + 30;
    const claims = await oidc.verifyIdToken(
      signIdToken(baseClaims({ nonce: 'n-1', iat: soon, exp: soon + 3600 })),
      'n-1',
    );
    assert.equal(claims.oid, 'oid-alice');
  });

  test('rejects a token signed with an unknown key after one JWKS refresh', async () => {
    await rejects(signIdToken(baseClaims({ nonce: 'n-1' }), 'no-such-kid'), 'n-1');
  });

  test('rejects a malformed token', async () => {
    await rejects('not-a-jwt', 'n-1');
    await rejects('a.b', 'n-1');
  });
});

// ============================================================== provisioning
describe(
  'Entra account resolution',
  { skip: TEST_DB ? false : 'TEST_DATABASE_URL not set' },
  () => {
    let resolveEntraUser: typeof import('../src/services/entraUsers.service.js').resolveEntraUser;
    let query: typeof import('../src/db/pool.js').query;
    let closePool: typeof import('../src/db/pool.js').closePool;
    let configRef: typeof import('../src/config/env.js').config;

    const tag = `en${Date.now()}`;
    const email = `${tag}-alice@contoso.com`;

    const claimsFor = (over: Record<string, unknown> = {}) =>
      ({ ...baseClaims({ oid: `${tag}-oid`, email, nonce: 'n' }), ...over }) as never;

    before(async () => {
      ({ resolveEntraUser } = await import('../src/services/entraUsers.service.js'));
      ({ query, closePool } = await import('../src/db/pool.js'));
      ({ config: configRef } = await import('../src/config/env.js'));
    });

    beforeEach(async () => {
      await query(`DELETE FROM users WHERE email LIKE $1`, [`${tag}-%`]);
      // config is frozen-ish at import; mutate the nested objects for the cases
      // that depend on the flags.
      (configRef.entra as { autoProvision: boolean }).autoProvision = false;
      (configRef.entra as { linkByEmail: boolean }).linkByEmail = false;
      (configRef.entra as { tenantId: string }).tenantId = TENANT;
    });

    after(async () => {
      await query(`DELETE FROM users WHERE email LIKE $1`, [`${tag}-%`]);
      await closePool();
    });

    test('an unknown identity is refused when provisioning is off', async () => {
      await assert.rejects(
        () => resolveEntraUser(claimsFor()),
        (err: { status?: number }) => err.status === 401,
      );
    });

    test('provisioning creates an account with NO roles', async () => {
      (configRef.entra as { autoProvision: boolean }).autoProvision = true;
      const { user, provisioned } = await resolveEntraUser(claimsFor());

      assert.equal(provisioned, true);
      assert.deepEqual(user.roles, [], 'provisioning must never imply authorization');
      assert.equal(user.passwordHash, null, 'an SSO account should have no password');
    });

    test('a second sign-in matches the existing account by oid', async () => {
      (configRef.entra as { autoProvision: boolean }).autoProvision = true;
      const first = await resolveEntraUser(claimsFor());
      const second = await resolveEntraUser(claimsFor());

      assert.equal(second.user.id, first.user.id);
      assert.equal(second.provisioned, false);
    });

    /**
     * The account-takeover case. The `email` claim is not proof of ownership —
     * in many tenants it is self-service editable — so it must not, on its own,
     * grant access to an existing portal account.
     */
    test('does NOT match an existing account by email when linking is disabled', async () => {
      await query(
        `INSERT INTO users (email, password_hash, display_name) VALUES ($1, 'x', 'Local Alice')`,
        [email],
      );
      await assert.rejects(
        () => resolveEntraUser(claimsFor()),
        (err: { status?: number }) => err.status === 401,
        'an email claim alone must not take over a local account',
      );
    });

    test('links by email only when explicitly enabled', async () => {
      const { rows } = await query<{ id: string }>(
        `INSERT INTO users (email, password_hash, display_name)
         VALUES ($1, 'x', 'Local Alice') RETURNING id`,
        [email],
      );
      (configRef.entra as { linkByEmail: boolean }).linkByEmail = true;

      const { user, linked } = await resolveEntraUser(claimsFor());
      assert.equal(linked, true);
      assert.equal(user.id, rows[0]!.id, 'should attach to the existing account, not create one');
    });

    test('refuses to relink an account already bound to a different identity', async () => {
      await query(
        `INSERT INTO users (email, password_hash, display_name, entra_object_id)
         VALUES ($1, 'x', 'Local Alice', $2)`,
        [email, 'some-other-oid'],
      );
      (configRef.entra as { linkByEmail: boolean }).linkByEmail = true;

      await assert.rejects(
        () => resolveEntraUser(claimsFor()),
        (err: { status?: number }) => err.status === 401,
        'two directory accounts must not take turns owning one portal account',
      );
    });

    test('a deactivated user cannot sign in through SSO', async () => {
      await query(
        `INSERT INTO users (email, password_hash, display_name, entra_object_id, is_active)
         VALUES ($1, 'x', 'Local Alice', $2, FALSE)`,
        [email, `${tag}-oid`],
      );
      await assert.rejects(
        () => resolveEntraUser(claimsFor()),
        (err: { status?: number }) => err.status === 401,
      );
    });

    /**
     * effective_username is what USERPRINCIPALNAME() resolves against inside
     * the dataset's DAX, so rewriting it on sign-in would silently move which
     * rows the user can see.
     */
    test('sign-in never rewrites effective_username', async () => {
      await query(
        `INSERT INTO users (email, password_hash, display_name, entra_object_id, effective_username)
         VALUES ($1, 'x', 'Local Alice', $2, 'pinned@contoso.com')`,
        [email, `${tag}-oid`],
      );
      const { user } = await resolveEntraUser(claimsFor({ email: 'changed@contoso.com' }));
      assert.equal(user.effectiveUsername, 'pinned@contoso.com');
    });

    test('display name is refreshed from the directory', async () => {
      await query(
        `INSERT INTO users (email, password_hash, display_name, entra_object_id)
         VALUES ($1, 'x', 'Old Name', $2)`,
        [email, `${tag}-oid`],
      );
      const { user } = await resolveEntraUser(claimsFor({ name: 'New Name' }));
      assert.equal(user.displayName, 'New Name');
    });
  },
);
