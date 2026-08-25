import crypto from 'node:crypto';
import { config } from '../../config/env.js';
import { logger } from '../../utils/logger.js';
import { unauthorized, upstreamError } from '../../utils/errors.js';

/**
 * Microsoft Entra ID sign-in via OIDC authorization code + PKCE.
 *
 * Written against the raw protocol rather than MSAL's browser-oriented helpers,
 * because the confidential-client flow here is small and the security-relevant
 * steps — PKCE, state, nonce, signature and issuer checks — are exactly the
 * parts worth having in plain sight.
 *
 * This is a DIFFERENT app registration from the Power BI service principal.
 * That one acts as itself to mint embed tokens; this one signs users in.
 * Sharing a registration would hand the sign-in path the service principal's
 * Power BI access.
 */

// ------------------------------------------------------------------- PKCE --
export interface Pkce {
  verifier: string;
  challenge: string;
}

/**
 * S256 only. The `plain` method offers no protection against an attacker who
 * can read the authorization request, which is the whole threat PKCE addresses.
 */
export function createPkce(): Pkce {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

export const randomToken = () => crypto.randomBytes(32).toString('base64url');

// -------------------------------------------------------------- discovery --
interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface Jwk extends crypto.JsonWebKey {
  kid: string;
  kty: string;
}

let discoveryCache: { doc: DiscoveryDocument; fetchedAt: number } | null = null;
let jwksCache: { keys: Jwk[]; fetchedAt: number } | null = null;

const DISCOVERY_TTL_MS = 24 * 60 * 60 * 1000;
const JWKS_TTL_MS = 60 * 60 * 1000;
const HTTP_TIMEOUT_MS = 10_000;

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw upstreamError(`Identity provider returned ${res.status}`, {
        url,
        body: body.slice(0, 500),
      });
    }
    return (await res.json()) as T;
  } catch (err) {
    if ((err as Error).name === 'AbortError') {
      throw upstreamError(`Identity provider timed out after ${HTTP_TIMEOUT_MS}ms`, { url });
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export async function getDiscovery(): Promise<DiscoveryDocument> {
  if (discoveryCache && Date.now() - discoveryCache.fetchedAt < DISCOVERY_TTL_MS) {
    return discoveryCache.doc;
  }
  const doc = await fetchJson<DiscoveryDocument>(config.entra.discoveryUrl);
  discoveryCache = { doc, fetchedAt: Date.now() };
  return doc;
}

/**
 * `forceRefresh` exists for one case: a token signed with a key we have not
 * seen. Entra rotates signing keys, so an unknown `kid` is normal rather than
 * an attack, and refusing it outright would break sign-in for hours at every
 * rotation. Refreshed at most once per verification, so an attacker cannot use
 * unknown kids to hammer the JWKS endpoint.
 */
async function getJwks(forceRefresh = false): Promise<Jwk[]> {
  if (!forceRefresh && jwksCache && Date.now() - jwksCache.fetchedAt < JWKS_TTL_MS) {
    return jwksCache.keys;
  }
  const { jwks_uri } = await getDiscovery();
  const { keys } = await fetchJson<{ keys: Jwk[] }>(jwks_uri);
  jwksCache = { keys, fetchedAt: Date.now() };
  return keys;
}

/** Test seam: drop cached discovery/JWKS between cases. */
export function resetOidcCaches(): void {
  discoveryCache = null;
  jwksCache = null;
}

// ------------------------------------------------------- authorization URL --
export async function buildAuthorizationUrl(args: {
  state: string;
  nonce: string;
  codeChallenge: string;
}): Promise<string> {
  const { authorization_endpoint } = await getDiscovery();
  const url = new URL(authorization_endpoint);
  url.searchParams.set('client_id', config.entra.clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('redirect_uri', config.entra.redirectUri);
  url.searchParams.set('response_mode', 'query');
  // openid+profile+email is all we need; we deliberately request no Graph or
  // Power BI scopes, so a leaked authorization code buys nothing beyond identity.
  url.searchParams.set('scope', 'openid profile email');
  url.searchParams.set('state', args.state);
  url.searchParams.set('nonce', args.nonce);
  url.searchParams.set('code_challenge', args.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');
  return url.toString();
}

// ------------------------------------------------------------ code exchange --
interface TokenResponse {
  id_token: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
}

export async function exchangeCode(args: {
  code: string;
  codeVerifier: string;
}): Promise<TokenResponse> {
  const { token_endpoint } = await getDiscovery();

  const body = new URLSearchParams({
    client_id: config.entra.clientId,
    client_secret: config.entra.clientSecret,
    code: args.code,
    redirect_uri: config.entra.redirectUri,
    grant_type: 'authorization_code',
    code_verifier: args.codeVerifier,
  });

  return fetchJson<TokenResponse>(token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
}

// ------------------------------------------------------- ID token verify ---
export interface IdTokenClaims {
  /** Immutable object id. The ONLY safe key for an existing account. */
  oid: string;
  /** Tenant id. */
  tid: string;
  sub: string;
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  nonce?: string;
  name?: string;
  preferred_username?: string;
  email?: string;
}

const decodeSegment = <T>(segment: string): T =>
  JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as T;

/**
 * Verify an ID token: signature, issuer, audience, expiry, and nonce binding.
 *
 * Every one of these matters. Skipping the signature accepts anything; skipping
 * `iss` accepts a token from another tenant; skipping `aud` accepts a token
 * minted for a different application (a confused-deputy); skipping `nonce`
 * accepts a token replayed from another session.
 */
export async function verifyIdToken(
  idToken: string,
  expectedNonce: string,
  now: number = Date.now(),
): Promise<IdTokenClaims> {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw unauthorized('Malformed ID token');

  const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

  let header: { alg: string; kid?: string };
  let claims: IdTokenClaims;
  try {
    header = decodeSegment(headerB64);
    claims = decodeSegment(payloadB64);
  } catch {
    throw unauthorized('Malformed ID token');
  }

  // Algorithm is pinned. Accepting the token's own `alg` is how "alg: none"
  // and RS256/HS256 confusion attacks work.
  if (header.alg !== 'RS256') {
    throw unauthorized(`Unsupported ID token algorithm: ${header.alg}`);
  }
  if (!header.kid) throw unauthorized('ID token has no key id');

  let keys = await getJwks();
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    // Probably a key rotation rather than an attack. One refresh, then give up.
    keys = await getJwks(true);
    jwk = keys.find((k) => k.kid === header.kid);
  }
  if (!jwk) throw unauthorized('ID token signed with an unknown key');

  let publicKey: crypto.KeyObject;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch (err) {
    logger.error({ err, kid: header.kid }, 'Could not import identity provider JWK');
    throw unauthorized('ID token key could not be used');
  }

  const signatureValid = crypto.verify(
    'RSA-SHA256',
    Buffer.from(`${headerB64}.${payloadB64}`),
    publicKey,
    Buffer.from(signatureB64, 'base64url'),
  );
  if (!signatureValid) throw unauthorized('ID token signature is invalid');

  // --- claim checks, all of them ------------------------------------------
  const { issuer } = await getDiscovery();
  // Entra's discovery issuer contains a {tenantid} placeholder for multi-tenant
  // apps; compare the concrete tenant form as well.
  const expectedIssuers = new Set([issuer, issuer.replace('{tenantid}', claims.tid ?? '')]);
  if (!expectedIssuers.has(claims.iss)) {
    throw unauthorized('ID token issued by an unexpected issuer');
  }

  if (claims.aud !== config.entra.clientId) {
    throw unauthorized('ID token was not issued for this application');
  }

  // 60s leeway for clock skew between us and the IdP.
  const nowSeconds = Math.floor(now / 1000);
  if (typeof claims.exp !== 'number' || claims.exp + 60 < nowSeconds) {
    throw unauthorized('ID token has expired');
  }
  if (typeof claims.iat === 'number' && claims.iat - 60 > nowSeconds) {
    throw unauthorized('ID token is not yet valid');
  }

  if (!claims.nonce || claims.nonce !== expectedNonce) {
    throw unauthorized('ID token nonce does not match this sign-in attempt');
  }

  if (!claims.oid) throw unauthorized('ID token has no object id');

  // Single-tenant deployments must not accept another tenant's users, even
  // though `aud` and the signature would both pass for a multi-tenant app
  // registration someone later flips on.
  if (config.entra.tenantId !== 'common' && claims.tid !== config.entra.tenantId) {
    throw unauthorized('ID token is from a different tenant');
  }

  return claims;
}
