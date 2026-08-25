import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { badRequest, unauthorized } from '../utils/errors.js';
import { signAccessToken } from '../auth/jwt.js';
import { issueRefreshToken } from '../auth/refreshTokens.js';
import { recordAudit } from '../services/audit.service.js';
import { toSessionUser } from '../services/users.service.js';
import { resolveEntraUser } from '../services/entraUsers.service.js';
import {
  buildAuthorizationUrl,
  createPkce,
  exchangeCode,
  randomToken,
  verifyIdToken,
} from '../auth/entra/oidc.js';
import { loginIpLimiter } from '../middleware/rateLimit.js';

export const entraAuthRouter = Router();

/**
 * The in-flight sign-in state (PKCE verifier + nonce) has to survive the round
 * trip to Entra and come back. It lives in a short-lived HttpOnly cookie rather
 * than server memory so the flow works across multiple backend instances
 * without a shared store.
 *
 * SameSite=Lax rather than Strict is required, not sloppiness: the callback
 * arrives as a top-level cross-site navigation from login.microsoftonline.com,
 * and Strict would withhold the cookie, breaking every sign-in.
 */
const TX_COOKIE = 'pbp_oidc_tx';
const TX_TTL_SECONDS = 600;

const txCookieOptions = () => ({
  httpOnly: true,
  secure: config.http.cookieSecure,
  sameSite: 'lax' as const,
  path: '/api/auth/entra',
  domain: config.http.cookieDomain,
  maxAge: TX_TTL_SECONDS * 1000,
});

const REFRESH_COOKIE = 'pbp_rt';
const refreshCookieOptions = () => ({
  httpOnly: true,
  secure: config.http.cookieSecure,
  sameSite: 'strict' as const,
  path: '/api/auth',
  domain: config.http.cookieDomain,
  maxAge: config.jwt.refreshTtlSeconds * 1000,
});

const clientMeta = (req: Request) => ({
  userAgent: req.get('user-agent') ?? undefined,
  ipAddress: req.ip,
});

/** Reject every route with 404 when Entra sign-in is not configured. */
entraAuthRouter.use((_req: Request, res: Response, next: NextFunction) => {
  if (!config.auth.entraEnabled) {
    res.status(404).json({
      error: { code: 'not_found', message: 'Entra ID sign-in is not enabled' },
    });
    return;
  }
  next();
});

// ------------------------------------------------------------------ start --
/**
 * GET /api/auth/entra/login — redirect the browser to Entra.
 *
 * Rate limited: this endpoint issues cookies and hits the discovery endpoint,
 * so it should not be a free amplifier.
 */
entraAuthRouter.get(
  '/login',
  loginIpLimiter,
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const { verifier, challenge } = createPkce();
      const state = randomToken();
      const nonce = randomToken();

      res.cookie(
        TX_COOKIE,
        JSON.stringify({ v: verifier, s: state, n: nonce }),
        txCookieOptions(),
      );

      res.redirect(await buildAuthorizationUrl({ state, nonce, codeChallenge: challenge }));
    } catch (err) {
      next(err);
    }
  },
);

// --------------------------------------------------------------- callback --
const callbackSchema = z.object({
  code: z.string().min(1).max(4096).optional(),
  state: z.string().min(1).max(512).optional(),
  error: z.string().max(256).optional(),
  error_description: z.string().max(2048).optional(),
});

const txSchema = z.object({
  v: z.string().min(1),
  s: z.string().min(1),
  n: z.string().min(1),
});

entraAuthRouter.get('/callback', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const params = callbackSchema.parse(req.query);

    if (params.error) {
      // The user declined consent, or the tenant blocked the app. Their choice,
      // not an error on our side — and the IdP's text is not ours to echo into
      // the page, so it goes to the log.
      logger.warn(
        { error: params.error, description: params.error_description },
        'Entra returned an error at the callback',
      );
      res.clearCookie(TX_COOKIE, { ...txCookieOptions(), maxAge: undefined });
      throw unauthorized('Sign-in was not completed');
    }

    if (!params.code || !params.state) throw badRequest('Missing authorization code or state');

    const raw = req.cookies?.[TX_COOKIE] as string | undefined;
    if (!raw) {
      // No transaction cookie: the flow did not start here, the cookie expired,
      // or this is a forged callback.
      throw unauthorized('Sign-in session expired. Please try again.');
    }

    let tx: z.infer<typeof txSchema>;
    try {
      tx = txSchema.parse(JSON.parse(raw));
    } catch {
      throw unauthorized('Sign-in session is invalid. Please try again.');
    }

    // The transaction is single-use whatever happens next.
    res.clearCookie(TX_COOKIE, { ...txCookieOptions(), maxAge: undefined });

    // CSRF: without this, an attacker can complete a sign-in in the victim's
    // browser using their OWN authorization code, silently logging the victim
    // into the attacker's account.
    if (params.state !== tx.s) {
      logger.warn(clientMeta(req), 'Entra callback state mismatch');
      throw unauthorized('Sign-in state mismatch. Please try again.');
    }

    const tokens = await exchangeCode({ code: params.code, codeVerifier: tx.v });
    if (!tokens.id_token) throw unauthorized('Identity provider returned no ID token');

    const claims = await verifyIdToken(tokens.id_token, tx.n);
    const { user, provisioned, linked } = await resolveEntraUser(claims);

    const { token: accessToken, expiresIn } = signAccessToken({
      userId: user.id,
      email: user.email,
      displayName: user.displayName,
      roles: user.roles,
      isAdmin: user.isAdmin,
    });
    const refreshToken = await issueRefreshToken({ userId: user.id, ...clientMeta(req) });

    await recordLogin(user.id, { provisioned, linked, oid: claims.oid }, req);

    res.cookie(REFRESH_COOKIE, refreshToken, refreshCookieOptions());

    // A browser redirect cannot carry the access token in a response body, and
    // putting it in the URL would leak it into history, logs and Referer. The
    // SPA calls /api/auth/refresh on landing and trades the cookie for one.
    if (req.query.format === 'json') {
      res.json({ accessToken, expiresIn, user: toSessionUser(user) });
      return;
    }
    res.redirect(config.entra.postLoginRedirect);
  } catch (err) {
    next(err);
  }
});

async function recordLogin(
  userId: string,
  detail: Record<string, unknown>,
  req: Request,
): Promise<void> {
  const { query } = await import('../db/pool.js');
  await query(`UPDATE users SET last_login_at = now() WHERE id = $1`, [userId]).catch(() => undefined);
  recordAudit({
    userId,
    action: 'login',
    detail: { provider: 'entra', ...detail },
    ipAddress: req.ip,
    userAgent: req.get('user-agent') ?? null,
  });
}
