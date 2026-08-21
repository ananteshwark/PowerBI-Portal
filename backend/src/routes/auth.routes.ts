import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { config } from '../config/env.js';
import { query } from '../db/pool.js';
import { signAccessToken } from '../auth/jwt.js';
import { verifyPassword, fakeVerify } from '../auth/password.js';
import {
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
} from '../auth/refreshTokens.js';
import { unauthorized } from '../utils/errors.js';
import { loginLimiter } from '../middleware/rateLimit.js';
import { requireAuth } from '../middleware/auth.middleware.js';
import { recordAudit } from '../services/audit.service.js';
import { invalidateUser } from '../services/tokenCache.js';

export const authRouter = Router();

const REFRESH_COOKIE = 'pbp_rt';

/**
 * Path-scoped so the refresh token is not attached to /api/embed or
 * /api/reports requests — it is only ever needed here, and not sending it
 * elsewhere shrinks its exposure. SameSite=Strict is the CSRF defence.
 */
const cookieOptions = () => ({
  httpOnly: true,
  secure: config.http.cookieSecure,
  sameSite: 'strict' as const,
  path: '/api/auth',
  domain: config.http.cookieDomain,
  maxAge: config.jwt.refreshTtlSeconds * 1000,
});

const loginSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(1).max(1024),
});

interface UserRow {
  id: string;
  email: string;
  display_name: string;
  password_hash: string | null;
  is_active: boolean;
  roles: string[] | null;
  is_admin: boolean;
}

async function loadUserByEmail(email: string): Promise<UserRow | undefined> {
  const { rows } = await query<UserRow>(
    `SELECT u.id,
            u.email::text AS email,
            u.display_name,
            u.password_hash,
            u.is_active,
            array_remove(array_agg(r.name), NULL) AS roles,
            COALESCE(bool_or(r.is_admin), FALSE)  AS is_admin
       FROM users u
       LEFT JOIN user_roles ur ON ur.user_id = u.id
       LEFT JOIN roles r       ON r.id = ur.role_id
      WHERE u.email = $1
      GROUP BY u.id`,
    [email],
  );
  return rows[0];
}

const clientMeta = (req: Request) => ({
  userAgent: req.get('user-agent') ?? undefined,
  ipAddress: req.ip,
});

// ------------------------------------------------------------------ login --
authRouter.post(
  '/login',
  loginLimiter,
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = loginSchema.parse(req.body);
      const user = await loadUserByEmail(email);

      // Same error, same approximate timing, whether the account is missing,
      // inactive, or the password is wrong — no account enumeration.
      if (!user || !user.is_active || !user.password_hash) {
        await fakeVerify(password);
        recordAudit({
          action: 'login_failed',
          detail: { email, reason: !user ? 'no_such_user' : 'inactive_or_sso_only' },
          ...clientMeta(req),
        });
        throw unauthorized('Invalid email or password');
      }

      if (!(await verifyPassword(user.password_hash, password))) {
        recordAudit({
          userId: user.id,
          action: 'login_failed',
          detail: { email, reason: 'bad_password' },
          ...clientMeta(req),
        });
        throw unauthorized('Invalid email or password');
      }

      const { token: accessToken, expiresIn } = signAccessToken({
        userId: user.id,
        email: user.email,
        displayName: user.display_name,
        roles: user.roles ?? [],
        isAdmin: user.is_admin,
      });

      const refreshToken = await issueRefreshToken({ userId: user.id, ...clientMeta(req) });

      await query(`UPDATE users SET last_login_at = now() WHERE id = $1`, [user.id]);
      recordAudit({ userId: user.id, action: 'login', ...clientMeta(req) });

      res.cookie(REFRESH_COOKIE, refreshToken, cookieOptions());
      res.json({
        accessToken,
        expiresIn,
        user: {
          id: user.id,
          email: user.email,
          displayName: user.display_name,
          roles: user.roles ?? [],
          isAdmin: user.is_admin,
        },
      });
    } catch (err) {
      next(err);
    }
  },
);

// ---------------------------------------------------------------- refresh --
authRouter.post('/refresh', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const presented = req.cookies?.[REFRESH_COOKIE] as string | undefined;
    if (!presented) throw unauthorized('No refresh token');

    const { userId, token: newRefresh } = await rotateRefreshToken(presented, clientMeta(req));

    const { rows } = await query<UserRow>(
      `SELECT u.id, u.email::text AS email, u.display_name, u.password_hash, u.is_active,
              array_remove(array_agg(r.name), NULL) AS roles,
              COALESCE(bool_or(r.is_admin), FALSE)  AS is_admin
         FROM users u
         LEFT JOIN user_roles ur ON ur.user_id = u.id
         LEFT JOIN roles r       ON r.id = ur.role_id
        WHERE u.id = $1
        GROUP BY u.id`,
      [userId],
    );

    const user = rows[0];
    if (!user || !user.is_active) throw unauthorized('Account is inactive');

    const { token: accessToken, expiresIn } = signAccessToken({
      userId: user.id,
      email: user.email,
      displayName: user.display_name,
      roles: user.roles ?? [],
      isAdmin: user.is_admin,
    });

    recordAudit({ userId: user.id, action: 'token_refresh', ...clientMeta(req) });

    res.cookie(REFRESH_COOKIE, newRefresh, cookieOptions());
    res.json({
      accessToken,
      expiresIn,
      user: {
        id: user.id,
        email: user.email,
        displayName: user.display_name,
        roles: user.roles ?? [],
        isAdmin: user.is_admin,
      },
    });
  } catch (err) {
    next(err);
  }
});

// ----------------------------------------------------------------- logout --
authRouter.post('/logout', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const presented = req.cookies?.[REFRESH_COOKIE] as string | undefined;
    if (presented) await revokeRefreshToken(presented);

    // Drop cached embed tokens too — otherwise a logged-out user's token
    // remains valid against Power BI for up to an hour.
    const header = req.headers.authorization;
    if (header?.startsWith('Bearer ')) {
      try {
        const { verifyAccessToken } = await import('../auth/jwt.js');
        const claims = verifyAccessToken(header.slice(7).trim());
        await invalidateUser(claims.sub);
        recordAudit({ userId: claims.sub, action: 'logout', ...clientMeta(req) });
      } catch {
        // Expired access token on logout is fine — the refresh token is gone.
      }
    }

    res.clearCookie(REFRESH_COOKIE, { ...cookieOptions(), maxAge: undefined });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------------- me ---
authRouter.get('/me', requireAuth, (req: Request, res: Response) => {
  const user = req.user!;
  res.json({
    id: user.id,
    email: user.email,
    displayName: user.displayName,
    department: user.department,
    roles: user.roles,
    isAdmin: user.isAdmin,
  });
});
