import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../auth/jwt.js';
import { query } from '../db/pool.js';
import { unauthorized, forbidden } from '../utils/errors.js';
import type { AuthenticatedUser } from '../types/domain.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

/**
 * Bearer-token authentication.
 *
 * The JWT is only used to establish *who* the caller is. Authorization data
 * (roles, report grants) is re-read from the database on every request that
 * needs it, so a revoked role takes effect immediately rather than when the
 * 15-minute token happens to expire.
 */
export async function requireAuth(
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      throw unauthorized('Missing Bearer token');
    }

    const claims = verifyAccessToken(header.slice(7).trim());

    const { rows } = await query<{
      id: string;
      email: string;
      display_name: string;
      department: string | null;
      effective_username: string;
      is_active: boolean;
      roles: string[] | null;
      is_admin: boolean;
    }>(
      `SELECT u.id,
              u.email::text                       AS email,
              u.display_name,
              u.department,
              u.effective_username,
              u.is_active,
              array_remove(array_agg(r.name), NULL)          AS roles,
              COALESCE(bool_or(r.is_admin), FALSE)           AS is_admin
         FROM users u
         LEFT JOIN user_roles ur ON ur.user_id = u.id
         LEFT JOIN roles r       ON r.id = ur.role_id
        WHERE u.id = $1
        GROUP BY u.id`,
      [claims.sub],
    );

    const row = rows[0];
    // Deactivated mid-session: reject even though the JWT is still valid.
    if (!row || !row.is_active) {
      throw unauthorized('Account is inactive');
    }

    req.user = {
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      department: row.department,
      effectiveUsername: row.effective_username,
      isActive: row.is_active,
      roles: row.roles ?? [],
      isAdmin: row.is_admin,
    };

    next();
  } catch (err) {
    next(err);
  }
}

/** Gate for /api/admin/*. Must be mounted after requireAuth. */
export function requireAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!req.user?.isAdmin) {
    next(forbidden('Administrator access required'));
    return;
  }
  next();
}
