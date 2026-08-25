import type { Request, Response, NextFunction } from 'express';
import { verifyAccessToken } from '../auth/jwt.js';
import { findUserById } from '../services/users.service.js';
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

    // Roles are re-read from the database on every request rather than trusted
    // from the JWT, so a revoked role takes effect immediately instead of when
    // the 15-minute token happens to expire.
    const user = await findUserById(claims.sub);

    // Deactivated mid-session: reject even though the JWT is still valid.
    if (!user || !user.isActive) {
      throw unauthorized('Account is inactive');
    }

    req.user = {
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      department: user.department,
      effectiveUsername: user.effectiveUsername,
      isActive: user.isActive,
      roles: user.roles,
      isAdmin: user.isAdmin,
    };

    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Gate for /api/admin/*. Must be mounted after requireAuth.
 *
 * Not yet wired to any route — there is no admin API. Kept because the
 * `roles.is_admin` column and the JWT `adm` claim already carry the flag, so
 * this is the one place that decision should be made when those routes land.
 * If admin functionality is dropped, delete this together with `is_admin`.
 */
export function requireAdmin(req: Request, _res: Response, next: NextFunction): void {
  if (!req.user?.isAdmin) {
    next(forbidden('Administrator access required'));
    return;
  }
  next();
}
