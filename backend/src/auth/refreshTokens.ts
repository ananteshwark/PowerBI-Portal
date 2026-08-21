import crypto from 'node:crypto';
import { query, withTransaction } from '../db/pool.js';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { unauthorized } from '../utils/errors.js';

/**
 * Rotating refresh tokens with reuse detection.
 *
 * On every refresh the presented token is revoked and a successor issued. If a
 * token that has *already* been rotated is presented again, that means someone
 * replayed a stolen value — we revoke the whole family, forcing re-login. This
 * is the standard defence for a token that, unlike the 15-minute access token,
 * is long-lived.
 */

const hash = (token: string) =>
  crypto.createHash('sha256').update(token).digest('hex');

const newOpaqueToken = () => crypto.randomBytes(32).toString('base64url');

interface IssueContext {
  userId: string;
  familyId?: string;
  userAgent?: string | undefined;
  ipAddress?: string | undefined;
}

export async function issueRefreshToken(ctx: IssueContext): Promise<string> {
  const token = newOpaqueToken();
  const expiresAt = new Date(Date.now() + config.jwt.refreshTtlSeconds * 1000);

  await query(
    `INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, user_agent, ip_address)
     VALUES ($1, $2, COALESCE($3::uuid, gen_random_uuid()), $4, $5, $6)`,
    [ctx.userId, hash(token), ctx.familyId ?? null, expiresAt, ctx.userAgent ?? null, ctx.ipAddress ?? null],
  );

  return token;
}

export interface RotationResult {
  userId: string;
  token: string;
}

/**
 * Validate + rotate. Throws 401 for anything that is not a live, unexpired,
 * unrevoked token.
 */
export async function rotateRefreshToken(
  presented: string,
  ctx: { userAgent?: string | undefined; ipAddress?: string | undefined },
): Promise<RotationResult> {
  const presentedHash = hash(presented);

  // Set when we detect a replay. The revocation it triggers CANNOT run inside
  // the transaction below: that transaction is rolled back by the 401 we throw,
  // which would silently undo the revocation and leave the stolen family live.
  // We therefore record the intent here and act on it after the rollback.
  let compromisedFamily: { familyId: string; userId: string } | null = null;

  try {
    return await withTransaction(async (client) => {
      // FOR UPDATE serialises concurrent refreshes of the same token, so a
      // double-submit cannot mint two successors.
      const { rows } = await client.query<{
        id: string;
        user_id: string;
        family_id: string;
        expires_at: Date;
        revoked_at: Date | null;
      }>(
        `SELECT id, user_id, family_id, expires_at, revoked_at
           FROM refresh_tokens
          WHERE token_hash = $1
          FOR UPDATE`,
        [presentedHash],
      );

      const row = rows[0];
      if (!row) throw unauthorized('Invalid refresh token');

      if (row.revoked_at) {
        // Replay of an already-rotated token => assume the value was stolen.
        // Flag the family; the revocation happens in the finally block, outside
        // this transaction, so it survives the rollback.
        compromisedFamily = { familyId: row.family_id, userId: row.user_id };
        throw unauthorized('Refresh token has already been used');
      }

      if (row.expires_at.getTime() <= Date.now()) {
        throw unauthorized('Refresh token expired');
      }

      const successor = newOpaqueToken();
      const expiresAt = new Date(Date.now() + config.jwt.refreshTtlSeconds * 1000);

      const inserted = await client.query<{ id: string }>(
        `INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at, user_agent, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        [row.user_id, hash(successor), row.family_id, expiresAt, ctx.userAgent ?? null, ctx.ipAddress ?? null],
      );

      await client.query(
        `UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $2 WHERE id = $1`,
        [row.id, inserted.rows[0]!.id],
      );

      return { userId: row.user_id, token: successor };
    });
  } finally {
    if (compromisedFamily) {
      const { familyId, userId } = compromisedFamily as { familyId: string; userId: string };
      // Fresh connection from the pool — the transaction above has ended.
      await query(
        `UPDATE refresh_tokens
            SET revoked_at = now()
          WHERE family_id = $1 AND revoked_at IS NULL`,
        [familyId],
      ).then(
        ({ rowCount }) =>
          logger.warn(
            { userId, familyId, revoked: rowCount },
            'Refresh token reuse detected — revoked entire token family',
          ),
        // Never let a failed revocation replace the 401 we are throwing.
        (err) => logger.error({ err, familyId }, 'Failed to revoke compromised token family'),
      );
    }
  }
}

/** Logout: revoke just this token's family. */
export async function revokeRefreshToken(presented: string): Promise<void> {
  await query(
    `UPDATE refresh_tokens
        SET revoked_at = now()
      WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE token_hash = $1)
        AND revoked_at IS NULL`,
    [hash(presented)],
  );
}

/** Revoke every session for a user (password change, deactivation, admin action). */
export async function revokeAllForUser(userId: string): Promise<void> {
  await query(
    `UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
    [userId],
  );
}

/** Housekeeping; call from a cron. Expired rows are dead weight. */
export async function purgeExpiredTokens(): Promise<number> {
  const { rowCount } = await query(
    `DELETE FROM refresh_tokens WHERE expires_at < now() - INTERVAL '30 days'`,
  );
  return rowCount ?? 0;
}
