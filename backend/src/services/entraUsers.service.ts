import { query } from '../db/pool.js';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';
import { unauthorized } from '../utils/errors.js';
import { findUserById, type UserWithRoles } from './users.service.js';
import type { IdTokenClaims } from '../auth/entra/oidc.js';

/**
 * Map a verified Entra identity onto a portal account.
 *
 * This is the security-critical half of SSO, and the danger is subtler than the
 * protocol work. A verified ID token proves "this person controls this Entra
 * account". It does NOT prove they own whatever address sits in the `email`
 * claim: in many tenants that value is self-service editable, and a guest
 * account can carry an arbitrary one. Matching an existing portal user on email
 * therefore hands an attacker who can set their own directory email a route
 * into someone else's account, roles and RLS identity.
 *
 * So resolution keys on `oid`, which is immutable and tenant-scoped. Linking by
 * email exists because migrations need it, but is off by default, is one-time,
 * and only ever fires for an account that has never been linked before.
 */

export interface ResolvedEntraUser {
  user: UserWithRoles;
  /** True when this sign-in created the account. */
  provisioned: boolean;
  /** True when this sign-in attached an Entra identity to an existing account. */
  linked: boolean;
}

/** Best available human-readable address. Used for display, never for matching. */
const claimEmail = (claims: IdTokenClaims): string | null =>
  claims.email ?? claims.preferred_username ?? null;

export async function resolveEntraUser(claims: IdTokenClaims): Promise<ResolvedEntraUser> {
  // ---- 1. The only trustworthy key ---------------------------------------
  const byOid = await query<{ id: string }>(
    `SELECT id FROM users WHERE entra_object_id = $1`,
    [claims.oid],
  );

  if (byOid.rows[0]) {
    const user = await findUserById(byOid.rows[0].id);
    if (!user || !user.isActive) throw unauthorized('Account is inactive');

    // Keep display fields current, but never touch effective_username here:
    // that is what USERPRINCIPALNAME() resolves against inside the dataset's
    // DAX, so silently rewriting it on every sign-in would move which rows the
    // user can see. Changing it is an explicit admin action.
    const email = claimEmail(claims);
    if (claims.name && claims.name !== user.displayName) {
      await query(`UPDATE users SET display_name = $2 WHERE id = $1`, [user.id, claims.name]);
    }
    if (email && email.toLowerCase() !== user.email.toLowerCase()) {
      logger.info(
        { userId: user.id, oid: claims.oid },
        'Entra email differs from the stored address; not overwriting',
      );
    }

    return { user: (await findUserById(user.id))!, provisioned: false, linked: false };
  }

  const email = claimEmail(claims);

  // ---- 2. One-time link to a pre-existing local account -------------------
  if (config.entra.linkByEmail && email) {
    const candidate = await query<{ id: string; entra_object_id: string | null }>(
      `SELECT id, entra_object_id FROM users WHERE email = $1`,
      [email],
    );
    const row = candidate.rows[0];

    if (row) {
      // Never re-point an account that is already bound to a different Entra
      // identity. Without this, two directory accounts claiming the same email
      // could take turns owning one portal account.
      if (row.entra_object_id && row.entra_object_id !== claims.oid) {
        logger.error(
          { userId: row.id, existing: row.entra_object_id, incoming: claims.oid },
          'Refusing to relink a portal account to a different Entra identity',
        );
        throw unauthorized('This account is linked to a different directory identity');
      }

      await query(`UPDATE users SET entra_object_id = $2 WHERE id = $1`, [row.id, claims.oid]);
      const user = await findUserById(row.id);
      if (!user || !user.isActive) throw unauthorized('Account is inactive');

      logger.info({ userId: user.id, oid: claims.oid }, 'Linked Entra identity to existing account');
      return { user, provisioned: false, linked: true };
    }
  }

  // ---- 3. Just-in-time provisioning --------------------------------------
  if (!config.entra.autoProvision) {
    // Deliberately the same message a disabled account gets: whether an address
    // has a portal account is not something an unauthenticated caller should be
    // able to probe.
    logger.warn({ oid: claims.oid }, 'Entra sign-in for an unknown user; provisioning disabled');
    throw unauthorized('No portal account exists for this identity');
  }

  if (!email) throw unauthorized('Identity provider returned no email address');

  const created = await query<{ id: string }>(
    `INSERT INTO users (email, display_name, entra_object_id, password_hash)
     VALUES ($1, $2, $3, NULL)
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [email, claims.name ?? email, claims.oid],
  );

  if (!created.rows[0]) {
    // Lost a race, or the address exists but linking is disabled. Either way we
    // must not silently adopt that account.
    throw unauthorized('An account already exists for this email address');
  }

  const user = await findUserById(created.rows[0].id);
  logger.info({ userId: user!.id, oid: claims.oid }, 'Provisioned portal account from Entra sign-in');

  // Note: no roles. A new account can sign in and sees an empty catalogue until
  // an admin grants something — provisioning must never imply authorization.
  return { user: user!, provisioned: true, linked: false };
}
