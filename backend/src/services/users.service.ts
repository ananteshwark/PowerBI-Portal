import { query } from '../db/pool.js';

/**
 * One definition of "load a user with their roles".
 *
 * This aggregate was previously written out three times — in requireAuth, in
 * login and in refresh. Three copies of an authorization query is three places
 * for the is_admin roll-up or the NULL handling to drift, and the drift would
 * be invisible until someone got permissions they should not have.
 */

export interface UserWithRoles {
  id: string;
  email: string;
  displayName: string;
  department: string | null;
  effectiveUsername: string;
  isActive: boolean;
  /** Present only when loaded by email for a password login. */
  passwordHash: string | null;
  roles: string[];
  isAdmin: boolean;
}

interface Row {
  id: string;
  email: string;
  display_name: string;
  department: string | null;
  effective_username: string;
  is_active: boolean;
  password_hash: string | null;
  roles: string[] | null;
  is_admin: boolean;
}

const SELECT = `
  SELECT u.id,
         u.email::text AS email,
         u.display_name,
         u.department,
         u.effective_username,
         u.is_active,
         u.password_hash,
         -- array_remove drops the NULL a LEFT JOIN produces for a user with no
         -- roles, so callers get [] rather than [null].
         array_remove(array_agg(r.name), NULL) AS roles,
         COALESCE(bool_or(r.is_admin), FALSE)  AS is_admin
    FROM users u
    LEFT JOIN user_roles ur ON ur.user_id = u.id
    LEFT JOIN roles r       ON r.id = ur.role_id
`;

const toUser = (row: Row): UserWithRoles => ({
  id: row.id,
  email: row.email,
  displayName: row.display_name,
  department: row.department,
  effectiveUsername: row.effective_username,
  isActive: row.is_active,
  passwordHash: row.password_hash,
  roles: row.roles ?? [],
  isAdmin: row.is_admin,
});

export async function findUserById(userId: string): Promise<UserWithRoles | null> {
  const { rows } = await query<Row>(`${SELECT} WHERE u.id = $1 GROUP BY u.id`, [userId]);
  return rows[0] ? toUser(rows[0]) : null;
}

/** Email match is case-insensitive: `users.email` is CITEXT. */
export async function findUserByEmail(email: string): Promise<UserWithRoles | null> {
  const { rows } = await query<Row>(`${SELECT} WHERE u.email = $1 GROUP BY u.id`, [email]);
  return rows[0] ? toUser(rows[0]) : null;
}

/** The shape returned to the browser. Never includes passwordHash. */
export const toSessionUser = (user: UserWithRoles) => ({
  id: user.id,
  email: user.email,
  displayName: user.displayName,
  roles: user.roles,
  isAdmin: user.isAdmin,
});
