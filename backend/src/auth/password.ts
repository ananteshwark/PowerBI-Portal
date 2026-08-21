import argon2 from 'argon2';

/**
 * Argon2id with OWASP-recommended parameters (19 MiB, t=2, p=1).
 * Argon2 over bcrypt: memory-hardness raises the cost of GPU cracking, and
 * there is no 72-byte input truncation to work around.
 */
const OPTIONS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
};

export const hashPassword = (plain: string) => argon2.hash(plain, OPTIONS);

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    // Malformed hash in the database — treat as a failed login, not a 500.
    return false;
  }
}

/**
 * Burn roughly the same CPU as a real verification when the user does not
 * exist, so response timing does not reveal which emails are registered.
 */
const DUMMY_HASH =
  '$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHR2YWx1ZXg$Q0uMuVDF/QRHXe0nA5tZ3ZaCvPUXeUZLI9zSptFmGjE';

export async function fakeVerify(plain: string): Promise<void> {
  await argon2.verify(DUMMY_HASH, plain).catch(() => undefined);
}
