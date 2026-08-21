import jwt from 'jsonwebtoken';
import { config } from '../config/env.js';
import { unauthorized } from '../utils/errors.js';

export interface AccessTokenClaims {
  sub: string;              // user id
  email: string;
  name: string;
  roles: string[];
  adm: boolean;             // is admin
  iss: string;
  aud: string;
  iat: number;
  exp: number;
}

export function signAccessToken(payload: {
  userId: string;
  email: string;
  displayName: string;
  roles: string[];
  isAdmin: boolean;
}): { token: string; expiresIn: number } {
  const token = jwt.sign(
    {
      sub: payload.userId,
      email: payload.email,
      name: payload.displayName,
      roles: payload.roles,
      adm: payload.isAdmin,
    },
    config.jwt.secret,
    {
      algorithm: 'HS256',
      expiresIn: config.jwt.accessTtlSeconds,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    },
  );
  return { token, expiresIn: config.jwt.accessTtlSeconds };
}

export function verifyAccessToken(token: string): AccessTokenClaims {
  try {
    // Pinning `algorithms` matters: without it a token signed with alg:none
    // (or a confused RS256/HS256 swap) can be accepted.
    return jwt.verify(token, config.jwt.secret, {
      algorithms: ['HS256'],
      issuer: config.jwt.issuer,
      audience: config.jwt.audience,
    }) as AccessTokenClaims;
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      throw unauthorized('Access token expired');
    }
    throw unauthorized('Invalid access token');
  }
}
