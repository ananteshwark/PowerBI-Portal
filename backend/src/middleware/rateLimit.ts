import rateLimit from 'express-rate-limit';
import { ipKey } from '../utils/ipKey.js';

/**
 * Login is the brute-force target; embed is the endpoint that costs us calls
 * against a throttled upstream. Both get their own budget.
 */

/**
 * Login needs TWO limits, because there are two different attacks.
 *
 * Per (IP, account) stops brute force against one password, and keying on the
 * account as well as the IP means one office NAT does not lock out a whole
 * floor when one person fumbles their password.
 *
 * But that alone gives every *attempted* account its own budget, so spraying
 * one common password across thousands of accounts from a single IP barely
 * touches it. The per-IP limit below is what bounds that.
 */
export const loginAccountLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) =>
    `${ipKey(req.ip)}:${String((req.body as { email?: string } | undefined)?.email ?? '')}`,
  message: { error: { code: 'rate_limited', message: 'Too many login attempts. Try again later.' } },
});

/** Per-IP ceiling across all accounts — the anti-spraying limit. */
export const loginIpLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 50,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  // ipKey collapses IPv6 to its /64, so an attacker with a routed prefix
  // cannot draw a fresh budget from every address in it.
  keyGenerator: (req) => ipKey(req.ip),
  message: {
    error: { code: 'rate_limited', message: 'Too many login attempts from this network.' },
  },
});

/**
 * A stolen refresh cookie should not be replayable at the global API budget.
 * Generous enough for legitimate multi-tab use, tight enough to matter.
 */
export const refreshLimiter = rateLimit({
  windowMs: 60_000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => ipKey(req.ip),
  message: { error: { code: 'rate_limited', message: 'Too many refresh attempts.' } },
});

/**
 * Generous, because the token cache means repeat views are free. Hitting this
 * indicates automation or a broken client retry loop, not normal use.
 */
export const embedLimiter = rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.id ?? ipKey(req.ip),
  message: { error: { code: 'rate_limited', message: 'Too many embed requests. Slow down.' } },
});

export const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});
