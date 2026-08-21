import rateLimit from 'express-rate-limit';

/**
 * Login is the brute-force target; embed is the endpoint that costs us calls
 * against a throttled upstream. Both get their own budget.
 */

export const loginLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  // Per email+IP rather than IP alone, so one office NAT does not lock out a
  // whole floor when one person fumbles their password.
  keyGenerator: (req) => `${req.ip}:${String((req.body as { email?: string } | undefined)?.email ?? '')}`,
  message: { error: { code: 'rate_limited', message: 'Too many login attempts. Try again later.' } },
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
  keyGenerator: (req) => req.user?.id ?? req.ip ?? 'anonymous',
  message: { error: { code: 'rate_limited', message: 'Too many embed requests. Slow down.' } },
});

export const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});
