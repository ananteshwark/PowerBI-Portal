import { Router, type Request, type Response, type NextFunction } from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.middleware.js';
import { embedLimiter } from '../middleware/rateLimit.js';
import { buildEmbedConfig, secondsUntilRefresh } from '../services/embed.service.js';

export const embedRouter = Router();

embedRouter.use(requireAuth);
embedRouter.use(embedLimiter);

// Accept either the portal report UUID or its slug.
const paramsSchema = z.object({
  reportIdOrSlug: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9][a-z0-9-]*$/i, 'Invalid report identifier'),
});

/**
 * GET /api/embed/:reportIdOrSlug
 *
 * The only endpoint that returns Power BI credentials, and it returns the
 * weakest possible one: an embed token scoped to a single report, a single
 * dataset and a single RLS identity, valid for at most an hour.
 *
 * The response is explicitly uncacheable. An embed token in a shared proxy
 * cache would be served to the wrong user under the wrong RLS identity — the
 * exact failure this whole design exists to prevent.
 */
embedRouter.get(
  '/:reportIdOrSlug',
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { reportIdOrSlug } = paramsSchema.parse(req.params);

      const embedConfig = await buildEmbedConfig(req.user!, reportIdOrSlug, {
        ipAddress: req.ip,
        userAgent: req.get('user-agent') ?? null,
        // The client sets this only after Power BI has rejected the token it
        // holds; re-serving the cached copy would hand back the same bad value.
        bypassCache: req.query.bypassCache === '1',
      });

      res.set('Cache-Control', 'no-store, private');
      res.set('Pragma', 'no-cache');

      res.json({
        ...embedConfig,
        // Tells the client when to call back, so the refresh policy lives on
        // the server and can be tuned without a frontend deploy.
        refreshInSeconds: secondsUntilRefresh(embedConfig.expiresAt),
      });
    } catch (err) {
      next(err);
    }
  },
);
