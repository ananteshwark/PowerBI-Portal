import { Router, type Request, type Response, type NextFunction } from 'express';
import { requireAuth } from '../middleware/auth.middleware.js';
import { listAccessibleReports } from '../services/reports.service.js';

export const reportsRouter = Router();

reportsRouter.use(requireAuth);

/**
 * GET /api/reports — the report catalogue for the signed-in user.
 *
 * Returns display metadata only. Workspace and Power BI report IDs are
 * deliberately withheld: the browser never needs them (the embed endpoint
 * returns the embedUrl already built), and not shipping them means a compromised
 * frontend cannot enumerate the workspace's contents.
 */
reportsRouter.get('/', async (req: Request, res: Response, next: NextFunction) => {
  try {
    const reports = await listAccessibleReports(req.user!.id);
    res.json({
      reports: reports.map((r) => ({
        id: r.reportId,
        slug: r.slug,
        name: r.name,
        description: r.description,
        category: r.category,
        rlsEnabled: r.rlsRequired,
      })),
    });
  } catch (err) {
    next(err);
  }
});
