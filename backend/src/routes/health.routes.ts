import { Router, type Request, type Response } from 'express';
import { query } from '../db/pool.js';
import { getAadToken } from '../powerbi/aadToken.js';
import { logger } from '../utils/logger.js';

export const healthRouter = Router();

/** Liveness — is the process up? Must not touch dependencies. */
healthRouter.get('/live', (_req: Request, res: Response) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

/**
 * Readiness — can we actually serve? Checks the database and Entra ID.
 * The Entra check is nearly free after the first call (MSAL serves from cache),
 * which is what makes it safe to expose to a load balancer's probe.
 */
healthRouter.get('/ready', async (_req: Request, res: Response) => {
  // Deliberately no `detail` field: this endpoint is unauthenticated, so it
  // reports liveness of each dependency and nothing about why one is down.
  const checks: Record<string, { ok: boolean }> = {};

  try {
    await query('SELECT 1');
    checks.database = { ok: true };
  } catch (err) {
    // The driver's message carries the database host, port and sometimes the
    // role name. This endpoint is anonymous, so the detail goes to the log and
    // only the boolean goes to the caller.
    logger.error({ err }, 'Readiness: database check failed');
    checks.database = { ok: false };
  }

  try {
    await getAadToken();
    checks.entraId = { ok: true };
  } catch (err) {
    logger.error({ err }, 'Readiness: Entra ID check failed');
    checks.entraId = { ok: false };
  }

  const ok = Object.values(checks).every((c) => c.ok);
  res.status(ok ? 200 : 503).json({ status: ok ? 'ready' : 'degraded', checks });
});
