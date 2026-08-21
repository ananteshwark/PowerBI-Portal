import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { AppError } from '../utils/errors.js';
import { logger } from '../utils/logger.js';
import { config } from '../config/env.js';

export function notFoundHandler(req: Request, res: Response): void {
  res.status(404).json({ error: { code: 'not_found', message: `No route ${req.method} ${req.path}` } });
}

/**
 * Terminal error handler. Anything that is not an explicit AppError becomes a
 * generic 500 — unexpected errors routinely carry stack traces, SQL fragments
 * and Power BI correlation identifiers that must not reach a browser.
 */
export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  if (err instanceof ZodError) {
    res.status(400).json({
      error: {
        code: 'validation_error',
        message: 'Request validation failed',
        details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      },
    });
    return;
  }

  if (err instanceof AppError) {
    // 5xx is our fault; log at error. 4xx is the caller's; log at warn/debug.
    const level = err.status >= 500 ? 'error' : err.status === 403 ? 'warn' : 'debug';
    logger[level](
      { err, internal: err.internal, path: req.path, userId: req.user?.id },
      err.message,
    );
    res.status(err.status).json({
      error: { code: err.code, message: err.message, ...(err.details ? { details: err.details } : {}) },
    });
    return;
  }

  logger.error({ err, path: req.path, userId: req.user?.id }, 'Unhandled error');
  res.status(500).json({
    error: {
      code: 'internal_error',
      message: 'An unexpected error occurred',
      ...(config.isProduction ? {} : { debug: err instanceof Error ? err.message : String(err) }),
    },
  });
}
