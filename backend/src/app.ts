import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import pinoHttp from 'pino-http';
import { config } from './config/env.js';
import { AppError } from './utils/errors.js';
import { logger } from './utils/logger.js';
import { apiLimiter } from './middleware/rateLimit.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';
import { authRouter } from './routes/auth.routes.js';
import { reportsRouter } from './routes/reports.routes.js';
import { embedRouter } from './routes/embed.routes.js';
import { healthRouter } from './routes/health.routes.js';

/** 'false' | 'true' | hop count | comma-separated CIDR list. */
function parseTrustProxy(value: string): boolean | number | string[] {
  if (value === 'false') return false;
  if (value === 'true') return true;
  if (/^\d+$/.test(value)) return Number(value);
  return value.split(',').map((s) => s.trim()).filter(Boolean);
}

export function createApp() {
  const app = express();

  // req.ip drives both rate limiters and audit_log.ip_address, so getting this
  // wrong is a security setting, not a cosmetic one. Trusting a hop that is not
  // actually there lets any client forge X-Forwarded-For and rotate past the
  // limiters. Defaults to false; set TRUST_PROXY to match the real topology.
  app.set('trust proxy', parseTrustProxy(config.http.trustProxy));
  app.disable('x-powered-by');

  app.use(
    helmet({
      // The API serves JSON only; a restrictive CSP here costs nothing. The
      // frontend sets its own, looser policy (it must allow the Power BI
      // iframe) — see frontend/next.config.mjs.
      contentSecurityPolicy: { directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
      crossOriginResourcePolicy: { policy: 'same-site' },
      hsts: config.isProduction ? { maxAge: 31_536_000, includeSubDomains: true } : false,
    }),
  );

  app.use(
    cors({
      origin: (origin, cb) => {
        // Same-origin / server-to-server requests carry no Origin header.
        if (!origin) return cb(null, true);
        if (config.http.corsOrigins.includes(origin)) return cb(null, true);
        // An AppError, not a bare Error: the latter fell through to the
        // terminal handler as an unhandled 500 and logged every probe as if it
        // were a server fault.
        cb(new AppError(403, 'cors_forbidden', 'Origin not allowed'));
      },
      credentials: true, // required for the refresh-token cookie
      methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      maxAge: 86_400,
    }),
  );

  app.use(express.json({ limit: '64kb' }));
  app.use(cookieParser());
  app.use(
    pinoHttp({
      logger,
      // Health probes at 1/sec would drown everything else.
      autoLogging: { ignore: (req) => req.url?.startsWith('/api/health') ?? false },
      customLogLevel: (_req, res, err) =>
        err || res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info',
    }),
  );

  app.use('/api/health', healthRouter);
  app.use('/api', apiLimiter);
  app.use('/api/auth', authRouter);
  app.use('/api/reports', reportsRouter);
  app.use('/api/embed', embedRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
