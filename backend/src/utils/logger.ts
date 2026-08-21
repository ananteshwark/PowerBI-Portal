import pino from 'pino';
import { config } from '../config/env.js';

/**
 * Redaction is not optional here: the Power BI request/response bodies we log
 * on error contain access tokens, and pino would happily write them to disk.
 */
export const logger = pino({
  level: config.logLevel,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      '*.accessToken',
      '*.access_token',
      '*.embedToken',
      '*.token',
      '*.password',
      '*.clientSecret',
      '*.refreshToken',
    ],
    censor: '[redacted]',
  },
  ...(config.isProduction
    ? {}
    : { transport: { target: 'pino/file', options: { destination: 1 } } }),
});
