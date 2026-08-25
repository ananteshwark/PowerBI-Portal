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
  // Logs go to stderr, always. Not merely convention: the CLI scripts print
  // machine-readable output on stdout, and interleaved log lines make
  // `validate:rls --json | jq` unparseable. Keeping the two streams separate is
  // what makes that output pipeable.
  ...(config.isProduction
    ? {}
    : { transport: { target: 'pino/file', options: { destination: 2 } } }),
}, config.isProduction ? pino.destination(2) : undefined);
