import { createApp } from './app.js';
import { config } from './config/env.js';
import { logger } from './utils/logger.js';
import { closePool } from './db/pool.js';
import { initTokenCache } from './services/tokenCache.js';
import { purgeExpiredTokens } from './auth/refreshTokens.js';

async function main(): Promise<void> {
  await initTokenCache();

  const app = createApp();
  const server = app.listen(config.port, () => {
    logger.info(
      { port: config.port, env: config.env, cache: config.cache.redisUrl ? 'redis' : 'memory' },
      'Power BI portal API listening',
    );
  });

  // Daily housekeeping of dead refresh tokens.
  const purgeTimer = setInterval(
    () => {
      void purgeExpiredTokens()
        .then((n) => n > 0 && logger.info({ deleted: n }, 'Purged expired refresh tokens'))
        .catch((err) => logger.error({ err }, 'Refresh token purge failed'));
    },
    24 * 60 * 60 * 1000,
  );
  purgeTimer.unref();

  /**
   * Graceful shutdown: stop accepting connections, let in-flight requests
   * finish, then close the pool. Without this, a rolling deploy drops the
   * embed request of whoever happened to be loading a dashboard.
   */
  const shutdown = (signal: string) => {
    logger.info({ signal }, 'Shutting down');
    server.close(async () => {
      clearInterval(purgeTimer);
      await closePool().catch(() => undefined);
      process.exit(0);
    });
    // Don't hang forever on a stuck keep-alive connection.
    setTimeout(() => process.exit(1), 15_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    logger.fatal({ reason }, 'Unhandled promise rejection');
    process.exit(1);
  });
}

main().catch((err) => {
  logger.fatal({ err }, 'Failed to start server');
  process.exit(1);
});
