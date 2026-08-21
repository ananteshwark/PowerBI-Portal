import pg from 'pg';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';

const { Pool } = pg;

// Return BIGINT (audit_log.id) as a JS number rather than a string. Safe here:
// audit ids will not approach 2^53.
pg.types.setTypeParser(20, (v) => Number.parseInt(v, 10));

export const pool = new Pool({
  connectionString: config.db.url,
  max: config.db.poolMax,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  ssl: config.db.ssl ? { rejectUnauthorized: true } : undefined,
});

pool.on('error', (err) => {
  // Idle client blew up (network drop, failover). The pool replaces it; log
  // rather than crash.
  logger.error({ err }, 'Unexpected error on idle database client');
});

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: readonly unknown[] = [],
): Promise<pg.QueryResult<T>> {
  const start = process.hrtime.bigint();
  try {
    return await pool.query<T>(text, params as unknown[]);
  } finally {
    const ms = Number(process.hrtime.bigint() - start) / 1e6;
    if (ms > 200) logger.warn({ ms, sql: text.slice(0, 120) }, 'Slow query');
  }
}

/** Run `fn` inside a transaction, rolling back on any throw. */
export async function withTransaction<T>(
  fn: (client: pg.PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

export async function closePool(): Promise<void> {
  await pool.end();
}
