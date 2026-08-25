/**
 * Minimal forward-only migration runner.
 *
 * Applies every .sql file in src/db/migrations in filename order, recording
 * each in schema_migrations so re-runs are no-ops. Each file runs inside a
 * transaction — a failing migration leaves no partial schema behind.
 */
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, withTransaction, closePool } from '../src/db/pool.js';

const MIGRATIONS_DIR = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'src',
  'db',
  'migrations',
);

async function run(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      filename    TEXT PRIMARY KEY,
      applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);

  const { rows } = await pool.query<{ filename: string }>(
    'SELECT filename FROM schema_migrations',
  );
  const applied = new Set(rows.map((r) => r.filename));

  const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort();

  let count = 0;
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = await readFile(path.join(MIGRATIONS_DIR, file), 'utf8');
    process.stdout.write(`  applying ${file} ... `);
    await withTransaction(async (client) => {
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [file]);
    });
    process.stdout.write('ok\n');
    count += 1;
  }

  console.log(count === 0 ? 'Schema already up to date.' : `Applied ${count} migration(s).`);
}

run()
  .then(() => closePool())
  .catch(async (err) => {
    console.error('Migration failed:', err.message);
    await closePool().catch(() => undefined);
    process.exit(1);
  });
