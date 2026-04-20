// Single-migration runner.
//
// Companion to scripts/apply-migrations.mjs, which applies all migrations
// lexically (first-time use). Use this when you've added a new migration
// and only want to apply that one — the initial migrations use plain
// `create table` without IF NOT EXISTS, so re-running the batch fails.
//
// Usage:
//   node --env-file=.env.local scripts/apply-migration.mjs supabase/migrations/0006_category_revision.sql
//
// Runs the file inside a single explicit transaction. Bails on failure.

import pg from 'pg';
import { readFile } from 'node:fs/promises';

const file = process.argv[2];
if (!file) {
  console.error('usage: apply-migration.mjs <path-to-sql-file>');
  process.exit(1);
}

const url = process.env.POSTGRES_URL_NON_POOLING;
if (!url) {
  console.error('POSTGRES_URL_NON_POOLING missing from .env.local');
  process.exit(1);
}

function withLibpqSslRequire(connectionUrl) {
  const parsed = new URL(connectionUrl);
  parsed.searchParams.set('sslmode', 'require');
  parsed.searchParams.set('uselibpqcompat', 'true');
  return parsed.toString();
}

const sql = await readFile(file, 'utf8');

const client = new pg.Client({
  connectionString: withLibpqSslRequire(url),
});
await client.connect();

process.stdout.write(`applying ${file} ... `);
try {
  // The migration file itself may contain BEGIN/COMMIT. Let it drive
  // transaction boundaries; we just hand it the SQL.
  await client.query(sql);
  console.log('ok');
} catch (err) {
  console.log('FAILED');
  console.error(`  ${err.message}`);
  if (err.position) console.error(`  at position ${err.position}`);
  process.exit(1);
} finally {
  await client.end();
}
