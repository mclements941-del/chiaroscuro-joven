// IMPL-0003 Phase 2 · Migration runner
//
// Applies supabase/migrations/*.sql in lexical order, each in its own
// transaction. Bails on first failure.
//
// Usage:
//   node --env-file=.env.local scripts/apply-migrations.mjs
//
// Uses POSTGRES_URL_NON_POOLING (direct connection, required for DDL —
// PgBouncer transaction pooling drops prepared statements and breaks
// SECURITY DEFINER function creation).

import pg from 'pg';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';

const url = process.env.POSTGRES_URL_NON_POOLING;
if (!url) {
  console.error('POSTGRES_URL_NON_POOLING missing from .env.local');
  process.exit(1);
}

const dir = 'supabase/migrations';
const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
if (files.length === 0) {
  console.error(`no .sql files in ${dir}`);
  process.exit(1);
}

function withLibpqSslRequire(connectionUrl) {
  const parsed = new URL(connectionUrl);
  parsed.searchParams.set('sslmode', 'require');
  parsed.searchParams.set('uselibpqcompat', 'true');
  return parsed.toString();
}

// Supabase hosts Postgres behind their own CA chain. pg 8.20 treats
// sslmode=require as verify-full unless libpq compatibility is enabled.
// This preserves encrypted transport while avoiding local CA-chain failures
// for this one-off migration runner.
const client = new pg.Client({
  connectionString: withLibpqSslRequire(url),
});
await client.connect();

try {
  for (const file of files) {
    const sql = await readFile(join(dir, file), 'utf8');
    process.stdout.write(`applying ${file} ... `);
    try {
      await client.query('begin');
      await client.query(sql);
      await client.query('commit');
      console.log('ok');
    } catch (err) {
      await client.query('rollback').catch(() => {});
      console.log('FAILED');
      console.error(`  ${err.message}`);
      if (err.position) console.error(`  at position ${err.position}`);
      process.exit(1);
    }
  }
  console.log(`\n${files.length} migrations applied successfully.`);
} finally {
  await client.end();
}
