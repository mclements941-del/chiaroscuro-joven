// IMPL-0003 Phase 2 · Bootstrap admin (one-time, post-migration)
//
// 1. Back-fills profiles rows for any auth.users that pre-date the
//    on_auth_user_created trigger (the trigger fires on INSERT only).
// 2. Promotes mclements941@gmail.com to admin + active member.
//
// Usage:
//   node --env-file=.env.local scripts/bootstrap-admin.mjs
//
// Safe to re-run: queries are idempotent.

import pg from 'pg';

const ADMIN_EMAIL = 'mclements941@gmail.com';
const ADMIN_DISPLAY_NAME = 'Matt';

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

// Supabase hosts Postgres behind their own CA chain. pg 8.20 treats
// sslmode=require as verify-full unless libpq compatibility is enabled.
// This preserves encrypted transport while avoiding local CA-chain failures
// for this one-off bootstrap script.
const client = new pg.Client({
  connectionString: withLibpqSslRequire(url),
});
await client.connect();

try {
  // Step 1: backfill profiles for existing auth.users.
  const backfill = await client.query(`
    insert into public.profiles (id, display_name, needs_setup, forum_joined_at)
      select u.id, 'member-' || substr(u.id::text, 1, 8), true, null
      from auth.users u
      where not exists (select 1 from public.profiles p where p.id = u.id)
      returning id
  `);
  console.log(`backfill: ${backfill.rowCount} profile(s) created for existing auth.users`);

  // Step 2: promote the admin.
  const promote = await client.query(
    `
    update public.profiles
      set is_admin = true,
          needs_setup = false,
          display_name = $2,
          forum_joined_at = coalesce(forum_joined_at, now())
      where id = (select id from auth.users where email = $1)
      returning id, display_name, is_admin, forum_joined_at, needs_setup
    `,
    [ADMIN_EMAIL, ADMIN_DISPLAY_NAME],
  );
  if (promote.rowCount === 0) {
    console.error(
      `admin promote: no auth.users row with email=${ADMIN_EMAIL}. Create the user first via auth.admin.createUser or the Supabase dashboard, then re-run.`,
    );
    process.exit(1);
  }
  console.log(`admin promote: ${JSON.stringify(promote.rows[0], null, 2)}`);
} finally {
  await client.end();
}
