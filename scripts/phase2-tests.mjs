// IMPL-0003 Phase 2 · Structural test harness
//
// Verifies that migrations 0001–0005 produced the expected schema shape:
// tables, RLS state, policies, EXECUTE grants per §3 matrix, helper-schema
// isolation (D37), and CHECK-constraint enforcement (D40).
//
// Does NOT exercise RLS/RPC functional behavior under role impersonation —
// that needs signed JWTs hitting PostgREST, which is a separate concern
// (see scripts/phase2-functional.mjs when we get around to it). Structural
// verification here plus the live token-hash roundtrip from Phase 1 is
// enough to close Phase 2 safely.
//
// Usage:
//   node --env-file=.env.local scripts/phase2-tests.mjs

import pg from 'pg';

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

const client = new pg.Client({ connectionString: withLibpqSslRequire(url) });
await client.connect();

// ──────────────────────────────────────────────────────────────────────────
// Test runner
// ──────────────────────────────────────────────────────────────────────────

const results = [];
let failures = 0;

async function check(name, fn) {
  try {
    const detail = await fn();
    results.push({ name, ok: true, detail: detail ?? '' });
  } catch (err) {
    results.push({ name, ok: false, detail: err.message });
    failures++;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// Find the bootstrapped admin (used for test data authorship).
const { rows: adminRows } = await client.query(
  `select id from public.profiles where is_admin = true and forum_joined_at is not null limit 1`,
);
if (adminRows.length === 0) {
  console.error('No admin user found. Run scripts/bootstrap-admin.mjs first.');
  process.exit(1);
}
const adminId = adminRows[0].id;

// ──────────────────────────────────────────────────────────────────────────
// 1. Tables present
// ──────────────────────────────────────────────────────────────────────────

await check('all 7 content tables exist in public schema', async () => {
  const expected = ['profiles', 'categories', 'threads', 'replies', 'invites', 'write_events', 'auth_events'];
  const { rows } = await client.query(
    `select table_name from information_schema.tables where table_schema='public' and table_type='BASE TABLE'`,
  );
  const got = new Set(rows.map((r) => r.table_name));
  for (const t of expected) assert(got.has(t), `missing: ${t}`);
});

await check('categories are seeded (craft, compass, field, formation)', async () => {
  // Original Phase 2 seed was art/literature/film/misc (0004_forum_seed.sql).
  // Launch-night migration 0006 replaced them with the community-thesis
  // categories; migration 0007 refined descriptions. See IMPL-0003 §11
  // Phase 7 discovery #6 for the rationale. Next revision of categories
  // updates this assertion.
  const { rows } = await client.query(
    `select slug, name, description from public.categories order by sort_order`,
  );
  const slugs = rows.map((r) => r.slug);
  const expected = ['craft', 'compass', 'field', 'formation'];
  assert(
    expected.every((s) => slugs.includes(s)),
    `expected ${expected.join('/')}, got ${slugs.join(',')}`,
  );
  // Migration 0006 added a non-null-content description column. Every
  // seeded category must have a meaningful description — catches partial
  // re-seed regressions where slugs land but description copy doesn't.
  for (const row of rows) {
    assert(
      typeof row.description === 'string' && row.description.length >= 20,
      `category ${row.slug} missing or thin description (${row.description?.length ?? 0} chars)`,
    );
  }
});

// ──────────────────────────────────────────────────────────────────────────
// 2. RLS enabled
// ──────────────────────────────────────────────────────────────────────────

for (const table of ['profiles', 'categories', 'threads', 'replies', 'invites', 'write_events', 'auth_events']) {
  await check(`RLS enabled on public.${table}`, async () => {
    const { rows } = await client.query(
      `select rowsecurity from pg_tables where schemaname='public' and tablename=$1`,
      [table],
    );
    assert(rows.length === 1 && rows[0].rowsecurity === true, 'not enabled');
  });
}

// ──────────────────────────────────────────────────────────────────────────
// 3. Policies present per spec
// ──────────────────────────────────────────────────────────────────────────

const expectedPolicies = {
  threads: ['threads_select_member', 'threads_select_admin'],
  replies: ['replies_select_member', 'replies_select_admin'],
  categories: ['categories_select'],
  profiles: ['profiles_select_self', 'profiles_select_member', 'profiles_select_admin'],
  invites: ['invites_select_admin'],
  write_events: [],
  auth_events: [],
};

for (const [table, policies] of Object.entries(expectedPolicies)) {
  await check(`policies on ${table}: [${policies.join(', ') || 'none'}]`, async () => {
    const { rows } = await client.query(
      `select policyname from pg_policies where schemaname='public' and tablename=$1 order by policyname`,
      [table],
    );
    const got = rows.map((r) => r.policyname).sort();
    const expected = [...policies].sort();
    assert(
      JSON.stringify(got) === JSON.stringify(expected),
      `expected [${expected.join(', ')}], got [${got.join(', ')}]`,
    );
  });
}

// ──────────────────────────────────────────────────────────────────────────
// 4. Helpers in private schema only (D37)
// ──────────────────────────────────────────────────────────────────────────

await check('private schema exists', async () => {
  const { rows } = await client.query(
    `select 1 from information_schema.schemata where schema_name='private'`,
  );
  assert(rows.length === 1, 'private schema missing');
});

await check('private.{is_active_member, is_admin_member, is_reserved_slug} exist', async () => {
  const { rows } = await client.query(
    `select proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
       where n.nspname='private' order by proname`,
  );
  const names = rows.map((r) => r.proname);
  for (const f of ['is_active_member', 'is_admin_member', 'is_reserved_slug']) {
    assert(names.includes(f), `private.${f} missing`);
  }
});

await check('no helpers leaked into public (is_active_member / is_admin_member)', async () => {
  const { rows } = await client.query(
    `select proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
       where n.nspname='public' and proname in ('is_active_member', 'is_admin_member')`,
  );
  assert(rows.length === 0, `leaked: ${rows.map((r) => r.proname).join(', ')}`);
});

// ──────────────────────────────────────────────────────────────────────────
// 5. All expected RPCs exist in public
// ──────────────────────────────────────────────────────────────────────────

await check('all 15 public RPCs exist', async () => {
  const expected = [
    'assert_rate_limit',
    'rpc_ban_user',
    'rpc_check_auth_rate_limit',
    'rpc_consume_invite',
    'rpc_create_reply',
    'rpc_create_thread',
    'rpc_edit_reply',
    'rpc_edit_thread',
    'rpc_issue_invite',
    'rpc_lock_thread',
    'rpc_lookup_user_by_email',
    'rpc_revoke_invite',
    'rpc_soft_delete_reply',
    'rpc_soft_delete_thread',
    'rpc_update_profile',
  ];
  const { rows } = await client.query(
    `select proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
       where n.nspname='public' and proname like 'rpc\\_%' escape '\\'
       union
     select proname from pg_proc p join pg_namespace n on n.oid=p.pronamespace
       where n.nspname='public' and proname='assert_rate_limit'`,
  );
  const got = rows.map((r) => r.proname).sort();
  for (const f of expected) {
    assert(got.includes(f), `missing: ${f}`);
  }
});

// ──────────────────────────────────────────────────────────────────────────
// 6. EXECUTE grant matrix per §3 / D19 / D38
// ──────────────────────────────────────────────────────────────────────────

const grantMatrix = [
  // Session-client RPCs → authenticated only
  ['rpc_create_thread(text, text, text, text)', 'authenticated', true],
  ['rpc_create_thread(text, text, text, text)', 'anon', false],
  ['rpc_create_thread(text, text, text, text)', 'public', false],
  ['rpc_edit_thread(uuid, text, text)', 'authenticated', true],
  ['rpc_edit_thread(uuid, text, text)', 'anon', false],
  ['rpc_create_reply(uuid, text)', 'authenticated', true],
  ['rpc_create_reply(uuid, text)', 'anon', false],
  ['rpc_edit_reply(uuid, text)', 'authenticated', true],
  ['rpc_soft_delete_thread(uuid)', 'authenticated', true],
  ['rpc_soft_delete_reply(uuid)', 'authenticated', true],
  ['rpc_update_profile(text, text)', 'authenticated', true],
  ['rpc_issue_invite(citext, integer)', 'authenticated', true],
  ['rpc_issue_invite(citext, integer)', 'anon', false],
  ['rpc_revoke_invite(uuid)', 'authenticated', true],
  ['rpc_lock_thread(uuid)', 'authenticated', true],
  ['rpc_ban_user(uuid)', 'authenticated', true],
  // Service-role-only RPCs
  ['rpc_consume_invite(uuid, uuid)', 'service_role', true],
  ['rpc_consume_invite(uuid, uuid)', 'authenticated', false],
  ['rpc_consume_invite(uuid, uuid)', 'anon', false],
  ['rpc_consume_invite(uuid, uuid)', 'public', false],
  ['rpc_lookup_user_by_email(citext)', 'service_role', true],
  ['rpc_lookup_user_by_email(citext)', 'authenticated', false],
  ['rpc_check_auth_rate_limit(bytea, bytea, text, integer, integer, integer)', 'service_role', true],
  ['rpc_check_auth_rate_limit(bytea, bytea, text, integer, integer, integer)', 'authenticated', false],
  ['assert_rate_limit(uuid, text, integer, integer)', 'service_role', true],
  ['assert_rate_limit(uuid, text, integer, integer)', 'authenticated', false],
];

for (const [fn, role, shouldHave] of grantMatrix) {
  await check(`grant: ${role} ${shouldHave ? 'has' : 'lacks'} EXECUTE on ${fn}`, async () => {
    const { rows } = await client.query(
      `select has_function_privilege($1, $2, 'EXECUTE') as ok`,
      [role, `public.${fn}`],
    );
    assert(rows[0].ok === shouldHave, `expected ${shouldHave}, got ${rows[0].ok}`);
  });
}

// ──────────────────────────────────────────────────────────────────────────
// 7. Table-level write revokes from anon + authenticated
// ──────────────────────────────────────────────────────────────────────────

for (const table of ['profiles', 'categories', 'threads', 'replies', 'invites', 'write_events', 'auth_events']) {
  for (const role of ['anon', 'authenticated']) {
    for (const priv of ['INSERT', 'UPDATE', 'DELETE']) {
      await check(`${role} lacks ${priv} on public.${table}`, async () => {
        const { rows } = await client.query(
          `select has_table_privilege($1, $2, $3) as has_priv`,
          [role, `public.${table}`, priv],
        );
        assert(rows[0].has_priv === false, `${role} still has ${priv} on ${table}`);
      });
    }
  }
}

// ──────────────────────────────────────────────────────────────────────────
// 8. D40 CHECK constraint enforcement on invites.email
// ──────────────────────────────────────────────────────────────────────────

await check('D40: invites CHECK rejects uppercase email', async () => {
  let raised = false;
  try {
    await client.query(
      `insert into public.invites (email, issued_by, expires_at) values ($1, $2, now() + interval '1 day')`,
      ['Bad@Example.com', adminId],
    );
  } catch (err) {
    if (/check constraint/i.test(err.message)) raised = true;
  }
  assert(raised, 'uppercase email passed the CHECK');
});

await check('D40: invites CHECK rejects trailing whitespace', async () => {
  let raised = false;
  try {
    await client.query(
      `insert into public.invites (email, issued_by, expires_at) values ($1, $2, now() + interval '1 day')`,
      ['bad@example.com ', adminId],
    );
  } catch (err) {
    if (/check constraint/i.test(err.message)) raised = true;
  }
  assert(raised, 'trailing-whitespace email passed the CHECK');
});

await check('D40: invites CHECK accepts normalized email (cleanup-safe)', async () => {
  // Use a unique email to avoid partial-unique-index conflicts; roll back so
  // the row doesn't persist.
  await client.query('begin');
  try {
    await client.query(
      `insert into public.invites (email, issued_by, expires_at)
         values ('phase2-check-test@example.com', $1, now() + interval '1 day')`,
      [adminId],
    );
  } finally {
    await client.query('rollback');
  }
});

// ──────────────────────────────────────────────────────────────────────────
// 9. D41: is_admin_member requires forum_joined_at
// ──────────────────────────────────────────────────────────────────────────

await check('D41: is_admin_member(<admin>) returns true', async () => {
  const { rows } = await client.query(
    `select private.is_admin_member($1) as is_admin`,
    [adminId],
  );
  assert(rows[0].is_admin === true, `got ${rows[0].is_admin}`);
});

await check('D41: is_admin_member(<null-id>) returns false', async () => {
  const { rows } = await client.query(
    `select private.is_admin_member($1) as is_admin`,
    ['00000000-0000-0000-0000-000000000000'],
  );
  assert(rows[0].is_admin === false, `got ${rows[0].is_admin}`);
});

await check('D41: is_active_member returns false for non-existent profile', async () => {
  // coalesce(..., false) branch — no matching row means not a member.
  const { rows } = await client.query(
    `select private.is_active_member('11111111-1111-1111-1111-111111111111'::uuid) as active`,
  );
  assert(rows[0].active === false, `got ${rows[0].active}`);
});

// ──────────────────────────────────────────────────────────────────────────
// 10. Triggers present on auth.users + public.replies
// ──────────────────────────────────────────────────────────────────────────

await check('on_auth_user_created trigger present on auth.users', async () => {
  const { rows } = await client.query(
    `select tgname from pg_trigger where tgname='on_auth_user_created'`,
  );
  assert(rows.length === 1, 'trigger not found');
});

await check('on_reply_insert trigger present on public.replies', async () => {
  const { rows } = await client.query(
    `select tgname from pg_trigger where tgname='on_reply_insert'`,
  );
  assert(rows.length === 1, 'trigger not found');
});

await check('on_reply_soft_delete trigger present on public.replies', async () => {
  const { rows } = await client.query(
    `select tgname from pg_trigger where tgname='on_reply_soft_delete'`,
  );
  assert(rows.length === 1, 'trigger not found');
});

// ──────────────────────────────────────────────────────────────────────────
await client.end();

// Report
const passed = results.length - failures;
console.log('');
for (const r of results) {
  const mark = r.ok ? '  ✓' : '  ✗';
  console.log(`${mark} ${r.name}${!r.ok && r.detail ? ` — ${r.detail}` : ''}`);
}
console.log('');
console.log(`${passed}/${results.length} passed${failures > 0 ? `, ${failures} FAILED` : ''}`);
process.exit(failures > 0 ? 1 : 0);
