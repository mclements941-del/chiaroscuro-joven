// IMPL-0004 Phase 1 · Behavioral RLS regression suite
//
// Complements scripts/phase2-tests.mjs (structural) by exercising the real
// PostgREST client path as different JWT-authenticated sessions. Where
// Phase 2 proves policies + grants *exist* with correct definitions, this
// proves they *actually enforce* when a real session hits the Data API.
//
// Coverage (IMPL-0004 §3.1):
//   * Visibility matrix — 5 sessions (anon / unjoined / banned / member /
//     admin) × 5 tables (threads / replies / categories / profiles /
//     invites). Filtered to fixture rows only so the harness is safe to
//     run against a populated prod DB.
//   * D43 specifically: active member must not be able to read
//     `profiles` rows where `forum_joined_at IS NULL`.
//   * RPC rejection matrix: content RPCs called via session JWTs must
//     reject per authorization rules (forbidden / thread_unavailable /
//     edit_forbidden / invite_user_mismatch / already_member / …).
//   * Admin rate-limit exemption (0008): admin can create two threads in
//     rapid succession where a member would be throttled.
//
// Fixtures (IMPL-0004 §3.1):
//   * Emails `rls-<role>@rls-test.local` — distinct from any other test
//     namespace so cleanup selectors are unambiguous
//   * Slugs `rls-test-<hex>` and invite emails `rls-invite-<kind>@rls-test.local`
//   * try/finally cleanup in reverse dependency order; stale fixtures
//     cleared at start-up in case an earlier run died mid-flight
//
// Usage:
//   node --env-file=.env.local scripts/rls-behavior-tests.mjs
//
// Required env:
//   SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY,
//   SUPABASE_JWT_SECRET, POSTGRES_URL_NON_POOLING
//
// Exit code: 0 if all assertions pass, 1 on any failure.

import { createHmac, randomBytes } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import pg from 'pg';

// ---------------------------------------------------------------------------
// Env
// ---------------------------------------------------------------------------

const {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_JWT_SECRET,
  POSTGRES_URL_NON_POOLING,
} = process.env;

for (const [name, value] of Object.entries({
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_JWT_SECRET,
  POSTGRES_URL_NON_POOLING,
})) {
  if (!value) {
    console.error(`Missing env: ${name}`);
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FIXTURE_DOMAIN = 'rls-test.local';
const USER_EMAILS = {
  unjoined: `rls-unjoined@${FIXTURE_DOMAIN}`,
  banned:   `rls-banned@${FIXTURE_DOMAIN}`,
  member:   `rls-member@${FIXTURE_DOMAIN}`,
  admin:    `rls-admin@${FIXTURE_DOMAIN}`,
};
const INVITE_EMAILS = {
  active:   `rls-invite-active@${FIXTURE_DOMAIN}`,
  consumed: `rls-invite-consumed@${FIXTURE_DOMAIN}`,
  revoked:  `rls-invite-revoked@${FIXTURE_DOMAIN}`,
};
const SLUG_PREFIX = 'rls-test-';

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signSessionJWT(userId) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    aud: 'authenticated',
    role: 'authenticated',
    sub: userId,
    iat: now,
    exp: now + 300,
  };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const sig = createHmac('sha256', SUPABASE_JWT_SECRET).update(signingInput).digest('base64url');
  return `${signingInput}.${sig}`;
}

function clientAs(userId) {
  return createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: `Bearer ${signSessionJWT(userId)}` } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

// ---------------------------------------------------------------------------
// Assertion harness
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, details) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    failures.push({ label, details });
    console.log(`  ✗ ${label}  ${details ?? ''}`);
  }
}

// Compact view of a PostgREST error for failure messages.
function err(e) {
  if (!e) return 'no error';
  return `${e.code ?? ''} ${e.message ?? ''}`.trim();
}

// ---------------------------------------------------------------------------
// Fixture state (cleanup targets)
// ---------------------------------------------------------------------------

const fixtures = {
  userIds: [],       // auth.users uuids (cascades to profiles)
  threadIds: [],
  replyIds: [],
  inviteIds: [],
};

const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const pgClient = new (pg.Client)({
  connectionString: (() => {
    const u = new URL(POSTGRES_URL_NON_POOLING);
    u.searchParams.set('sslmode', 'require');
    u.searchParams.set('uselibpqcompat', 'true');
    return u.toString();
  })(),
});

// ---------------------------------------------------------------------------
// Pre-flight: purge any residue from prior dead runs
// ---------------------------------------------------------------------------

async function purgeResidue() {
  const { rows: stale } = await pgClient.query(
    `SELECT id, email FROM auth.users WHERE email LIKE $1`,
    [`%@${FIXTURE_DOMAIN}`],
  );
  if (stale.length === 0) return;
  console.log(`\n[pre-flight] removing ${stale.length} residue user(s) from prior run`);
  const ids = stale.map((r) => r.id);
  // Reverse dependency order. write_events is the non-obvious one — it
  // audit-logs every mutation via a trigger, FK-references profiles.id
  // without CASCADE, and blocks auth.users deletion otherwise. Any
  // future FK-to-profiles table added will need its own line here.
  await pgClient.query(`DELETE FROM public.invites      WHERE issued_by = ANY($1) OR used_by = ANY($1)`, [ids]);
  await pgClient.query(`DELETE FROM public.replies      WHERE author_id = ANY($1)`, [ids]);
  await pgClient.query(`DELETE FROM public.threads      WHERE author_id = ANY($1)`, [ids]);
  await pgClient.query(`DELETE FROM public.write_events WHERE actor_id  = ANY($1)`, [ids]);
  // Use direct pg DELETE on auth.users rather than admin.auth.admin.deleteUser;
  // the admin API surfaces "Database error deleting user" on any FK restriction
  // rather than propagating the actual pg error, which makes debugging brutal.
  // Direct pg cascade to profiles works reliably once write_events is cleared.
  await pgClient.query(`DELETE FROM auth.users WHERE id = ANY($1)`, [ids]);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

await pgClient.connect();

try {
  await purgeResidue();

  console.log('\n=== Setup: create fixture users ===');
  const users = {};
  for (const [role, email] of Object.entries(USER_EMAILS)) {
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password: `${randomBytes(16).toString('hex')}-rls`,
      email_confirm: true,
    });
    if (error || !data.user) throw new Error(`createUser(${role}): ${error?.message ?? 'no user returned'}`);
    users[role] = data.user;
    fixtures.userIds.push(data.user.id);
    console.log(`  created ${role}: ${data.user.id}`);
  }

  console.log('\n=== Setup: configure profile state (direct pg bypasses RLS) ===');
  // Profiles are auto-created by a trigger on auth.users insert. We set
  // state post-creation so each fixture user matches its role.
  await pgClient.query(
    `UPDATE public.profiles SET forum_joined_at = NULL, needs_setup = true WHERE id = $1`,
    [users.unjoined.id],
  );
  await pgClient.query(
    `UPDATE public.profiles SET forum_joined_at = now(), banned_at = now(), needs_setup = false WHERE id = $1`,
    [users.banned.id],
  );
  await pgClient.query(
    `UPDATE public.profiles SET forum_joined_at = now(), needs_setup = false, display_name = 'rls-member-fixture' WHERE id = $1`,
    [users.member.id],
  );
  await pgClient.query(
    `UPDATE public.profiles SET forum_joined_at = now(), is_admin = true, needs_setup = false, display_name = 'rls-admin-fixture' WHERE id = $1`,
    [users.admin.id],
  );
  console.log('  profiles configured');

  console.log('\n=== Setup: seed content (as admin fixture) ===');
  const slug = (kind) => `${SLUG_PREFIX}${kind}-${randomBytes(4).toString('hex')}`;

  const { rows: [liveThread] } = await pgClient.query(
    `INSERT INTO public.threads (slug, category_slug, author_id, title, body)
     VALUES ($1, 'craft', $2, 'RLS fixture live thread', 'Body of live fixture thread.')
     RETURNING id`,
    [slug('live'), users.admin.id],
  );
  fixtures.threadIds.push(liveThread.id);

  const { rows: [deletedThread] } = await pgClient.query(
    `INSERT INTO public.threads (slug, category_slug, author_id, title, body, deleted_at)
     VALUES ($1, 'craft', $2, 'RLS fixture deleted thread', 'Body of deleted fixture thread.', now())
     RETURNING id`,
    [slug('deleted'), users.admin.id],
  );
  fixtures.threadIds.push(deletedThread.id);

  for (let i = 0; i < 2; i++) {
    const { rows: [r] } = await pgClient.query(
      `INSERT INTO public.replies (thread_id, author_id, body) VALUES ($1, $2, $3) RETURNING id`,
      [liveThread.id, users.admin.id, `RLS fixture live reply ${i}`],
    );
    fixtures.replyIds.push(r.id);
  }
  const { rows: [deletedReply] } = await pgClient.query(
    `INSERT INTO public.replies (thread_id, author_id, body, deleted_at)
     VALUES ($1, $2, 'RLS fixture deleted reply', now()) RETURNING id`,
    [liveThread.id, users.admin.id],
  );
  fixtures.replyIds.push(deletedReply.id);

  const { rows: [activeInvite] } = await pgClient.query(
    `INSERT INTO public.invites (email, issued_by, expires_at)
     VALUES ($1, $2, now() + interval '14 days') RETURNING id`,
    [INVITE_EMAILS.active, users.admin.id],
  );
  fixtures.inviteIds.push(activeInvite.id);
  const { rows: [consumedInvite] } = await pgClient.query(
    `INSERT INTO public.invites (email, issued_by, expires_at, used_at, used_by)
     VALUES ($1, $2, now() + interval '14 days', now(), $3) RETURNING id`,
    [INVITE_EMAILS.consumed, users.admin.id, users.member.id],
  );
  fixtures.inviteIds.push(consumedInvite.id);
  const { rows: [revokedInvite] } = await pgClient.query(
    `INSERT INTO public.invites (email, issued_by, expires_at, revoked_at)
     VALUES ($1, $2, now() + interval '14 days', now()) RETURNING id`,
    [INVITE_EMAILS.revoked, users.admin.id],
  );
  fixtures.inviteIds.push(revokedInvite.id);
  console.log(`  seeded 2 threads, 3 replies, 3 invites`);

  // ------------------------------------------------------------------------
  // Build session clients
  // ------------------------------------------------------------------------
  const sessions = {
    anon:     createClient(SUPABASE_URL, SUPABASE_ANON_KEY, { auth: { persistSession: false } }),
    unjoined: clientAs(users.unjoined.id),
    banned:   clientAs(users.banned.id),
    member:   clientAs(users.member.id),
    admin:    clientAs(users.admin.id),
  };

  // ------------------------------------------------------------------------
  // Visibility assertions — all scoped to fixture rows so a populated
  // prod DB doesn't inflate expected counts.
  // ------------------------------------------------------------------------

  console.log('\n=== Visibility: threads (fixture rows only) ===');
  for (const [role, client] of Object.entries(sessions)) {
    // live fixture threads
    const { data: live, error: liveErr } = await client
      .from('threads').select('id').in('id', fixtures.threadIds).is('deleted_at', null);
    const liveN = (live ?? []).length;

    // deleted fixture threads
    const { data: del } = await client
      .from('threads').select('id').in('id', fixtures.threadIds).not('deleted_at', 'is', null);
    const delN = (del ?? []).length;

    const expectedLive = role === 'admin' ? 1 : role === 'member' ? 1 : 0;
    const expectedDel  = role === 'admin' ? 1 : 0;

    assert(`${role}: live fixture threads visible = ${expectedLive}`,
      liveN === expectedLive, `got ${liveN}, err=${err(liveErr)}`);
    assert(`${role}: deleted fixture threads visible = ${expectedDel}`,
      delN === expectedDel, `got ${delN}`);
  }

  console.log('\n=== Visibility: replies (fixture rows only) ===');
  for (const [role, client] of Object.entries(sessions)) {
    const { data: live } = await client
      .from('replies').select('id').in('id', fixtures.replyIds).is('deleted_at', null);
    const { data: del } = await client
      .from('replies').select('id').in('id', fixtures.replyIds).not('deleted_at', 'is', null);

    const expectedLive = (role === 'admin' || role === 'member') ? 2 : 0;
    const expectedDel  = role === 'admin' ? 1 : 0;

    assert(`${role}: live fixture replies visible = ${expectedLive}`,
      (live ?? []).length === expectedLive, `got ${(live ?? []).length}`);
    assert(`${role}: deleted fixture replies visible = ${expectedDel}`,
      (del ?? []).length === expectedDel, `got ${(del ?? []).length}`);
  }

  console.log('\n=== Visibility: categories ===');
  for (const [role, client] of Object.entries(sessions)) {
    const { data } = await client.from('categories').select('slug');
    const n = (data ?? []).length;
    // Categories: anon gets 0 (no SELECT grant); members + admins see all 4.
    // Unjoined + banned are authenticated but not members → still 0 per RLS.
    const expected = (role === 'member' || role === 'admin') ? 4 : 0;
    assert(`${role}: categories visible = ${expected}`, n === expected, `got ${n}`);
  }

  console.log('\n=== Visibility: profiles (fixture users only) ===');
  for (const [role, client] of Object.entries(sessions)) {
    const { data } = await client
      .from('profiles').select('id, display_name, forum_joined_at, banned_at')
      .in('id', fixtures.userIds);
    const rows = data ?? [];

    let expected;
    if (role === 'anon') expected = 0;
    else if (role === 'unjoined') expected = 1;   // own row only
    else if (role === 'banned') expected = 1;     // own row only
    else if (role === 'member') expected = 2;     // admin + self, both joined+nonbanned (D43)
    else expected = 4;                            // admin sees all

    assert(`${role}: fixture profiles visible = ${expected}`, rows.length === expected, `got ${rows.length}`);

    // D43: member must NOT see the unjoined fixture profile
    if (role === 'member') {
      const sawUnjoined = rows.some((r) => r.id === users.unjoined.id);
      assert('D43: member does NOT see unjoined profile', !sawUnjoined, `member saw unjoined: ${sawUnjoined}`);
      const sawBanned = rows.some((r) => r.id === users.banned.id);
      assert('D43: member does NOT see banned profile', !sawBanned, `member saw banned: ${sawBanned}`);
    }
  }

  console.log('\n=== Visibility: invites (fixture rows only) ===');
  for (const [role, client] of Object.entries(sessions)) {
    const { data } = await client.from('invites').select('id').in('id', fixtures.inviteIds);
    const n = (data ?? []).length;
    const expected = role === 'admin' ? 3 : 0;
    assert(`${role}: fixture invites visible = ${expected}`, n === expected, `got ${n}`);
  }

  // ------------------------------------------------------------------------
  // RPC rejection matrix
  // ------------------------------------------------------------------------

  console.log('\n=== RPCs: rejection matrix ===');

  // rpc_create_thread: anon/unjoined/banned → forbidden
  for (const role of ['unjoined', 'banned']) {
    const { error } = await sessions[role].rpc('rpc_create_thread', {
      p_category_slug: 'craft',
      p_title: 'should fail',
      p_body: 'nope',
      p_slug: slug('reject'),
    });
    assert(`rpc_create_thread as ${role} → forbidden`,
      !!error && /forbidden/i.test(error.message), `err=${err(error)}`);
  }

  // rpc_create_reply on deleted thread → thread_unavailable
  {
    const { error } = await sessions.member.rpc('rpc_create_reply', {
      p_thread_id: deletedThread.id,
      p_body: 'reply on dead thread',
    });
    assert('rpc_create_reply on deleted thread → thread_unavailable',
      !!error && /thread_unavailable/i.test(error.message), `err=${err(error)}`);
  }

  // rpc_ban_user from non-admin → forbidden
  {
    const { error } = await sessions.member.rpc('rpc_ban_user', { p_id: users.unjoined.id });
    assert('rpc_ban_user from non-admin → forbidden',
      !!error && /forbidden/i.test(error.message), `err=${err(error)}`);
  }

  // rpc_lock_thread from non-admin → forbidden
  {
    const { error } = await sessions.member.rpc('rpc_lock_thread', { p_id: liveThread.id });
    assert('rpc_lock_thread from non-admin → forbidden',
      !!error && /forbidden/i.test(error.message), `err=${err(error)}`);
  }

  // rpc_issue_invite for already-joined email → already_member
  {
    const { error } = await sessions.admin.rpc('rpc_issue_invite', {
      p_email: USER_EMAILS.member,
      p_ttl_days: 14,
    });
    assert('rpc_issue_invite for already-joined → already_member',
      !!error && /already_member/i.test(error.message), `err=${err(error)}`);
  }

  // rpc_update_profile: rewriting should only ever touch auth.uid()'s row.
  // We can't target a foreign row via the RPC signature (p_display_name/p_bio
  // only), but verify the RPC succeeds for a member and rejects for banned.
  {
    const { error: memberErr } = await sessions.member.rpc('rpc_update_profile', {
      p_display_name: 'rls-member-updated',
      p_bio: null,
    });
    assert('rpc_update_profile succeeds for member', !memberErr, `err=${err(memberErr)}`);

    const { error: bannedErr } = await sessions.banned.rpc('rpc_update_profile', {
      p_display_name: 'should-fail',
      p_bio: null,
    });
    assert('rpc_update_profile from banned → forbidden',
      !!bannedErr && /forbidden/i.test(bannedErr.message), `err=${err(bannedErr)}`);
  }

  // ------------------------------------------------------------------------
  // Admin rate-limit exemption (0008 migration)
  // ------------------------------------------------------------------------

  console.log('\n=== 0008: admin rate-limit exemption ===');
  {
    const slugA = slug('rl-a');
    const slugB = slug('rl-b');
    const { error: errA } = await sessions.admin.rpc('rpc_create_thread', {
      p_category_slug: 'craft', p_title: 'RL test A', p_body: 'a', p_slug: slugA,
    });
    const { error: errB } = await sessions.admin.rpc('rpc_create_thread', {
      p_category_slug: 'craft', p_title: 'RL test B', p_body: 'b', p_slug: slugB,
    });
    assert('admin creates 1st rapid thread', !errA, `err=${err(errA)}`);
    assert('admin creates 2nd rapid thread (no rate limit)', !errB, `err=${err(errB)}`);

    // track for cleanup
    const { rows: newThreads } = await pgClient.query(
      `SELECT id FROM public.threads WHERE slug = ANY($1)`, [[slugA, slugB]],
    );
    fixtures.threadIds.push(...newThreads.map((r) => r.id));
  }

  // ------------------------------------------------------------------------
  // Summary
  // ------------------------------------------------------------------------

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f.label}  ${f.details ?? ''}`);
  }
} catch (err) {
  console.error('\n!!! harness error:', err);
  failed++;
} finally {
  // Cleanup — reverse dependency order, each wrapped so one failure doesn't
  // block others. Fixture ids are from this run only, so we never touch
  // real data.
  console.log('\n=== Cleanup ===');

  if (fixtures.inviteIds.length) {
    await pgClient.query(`DELETE FROM public.invites WHERE id = ANY($1)`, [fixtures.inviteIds]).catch((e) => console.log('  cleanup invites:', e.message));
  }
  if (fixtures.replyIds.length) {
    await pgClient.query(`DELETE FROM public.replies WHERE id = ANY($1)`, [fixtures.replyIds]).catch((e) => console.log('  cleanup replies:', e.message));
  }
  if (fixtures.threadIds.length) {
    await pgClient.query(`DELETE FROM public.threads WHERE id = ANY($1)`, [fixtures.threadIds]).catch((e) => console.log('  cleanup threads:', e.message));
  }
  if (fixtures.userIds.length) {
    // Clear write_events entries authored by fixture users; otherwise the
    // FK write_events.actor_id → profiles(id) (no CASCADE) blocks the
    // auth.users → profiles cascade deletion.
    await pgClient.query(`DELETE FROM public.write_events WHERE actor_id = ANY($1)`, [fixtures.userIds]).catch((e) => console.log('  cleanup write_events:', e.message));
    // Direct pg delete — see purgeResidue() note on why this beats admin API.
    await pgClient.query(`DELETE FROM auth.users WHERE id = ANY($1)`, [fixtures.userIds]).catch((e) => console.log('  cleanup auth.users:', e.message));
  }

  // Final verification: no rls-test.local rows remain
  const { rows: residue } = await pgClient.query(
    `SELECT count(*)::int AS n FROM auth.users WHERE email LIKE $1`,
    [`%@${FIXTURE_DOMAIN}`],
  );
  if (residue[0].n > 0) {
    console.log(`  WARN: ${residue[0].n} auth.users with @${FIXTURE_DOMAIN} remain after cleanup`);
    failed++;
  } else {
    console.log('  clean — no fixture residue remains');
  }

  await pgClient.end();
}

process.exit(failed > 0 ? 1 : 0);
