// IMPL-0003 §4 callback contract. POST ONLY.
//
// Full Phase 3 flow:
//  1. Read token_hash + type from form body (not query string)
//  2. verifyOtp server-side → sets session cookies
//  3. Load user + profile
//  4. Banned check (D32) → sign out + ?reason=account_closed
//  5. Service-role invite lookup by session email
//  6. If active invite → rpc_consume_invite (atomic per D30); on failure
//     reload profile — a concurrent call may already have succeeded
//  7. Final membership check: if still no forum_joined_at → sign out + not_member
//  8. Route by needs_setup: → /profile/setup or → /community

import type { APIRoute } from 'astro';
import { createSupabaseServerClient } from '../../../lib/supabase/server';
import { createSupabaseAdminClient } from '../../../lib/supabase/admin';

export const GET: APIRoute = () =>
  new Response('Method Not Allowed', {
    status: 405,
    headers: { Allow: 'POST' },
  });

export const POST: APIRoute = async ({ request, cookies, redirect }) => {
  const form = await request.formData();
  const token_hash = String(form.get('token_hash') ?? '');
  const type = String(form.get('type') ?? '');

  if (!token_hash || !type) {
    return new Response('Invalid confirmation link.', { status: 400 });
  }

  const supabase = createSupabaseServerClient(cookies);
  const { error: verifyErr } = await supabase.auth.verifyOtp({
    token_hash,
    type: type as 'invite' | 'email' | 'magiclink' | 'signup' | 'recovery',
  });

  if (verifyErr) {
    console.error('[auth/callback] verifyOtp failed:', verifyErr.message);
    return new Response(
      'This link has expired or is invalid. Request a new one from /community/login.',
      { status: 400 },
    );
  }

  const { data: { user } } = await supabase.auth.getUser();
  if (!user?.email) {
    console.error('[auth/callback] session missing after verifyOtp');
    return new Response('Authentication failed.', { status: 400 });
  }

  // Load profile (own row via profiles_select_self policy).
  let { data: profile } = await supabase
    .from('profiles')
    .select('id, banned_at, forum_joined_at, needs_setup')
    .eq('id', user.id)
    .maybeSingle();

  // Banned check (D32): fires BEFORE destination logic. Middleware also
  // catches this on subsequent requests; the callback check closes the
  // fresh-session window between ban and first authed hit.
  if (profile?.banned_at) {
    await supabase.auth.signOut();
    return redirect('/community/login?reason=account_closed');
  }

  // Invite consumption path (service-role).
  const admin = createSupabaseAdminClient();
  const { data: invite } = await admin
    .from('invites')
    .select('id')
    .eq('email', user.email)
    .is('used_at', null)
    .is('revoked_at', null)
    .gt('expires_at', new Date().toISOString())
    .limit(1)
    .maybeSingle();

  if (invite) {
    const { error: consumeErr } = await admin.rpc('rpc_consume_invite', {
      p_invite_id: invite.id,
      p_user_id: user.id,
    });
    if (consumeErr) {
      // D30: two-parallel-consume case raises invite_invalid on the loser.
      // Reload profile — if membership got set by a concurrent call we're
      // still fine.
      console.error('[auth/callback] rpc_consume_invite:', consumeErr.message);
    }
    // Always reload after consumption attempt so the destination logic sees
    // the current state.
    ({ data: profile } = await supabase
      .from('profiles')
      .select('id, banned_at, forum_joined_at, needs_setup')
      .eq('id', user.id)
      .maybeSingle());
  }

  // Final membership gate.
  if (!profile?.forum_joined_at) {
    await supabase.auth.signOut();
    return redirect('/community/login?reason=not_member');
  }

  // Destination: setup on first login, community thereafter.
  if (profile.needs_setup) {
    return redirect('/community/profile/setup');
  }
  return redirect('/community');
};
