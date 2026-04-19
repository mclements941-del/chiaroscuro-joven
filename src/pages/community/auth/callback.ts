// IMPL-0003 §4 callback contract. POST ONLY.
// Reads token_hash + type from form body (not query string), calls
// verifyOtp server-side, sets session cookies via @supabase/ssr.
// Phase 2/3 add: banned_at check (D32), invite lookup + consumption,
// needs_setup routing. Phase 1 smoke-tests the auth flow by redirecting
// all successful verifications to /probe.

import type { APIRoute } from 'astro';
import { createSupabaseServerClient } from '../../../lib/supabase/server';

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
  const { error } = await supabase.auth.verifyOtp({
    token_hash,
    type: type as 'invite' | 'email' | 'magiclink' | 'signup' | 'recovery',
  });

  if (error) {
    // Keep the response generic — don't leak which condition failed.
    console.error('[auth/callback] verifyOtp failed:', error.message);
    return new Response(
      'This link has expired or is invalid. Request a new one from /community/login.',
      { status: 400 },
    );
  }

  // Phase 2/3 TODO:
  //  1. Check profiles.banned_at — sign out + redirect to ?reason=account_closed if banned (D32)
  //  2. Service-role invite lookup by session email
  //  3. If active invite → rpc_consume_invite
  //  4. Route by state: needs_setup → /profile/setup, joined → /community,
  //     otherwise sign out + ?reason=not_member
  //
  // Phase 1: successful auth → /probe for smoke-test visibility.
  return redirect('/community/probe');
};
