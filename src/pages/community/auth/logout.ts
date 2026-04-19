// POST → clear session cookies and redirect to /community/login.
// IMPL-0003 §4: session-only bucket; banned sessions still allowed through
// here so the user can complete logout. Phase 6 adds CSRF + Origin guards.

import type { APIRoute } from 'astro';
import { createSupabaseServerClient } from '../../../lib/supabase/server';

export const GET: APIRoute = () =>
  new Response('Method Not Allowed', {
    status: 405,
    headers: { Allow: 'POST' },
  });

export const POST: APIRoute = async ({ cookies, redirect }) => {
  const supabase = createSupabaseServerClient(cookies);
  await supabase.auth.signOut();
  return redirect('/community/login');
};
