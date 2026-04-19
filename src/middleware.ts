// Phase 3 middleware: route bucket classification + session load + profile
// load + banned/joined/admin enforcement (D18 + D29 + D32 + D41).
// Phase 6 will add CSRF double-submit cookie + Origin allowlist checks.
//
// IMPL-0003 §4 (Middleware route classes) + §8 D18/D29/D32/D35/D41.
// FORUM_ENABLED read via process.env at request time (D35); flip requires
// a new Vercel deployment per Vercel's env semantics.

import { defineMiddleware } from 'astro:middleware';
import { createSupabaseServerClient } from './lib/supabase/server';

type Bucket = 'public' | 'session' | 'member' | 'admin';

const PUBLIC_PATHS = new Set([
  '/community/login',
  '/community/login/',
  '/community/auth/confirm',
  '/community/auth/confirm/',
  '/community/auth/callback',
  '/community/auth/callback/',
]);

const SESSION_ONLY_PATHS = new Set([
  '/community/auth/logout',
  '/community/auth/logout/',
  '/community/probe',
  '/community/probe/',
]);

function classifyRoute(pathname: string, forumEnabled: boolean): Bucket | null {
  if (!pathname.startsWith('/community')) return null;
  if (PUBLIC_PATHS.has(pathname)) return 'public';
  if (SESSION_ONLY_PATHS.has(pathname)) return 'session';
  if (pathname.startsWith('/community/admin')) return 'admin';
  // Flag-dependent: /community and all other /community/** routes
  // (e.g., /community/new, /community/[slug], /community/profile/setup).
  // When FORUM_ENABLED=false they render a placeholder under the Public
  // bucket; when true they move to Members.
  if (pathname === '/community' || pathname === '/community/') {
    return forumEnabled ? 'member' : 'public';
  }
  return forumEnabled ? 'member' : 'public';
}

export const onRequest = defineMiddleware(async (context, next) => {
  const { url, cookies, locals } = context;
  const pathname = url.pathname;

  // Initialize locals for every request so page code can read them without
  // defensive undefined checks.
  locals.user = null;
  locals.profile = null;

  if (!pathname.startsWith('/community')) return next();

  const forumEnabled = process.env.FORUM_ENABLED === 'true';
  const bucket = classifyRoute(pathname, forumEnabled);
  if (bucket === null || bucket === 'public') return next();

  // Session-bound client for session/member/admin buckets.
  const supabase = createSupabaseServerClient(cookies);
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    // IMPL-0003 §7 Phase 1 AC: `/community/probe` returns 401 unauthed
    // (rather than redirecting) so smoke tests can detect the auth gate
    // programmatically. All other protected routes redirect to login.
    if (pathname === '/community/probe' || pathname === '/community/probe/') {
      return new Response('Unauthorized', { status: 401 });
    }
    return context.redirect('/community/login');
  }

  locals.user = user;

  // Load profile (own row via profiles_select_self RLS policy).
  const { data: profile } = await supabase
    .from('profiles')
    .select('id, display_name, is_admin, banned_at, needs_setup, forum_joined_at')
    .eq('id', user.id)
    .maybeSingle();

  locals.profile = profile ?? null;

  // Banned check (D32). /community/auth/logout proceeds regardless so a
  // banned user can still complete their logout flow; every other protected
  // route signs them out and redirects.
  const isLogout =
    pathname === '/community/auth/logout' || pathname === '/community/auth/logout/';
  if (profile?.banned_at && !isLogout) {
    await supabase.auth.signOut();
    return context.redirect('/community/login?reason=account_closed');
  }

  // Session-only bucket (/probe, /auth/logout) needs session but not
  // membership. Callback grants membership on first invite consumption.
  if (bucket === 'session') return next();

  // Member + Admin buckets require active membership.
  if (!profile?.forum_joined_at) {
    return context.redirect('/community/login?reason=not_member');
  }

  // Admin: non-admin → 404 (don't advertise existence of admin surface).
  if (bucket === 'admin' && !profile.is_admin) {
    return new Response('Not Found', { status: 404 });
  }

  return next();
});
