// Phase 1 middleware: route bucket classification + session load.
// Phase 2 will add profile query for banned/joined/admin enforcement
// (the `profiles` table does not exist yet at Phase 1 time).
// Phase 6 will add CSRF double-submit cookie + Origin allowlist check.
//
// IMPL-0003 §4 (Middleware route classes) + §8 D18/D29/D35.
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

  // Phase 2 will add:
  //   - profile load from `profiles` table
  //   - banned_at check (D32): sign out + redirect to ?reason=account_closed
  //     (except on /community/auth/logout, which always proceeds)
  //   - forum_joined_at check for member/admin buckets
  //   - is_admin check for admin bucket (404 on non-admin, not 403)
  //
  // For Phase 1 exit-gate purposes, session presence is enough to serve
  // /probe and /auth/logout. The invite + return-login flow (Phase 3)
  // depends on the schema landing first in Phase 2.

  return next();
});
