// Phase 3 middleware + Phase 6 CSRF/Origin (IMPL-0003 §4 + D12 + D18 +
// D20 + D29 + D32 + D35 + D36 + D41).
//
// Request lifecycle for /community/**:
//   1. Mint/refresh the CSRF cookie so every rendered form can include it.
//   2. On non-GET (except /community/auth/callback — D36): validate
//      Origin allowlist, then validate CSRF double-submit.
//   3. Classify route bucket and enforce auth/membership/admin.
//
// FORUM_ENABLED read via process.env at request time (D35); flip requires
// a new Vercel deployment per Vercel's env semantics.

import { defineMiddleware } from 'astro:middleware';
import { createSupabaseServerClient } from './lib/supabase/server';
import { getOrSetCsrfCookie, validateCsrfRequest } from './lib/csrf';
import { isAllowedOrigin } from './lib/origin-allowlist';

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

// Paths exempt from CSRF enforcement on non-GET. `/community/auth/callback`
// is the only one — it's a POST where the browser arrives with a
// `token_hash` from the confirm interstitial that is itself proof of
// possession (D36). No cookie existed before the callback so double-submit
// is impossible there. Origin allowlist STILL applies to the callback.
const CSRF_EXEMPT_NONGET = new Set([
  '/community/auth/callback',
  '/community/auth/callback/',
]);

function isInviteApi(p: string): boolean {
  return (
    p === '/community/api/invites' ||
    p === '/community/api/invites/' ||
    p.startsWith('/community/api/invites/')
  );
}

function isAdminApi(p: string): boolean {
  return p.startsWith('/community/api/admin/') || isInviteApi(p);
}

function isMemberApi(p: string): boolean {
  return p.startsWith('/community/api/');
}

function isProfile(p: string): boolean {
  return p.startsWith('/community/profile');
}

function classifyRoute(pathname: string, forumEnabled: boolean): Bucket | null {
  if (!pathname.startsWith('/community')) return null;

  if (PUBLIC_PATHS.has(pathname)) return 'public';
  if (SESSION_ONLY_PATHS.has(pathname)) return 'session';
  if (pathname.startsWith('/community/admin')) return 'admin';
  if (isAdminApi(pathname)) return 'admin';
  if (isMemberApi(pathname)) return 'member';
  if (isProfile(pathname)) return 'member';

  if (pathname === '/community' || pathname === '/community/') {
    return forumEnabled ? 'member' : 'public';
  }
  return forumEnabled ? 'member' : 'public';
}

export const onRequest = defineMiddleware(async (context, next) => {
  const { url, cookies, locals, request } = context;
  const pathname = url.pathname;

  locals.user = null;
  locals.profile = null;
  locals.csrfToken = '';

  if (!pathname.startsWith('/community')) return next();

  // Always mint/refresh the CSRF cookie on /community/** — makes forms on
  // login, probe, confirm, callback, member, admin pages all work.
  locals.csrfToken = getOrSetCsrfCookie(cookies);

  // Non-GET pre-flight: Origin allowlist + CSRF double-submit.
  const method = request.method;
  if (method !== 'GET' && method !== 'HEAD') {
    const origin = request.headers.get('origin');
    if (!isAllowedOrigin(origin)) {
      return new Response('Forbidden', { status: 403 });
    }
    if (!CSRF_EXEMPT_NONGET.has(pathname)) {
      const csrf = await validateCsrfRequest(request, cookies);
      if (!csrf.ok) {
        // Don't leak which check failed externally; log for diagnosis.
        console.warn('[middleware] CSRF reject:', csrf.reason, pathname);
        return new Response('Forbidden', { status: 403 });
      }
    }
  }

  const forumEnabled = process.env.FORUM_ENABLED === 'true';
  const bucket = classifyRoute(pathname, forumEnabled);
  if (bucket === null || bucket === 'public') return next();

  const supabase = createSupabaseServerClient(cookies);
  const { data: { user } } = await supabase.auth.getUser();

  if (!user) {
    if (pathname === '/community/probe' || pathname === '/community/probe/') {
      return new Response('Unauthorized', { status: 401 });
    }
    return context.redirect('/community/login');
  }

  locals.user = user;

  const { data: profile } = await supabase
    .from('profiles')
    .select('id, display_name, bio, is_admin, banned_at, needs_setup, forum_joined_at')
    .eq('id', user.id)
    .maybeSingle();

  locals.profile = profile ?? null;

  const isLogout =
    pathname === '/community/auth/logout' || pathname === '/community/auth/logout/';
  if (profile?.banned_at && !isLogout) {
    await supabase.auth.signOut();
    return context.redirect('/community/login?reason=account_closed');
  }

  if (bucket === 'session') return next();

  if (!profile?.forum_joined_at) {
    return context.redirect('/community/login?reason=not_member');
  }

  if (profile.needs_setup) {
    const isSetup =
      pathname === '/community/profile/setup' ||
      pathname === '/community/profile/setup/';
    if (!isSetup && !isLogout) {
      return context.redirect('/community/profile/setup');
    }
  }

  if (bucket === 'admin' && !profile.is_admin) {
    return new Response('Not Found', { status: 404 });
  }

  return next();
});
