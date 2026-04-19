// POST /community/api/admin/ban — ban a member (admin only).
// Body: form-encoded `user_id=<uuid>` OR JSON { "user_id": "<uuid>" }
// On success: 303 redirect back to /community/admin (form submission),
// or 200 JSON (JSON submission).
//
// rpc_ban_user enforces admin status via private.is_admin_member(auth.uid()),
// so non-admin callers get a P0001 forbidden from the DB. Middleware also
// routes /community/api/admin/** into the Admin bucket, so unauthenticated
// and non-admin callers bounce before this handler runs.

import type { APIRoute } from 'astro';
import { createSupabaseServerClient } from '../../../../lib/supabase/server';

function isUuid(s: string): boolean {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);
}

export const POST: APIRoute = async ({ request, cookies, locals }) => {
  if (!locals.profile?.is_admin) {
    return new Response('Not Found', { status: 404 });
  }

  const contentType = request.headers.get('content-type') ?? '';
  let userId: string | null = null;
  let wantsJson = false;

  if (contentType.includes('application/json')) {
    wantsJson = true;
    try {
      const body = (await request.json()) as { user_id?: unknown };
      if (typeof body.user_id === 'string') userId = body.user_id;
    } catch {
      return new Response(JSON.stringify({ error: 'invalid_body' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  } else {
    let form: FormData | null = null;
    try {
      form = await request.formData();
    } catch {
      return new Response('Bad Request', { status: 400 });
    }
    userId = String(form.get('user_id') ?? '');
  }

  if (!userId || !isUuid(userId)) {
    return wantsJson
      ? new Response(JSON.stringify({ error: 'invalid_user_id' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      : new Response('Invalid user_id', { status: 400 });
  }

  // Refuse self-ban — defensive; admin can't ban the last admin out of the
  // room. `private.is_admin_member` in rpc_ban_user lets this through today;
  // layering the check here prevents the "admin accidentally bans self" foot-gun.
  if (userId === locals.user?.id) {
    return wantsJson
      ? new Response(JSON.stringify({ error: 'cannot_self_ban' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      : new Response('Cannot ban yourself', { status: 400 });
  }

  const supabase = createSupabaseServerClient(cookies);
  const { error } = await supabase.rpc('rpc_ban_user', { p_id: userId });
  if (error) {
    if (/forbidden/.test(error.message)) {
      return new Response('Forbidden', { status: 403 });
    }
    console.error('[admin ban] rpc_ban_user:', error.message);
    return wantsJson
      ? new Response(JSON.stringify({ error: 'ban_failed' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        })
      : new Response('Ban failed', { status: 500 });
  }

  if (wantsJson) {
    return new Response(JSON.stringify({ ok: true, user_id: userId }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(null, {
    status: 303,
    headers: { Location: '/community/admin' },
  });
};
