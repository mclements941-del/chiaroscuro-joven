// POST /community/api/admin/revoke-invite — revoke an invite (admin only).
// Body: form-encoded `invite_id=<uuid>` OR JSON { "invite_id": "<uuid>" }
// rpc_revoke_invite is idempotent — already-consumed / already-revoked rows
// are left alone.

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
  let inviteId: string | null = null;
  let wantsJson = false;

  if (contentType.includes('application/json')) {
    wantsJson = true;
    try {
      const body = (await request.json()) as { invite_id?: unknown };
      if (typeof body.invite_id === 'string') inviteId = body.invite_id;
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
    inviteId = String(form.get('invite_id') ?? '');
  }

  if (!inviteId || !isUuid(inviteId)) {
    return wantsJson
      ? new Response(JSON.stringify({ error: 'invalid_invite_id' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        })
      : new Response('Invalid invite_id', { status: 400 });
  }

  const supabase = createSupabaseServerClient(cookies);
  const { error } = await supabase.rpc('rpc_revoke_invite', { p_id: inviteId });
  if (error) {
    if (/forbidden/.test(error.message)) {
      return new Response('Forbidden', { status: 403 });
    }
    console.error('[admin revoke-invite] rpc_revoke_invite:', error.message);
    return wantsJson
      ? new Response(JSON.stringify({ error: 'revoke_failed' }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' },
        })
      : new Response('Revoke failed', { status: 500 });
  }

  if (wantsJson) {
    return new Response(JSON.stringify({ ok: true, invite_id: inviteId }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(null, {
    status: 303,
    headers: { Location: '/community/admin' },
  });
};
