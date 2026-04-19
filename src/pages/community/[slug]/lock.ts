// POST /community/[slug]/lock — lock a thread (admin only).
// rpc_lock_thread enforces admin membership. Non-admin → 403.

import type { APIRoute } from 'astro';
import { createSupabaseServerClient } from '../../../lib/supabase/server';

export const POST: APIRoute = async ({ params, cookies, locals }) => {
  const slug = params.slug;
  if (!slug) return new Response('Not Found', { status: 404 });
  if (!locals.profile?.is_admin) {
    // Don't advertise the lock surface to non-admins.
    return new Response('Not Found', { status: 404 });
  }

  const supabase = createSupabaseServerClient(cookies);

  const { data: thread } = await supabase
    .from('threads')
    .select('id')
    .eq('slug', slug)
    .maybeSingle();
  if (!thread) return new Response('Not Found', { status: 404 });

  const { error } = await supabase.rpc('rpc_lock_thread', { p_id: thread.id });
  if (error) {
    if (/forbidden/.test(error.message)) {
      return new Response('Forbidden', { status: 403 });
    }
    console.error('[thread lock] rpc_lock_thread:', error.message);
    return new Response('Lock failed', { status: 500 });
  }

  return new Response(null, {
    status: 303,
    headers: { Location: `/community/${slug}` },
  });
};
