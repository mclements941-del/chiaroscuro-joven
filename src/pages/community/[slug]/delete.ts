// POST /community/[slug]/delete — soft-delete a thread.
// Authorization is enforced in rpc_soft_delete_thread:
//   - owner within 10-min window, OR
//   - admin (any time)
// Non-eligible callers get P0012 delete_forbidden and this handler
// responds 403. On success: redirect to /community.

import type { APIRoute } from 'astro';
import { createSupabaseServerClient } from '../../../lib/supabase/server';

export const POST: APIRoute = async ({ params, cookies, locals }) => {
  const slug = params.slug;
  if (!slug) return new Response('Not Found', { status: 404 });
  if (!locals.user) return new Response('Unauthorized', { status: 401 });

  const supabase = createSupabaseServerClient(cookies);

  const { data: thread } = await supabase
    .from('threads')
    .select('id')
    .eq('slug', slug)
    .maybeSingle();
  if (!thread) return new Response('Not Found', { status: 404 });

  const { error } = await supabase.rpc('rpc_soft_delete_thread', {
    p_id: thread.id,
  });
  if (error) {
    if (/delete_forbidden/.test(error.message)) {
      return new Response('Forbidden', { status: 403 });
    }
    if (/forbidden/.test(error.message)) {
      return new Response('Forbidden', { status: 403 });
    }
    console.error('[thread delete] rpc_soft_delete_thread:', error.message);
    return new Response('Delete failed', { status: 500 });
  }

  return new Response(null, {
    status: 303,
    headers: { Location: '/community' },
  });
};
