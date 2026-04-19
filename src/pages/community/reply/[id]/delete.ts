// POST /community/reply/[id]/delete — soft-delete a reply.
// Authorization mirrors rpc_soft_delete_reply: owner ≤ 10 min OR admin.

import type { APIRoute } from 'astro';
import { createSupabaseServerClient } from '../../../../lib/supabase/server';

export const POST: APIRoute = async ({ params, cookies, locals }) => {
  const id = params.id;
  if (!id) return new Response('Not Found', { status: 404 });
  if (!locals.user) return new Response('Unauthorized', { status: 401 });

  const supabase = createSupabaseServerClient(cookies);

  // Fetch the reply's thread slug for post-delete redirect.
  const { data: reply } = await supabase
    .from('replies')
    .select('thread_id')
    .eq('id', id)
    .maybeSingle();
  if (!reply) return new Response('Not Found', { status: 404 });

  const { data: thread } = await supabase
    .from('threads')
    .select('slug')
    .eq('id', reply.thread_id)
    .maybeSingle();
  // If thread was deleted out from under the reply, still try the RPC and
  // fall back to /community on success.
  const redirectTo = thread?.slug ? `/community/${thread.slug}` : '/community';

  const { error } = await supabase.rpc('rpc_soft_delete_reply', { p_id: id });
  if (error) {
    if (/delete_forbidden|forbidden/.test(error.message)) {
      return new Response('Forbidden', { status: 403 });
    }
    console.error('[reply delete] rpc_soft_delete_reply:', error.message);
    return new Response('Delete failed', { status: 500 });
  }

  return new Response(null, {
    status: 303,
    headers: { Location: redirectTo },
  });
};
