// POST /community/api/invites — admin-only invite issuance.
// Body: { "email": "person@example.com" }
//
// Flow (IMPL-0003 §6 Phase 3):
//   0. Handler-side normalization: trim + lowercase, zod-validate
//   1. Middleware already enforces admin bucket (locals.profile.is_admin)
//   2. Session client: rpc_issue_invite(email, 14) — admin check via auth.uid(),
//      rejects already-joined, revokes prior active, inserts new
//   3. Service-role client: rpc_lookup_user_by_email to check auth.users state
//   4. Branch:
//      - no existing user → auth.admin.inviteUserByEmail (creates user + email)
//      - existing unjoined → signInWithOtp({ shouldCreateUser: false }) — sends
//        magic link; callback consumes the new invite
//   5. On Supabase failure → rpc_revoke_invite to keep DB state consistent

import type { APIRoute } from 'astro';
import { z } from 'zod';
import { createSupabaseServerClient } from '../../../lib/supabase/server';
import { createSupabaseAdminClient } from '../../../lib/supabase/admin';
import { getCallbackUrl } from '../../../lib/auth-origin';

const bodySchema = z.object({
  email: z.email().trim().toLowerCase(),
});

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export const POST: APIRoute = async ({ request, cookies, locals }) => {
  // Admin guard (middleware enforces this at the route level too, but
  // defense-in-depth).
  if (!locals.profile?.is_admin) {
    return json(404, { error: 'not_found' });
  }

  let parsed: { email: string };
  try {
    const raw = await request.json();
    const result = bodySchema.safeParse(raw);
    if (!result.success) {
      return json(400, { error: 'invalid_email' });
    }
    parsed = result.data;
  } catch {
    return json(400, { error: 'invalid_body' });
  }
  const email = parsed.email;

  // 1. rpc_issue_invite via session client (needs auth.uid())
  const supabase = createSupabaseServerClient(cookies);
  const { data: inviteId, error: issueErr } = await supabase.rpc(
    'rpc_issue_invite',
    { p_email: email, p_ttl_days: 14 },
  );
  if (issueErr) {
    if (issueErr.message.includes('already_member')) {
      return json(400, { error: 'already_member' });
    }
    console.error('[invites POST] rpc_issue_invite:', issueErr.message);
    return json(500, { error: 'issue_failed' });
  }

  // 2. Check whether auth.users row already exists for email
  const admin = createSupabaseAdminClient();
  const { data: existingUserId, error: lookupErr } = await admin.rpc(
    'rpc_lookup_user_by_email',
    { p_email: email },
  );
  if (lookupErr) {
    console.error('[invites POST] rpc_lookup_user_by_email:', lookupErr.message);
    await supabase.rpc('rpc_revoke_invite', { p_id: inviteId });
    return json(500, { error: 'lookup_failed' });
  }

  // 3. Send the right email.
  let sendErr: { message: string } | null = null;
  if (!existingUserId) {
    const { error } = await admin.auth.admin.inviteUserByEmail(email, {
      redirectTo: getCallbackUrl(),
    });
    sendErr = error;
  } else {
    const { error } = await admin.auth.signInWithOtp({
      email,
      options: {
        shouldCreateUser: false,
        emailRedirectTo: getCallbackUrl(),
      },
    });
    sendErr = error;
  }

  if (sendErr) {
    console.error('[invites POST] send failure:', sendErr.message);
    await supabase.rpc('rpc_revoke_invite', { p_id: inviteId });
    return json(500, { error: 'send_failed' });
  }

  return json(201, {
    invite_id: inviteId,
    email,
    path: existingUserId ? 'signInWithOtp' : 'inviteUserByEmail',
  });
};
