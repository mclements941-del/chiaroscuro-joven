-- IMPL-0003 Phase 2 · Migration 0005 · Explicit EXECUTE grants
-- PostgreSQL's default is to GRANT EXECUTE ON FUNCTION to PUBLIC, which means
-- any role can call the function via PostgREST. Revoke that and grant only to
-- the intended role per IMPL-0003 §3 matrix (D19).

-- -----------------------------------------------------------------------------
-- Session-client callable (authenticated role)
-- -----------------------------------------------------------------------------

do $$
declare fn text;
begin
  for fn in
    select unnest(array[
      'rpc_create_thread(text, text, text, text)',
      'rpc_edit_thread(uuid, text, text)',
      'rpc_create_reply(uuid, text)',
      'rpc_edit_reply(uuid, text)',
      'rpc_soft_delete_thread(uuid)',
      'rpc_soft_delete_reply(uuid)',
      'rpc_update_profile(text, text)',
      'rpc_issue_invite(citext, integer)',
      'rpc_revoke_invite(uuid)',
      'rpc_lock_thread(uuid)',
      'rpc_ban_user(uuid)'
    ])
  loop
    execute format('revoke execute on function public.%s from public, anon', fn);
    execute format('grant execute on function public.%s to authenticated', fn);
  end loop;
end $$;

-- -----------------------------------------------------------------------------
-- Service-role-only (D38)
-- -----------------------------------------------------------------------------
-- These RPCs assert `auth.role() = 'service_role'` in their body, but we also
-- revoke EXECUTE from authenticated so a misconfigured client library can't
-- even attempt the call.

do $$
declare fn text;
begin
  for fn in
    select unnest(array[
      'rpc_consume_invite(uuid, uuid)',
      'rpc_lookup_user_by_email(citext)',
      'rpc_check_auth_rate_limit(bytea, bytea, text, integer, integer, integer)',
      'assert_rate_limit(uuid, text, integer, integer)'
    ])
  loop
    execute format('revoke execute on function public.%s from public, anon, authenticated', fn);
    execute format('grant execute on function public.%s to service_role', fn);
  end loop;
end $$;

-- private.is_active_member + private.is_admin_member + private.is_reserved_slug
-- grants were set in 0002 + 0003 alongside their definitions. The `private`
-- schema itself is excluded from PostgREST's db-schemas list (default config),
-- so these helpers cannot be called over the Data API regardless.
