-- IMPL-0003 Phase 2 · Migration 0003 · SECURITY DEFINER RPCs
-- All mutation paths + admin operations + rate limits live here.
-- Every function:
--   - is SECURITY DEFINER (runs as function owner, bypasses RLS on its inserts)
--   - has SET search_path = public, pg_temp (prevents search-path injection)
--   - begins with an eligibility check (role, membership, admin, ownership)
--   - raises a P0xxx-coded exception on rejection
-- See IMPL-0003 §3 (RPC catalog) for the contract; §8 D8/D30/D31/D40/D41
-- for individual design notes.

-- -----------------------------------------------------------------------------
-- Rate-limit helpers
-- -----------------------------------------------------------------------------

-- assert_rate_limit: post-auth, called from mutating RPCs. Advisory lock on
-- (actor, kind); count + insert atomic in one tx (D17).
create function public.assert_rate_limit(
  p_actor uuid, p_kind text, p_window_secs int, p_max int
) returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
declare n int;
begin
  perform pg_advisory_xact_lock(hashtextextended(p_actor::text || ':' || p_kind, 0));
  select count(*) into n from public.write_events
    where actor_id = p_actor
      and kind = p_kind
      and created_at > now() - (p_window_secs || ' seconds')::interval;
  if n >= p_max then
    raise exception 'rate_limit_exceeded' using errcode = 'P0010';
  end if;
  insert into public.write_events(actor_id, kind) values (p_actor, p_kind);
end;
$$;

-- rpc_check_auth_rate_limit: pre-auth magic-link rate limit; dual advisory
-- locks (email + IP) in deterministic order to prevent same-IP/diff-emails
-- from racing past the IP limit (D26).
create function public.rpc_check_auth_rate_limit(
  p_email_hash bytea, p_ip_hash bytea, p_kind text,
  p_max_email int, p_max_ip int, p_window_secs int
) returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
declare n_email int; n_ip int;
begin
  if auth.role() <> 'service_role' then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(
    'email:' || encode(p_email_hash, 'hex') || ':' || p_kind, 0
  ));
  if p_ip_hash is not null then
    perform pg_advisory_xact_lock(hashtextextended(
      'ip:' || encode(p_ip_hash, 'hex') || ':' || p_kind, 0
    ));
  end if;
  select count(*) into n_email from public.auth_events
    where email_hash = p_email_hash and kind = p_kind
    and created_at > now() - (p_window_secs || ' seconds')::interval;
  if n_email >= p_max_email then
    raise exception 'rate_limit_exceeded' using errcode = 'P0010';
  end if;
  if p_ip_hash is not null then
    select count(*) into n_ip from public.auth_events
      where ip_hash = p_ip_hash and kind = p_kind
      and created_at > now() - (p_window_secs || ' seconds')::interval;
    if n_ip >= p_max_ip then
      raise exception 'rate_limit_exceeded' using errcode = 'P0010';
    end if;
  end if;
  insert into public.auth_events(email_hash, ip_hash, kind)
    values (p_email_hash, p_ip_hash, p_kind);
end;
$$;

-- -----------------------------------------------------------------------------
-- Service-role-only: user lookup + invite consumption
-- -----------------------------------------------------------------------------

-- rpc_lookup_user_by_email: D31. Only supported way to check auth.users from
-- app code. auth.admin.listUsers is pagination-only; direct SQL not exposed
-- via PostgREST without adding private-schema routes.
create function public.rpc_lookup_user_by_email(p_email citext)
returns uuid security definer language plpgsql
set search_path = public, pg_temp
as $$
declare v_id uuid;
begin
  if auth.role() <> 'service_role' then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  select id into v_id from auth.users
    where email = lower(trim(p_email::text))::citext
    limit 1;
  return v_id;
end;
$$;

-- rpc_consume_invite: D30. TOCTOU-proof via guarded UPDATEs; every check is
-- also the lock-acquiring operation. Any raise unwinds the entire function tx,
-- rolling back the invite claim.
create function public.rpc_consume_invite(p_invite_id uuid, p_user_id uuid)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
declare v_invite_email citext; v_user_email citext;
begin
  if auth.role() <> 'service_role' then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;

  -- 1. Atomically claim invite. Row lock held for the rest of the tx.
  update public.invites
    set used_by = p_user_id, used_at = now()
    where id = p_invite_id
      and used_at is null
      and revoked_at is null
      and expires_at > now()
    returning email into v_invite_email;
  if v_invite_email is null then
    raise exception 'invite_invalid' using errcode = 'P0002';
  end if;

  -- 2. Verify the bound email matches the consuming user's email.
  select email::citext into v_user_email
    from auth.users where id = p_user_id;
  if v_user_email is null or v_user_email <> v_invite_email then
    raise exception 'invite_user_mismatch' using errcode = 'P0003';
  end if;

  -- 3. Atomically grant membership. Guarded WHERE re-checks banned/joined.
  update public.profiles
    set forum_joined_at = now()
    where id = p_user_id
      and forum_joined_at is null
      and banned_at is null;
  if not found then
    raise exception 'profile_not_eligible' using errcode = 'P0004';
  end if;
end;
$$;

-- -----------------------------------------------------------------------------
-- Admin-only: invite issuance + moderation
-- -----------------------------------------------------------------------------

-- rpc_issue_invite: admin issues invite for a given email. Rejects already-
-- joined emails (P0007); revokes any prior active invite (D23); inserts a new
-- invite with normalized email (D40). CHECK on table is a second line of defense.
create function public.rpc_issue_invite(p_email citext, p_ttl_days int)
returns uuid security definer language plpgsql
set search_path = public, pg_temp
as $$
declare
  v_email citext := lower(trim(p_email::text))::citext;
  v_invite_id uuid;
begin
  if not private.is_admin_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;

  if exists (
    select 1 from auth.users u join public.profiles p on p.id = u.id
    where u.email::citext = v_email
      and p.forum_joined_at is not null
  ) then
    raise exception 'already_member' using errcode = 'P0007';
  end if;

  update public.invites set revoked_at = now()
    where email = v_email and used_at is null and revoked_at is null;

  insert into public.invites(email, issued_by, expires_at)
    values (v_email, auth.uid(), now() + (p_ttl_days || ' days')::interval)
    returning id into v_invite_id;
  return v_invite_id;
end;
$$;

create function public.rpc_revoke_invite(p_id uuid)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  if not private.is_admin_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  update public.invites set revoked_at = now()
    where id = p_id and used_at is null and revoked_at is null;
end;
$$;

create function public.rpc_lock_thread(p_id uuid)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  if not private.is_admin_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  update public.threads set locked_at = now()
    where id = p_id and locked_at is null and deleted_at is null;
end;
$$;

create function public.rpc_ban_user(p_id uuid)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  if not private.is_admin_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  update public.profiles set banned_at = now()
    where id = p_id and banned_at is null;
end;
$$;

-- -----------------------------------------------------------------------------
-- Member: content RPCs
-- -----------------------------------------------------------------------------

-- Reserved slug check. Canonical list lives in app code (IMPL-0003 §4);
-- duplicated here as defense-in-depth. Matches exact slug OR slug-dash-prefix.
create function private.is_reserved_slug(p_slug text)
returns boolean language sql immutable
set search_path = public, pg_temp as $$
  select p_slug ~ '^(new|login|logout|auth|api|admin|profile|setup|settings|mod|moderation|help|feed|rss|invite|invites|categories|category|search|probe|confirm)(-|$)';
$$;
revoke execute on function private.is_reserved_slug(text) from public;
grant execute on function private.is_reserved_slug(text) to authenticated, service_role;

create function public.rpc_create_thread(
  p_category_slug text,
  p_title text,
  p_body text,
  p_slug text
) returns uuid security definer language plpgsql
set search_path = public, pg_temp
as $$
declare v_id uuid;
begin
  if not private.is_active_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  if private.is_reserved_slug(p_slug) then
    raise exception 'slug_reserved' using errcode = 'P0008';
  end if;
  perform public.assert_rate_limit(auth.uid(), 'thread', 600, 1);
  insert into public.threads (slug, category_slug, author_id, title, body)
    values (p_slug, p_category_slug, auth.uid(), p_title, p_body)
    returning id into v_id;
  return v_id;
end;
$$;

create function public.rpc_edit_thread(p_id uuid, p_title text, p_body text)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  if not private.is_active_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  update public.threads
    set title = p_title, body = p_body, edited_at = now()
    where id = p_id
      and author_id = auth.uid()
      and created_at > now() - interval '10 minutes'
      and deleted_at is null
      and locked_at is null;
  if not found then
    raise exception 'edit_forbidden' using errcode = 'P0009';
  end if;
  perform public.assert_rate_limit(auth.uid(), 'edit_thread', 600, 5);
end;
$$;

create function public.rpc_create_reply(p_thread_id uuid, p_body text)
returns uuid security definer language plpgsql
set search_path = public, pg_temp
as $$
declare v_id uuid; v_thread_eligible boolean;
begin
  if not private.is_active_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  select true into v_thread_eligible
    from public.threads
    where id = p_thread_id
      and locked_at is null
      and deleted_at is null;
  if v_thread_eligible is null then
    raise exception 'thread_unavailable' using errcode = 'P0011';
  end if;
  perform public.assert_rate_limit(auth.uid(), 'reply', 30, 1);
  insert into public.replies (thread_id, author_id, body)
    values (p_thread_id, auth.uid(), p_body)
    returning id into v_id;
  return v_id;
end;
$$;

create function public.rpc_edit_reply(p_id uuid, p_body text)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  if not private.is_active_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  update public.replies
    set body = p_body, edited_at = now()
    where id = p_id
      and author_id = auth.uid()
      and created_at > now() - interval '10 minutes'
      and deleted_at is null;
  if not found then
    raise exception 'edit_forbidden' using errcode = 'P0009';
  end if;
  perform public.assert_rate_limit(auth.uid(), 'edit_reply', 600, 5);
end;
$$;

-- Soft delete: author within 10 min OR admin. The trigger on replies
-- auto-decrements thread.reply_count on deleted_at transition.
create function public.rpc_soft_delete_thread(p_id uuid)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
declare v_is_admin boolean := private.is_admin_member(auth.uid());
begin
  if not private.is_active_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  if v_is_admin then
    update public.threads set deleted_at = now()
      where id = p_id and deleted_at is null;
  else
    update public.threads set deleted_at = now()
      where id = p_id
        and author_id = auth.uid()
        and created_at > now() - interval '10 minutes'
        and deleted_at is null;
  end if;
  if not found then
    raise exception 'delete_forbidden' using errcode = 'P0012';
  end if;
end;
$$;

create function public.rpc_soft_delete_reply(p_id uuid)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
declare v_is_admin boolean := private.is_admin_member(auth.uid());
begin
  if not private.is_active_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  if v_is_admin then
    update public.replies set deleted_at = now()
      where id = p_id and deleted_at is null;
  else
    update public.replies set deleted_at = now()
      where id = p_id
        and author_id = auth.uid()
        and created_at > now() - interval '10 minutes'
        and deleted_at is null;
  end if;
  if not found then
    raise exception 'delete_forbidden' using errcode = 'P0012';
  end if;
end;
$$;

-- rpc_update_profile: only touches display_name, bio, needs_setup.
-- Ignores any user-supplied id (always targets auth.uid()).
create function public.rpc_update_profile(p_display_name text, p_bio text default null)
returns void security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  if not private.is_active_member(auth.uid()) then
    raise exception 'forbidden' using errcode = 'P0001';
  end if;
  if length(p_display_name) < 2 or length(p_display_name) > 40 then
    raise exception 'invalid_display_name' using errcode = 'P0013';
  end if;
  if p_bio is not null and length(p_bio) > 280 then
    raise exception 'invalid_bio' using errcode = 'P0013';
  end if;
  update public.profiles
    set display_name = p_display_name,
        bio = p_bio,
        needs_setup = false
    where id = auth.uid();
  perform public.assert_rate_limit(auth.uid(), 'update_profile', 3600, 5);
end;
$$;
