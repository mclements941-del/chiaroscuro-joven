-- IMPL-0003 · Migration 0008 · Admin rate-limit exemption
--
-- The content RPCs (create_thread, create_reply, edit_thread, edit_reply,
-- update_profile) call public.assert_rate_limit to bound member behavior.
-- Admins are operators, not threat actors in the abuse-model sense — they
-- seed content in bursts, moderate in bursts, and shouldn't be throttled
-- like regular members. Wraps each assert_rate_limit call in an admin
-- check so admins pass through.
--
-- Trust model: an admin-compromised session could now post unbounded
-- threads/replies. Acceptable because (a) admin count is 1, (b) admin
-- sessions are magic-link-gated like everyone else, and (c) admin-scoped
-- destructive actions (ban, lock, delete) would already be worse than
-- spam if an admin account were compromised. The ban on unbounded posting
-- doesn't buy defense-in-depth that the ban on the worse actions doesn't
-- already provide.
--
-- Idempotent via CREATE OR REPLACE FUNCTION. Signatures unchanged, so
-- grants from 0005_forum_grants.sql carry over without re-granting.

begin;

-- -----------------------------------------------------------------------
-- rpc_create_thread
-- -----------------------------------------------------------------------
create or replace function public.rpc_create_thread(
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
  if not private.is_admin_member(auth.uid()) then
    perform public.assert_rate_limit(auth.uid(), 'thread', 600, 1);
  end if;
  insert into public.threads (slug, category_slug, author_id, title, body)
    values (p_slug, p_category_slug, auth.uid(), p_title, p_body)
    returning id into v_id;
  return v_id;
end;
$$;

-- -----------------------------------------------------------------------
-- rpc_edit_thread
-- -----------------------------------------------------------------------
create or replace function public.rpc_edit_thread(p_id uuid, p_title text, p_body text)
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
  if not private.is_admin_member(auth.uid()) then
    perform public.assert_rate_limit(auth.uid(), 'edit_thread', 600, 5);
  end if;
end;
$$;

-- -----------------------------------------------------------------------
-- rpc_create_reply
-- -----------------------------------------------------------------------
create or replace function public.rpc_create_reply(p_thread_id uuid, p_body text)
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
  if not private.is_admin_member(auth.uid()) then
    perform public.assert_rate_limit(auth.uid(), 'reply', 30, 1);
  end if;
  insert into public.replies (thread_id, author_id, body)
    values (p_thread_id, auth.uid(), p_body)
    returning id into v_id;
  return v_id;
end;
$$;

-- -----------------------------------------------------------------------
-- rpc_edit_reply
-- -----------------------------------------------------------------------
create or replace function public.rpc_edit_reply(p_id uuid, p_body text)
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
  if not private.is_admin_member(auth.uid()) then
    perform public.assert_rate_limit(auth.uid(), 'edit_reply', 600, 5);
  end if;
end;
$$;

-- -----------------------------------------------------------------------
-- rpc_update_profile
-- -----------------------------------------------------------------------
create or replace function public.rpc_update_profile(p_display_name text, p_bio text default null)
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
  if not private.is_admin_member(auth.uid()) then
    perform public.assert_rate_limit(auth.uid(), 'update_profile', 3600, 5);
  end if;
end;
$$;

commit;
