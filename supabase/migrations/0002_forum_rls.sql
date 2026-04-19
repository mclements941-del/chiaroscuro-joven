-- IMPL-0003 Phase 2 · Migration 0002 · RLS helpers + SELECT policies + table-write revokes
-- Helpers live in `private` schema so PostgREST does not expose them (D37).
-- SELECT policies gate on active-member + non-banned status (D34, D41).
-- Table-level INSERT/UPDATE/DELETE is revoked from client roles so all
-- mutations must flow through SECURITY DEFINER RPCs (D8).

create schema if not exists private;
grant usage on schema private to authenticated, service_role;

-- -----------------------------------------------------------------------------
-- RLS helper functions (private schema, not exposed via PostgREST)
-- -----------------------------------------------------------------------------

-- is_active_member: forum_joined_at set AND not banned.
create function private.is_active_member(p_user_id uuid)
returns boolean security definer language sql stable
set search_path = public, pg_temp as $$
  select coalesce((
    select forum_joined_at is not null and banned_at is null
      from public.profiles where id = p_user_id
  ), false);
$$;
revoke execute on function private.is_active_member(uuid) from public;
grant execute on function private.is_active_member(uuid) to authenticated, service_role;

-- is_admin_member: is_admin AND active member (D41).
create function private.is_admin_member(p_user_id uuid)
returns boolean security definer language sql stable
set search_path = public, pg_temp as $$
  select coalesce((
    select is_admin = true
           and banned_at is null
           and forum_joined_at is not null
      from public.profiles where id = p_user_id
  ), false);
$$;
revoke execute on function private.is_admin_member(uuid) from public;
grant execute on function private.is_admin_member(uuid) to authenticated, service_role;

-- -----------------------------------------------------------------------------
-- RLS policies
-- -----------------------------------------------------------------------------

-- threads: members see non-deleted; admins see all.
alter table public.threads enable row level security;
create policy threads_select_member on public.threads for select to authenticated
  using (deleted_at is null and private.is_active_member(auth.uid()));
create policy threads_select_admin on public.threads for select to authenticated
  using (private.is_admin_member(auth.uid()));

-- replies: members see non-deleted replies on non-deleted threads; admins see all.
alter table public.replies enable row level security;
create policy replies_select_member on public.replies for select to authenticated
  using (
    deleted_at is null
    and private.is_active_member(auth.uid())
    and exists (
      select 1 from public.threads t
      where t.id = replies.thread_id and t.deleted_at is null
    )
  );
create policy replies_select_admin on public.replies for select to authenticated
  using (private.is_admin_member(auth.uid()));

-- categories: visible to members and admins.
alter table public.categories enable row level security;
create policy categories_select on public.categories for select to authenticated
  using (private.is_active_member(auth.uid()) or private.is_admin_member(auth.uid()));

-- profiles: self-visibility always on (needed for callback flow pre-consume);
-- member visibility only covers joined non-banned members (D43);
-- admin sees everything.
alter table public.profiles enable row level security;
create policy profiles_select_self on public.profiles for select to authenticated
  using (id = auth.uid());
create policy profiles_select_member on public.profiles for select to authenticated
  using (
    private.is_active_member(auth.uid())
    and banned_at is null
    and forum_joined_at is not null
  );
create policy profiles_select_admin on public.profiles for select to authenticated
  using (private.is_admin_member(auth.uid()));

-- invites: admin-only read.
alter table public.invites enable row level security;
create policy invites_select_admin on public.invites for select to authenticated
  using (private.is_admin_member(auth.uid()));

-- write_events + auth_events: RLS enabled with no policies → no rows visible
-- to anon or authenticated. service_role bypasses RLS.
alter table public.write_events enable row level security;
alter table public.auth_events  enable row level security;

-- -----------------------------------------------------------------------------
-- Revoke table-level INSERT/UPDATE/DELETE from client roles
-- -----------------------------------------------------------------------------
-- Supabase grants INSERT/UPDATE/DELETE to anon + authenticated by default on
-- tables in `public`. Revoke so the only mutation path is SECURITY DEFINER
-- RPCs (which run as the function owner and bypass these revokes).

revoke insert, update, delete on public.profiles     from anon, authenticated;
revoke insert, update, delete on public.categories   from anon, authenticated;
revoke insert, update, delete on public.threads      from anon, authenticated;
revoke insert, update, delete on public.replies      from anon, authenticated;
revoke insert, update, delete on public.invites      from anon, authenticated;
revoke insert, update, delete on public.write_events from anon, authenticated;
revoke insert, update, delete on public.auth_events  from anon, authenticated;
