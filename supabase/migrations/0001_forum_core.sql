-- IMPL-0003 Phase 2 · Migration 0001 · Core schema
-- Tables, indexes, trigger functions, triggers. No RLS, no RPCs, no grants.
-- See IMPL-0003 §3 for full rationale.

create extension if not exists citext;

-- -----------------------------------------------------------------------------
-- Tables
-- -----------------------------------------------------------------------------

-- profiles: 1:1 with auth.users. forum_joined_at is the membership gate (D21).
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (length(display_name) between 2 and 40),
  bio text check (length(bio) <= 280),
  is_admin boolean not null default false,
  banned_at timestamptz,
  needs_setup boolean not null default true,
  forum_joined_at timestamptz,
  created_at timestamptz not null default now()
);

-- categories: seed-only; not user-editable.
create table public.categories (
  slug text primary key,
  name text not null,
  sort_order int not null default 0
);

-- threads.
create table public.threads (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  category_slug text not null references public.categories(slug),
  author_id uuid not null references public.profiles(id),
  title text not null check (length(title) between 3 and 140),
  body text not null check (length(body) between 1 and 20000),
  created_at timestamptz not null default now(),
  edited_at timestamptz,
  last_activity_at timestamptz not null default now(),
  reply_count int not null default 0,
  locked_at timestamptz,
  deleted_at timestamptz
);
create index threads_category_activity on public.threads (category_slug, last_activity_at desc)
  where deleted_at is null;

-- replies (flat, no nesting).
create table public.replies (
  id uuid primary key default gen_random_uuid(),
  thread_id uuid not null references public.threads(id) on delete cascade,
  author_id uuid not null references public.profiles(id),
  body text not null check (length(body) between 1 and 10000),
  created_at timestamptz not null default now(),
  edited_at timestamptz,
  deleted_at timestamptz
);
create index replies_thread_created on public.replies (thread_id, created_at asc)
  where deleted_at is null;

-- invites: email-bound; D40 CHECK enforces lowercase + trimmed storage
-- (citext equality is case-insensitive, so CHECK must use ::text comparison
-- to actually enforce the canonical shape).
create table public.invites (
  id uuid primary key default gen_random_uuid(),
  email citext not null
    check (email::text = lower(trim(email::text))),
  issued_by uuid not null references public.profiles(id),
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_by uuid references public.profiles(id),
  used_at timestamptz,
  revoked_at timestamptz
);
create unique index invites_active_email_idx on public.invites (email)
  where used_at is null and revoked_at is null;

-- write_events: post-auth audit log + rate-limit substrate.
create table public.write_events (
  id bigserial primary key,
  actor_id uuid not null references public.profiles(id),
  kind text not null,
  subject_id uuid,
  created_at timestamptz not null default now()
);
create index write_events_actor_kind_time
  on public.write_events (actor_id, kind, created_at desc);

-- auth_events: pre-auth attempts, HMAC-hashed identifiers only.
create table public.auth_events (
  id bigserial primary key,
  email_hash bytea not null,
  ip_hash bytea,
  kind text not null,
  created_at timestamptz not null default now()
);
create index auth_events_email_time on public.auth_events (email_hash, created_at desc);
create index auth_events_ip_time    on public.auth_events (ip_hash, created_at desc)
  where ip_hash is not null;

-- -----------------------------------------------------------------------------
-- Triggers
-- -----------------------------------------------------------------------------

-- on_auth_user_created: create a profiles row with safe default name +
-- needs_setup=true + forum_joined_at=null (the membership gate is OFF
-- until rpc_consume_invite sets it).
create or replace function public.handle_new_auth_user()
returns trigger security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  insert into public.profiles (id, display_name, needs_setup, forum_joined_at)
    values (
      new.id,
      'member-' || substr(new.id::text, 1, 8),
      true,
      null
    );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_auth_user();

-- on_reply_insert: bump thread's reply_count + last_activity_at.
create or replace function public.handle_reply_insert()
returns trigger security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  update public.threads
    set reply_count = reply_count + 1,
        last_activity_at = now()
    where id = new.thread_id;
  return new;
end;
$$;

drop trigger if exists on_reply_insert on public.replies;
create trigger on_reply_insert
  after insert on public.replies
  for each row execute function public.handle_reply_insert();

-- on_reply_soft_delete: decrement reply_count when deleted_at transitions
-- from NULL to NOT NULL. No-op for other UPDATEs or hard deletes.
create or replace function public.handle_reply_soft_delete()
returns trigger security definer language plpgsql
set search_path = public, pg_temp
as $$
begin
  if old.deleted_at is null and new.deleted_at is not null then
    update public.threads
      set reply_count = greatest(reply_count - 1, 0)
      where id = new.thread_id;
  end if;
  return new;
end;
$$;

drop trigger if exists on_reply_soft_delete on public.replies;
create trigger on_reply_soft_delete
  after update of deleted_at on public.replies
  for each row execute function public.handle_reply_soft_delete();
