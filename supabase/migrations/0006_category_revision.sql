-- IMPL-0003 · Migration 0006 · Category revision for launch
--
-- The original v1 categories (art, literature, film, miscellany) were
-- aesthetic placeholders chosen before the community thesis was clear.
-- At launch the thesis crystallized: a community for people building
-- tomorrow who hold the balance between technology and humanity. The
-- four categories below reflect that thesis — Craft (how we build),
-- Compass (how we decide), Field (what's moving around us), Formation
-- (who we become while doing the work).
--
-- Adds a `description` column so the forum UI can render a one-sentence
-- purpose statement next to each category (both on the thread list
-- filter and on the new-thread form).
--
-- Safe without orphan-FK handling because FORUM_ENABLED was false until
-- launch night and no threads were created under the old slugs. The
-- DELETE below only matches the original seed rows; it's a no-op on
-- re-runs and doesn't cascade into live user data.

begin;

-- Idempotent schema add.
alter table public.categories add column if not exists description text;

-- Remove the original placeholder categories. If a thread has ever been
-- created under one of these slugs, this DELETE will raise an FK violation
-- and the whole migration rolls back — the right failure mode.
delete from public.categories where slug in ('art', 'literature', 'film', 'misc');

-- Insert new thesis-aligned categories. ON CONFLICT makes this re-runnable.
insert into public.categories (slug, name, description, sort_order) values
  ('craft',     'Craft',     'Architecture, evals, infrastructure, and the engineering choices behind what we ship.',                 10),
  ('compass',   'Compass',   'The tradeoffs, refusals, and ethical weight of putting something into the world.',                      20),
  ('field',     'Field',     'The wider landscape we build inside, including research, policy, and the decisions of other builders.', 30),
  ('formation', 'Formation', 'The interior question of who we become while doing this work.',                                         40)
on conflict (slug) do update set
  name = excluded.name,
  description = excluded.description,
  sort_order = excluded.sort_order;

commit;
