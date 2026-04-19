-- IMPL-0003 Phase 2 · Migration 0004 · Seed data
-- Categories are the only seeded content. Everything else arrives at runtime
-- via member activity or admin action.

insert into public.categories (slug, name, sort_order) values
  ('art',        'Art',         1),
  ('literature', 'Literature',  2),
  ('film',       'Film',        3),
  ('misc',       'Miscellany', 99)
on conflict (slug) do update set
  name = excluded.name,
  sort_order = excluded.sort_order;
