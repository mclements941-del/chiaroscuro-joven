-- IMPL-0003 · Migration 0007 · Category description refinements (launch night)
--
-- The 0006 descriptions were drafted before the community thesis fully
-- crystallized. After a pass of live iteration with the operator, the
-- four descriptions below reflect the settled framing:
--
--   Craft      -> the doing  (making the future)
--   Compass    -> the deciding  (weighing AI's tradeoffs + ethics)
--   Field      -> the watching  (research, policy, design shaping the terrain)
--   Formation  -> the becoming  (who we are turning into, and what it's for)
--
-- Idempotent via WHERE slug; safe to re-apply.

begin;

update public.categories
  set description = 'Where founders come to discuss building the future.'
  where slug = 'craft';

update public.categories
  set description = 'A place to discuss the tradeoffs, risks, advantages, and ethics of AI.'
  where slug = 'compass';

update public.categories
  set description = 'The wider landscape of research, policy, and design shaping the future.'
  where slug = 'field';

update public.categories
  set description = 'Where we ask who we are becoming, and what this is all for.'
  where slug = 'formation';

commit;
