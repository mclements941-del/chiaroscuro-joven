# Chiaroscuro Joven

> The art of summoning light from darkness.

Personal publication + invite-only community. Astro SSR on Vercel with Supabase Postgres + Auth, MailerSend for transactional email.

**Live:** https://chiaroscurojoven.com

## Status

- ✅ Publication layer: home, blog (with scheduled publishing), gallery, RSS, about
- ✅ IMPL-0002 site hardening: SSR adapter, scoped prose styles, content collections, CI typecheck
- ✅ IMPL-0003 Phase 1: SSR auth spike (Supabase `@supabase/ssr`, token-hash flow, prefetch-safe interstitial)
- ✅ IMPL-0003 Phase 2: schema + RLS + 15 `SECURITY DEFINER` RPCs + explicit EXECUTE grants
- ✅ IMPL-0003 Phase 3: invite issuance, full auth callback, profile setup, middleware membership enforcement
- ✅ IMPL-0003 Phase 4: forum read/create UI (thread list, detail, new-thread) with markdown + sanitizer + link rewriter
- ⬜ IMPL-0003 Phase 5: edit / delete / lock / ban / admin dashboard
- ⬜ IMPL-0003 Phase 6: CSRF + Origin middleware, sanitizer hardening, load tests
- ⬜ IMPL-0003 Phase 7: flip `FORUM_ENABLED=true` + launch

Public forum is behind the `FORUM_ENABLED` runtime flag; `/community` renders the placeholder until flipped at Phase 7.

## Stack

| Concern | Choice |
|---|---|
| Framework | Astro 6 (SSR) |
| Hosting | Vercel (Fluid Compute, Node 24 runtime) |
| Database + Auth | Supabase (via Vercel Marketplace) |
| Transactional email | MailerSend (routed through Supabase Auth SMTP) |
| DNS / registrar | Cloudflare |
| Fonts | Cormorant Garamond + Inter (self-hosted via `@fontsource/*`) |
| Markdown (UGC) | `marked` → `sanitize-html` |

## Structure

```
src/
├── env.d.ts                   App.Locals + ImportMetaEnv type augmentations
├── middleware.ts              /community/** route classifier + auth guards
├── components/                Nav, Footer
├── layouts/BaseLayout.astro
├── lib/
│   ├── auth-origin.ts         getAuthOrigin() / getCallbackUrl() per env
│   ├── identity-hash.ts       HMAC-SHA256 rate-limit identifier hashing
│   ├── markdown.ts            User-markdown → sanitized HTML
│   ├── posts.ts               Published-post visibility helpers (blog)
│   ├── slug.ts                Forum slug generator
│   └── supabase/              browser.ts, server.ts, admin.ts clients
├── pages/
│   ├── index.astro            Home
│   ├── about.astro
│   ├── rss.xml.ts
│   ├── blog/                  Writing
│   ├── gallery/               Curated collections
│   └── community/
│       ├── index.astro        Placeholder (flag off) / thread list (flag on)
│       ├── [slug].astro       Thread detail + flat replies + reply form
│       ├── new.astro          Thread creation form
│       ├── login.astro        Magic-link request (uniform response)
│       ├── probe.astro        Session probe (smoke-test route)
│       ├── profile/setup.astro
│       ├── auth/
│       │   ├── confirm.astro  Email-prefetch interstitial (GET only)
│       │   ├── callback.ts    verifyOtp + banned + invite-consume + routing (POST only)
│       │   └── logout.ts
│       └── api/
│           └── invites.ts     Admin-only invite issuance
├── content/
│   ├── gallery/               YAML curation entries
│   └── posts/                 MDX essays
└── styles/global.css          Palette, typography, prose primitives

supabase/migrations/            0001_forum_core → 0005_forum_grants
scripts/
├── apply-migrations.mjs       Idempotent migration runner
├── bootstrap-admin.mjs        Back-fill profiles + promote first admin
└── phase2-tests.mjs           97-assertion schema/RLS/grants harness

docs/auth-email-templates.md   Canonical Invite + Magic Link template source
```

## Local development

Requires Node **24** (pinned via `.nvmrc` and `.node-version`), a Supabase Marketplace integration on the Vercel project, and MailerSend credentials configured in Supabase's Auth → SMTP.

```bash
npm install
vercel env pull .env.local            # Marketplace-injected Supabase vars
# Append manual server secrets:
{
  printf 'CSRF_SECRET=%s\n' "$(openssl rand -base64 32)"
  printf 'IDENTITY_HASH_PEPPER=%s\n' "$(openssl rand -base64 32)"
} >> .env.local

npm run dev                            # dev server at http://localhost:4321
npm run check                          # typecheck via astro check
npm run build                          # SSR build to ./dist + ./.vercel/output
```

> `astro preview` is not used on this project — the `@astrojs/vercel` adapter
> does not support it. Use `vercel dev` for local preview of the full built
> output (SSR routes included); standard development uses `npm run dev`.

### Environment variables

Auto-injected by Vercel Marketplace (via `vercel env pull`):

- `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` (and Next-prefixed aliases)
- `POSTGRES_URL`, `POSTGRES_URL_NON_POOLING`, etc.
- `VERCEL_ENV`, `VERCEL_URL` (runtime)

Set manually (server-only, never committed):

- `CSRF_SECRET` — 32-byte random; signs CSRF double-submit cookies (Phase 6)
- `IDENTITY_HASH_PEPPER` — 32-byte random; HMAC pepper for pre-auth rate-limit hashes
- `FORUM_ENABLED` — `'true'` or `'false'`; runtime flag gating the public forum surface
- `SITE_URL` — optional dev-only fallback for `getAuthOrigin()` when not running under Vercel

### Supabase dashboard configuration

Not env-vars, but required for Phase 1+ auth flows:

- Auth → **Enable email signup = `false`** — users are only created via the admin API
- Auth → **SMTP**: MailerSend credentials; sender address on `chiaroscurojoven.com`
- Auth → **Email Templates → Invite user** and **Magic Link**: customized per [docs/auth-email-templates.md](docs/auth-email-templates.md) to use `{{ .RedirectTo }}` + `{{ .TokenHash }}` (so preview and localhost redirects resolve correctly)
- Auth → **Redirect URLs**: `https://chiaroscurojoven.com/community/auth/confirm`, `http://localhost:4321/community/auth/confirm`, `https://chiaroscuro-joven-*.vercel.app/community/auth/confirm`
- API → **Schemas exposed (`db-schemas`)**: `public, graphql_public` — `private` schema must stay excluded (RLS helpers live there)

### Database migrations

```bash
node --env-file=.env.local scripts/apply-migrations.mjs   # applies 0001 through 0005 idempotently
node --env-file=.env.local scripts/bootstrap-admin.mjs    # back-fills profiles + promotes admin
node --env-file=.env.local scripts/phase2-tests.mjs       # schema + RLS + grants harness (97 assertions)
```

Scripts use `POSTGRES_URL_NON_POOLING` with libpq-compat SSL for direct-connection DDL.

## Deploy

Pushes to `main` auto-deploy via Vercel. Preview deploys on every push to any branch.

```bash
vercel          # manual preview deploy
vercel --prod   # manual production deploy
```

## Design reference

Visual language follows `chiaroscuro-gallery.html` (the Herald-curated reference file on the operator Mac). Cormorant Garamond + Inter, `#0a0a0a` ground, `#e8e0d4` text, `#b8a88a` gold accents. Global CSS variables in `src/styles/global.css`.

## Planning docs

Implementation plans and decision log live in the companion directory (not tracked in this repo):

- `IMPL-0001` — founding launch + forum vision
- `IMPL-0002` — post-launch site hardening
- `IMPL-0003` — community forum (trust boundary, schema, auth flow, all 44 decisions)
- `IMPL-TBD` — home server platform (future)
- `STYLE-GUIDE-001` — essay voice
