# Chiaroscuro Joven

> The art of summoning light from darkness.

Personal publication + eventual community site. Astro static site scaffold with a forthcoming integrated forum layer (Supabase auth + Postgres). See `IMPL-0001` in the companion project directory for full scope.

**Live:** https://chiaroscurojoven.com

## Stack

- **Astro** (static site + server endpoints when forum lands)
- **Vercel** (hosting, deploy on push)
- **Cloudflare** (DNS, registrar)
- **Resend** (transactional email — once forum lands)
- **Supabase** (auth + Postgres for forum — once it lands)

## Structure

```
src/
├── components/     Nav, Footer, eventually forum UI
├── layouts/        BaseLayout.astro — HTML skeleton + meta
├── pages/          Routes — one file per URL
│   ├── index.astro       Hero + intro
│   ├── blog/             Writing
│   ├── gallery/          Curated collections
│   ├── community/        Forum (coming)
│   └── about.astro
└── styles/global.css     Palette, typography, hero/section primitives
```

## Local development

```bash
npm install
npm run dev       # dev server at http://localhost:4321
npm run build     # production build to ./dist
npm run preview   # preview the build locally
```

## Deploy

Pushes to `main` auto-deploy via Vercel. For manual deploy:

```bash
vercel          # preview deploy
vercel --prod   # production deploy
```

## Design reference

Visual language follows `chiaroscuro-gallery.html` (the Herald-curated reference file on the operator Mac). Cormorant Garamond + Inter, `#0a0a0a` ground, `#e8e0d4` text, `#b8a88a` gold accents.
