// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import vercel from '@astrojs/vercel';

// https://astro.build/config
export default defineConfig({
  site: 'https://chiaroscurojoven.com',
  output: 'server',
  adapter: vercel(),
  integrations: [mdx(), sitemap()],
  security: {
    // IMPL-0003 D20 / Phase 6: src/middleware.ts is the canonical Origin
    // enforcer. Astro's built-in checkOrigin runs BEFORE middleware (via
    // createOriginCheckMiddleware()), so it can't participate in the D36
    // callback CSRF exemption or emit our logging on reject. It is also
    // non-configurable (exact url.origin match only) and its error message
    // leaks implementation detail to users.
    //
    // Disabling it is only safe because src/middleware.ts enforces Origin
    // on EVERY non-GET site-wide (not just /community/**). Maintain that
    // invariant before adding any SSR mutation route outside /community.
    checkOrigin: false,
  },
});
