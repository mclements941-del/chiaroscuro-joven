// Session-bound Supabase client for Astro SSR.
// IMPL-0003 §3: `auth.uid()` is the caller's user id; use this client for
// all RPCs that depend on `auth.uid()` (content RPCs, admin RPCs, profile
// updates). Do NOT use this for service-role-only RPCs — see admin.ts.

import { createServerClient } from '@supabase/ssr';
import type { CookieOptions } from '@supabase/ssr';
import type { AstroCookieSetOptions, AstroCookies } from 'astro';

type AstroCookieDeleteOptions = Parameters<AstroCookies['delete']>[1];

function toAstroSetOptions(options: CookieOptions): AstroCookieSetOptions {
  const { domain, path, expires, maxAge, httpOnly, sameSite, secure, encode, partitioned } = options;
  return { domain, path, expires, maxAge, httpOnly, sameSite, secure, encode, partitioned };
}

function toAstroDeleteOptions(options: CookieOptions): AstroCookieDeleteOptions {
  const { domain, path, httpOnly, sameSite, secure, partitioned } = options;
  return { domain, path, httpOnly, sameSite, secure, partitioned };
}

function requireEnv(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(
      `${name} is missing. Run \`vercel env pull .env.local\` after installing Supabase via the Vercel Marketplace.`,
    );
  }
  return value;
}

// Astro dev only populates import.meta.env from .env files; Vercel Functions
// runtime populates process.env. Read both so the same code works in dev + prod.
const SUPABASE_URL = requireEnv('SUPABASE_URL', import.meta.env.SUPABASE_URL ?? process.env.SUPABASE_URL);
const SUPABASE_ANON_KEY = requireEnv(
  'SUPABASE_ANON_KEY',
  import.meta.env.SUPABASE_ANON_KEY ?? process.env.SUPABASE_ANON_KEY,
);

export function createSupabaseServerClient(cookies: AstroCookies) {
  return createServerClient(
    SUPABASE_URL,
    SUPABASE_ANON_KEY,
    {
      cookies: {
        get(name) {
          return cookies.get(name)?.value;
        },
        set(name, value, options) {
          cookies.set(name, value, toAstroSetOptions(options));
        },
        remove(name, options) {
          cookies.delete(name, toAstroDeleteOptions(options));
        },
      },
    },
  );
}
