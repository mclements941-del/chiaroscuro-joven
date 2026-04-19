/// <reference types="astro/client" />

import type { User } from '@supabase/supabase-js';

type ForumProfile = {
  id: string;
  display_name: string;
  is_admin: boolean;
  banned_at: string | null;
  needs_setup: boolean;
  forum_joined_at: string | null;
};

declare global {
  namespace App {
    interface Locals {
      user: User | null;
      profile: ForumProfile | null;
    }
  }

  namespace NodeJS {
    interface ProcessEnv {
      // Optional at the type level because in `astro dev` these arrive via
      // import.meta.env (Vite's dotenv) rather than process.env. In Vercel
      // Functions runtime they arrive via process.env. lib/supabase/{server,admin}
      // reads both sources.
      SUPABASE_URL?: string;
      SUPABASE_ANON_KEY?: string;
      SUPABASE_SERVICE_ROLE_KEY?: string;
      CSRF_SECRET?: string;
      IDENTITY_HASH_PEPPER?: string;
      FORUM_ENABLED?: string;
      SITE_URL?: string;
      VERCEL_ENV?: string;
      VERCEL_URL?: string;
    }
  }

  interface ImportMetaEnv {
    readonly SUPABASE_URL?: string;
    readonly SUPABASE_ANON_KEY?: string;
    readonly SUPABASE_SERVICE_ROLE_KEY?: string;
    readonly IDENTITY_HASH_PEPPER?: string;
    readonly CSRF_SECRET?: string;
    readonly FORUM_ENABLED?: string;
    readonly SITE_URL?: string;
  }

  interface ImportMeta {
    readonly env: ImportMetaEnv;
  }
}

export {};
