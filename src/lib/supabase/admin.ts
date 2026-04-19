// Service-role Supabase client. Bypasses RLS. SERVER ONLY.
// IMPL-0003 §3 (RPC catalog) + §8 D38: used for RPCs where
// `auth.role() = 'service_role'` is asserted internally
// (rpc_consume_invite, rpc_lookup_user_by_email, rpc_check_auth_rate_limit)
// and for Supabase Auth Admin API calls (inviteUserByEmail, createUser).
// NEVER import this module from browser code.

import { createClient, type SupabaseClient } from '@supabase/supabase-js';

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
const SUPABASE_SERVICE_ROLE_KEY = requireEnv(
  'SUPABASE_SERVICE_ROLE_KEY',
  import.meta.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY,
);

let _admin: SupabaseClient | null = null;

export function createSupabaseAdminClient(): SupabaseClient {
  if (!_admin) {
    _admin = createClient(
      SUPABASE_URL,
      SUPABASE_SERVICE_ROLE_KEY,
      { auth: { persistSession: false, autoRefreshToken: false } },
    );
  }
  return _admin;
}
