// HMAC-SHA256 helpers for pre-auth rate-limit identifiers.
// IMPL-0003 §3 + §8 D16: auth_events stores email_hash and ip_hash so we can
// rate-limit without keeping raw PII in the table. Plain SHA would be
// dictionary-reversible; HMAC with an app-side pepper resists that.
//
// The pepper never leaves the application server. DB just stores bytea.

import { createHmac } from 'node:crypto';

function requireEnv(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(
      `${name} is missing. Add a 32-byte random value to .env.local.`,
    );
  }
  return value;
}

// Astro dev populates import.meta.env from .env; Vercel Functions populate
// process.env. Read both for dev + prod parity.
const PEPPER = requireEnv(
  'IDENTITY_HASH_PEPPER',
  import.meta.env.IDENTITY_HASH_PEPPER ?? process.env.IDENTITY_HASH_PEPPER,
);

/** HMAC-SHA256 of a normalized email, as Buffer (passable as bytea). */
export function hashEmail(email: string): Buffer {
  const normalized = email.trim().toLowerCase();
  return createHmac('sha256', PEPPER).update(normalized).digest();
}

/** HMAC-SHA256 of an IP address. Returns null for missing/empty IP. */
export function hashIp(ip: string | null | undefined): Buffer | null {
  if (!ip) return null;
  return createHmac('sha256', PEPPER).update(ip).digest();
}

/** Format a Buffer as the Postgres hex bytea literal (`\xABCD…`) that
 *  PostgREST accepts for bytea RPC parameters. */
export function asByteaLiteral(buf: Buffer | null): string | null {
  if (buf === null) return null;
  return '\\x' + buf.toString('hex');
}
