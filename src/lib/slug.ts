// Slug generation for forum threads.
// Pattern: `slugify(title)-<base62 suffix>` — the suffix gives us uniqueness
// without a DB round-trip on every attempt and leaves room for a clean
// shareable URL.
//
// Reserved-word protection lives on the DB side (private.is_reserved_slug),
// not here — the RPC will raise `slug_reserved` and the caller retries.

import { randomBytes } from 'node:crypto';

const ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function randomSuffix(length = 6): string {
  const bytes = randomBytes(length);
  let out = '';
  for (let i = 0; i < length; i++) {
    out += ALPHABET[bytes[i] % ALPHABET.length];
  }
  return out;
}

function slugify(title: string): string {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
    .replace(/-+$/g, ''); // drop trailing dash after slice
}

export function generateSlug(title: string): string {
  const base = slugify(title);
  const suffix = randomSuffix(6);
  return base ? `${base}-${suffix}` : suffix;
}
