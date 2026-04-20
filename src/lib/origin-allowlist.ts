// Origin allowlist for EVERY non-GET request site-wide (IMPL-0003 D20 + D45).
//
// Was originally scoped to `/community/**` during Phase 6. Promoted site-wide
// during Phase 7 launch night (commit 115e5bb) when Astro's built-in
// `security.checkOrigin` was disabled — this file became the canonical
// Origin enforcer. See IMPL-0003 §8 D45 for the full invariant: any new
// non-GET SSR route outside `/community/**` must either move under
// `/community/**` (gaining both Origin + CSRF checks) or extend
// `src/middleware.ts`'s Origin surface before merging.
//
// On every non-GET, the Origin header's scheme + host + port must match an
// entry in the allowlist. Missing `Origin` → 403 (browsers send Origin on
// all cross-origin + same-origin POSTs; its absence indicates either an
// ancient browser or a non-browser caller trying to bypass CSRF).
//
// `Origin: null` is also rejected — browsers send the literal string "null"
// under specific Referrer-Policy configs (the Phase 7 discovery that forced
// confirm.astro off of `no-referrer`; see D42 amendment note in §11).
//
// Preview URL shapes match the exact Vercel-generated pattern:
//   chiaroscuro-joven-<git-slug>-mclements941-del.vercel.app
//   chiaroscuro-joven-git-<branch>-mclements941-del.vercel.app
//   chiaroscuro-joven-<hash>-<something>.vercel.app
// We keep the wildcard conservative: any hostname starting with
// `chiaroscuro-joven-` and ending in `.vercel.app` over https is accepted.

const EXACT_ALLOWED = new Set<string>([
  'https://chiaroscurojoven.com',
  'http://localhost:4321',
]);

export function isAllowedOrigin(originHeader: string | null | undefined): boolean {
  if (!originHeader) return false;
  if (EXACT_ALLOWED.has(originHeader)) return true;
  try {
    const url = new URL(originHeader);
    if (
      url.protocol === 'https:' &&
      url.hostname.startsWith('chiaroscuro-joven-') &&
      url.hostname.endsWith('.vercel.app') &&
      !url.port // Vercel preview URLs never use non-default port
    ) {
      return true;
    }
  } catch {
    // Not a parseable URL; fall through to reject.
  }
  return false;
}
