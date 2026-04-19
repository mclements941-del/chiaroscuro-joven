// Origin allowlist for non-GET /community/** requests (IMPL-0003 D20, §6 Phase 6).
//
// On every non-GET, the Origin header's scheme + host + port must match an
// entry in the allowlist. Missing `Origin` → 403 (browsers send Origin on
// all cross-origin + same-origin POSTs; its absence indicates either an
// ancient browser or a non-browser caller trying to bypass CSRF).
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
