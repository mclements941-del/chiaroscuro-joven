// Derives the canonical auth callback origin for the current environment.
// IMPL-0003 §8 D39: prod is hard-pinned; preview uses Vercel's deployment
// URL so preview auth loops self-host; dev falls back to SITE_URL or
// localhost:4321.

export function getAuthOrigin(): string {
  const env = process.env.VERCEL_ENV;
  if (env === 'production') {
    return 'https://chiaroscurojoven.com';
  }
  if (env === 'preview' && process.env.VERCEL_URL) {
    return `https://${process.env.VERCEL_URL}`;
  }
  return process.env.SITE_URL ?? 'http://localhost:4321';
}

// IMPL-0003 D36: email templates redirect to /auth/confirm (GET interstitial),
// NOT /auth/callback (POST endpoint). Confirm renders a form; POST from that
// form is the sole consuming path. Prefetchers cannot burn tokens by hitting
// the GET URL.
export function getCallbackUrl(): string {
  return `${getAuthOrigin()}/community/auth/confirm`;
}
