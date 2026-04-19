// CSRF double-submit cookie + HMAC token (IMPL-0003 D12, §6 Phase 6).
//
// Token format: `<random-16-bytes-base64url>.<hmac-sha256-base64url>`
// The HMAC over the random value lets the server verify token integrity
// statelessly (no need to remember which random we issued). The double-submit
// requirement (cookie === form field) still holds — attackers can't read
// victim cookies cross-origin, so a forged form field won't match the
// victim's cookie even if the HMAC is valid for some attacker-chosen random.
//
// Cookie is HttpOnly so JS cannot read it; server reads it via Astro
// cookies and injects into forms as Astro.locals.csrfToken.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AstroCookies } from 'astro';

export const CSRF_COOKIE_NAME = 'cj_csrf';
const MAX_AGE_SECONDS = 60 * 60 * 24 * 7; // 7 days

function getSecret(): string {
  const s = process.env.CSRF_SECRET;
  if (!s || s.length < 16) {
    throw new Error(
      'CSRF_SECRET is missing or too short (need 32-byte random, base64-encoded)',
    );
  }
  return s;
}

function hmac(value: string): string {
  return createHmac('sha256', getSecret()).update(value).digest('base64url');
}

export function generateCsrfToken(): string {
  const random = randomBytes(16).toString('base64url');
  return `${random}.${hmac(random)}`;
}

/**
 * Verifies the HMAC signature on a token. Does NOT check the double-submit
 * invariant — pair with `tokensMatch` for full validation.
 */
export function verifyCsrfToken(token: string | null | undefined): boolean {
  if (!token || typeof token !== 'string') return false;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot === token.length - 1) return false;
  const random = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  let expected: string;
  try {
    expected = hmac(random);
  } catch {
    return false;
  }
  try {
    const a = Buffer.from(sig, 'base64url');
    const b = Buffer.from(expected, 'base64url');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Timing-safe equality on two string tokens. Used to compare the cookie
 * token and the submitted form field.
 */
export function tokensMatch(
  a: string | null | undefined,
  b: string | null | undefined,
): boolean {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  try {
    return timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Returns the current token if valid, else mints a fresh one and writes the
 * cookie. Called by middleware on every /community/** request so every
 * rendered form can embed `Astro.locals.csrfToken`.
 */
export function getOrSetCsrfCookie(cookies: AstroCookies): string {
  const existing = cookies.get(CSRF_COOKIE_NAME)?.value;
  if (existing && verifyCsrfToken(existing)) return existing;
  const token = generateCsrfToken();
  cookies.set(CSRF_COOKIE_NAME, token, {
    path: '/',
    sameSite: 'lax',
    httpOnly: true,
    secure: process.env.VERCEL_ENV !== undefined, // HTTPS on Vercel, HTTP for astro dev
    maxAge: MAX_AGE_SECONDS,
  });
  return token;
}

/**
 * Reads the CSRF cookie as-is (does not mint). For use in non-GET middleware
 * validation where we compare cookie vs. submitted form field.
 */
export function readCsrfCookie(cookies: AstroCookies): string | undefined {
  return cookies.get(CSRF_COOKIE_NAME)?.value;
}

/**
 * Validates a non-GET request's CSRF token. Returns true when:
 *   1. Cookie token exists AND passes HMAC check
 *   2. Submitted token (header or form field) equals the cookie token
 *
 * Accepts either:
 *   - `X-CSRF-Token` header (JSON/fetch callers)
 *   - `cj_csrf` form field (HTML form submissions)
 *
 * Consumes the FormData when reading the form field, so non-GET handlers
 * that need the body themselves should pass their already-parsed FormData
 * via `submittedToken`. For middleware pre-validation we re-parse.
 */
export async function validateCsrfRequest(
  request: Request,
  cookies: AstroCookies,
): Promise<{ ok: boolean; reason?: string }> {
  const cookieToken = readCsrfCookie(cookies);
  if (!cookieToken || !verifyCsrfToken(cookieToken)) {
    return { ok: false, reason: 'csrf_cookie_missing_or_invalid' };
  }

  // Header path (JSON/fetch).
  const headerToken = request.headers.get('x-csrf-token');
  if (headerToken) {
    if (tokensMatch(cookieToken, headerToken)) return { ok: true };
    return { ok: false, reason: 'csrf_header_mismatch' };
  }

  // Form path — clone so the handler can still read the body.
  const contentType = request.headers.get('content-type') ?? '';
  if (
    contentType.includes('application/x-www-form-urlencoded') ||
    contentType.includes('multipart/form-data')
  ) {
    try {
      const cloned = request.clone();
      const form = await cloned.formData();
      const formToken = String(form.get(CSRF_COOKIE_NAME) ?? '');
      if (tokensMatch(cookieToken, formToken)) return { ok: true };
      return { ok: false, reason: 'csrf_form_mismatch' };
    } catch {
      return { ok: false, reason: 'csrf_form_unparseable' };
    }
  }

  return { ok: false, reason: 'csrf_token_missing' };
}
