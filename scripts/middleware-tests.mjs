// IMPL-0004 Phase 1 · Middleware regression suite
//
// Exercises the middleware layer via real HTTP against a running server
// (dev by default; --base-url accepts any origin). Pins down the ordering
// site-wide Origin → /community/** CSRF → route bucket → session → admin
// so a future regression in any layer surfaces as a specific red probe.
//
// Scope (IMPL-0004 §3.2):
//   1. GET /community/login → 200, Set-Cookie: cj_csrf present
//   2. POST /community/login missing Origin → 403
//   3. POST /community/login evil Origin → 403
//   4. POST /community/login valid Origin + no CSRF → 403
//   5. POST /community/login valid Origin + matching CSRF → 302 (uniform redirect)
//   6. GET /community/auth/confirm → 200 with: Cache-Control: no-store
//      variant, Referrer-Policy: same-origin, X-Robots-Tag: noindex, CSP
//      present, zero third-party asset refs in body
//   7. POST /community/auth/callback Origin: null → 403
//      (the launch-night regression — Referrer-Policy: no-referrer caused
//       browsers to send Origin: null and Astro's built-in checkOrigin
//       rejected the callback before middleware could see it)
//   8. POST /community/auth/callback same-origin + bogus token → 4xx from
//      verifyOtp, NOT 403 from middleware (proves D36 CSRF exemption +
//      Origin allowlist let the handler run)
//   9. POST /community/auth/logout valid Origin, no CSRF → 403
//  10. POST /community/api/admin/ban valid Origin, no CSRF, no session → 403
//      (CSRF fires first, before any admin / auth guard)
//  11. POST /community/api/admin/ban valid Origin, valid CSRF, no session →
//      302 redirect to /community/login (proves unauthed requests land at
//      login rather than 404'ing the admin surface; pins middleware ordering)
//
// Deferred (follow-up, not blocking Phase 1 exit):
//  12. POST /community/api/admin/ban valid Origin, valid CSRF, authed
//      non-admin → 404. Requires minting a real @supabase/ssr session
//      cookie (access_token + refresh_token JSON, specific cookie naming).
//      Easiest via a full magic-link roundtrip (generateLink → verifyOtp
//      → extract Set-Cookie). Implementable but multiplies the harness
//      complexity for one assertion. Add when the admin-vs-non-admin
//      boundary needs regression coverage.
//
// Usage:
//   node scripts/middleware-tests.mjs
//   node scripts/middleware-tests.mjs --base-url https://chiaroscuro-joven-xxx.vercel.app
//
// Requires the target to have FORUM_ENABLED set (true or false — the
// middleware runs either way; the probes don't depend on flag state).
//
// Exit: 0 all pass, 1 on any failure.

const argv = process.argv.slice(2);
const baseArgIdx = argv.indexOf('--base-url');
// Default matches what `astro dev` binds to ("localhost:4321"). Node's
// `fetch` resolves 127.0.0.1 explicitly and can get ECONNREFUSED if the
// dev server is bound only to the localhost hostname; `localhost` works
// in both IPv4 and IPv6 resolution paths.
const BASE_URL = baseArgIdx >= 0 ? argv[baseArgIdx + 1] : 'http://localhost:4321';
const ORIGIN = new URL(BASE_URL).origin;

console.log(`\ntarget: ${BASE_URL}\n`);

// ---------------------------------------------------------------------------
// Assertion harness
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;
const failures = [];

function assert(label, condition, details) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${label}`);
  } else {
    failed++;
    failures.push({ label, details });
    console.log(`  ✗ ${label}  ${details ?? ''}`);
  }
}

// ---------------------------------------------------------------------------
// Cookie jar — minimal, no domain/path matching beyond what we need
// ---------------------------------------------------------------------------

class CookieJar {
  constructor() { this.cookies = new Map(); }
  setFrom(response) {
    // `fetch` gives us a single `set-cookie` string with multiple cookies
    // merged by commas in some implementations; use getSetCookie() if
    // available (Node 22+), else fall back to the header value.
    const raw = response.headers.getSetCookie ? response.headers.getSetCookie() : (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : []);
    for (const line of raw) {
      const [pair] = line.split(';');
      const eq = pair.indexOf('=');
      if (eq < 1) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      this.cookies.set(name, value);
    }
  }
  header() {
    if (this.cookies.size === 0) return undefined;
    return Array.from(this.cookies.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
  }
  get(name) { return this.cookies.get(name); }
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

async function run() {
  // ------------------------------------------------------------------------
  // 1. GET /community/login → 200, Set-Cookie: cj_csrf present
  // ------------------------------------------------------------------------
  console.log('=== 1. GET /community/login ===');
  {
    const jar = new CookieJar();
    const res = await fetch(`${BASE_URL}/community/login?_t=${Date.now()}`, {
      redirect: 'manual',
    });
    jar.setFrom(res);
    assert('GET /community/login → 200', res.status === 200, `got ${res.status}`);
    assert('Set-Cookie: cj_csrf present', !!jar.get('cj_csrf'), `cookies: ${Array.from(jar.cookies.keys()).join(',')}`);
  }

  // ------------------------------------------------------------------------
  // 2. POST /community/login missing Origin → 403
  // ------------------------------------------------------------------------
  console.log('\n=== 2. POST /community/login missing Origin → 403 ===');
  {
    const res = await fetch(`${BASE_URL}/community/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'email=probe@example.invalid',
    });
    assert('POST login no Origin → 403', res.status === 403, `got ${res.status}`);
  }

  // ------------------------------------------------------------------------
  // 3. POST /community/login evil Origin → 403
  // ------------------------------------------------------------------------
  console.log('\n=== 3. POST /community/login evil Origin → 403 ===');
  {
    const res = await fetch(`${BASE_URL}/community/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://evil.attacker.com',
      },
      body: 'email=probe@example.invalid',
    });
    assert('POST login evil Origin → 403', res.status === 403, `got ${res.status}`);
  }

  // ------------------------------------------------------------------------
  // 4. POST /community/login valid Origin + no CSRF → 403
  // ------------------------------------------------------------------------
  console.log('\n=== 4. POST /community/login valid Origin, no CSRF → 403 ===');
  {
    const res = await fetch(`${BASE_URL}/community/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: ORIGIN,
      },
      body: 'email=probe@example.invalid',
    });
    assert('POST login valid Origin no CSRF → 403', res.status === 403, `got ${res.status}`);
  }

  // ------------------------------------------------------------------------
  // 5. POST /community/login valid Origin + matching CSRF → 302
  // ------------------------------------------------------------------------
  console.log('\n=== 5. POST /community/login with matching CSRF → 302 ===');
  {
    const jar = new CookieJar();
    const getRes = await fetch(`${BASE_URL}/community/login?_t=${Date.now()}`, {
      redirect: 'manual',
    });
    jar.setFrom(getRes);
    const csrf = jar.get('cj_csrf');
    assert('setup: cj_csrf cookie obtained', !!csrf, 'no cj_csrf');
    if (!csrf) return;

    const body = new URLSearchParams({ cj_csrf: csrf, email: 'probe@example.invalid' });
    const res = await fetch(`${BASE_URL}/community/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: ORIGIN,
        Cookie: jar.header(),
      },
      body: body.toString(),
    });
    assert('POST login w/ CSRF → 302', res.status === 302, `got ${res.status}`);
    assert('302 Location → /community/login?status=check_email',
      (res.headers.get('location') ?? '').includes('status=check_email'),
      `location: ${res.headers.get('location')}`);
  }

  // ------------------------------------------------------------------------
  // 6. GET /community/auth/confirm → full security header set + no 3rd-party
  // ------------------------------------------------------------------------
  console.log('\n=== 6. GET /community/auth/confirm — security headers ===');
  {
    const res = await fetch(`${BASE_URL}/community/auth/confirm?token_hash=probe&type=email`, {
      redirect: 'manual',
    });
    assert('GET /auth/confirm → 200', res.status === 200, `got ${res.status}`);
    const cc = res.headers.get('cache-control') ?? '';
    assert('Cache-Control contains no-store', cc.includes('no-store'), `got: ${cc}`);
    assert('Referrer-Policy: same-origin',
      res.headers.get('referrer-policy') === 'same-origin',
      `got: ${res.headers.get('referrer-policy')}`);
    const xrt = res.headers.get('x-robots-tag') ?? '';
    assert('X-Robots-Tag contains noindex', xrt.includes('noindex'), `got: ${xrt}`);
    const csp = res.headers.get('content-security-policy') ?? '';
    assert('CSP present', csp.length > 0, 'missing CSP header');
    assert("CSP includes default-src 'none'", csp.includes("default-src 'none'"), `csp: ${csp}`);
    assert("CSP includes form-action 'self'", csp.includes("form-action 'self'"), `csp: ${csp}`);
    assert("CSP includes frame-ancestors 'none'", csp.includes("frame-ancestors 'none'"), `csp: ${csp}`);

    const html = await res.text();
    // Cheap third-party check: any <link>/<script>/<img> src/href pointing
    // outside origin (or inlined) would be a concern. Confirm page is
    // supposed to be fully inlined.
    const thirdParty = /<(script|link|img)[^>]*\s(href|src)=["']https?:\/\/(?!(localhost|127\.0\.0\.1|chiaroscurojoven\.com))/i.test(html);
    assert('confirm body references zero third-party hosts', !thirdParty, 'external asset detected');
  }

  // ------------------------------------------------------------------------
  // 7. POST /community/auth/callback Origin: null → 403
  //    (the launch-night regression — must stay red if re-regressed)
  // ------------------------------------------------------------------------
  console.log('\n=== 7. POST /auth/callback Origin: null → 403 ===');
  {
    const res = await fetch(`${BASE_URL}/community/auth/callback`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'null', // literal string — browsers send this under certain Referrer-Policy configs
      },
      body: 'token_hash=probe&type=email',
    });
    assert('POST callback Origin: null → 403', res.status === 403, `got ${res.status}`);
  }

  // ------------------------------------------------------------------------
  // 8. POST /community/auth/callback same-origin + bogus token → 4xx from
  //    handler (verifyOtp), NOT 403 from middleware. Proves D36 CSRF
  //    exemption + Origin allowlist let the request through.
  // ------------------------------------------------------------------------
  console.log('\n=== 8. POST /auth/callback same-origin + bad token → handler 4xx, not middleware 403 ===');
  {
    const res = await fetch(`${BASE_URL}/community/auth/callback`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: ORIGIN,
      },
      body: 'token_hash=bogus_never_existed&type=email',
    });
    assert('POST callback same-origin reaches handler',
      res.status >= 400 && res.status < 500 && res.status !== 403,
      `got ${res.status} — 403 means middleware rejected before handler`);
  }

  // ------------------------------------------------------------------------
  // 9. POST /community/auth/logout valid Origin, no CSRF → 403
  // ------------------------------------------------------------------------
  console.log('\n=== 9. POST /auth/logout no CSRF → 403 ===');
  {
    const res = await fetch(`${BASE_URL}/community/auth/logout`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: ORIGIN,
      },
      body: '',
    });
    assert('POST logout no CSRF → 403', res.status === 403, `got ${res.status}`);
  }

  // ------------------------------------------------------------------------
  // 10. POST /community/api/admin/ban valid Origin, no CSRF, no session → 403
  //     (CSRF check fires before auth/admin guard; proves ordering)
  // ------------------------------------------------------------------------
  console.log('\n=== 10. POST /api/admin/ban no CSRF → 403 (CSRF fires first) ===');
  {
    const res = await fetch(`${BASE_URL}/community/api/admin/ban`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: ORIGIN,
      },
      body: 'user_id=00000000-0000-0000-0000-000000000000',
    });
    assert('POST /api/admin/ban no CSRF → 403', res.status === 403, `got ${res.status}`);
  }

  // ------------------------------------------------------------------------
  // 11. POST /api/admin/ban valid Origin + valid CSRF + no session
  //     → 302 redirect to /community/login
  // ------------------------------------------------------------------------
  console.log('\n=== 11. POST /api/admin/ban w/ CSRF, no session → 302 login ===');
  {
    const jar = new CookieJar();
    const getRes = await fetch(`${BASE_URL}/community/login?_t=${Date.now()}`, {
      redirect: 'manual',
    });
    jar.setFrom(getRes);
    const csrf = jar.get('cj_csrf');
    if (!csrf) {
      assert('setup: cj_csrf for probe 11', false, 'no CSRF cookie');
      return;
    }
    const body = new URLSearchParams({
      cj_csrf: csrf,
      user_id: '00000000-0000-0000-0000-000000000000',
    });
    const res = await fetch(`${BASE_URL}/community/api/admin/ban`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: ORIGIN,
        Cookie: jar.header(),
      },
      body: body.toString(),
    });
    assert('POST /api/admin/ban w/ CSRF, no session → 302',
      res.status === 302, `got ${res.status}`);
    assert('302 location → /community/login',
      (res.headers.get('location') ?? '').includes('/community/login'),
      `location: ${res.headers.get('location')}`);
  }

  // ------------------------------------------------------------------------
  // Summary
  // ------------------------------------------------------------------------
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  - ${f.label}  ${f.details ?? ''}`);
  }
}

try {
  await run();
} catch (e) {
  console.error('\n!!! harness error:', e);
  process.exit(1);
}

process.exit(failed > 0 ? 1 : 0);
