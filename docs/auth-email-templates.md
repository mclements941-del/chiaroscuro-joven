# Supabase Auth Email Templates — Canonical Copy

This file is the source of truth for the Invite and Magic Link email
templates configured in Supabase's Auth → Email Templates dashboard.
Keeping it in sync lets us detect drift if someone edits the templates
via the browser.

See IMPL-0003 §4 (Auth flow) and §8 D22 / D28 / D36 / D42 for design
rationale.

---

## Invite

**Trigger:** `supabaseAdmin.auth.admin.inviteUserByEmail(email, { redirectTo: getCallbackUrl() })`

**Dashboard location:** Auth → Email Templates → **Invite user**

**Link markup (security-critical portion):**

```html
<a href="{{ .RedirectTo }}?token_hash={{ .TokenHash }}&type=invite">Accept invite</a>
```

**Why this exact shape:**

- `{{ .RedirectTo }}` — per-call redirect URL (supports prod / preview / dev). **Not** `{{ .SiteURL }}`, which is pinned to the configured site URL and breaks preview + localhost roundtrips.
- Target is `/community/auth/confirm` (GET interstitial), **not** `/community/auth/callback` (POST endpoint). This prevents mail-security prefetchers from consuming the invite and token before the human clicks (D36).
- `type=invite` tells the callback's `verifyOtp` call to use the invite flow.

Visual styling (greetings, branding, unsubscribe, etc.) can evolve freely
in the dashboard — only the link `<a>` tag is security-critical.

---

## Magic Link

**Trigger:** `supabase.auth.signInWithOtp({ email, options: { shouldCreateUser: false, emailRedirectTo: getCallbackUrl() } })`

**Dashboard location:** Auth → Email Templates → **Magic Link**

**Link markup (security-critical portion):**

```html
<a href="{{ .RedirectTo }}?token_hash={{ .TokenHash }}&type=email">Sign in</a>
```

Same rules as Invite. `type=email` routes the callback's `verifyOtp` call.

---

## Drift detection

Phase 1 exit gate includes a localhost roundtrip AC that verifies the
template link resolves to `http://localhost:4321/...` (not prod). If a
dashboard edit reverts the template to default (using `{{ .SiteURL }}`),
the preview/localhost roundtrip test fails immediately.

A future CI check could diff the live template (via Supabase Management
API) against this file on every main-branch build — see IMPL-0003 §10 Q8.
Out of scope for v1.
