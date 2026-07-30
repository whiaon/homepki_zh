# homepki — HTTP API

> Documents the HTTP surface of homepki: routes, request and response shapes,
> authentication state, content types, and error encoding. The underlying
> *behaviour* (what happens to a cert when revoked, how CRLs are regenerated,
> etc.) lives in [LIFECYCLE.md](LIFECYCLE.md). This doc is the wire-level
> contract.

---

## 1. Overview

homepki is server-rendered HTML + htmx. There is **no JSON / REST surface in
v1.** All state-changing endpoints accept `application/x-www-form-urlencoded`
and respond with HTML or a binary download. htmx fragment responses are still
HTML, just smaller.

The same handler is used by browsers and by curl/scripts; if a client wants
machine-friendly access, the cert/key/CRL download endpoints already serve
PEM/DER directly.

---

## 2. Conventions

### 2.1 Request encoding

- **GET**: query parameters are case-sensitive, conventional names.
- **POST**: `Content-Type: application/x-www-form-urlencoded`. No multipart.
- Trailing slashes are not significant.
- Path parameters are always lowercase UUIDs (cert IDs, deploy target IDs).

### 2.2 CSRF

Every state-changing route (POST) requires a CSRF token.

- A cookie `csrf` is set on first GET to any HTML page, value = 32 random
  bytes hex-encoded, attributes `HttpOnly; SameSite=Lax; Path=/`.
- Every form posts a hidden input `csrf_token` whose value must equal the
  cookie. Mismatch → **403 Forbidden** with body `csrf token mismatch`.
- The CRL endpoint (`GET /crl/...`) and `GET /healthz` are exempt — neither
  is state-changing.

### 2.3 Response types

| Route family                  | Default content type                | Notes                       |
| ----------------------------- | ----------------------------------- | --------------------------- |
| HTML pages                    | `text/html; charset=utf-8`          | full page                   |
| htmx fragments                | `text/html; charset=utf-8`          | partial; sent for `HX-Request: true` |
| `*.pem` downloads             | `application/x-pem-file`            | with `Content-Disposition: attachment` |
| `bundle.p12`                  | `application/x-pkcs12`              | with `Content-Disposition: attachment` |
| CRL                           | `application/pkix-crl`              | binary DER                  |
| `/healthz`                    | `text/plain; charset=utf-8`         | body `ok`                   |

### 2.4 Cache headers

- HTML pages: `Cache-Control: no-store`.
- `cert.pem`, `chain.pem`, `fullchain.pem`: `Cache-Control: private, max-age=0, must-revalidate`.
- `key.pem`, `bundle.p12`: `Cache-Control: no-store, no-cache` and `Pragma: no-cache`.
- `/crl/{id}.crl`: `Cache-Control: public, max-age=300, must-revalidate`. Five
  minutes is short enough to roughly track revocations and long enough for the
  endpoint to act as a usable distribution point.

### 2.5 Status codes used

| Status | Meaning in homepki                                                                  |
| ------ | ----------------------------------------------------------------------------------- |
| 200    | Success.                                                                            |
| 303    | Redirect after a successful POST (POST → GET pattern).                              |
| 400    | Form validation failure — page re-renders with field-level errors.                  |
| 403    | CSRF token missing or mismatched.                                                   |
| 404    | Cert / deploy target / CRL not found.                                               |
| 409    | Lifecycle conflict — only used for *invalid* transitions (rotating a revoked or superseded cert). "Already in target state" cases are handled idempotently per §2.7.2. |
| 423    | Locked — request requires unlocked state. Body links to `/unlock`.                  |
| 500    | Unexpected server error.                                                            |
| 503    | Only `/crl/{id}.crl` when no DER is available at all (no initial CRL row).          |

### 2.6 Lock state

The "Lock state" column in the route tables below means:

- **none** — works regardless of lock state.
- **session** — requires an authenticated UI session (set after a successful
  unlock or first-run setup); not the same as the KEK being in memory. Used
  for browsing and metadata edits.
- **kek** — requires the KEK (i.e. the app must be unlocked). Returns
  **423** if the app is locked. See [LIFECYCLE.md §1.7](LIFECYCLE.md#17-what-requires-unlocked-state)
  for the rationale per operation.

A request that needs `kek` while the app is locked is rejected before any
DB-state change. Lock state is checked at the start of the handler, after
CSRF.

### 2.7 Idempotency

**Every state-changing endpoint is safe to retry.** Replaying the same
request — whether from a network retry, a double-clicked button, or a
browser back-and-resubmit — never produces duplicate state and never
returns an error simply because the request had already taken effect.

The mechanism varies by endpoint shape, with five categories:

#### 2.7.1 Form tokens (used by all *create* and *replace* endpoints)

The GET that renders a form for an operation that **creates a new resource
or atomically replaces a sensitive value** embeds a hidden field
`form_token` whose value is 32 random bytes hex-encoded. The token is
recorded server-side in the `idempotency_tokens` table (see [STORAGE.md
§5.7](STORAGE.md#57-idempotency_tokens)) with TTL 24h. The matching POST
handler:

1. Validates CSRF.
2. Looks up `form_token`. Missing, unknown, or expired → **400** with body
   `stale form — please reload`.
3. If the token row already has a non-NULL `result_url` (it was used by a
   previous successful submission), **303 → result_url** without re-executing
   the operation. Body of the new request is ignored — replay returns the
   redirect from the original.
4. Otherwise: execute the operation in a transaction, set
   `result_url = <new resource URL>` and `used_at = now()` on the token row,
   commit. **303 → result_url**.

A fresh GET to the form-render endpoint always issues a new `form_token`,
so genuine "issue another cert with the same data" still works (it's a new
form ⇒ new token ⇒ new resource).

Endpoints that use form tokens: `POST /setup`, `POST /settings/passphrase`,
`POST /certs/new/root`, `POST /certs/new/intermediate`, `POST /certs/new/leaf`,
`POST /certs/{id}/rotate`, `POST /certs/{id}/deploy/new`,
`POST /certs/{id}/deploy/{tid}/edit`.

#### 2.7.2 Ensure-state semantics (used by terminal-state transitions)

Endpoints that move a resource toward a terminal state succeed even if
the resource is already there. Returning **409** for "already revoked /
already deleted" would force every caller to special-case retries; instead
the handler is a no-op and returns **303** to the canonical view of the
resource:

- `POST /lock` while already locked → 303, no-op.
- `POST /certs/{id}/revoke` on an already-revoked cert → 303 to detail,
  no-op (the existing reason and timestamp are preserved).
- `POST /certs/{id}/deploy/{tid}/delete` on a missing target → 303, no-op.

#### 2.7.3 Side-effecting "run" actions (used by deploys)

`POST /certs/{id}/deploy[/{tid}]/run` writes the cert/key files to disk
and optionally invokes `post_command`.

- **The file writes are idempotent.** Each target file is written via
  write-to-temp-then-atomic-rename with the current cert content — a retry
  produces the same final bytes.
- **`post_command` MAY run more than once on retry.** Operators must use
  reload commands that are themselves safe to invoke twice — `nginx -s
  reload`, `systemctl reload caddy`, etc., already are. This is conventional
  but documented here so it isn't a surprise.

The endpoint returns **303 → cert detail** regardless of per-target
outcomes; statuses are visible on the detail page.

#### 2.7.4 Reads disguised as POSTs (`bundle.p12`)

`POST /certs/{id}/bundle.p12` is POST only because the password belongs in
a body, not a URL. It does not mutate state. Two identical requests return
two identical bundles.

#### 2.7.5 Authentication endpoints

- `POST /unlock` with a correct passphrase: **idempotent**. If already
  unlocked, the handler verifies the passphrase against the in-memory KEK
  and returns 303 to the dashboard without reinstalling state.
- `POST /unlock` with an incorrect passphrase: returns 400; does not
  consume the form token (you can retry with the right passphrase).
- `POST /setup`: form-token gated (§2.7.1). After first run, the form
  redirects to `/unlock` so a stale POST simply lands at the unlock screen.
- `POST /settings/passphrase`: form-token gated. A successful rotation
  consumes the token; a replay returns 303 to `/settings` without
  re-rotating. (Without form tokens, replay would fail because `current` no
  longer matches.)

---

## 3. Route table

Single canonical list. Per-endpoint specifics in §4 onward.

| Method   | Path                                | Purpose                                | Lock state |
| -------- | ----------------------------------- | -------------------------------------- | ---------- |
| GET      | `/`                                 | main view: CAs + leaves tables         | session    |
| GET      | `/setup`                            | first-run setup form                   | none       |
| POST     | `/setup`                            | submit first-run passphrase            | none       |
| GET      | `/unlock`                           | unlock form                            | none       |
| POST     | `/unlock`                           | submit passphrase, install KEK         | none       |
| POST     | `/lock`                             | zero the KEK                           | session    |
| POST     | `/settings/passphrase`              | rotate passphrase                      | kek        |
| GET      | `/certs/{id}`                       | cert detail page                       | session    |
| GET      | `/certs/new/root`                   | issue-root form                        | session    |
| POST     | `/certs/new/root`                   | issue a root CA                        | kek        |
| GET      | `/certs/new/intermediate`           | issue-intermediate form                | session    |
| POST     | `/certs/new/intermediate`           | issue an intermediate CA               | kek        |
| GET      | `/certs/new/leaf`                   | issue-leaf form                        | session    |
| POST     | `/certs/new/leaf`                   | issue a leaf cert                      | kek        |
| GET      | `/certs/import/root`                | import-root form                       | kek        |
| POST     | `/certs/import/root`                | import an existing self-signed root CA | kek        |
| GET      | `/certs/{id}/rotate`                | rotation form (pre-filled)             | session    |
| POST     | `/certs/{id}/rotate`                | issue successor; mark old superseded   | kek        |
| POST     | `/certs/{id}/revoke`                | revoke with reason code                | kek        |
| GET      | `/certs/{id}/cert.pem`              | cert PEM download                      | session    |
| GET      | `/certs/{id}/key.pem`               | private key PEM download               | kek        |
| GET      | `/certs/{id}/chain.pem`             | chain (excludes self and root)         | session    |
| GET      | `/certs/{id}/fullchain.pem`         | leaf + chain                           | session    |
| POST     | `/certs/{id}/bundle.p12`            | PKCS#12 bundle download                | kek        |
| GET      | `/certs/{id}/crls`                  | CRL history page (CAs only)            | session    |
| GET      | `/certs/{id}/deploy/new`            | new-deploy-target form                 | session    |
| POST     | `/certs/{id}/deploy/new`            | create deploy target                   | session    |
| GET      | `/certs/{id}/deploy/{tid}/edit`     | edit-deploy-target form                | session    |
| POST     | `/certs/{id}/deploy/{tid}/edit`     | update deploy target                   | session    |
| POST     | `/certs/{id}/deploy/{tid}/delete`   | delete deploy target                   | session    |
| POST     | `/certs/{id}/deploy/{tid}/run`      | run a single target now                | kek        |
| POST     | `/certs/{id}/deploy`                | run all targets now                    | kek        |
| GET      | `/crl/{issuer-id}.crl`              | public CRL distribution endpoint       | none       |
| GET      | `/healthz`                          | liveness                               | none       |
| GET      | `/static/*`                         | embedded static assets                 | none       |

---

## 4. Authentication and session

### 4.1 `GET /setup`, `POST /setup`

First-run only. If a passphrase verifier already exists in the DB, both
methods 303-redirect to `/unlock`.

POST form:

| field            | constraints                          |
| ---------------- | ------------------------------------ |
| `passphrase`     | required, ≥ 12 characters            |
| `passphrase2`    | required, must equal `passphrase`    |
| `form_token`     | required                             |
| `csrf_token`     | required                             |

On success: install KEK in memory, set session cookie, **303 → `/`**. On
validation failure: **400** with the form re-rendered and an error message.

Form-token gated (§2.7.1). Combined with the natural one-shot nature of
setup (subsequent requests redirect to `/unlock`), this means a
double-submitted setup form never creates two installations.

### 4.2 `GET /unlock`, `POST /unlock`

If no setup has been done, both **303 → `/setup`**.

POST form:

| field          | constraints |
| -------------- | ----------- |
| `passphrase`   | required    |
| `csrf_token`   | required    |

On success: install KEK, set session cookie, **303 → `/`** (or to the
`return_to` query parameter if present and same-origin).

On wrong passphrase: **400** with the form re-rendered and the error
"incorrect passphrase". Backoff after repeated failures is in-process and
not reflected in the HTTP response — see [LIFECYCLE.md §1.2](LIFECYCLE.md#12-unlock).

Idempotent (§2.7.5): replaying with the correct passphrase when already
unlocked returns 303 to the dashboard without reinstalling KEK state. No
`form_token` needed; the worst replay outcome is "log in twice", which
is harmless.

### 4.3 `POST /lock`

Zeroes the KEK and clears the session cookie. **303 → `/unlock`**.

Idempotent (§2.7.2): replaying when already locked returns 303 without
error.

### 4.4 `POST /settings/passphrase`

Rotates the passphrase. Requires `kek`.

POST form:

| field          | constraints                          |
| -------------- | ------------------------------------ |
| `current`      | required                             |
| `new`          | required, ≥ 12 characters            |
| `new2`         | required, must equal `new`           |
| `form_token`   | required                             |
| `csrf_token`   | required                             |

Wrong `current` → **400**. Success → KEK is replaced in-memory (the existing
session stays valid), **303 → `/settings`**.

Form-token gated (§2.7.1). Replay-safe: a second submission of the same
form returns 303 to `/settings` without attempting to re-verify `current`
(which would have failed because the passphrase has already changed).

---

## 5. Browse

### 5.1 `GET /`

Two flat tables: authorities and leaves. Filters via query parameters,
re-applied client-side too:

| query param  | values                                       |
| ------------ | -------------------------------------------- |
| `q`          | freeform; matches CN, SANs, serial, fingerprint |
| `status`     | `active` \| `expiring` \| `expired` \| `revoked` \| `superseded` |

### 5.2 `GET /certs/{id}`

Cert detail page. Includes metadata, chain visualization, deploy targets
(if leaf), CRL history (if CA), and download links.

### 5.3 `GET /certs/{id}/crls`

CRL history page for a CA. Lists every historical CRL with `crl_number`,
`this_update`, `next_update`, and a download link to that specific CRL DER.

---

## 6. Issuance and rotation

All issuance and rotation endpoints accept the same core fields (subject,
key, validity); the variants differ in defaults and required parents.

### 6.1 Common form fields

| field               | applies to       | notes                                                      |
| ------------------- | ---------------- | ---------------------------------------------------------- |
| `subject_cn`        | all              | required                                                   |
| `subject_o`, `subject_ou`, `subject_l`, `subject_st`, `subject_c` | all | optional                                  |
| `key_algo`          | all              | `rsa` \| `ecdsa` \| `ed25519`                              |
| `key_algo_params`   | all              | `2048`/`3072`/`4096` for RSA; `P-256`/`P-384` for ECDSA; ignored for ed25519 |
| `validity_days`     | all              | optional; default per [LIFECYCLE §4.3](LIFECYCLE.md#43-effect-on-the-new-cert) |
| `parent_id`         | intermediate, leaf | required; UUID of the issuing CA                         |
| `san_dns`           | leaf             | newline- or comma-separated DNS names                       |
| `san_ip`            | leaf             | newline- or comma-separated IP literals                     |
| `path_len_constraint` | intermediate   | optional integer                                           |
| `form_token`        | all (POST)       | required; from the rendered form (§2.7.1)                  |
| `csrf_token`        | all (POST)       | required                                                   |

All three issuance endpoints (and rotation, §6.5) are form-token gated
(§2.7.1). A retried POST returns 303 to the originally-created cert; only a
genuinely new GET-of-the-form yields a new resource.

### 6.2 `POST /certs/new/root`

No `parent_id`. Defaults: RSA 4096, 10y validity. Success → **303 →
`/certs/{new-id}`**.

### 6.3 `POST /certs/new/intermediate`

`parent_id` must reference a CA cert (`is_ca = 1`) that is `active` or
`superseded` (you can issue a new intermediate from a superseded root if you
need to extend its lifetime, though usually you'd rotate the root). Defaults:
ECDSA P-384, 5y validity. Success → **303 → `/certs/{new-id}`**.

### 6.4 `POST /certs/new/leaf`

`parent_id` must reference an intermediate (or, against the spec's
recommendation, a root) that is `active`. At least one of `san_dns` or
`san_ip` is required. Defaults: ECDSA P-256, 3-month validity. Success →
**303 → `/certs/{new-id}`**.

### 6.5 `POST /certs/{id}/rotate`

Form is the same shape as the matching issuance endpoint, pre-filled from
the current cert. The path-parameter `{id}` is the cert being rotated; the
new cert's `replaces_id` is set to `{id}`, and `{id}`'s status becomes
`superseded` and `replaced_by_id` is set to the new id (atomic). Success →
**303 → `/certs/{new-id}`**.

If `{id}` is `revoked` or `superseded` → **409**. (Rotate operates on the
active version; rotate the successor instead.)

Form-token gated (§2.7.1). Replay returns 303 to the same successor that
was created on the first submission — never creates a second one.

The old cert's deploy targets are copied onto the successor as part of the
same transaction (LIFECYCLE.md §4.3). Of those copies, the ones with
`auto_on_rotate = true` run inside the same handler before redirecting,
writing the new cert. Per-target failures are recorded
on the target row but do not fail the rotation — the redirect lands on the
new cert's detail page where the target statuses are visible.

### 6.6 `POST /certs/{id}/revoke`

POST form:

| field          | constraints                                       |
| -------------- | ------------------------------------------------- |
| `reason`       | required; one of the supported codes (see [LIFECYCLE §5.2](LIFECYCLE.md#52-supported-reasons)) |
| `csrf_token`   | required                                          |

Cert row updated, the direct issuer's CRL is regenerated in the same
transaction, **303 → `/certs/{id}`**.

Idempotent (§2.7.2): replaying on an already-revoked cert returns 303 to
the detail page without modifying `revoked_at`, `revocation_reason`, or
the CRL. Submitting a *different* reason for an already-revoked cert is
not an error — the original reason is preserved (a once-revoked cert has
one canonical revocation event, and changing the reason later would make
the CRL history inconsistent).

### 6.7 `POST /certs/import/root`

Register an existing self-signed root CA — minted offline or by another
tool — inside homepki, including its private key. After import the row
behaves like any other CA: children can be issued under it, it can be
rotated and revoked, and its key is sealed under the in-memory KEK like
any homepki-generated cert. The `source` column distinguishes it from
homepki-issued rows; the dashboard surfaces an "imported" pill.

Scope is roots only. Importing intermediates and leaves is intentionally
not supported in v1 — those carry a CRL Distribution Point baked in by
their original issuer that homepki can't change without reissuing the
cert. Once a root is imported, new children issued through homepki get
a homepki CRL DP automatically, so the distribution-point problem fades
naturally for everything new.

POST form:

| field          | constraints                                                |
| -------------- | ---------------------------------------------------------- |
| `cert_pem`     | required; exactly one `CERTIFICATE` PEM block, self-signed CA |
| `key_pem`      | required; one `PRIVATE KEY` (PKCS#8) block matching the cert |
| `form_token`   | required; from the rendered form (§2.7.1)                  |
| `csrf_token`   | required                                                   |

Validation, in order:

1. Parse exactly one `CERTIFICATE` block.
2. Parse exactly one `PRIVATE KEY` block. Legacy `RSA PRIVATE KEY` and
   `EC PRIVATE KEY` blocks are rejected with a hint pointing at
   `openssl pkcs8 -topk8` to convert them.
3. The cert must have `BasicConstraints CA=true`, `Subject == Issuer`,
   and the signature must verify under its own public key.
4. The cert's public key must match the supplied private key.

Failures re-render the form with **400** and the operator's pasted PEM
preserved.

Form-token gated (§2.7.1) **and** idempotent on the cert's SHA-256
fingerprint: re-uploading the same root resolves to the existing row's
URL with **303 → `/certs/{id}`** instead of inserting a duplicate. The
form-token replay path returns the same redirect as the original
submission.

After successful insert: an empty initial CRL signed by the imported
key is written so `GET /crl/{id}.crl` returns 200 immediately — but
**only when the imported cert carries the `cRLSign` KeyUsage bit**. If
it doesn't (older or constrained PKIs sometimes omit it), the cert is
still imported, the CRL row is skipped, and `GET /crl/{id}.crl`
returns **404** for that issuer. The dashboard hides the CRL download
links for such CAs and revoking children under them succeeds without a
CRL update — see [LIFECYCLE.md §7.5](LIFECYCLE.md#75-imported-roots-without-crlsign)
for the full trade-off.

---

## 7. Downloads

### 7.1 `GET /certs/{id}/cert.pem`

PEM-encoded cert. `Content-Disposition: attachment; filename="<sanitized-cn>.crt"`.

### 7.2 `GET /certs/{id}/key.pem`

PEM-encoded PKCS#8 private key. **Requires `kek`** (returns **423** if
locked). `Content-Disposition: attachment; filename="<sanitized-cn>.key"`.
Strict no-cache headers (§2.4).

### 7.3 `GET /certs/{id}/chain.pem`

Concatenated PEM of all certs in the chain *above* this one, excluding the
self-signed root. For a leaf this is the issuing intermediate (and any
further intermediates). For a root, **404** (no chain). Filename:
`<sanitized-cn>-chain.crt`.

### 7.4 `GET /certs/{id}/fullchain.pem`

`cert.pem` followed by `chain.pem`. Leaf certs only; for CAs **404**.
Filename: `<sanitized-cn>-fullchain.crt`.

### 7.5 `POST /certs/{id}/bundle.p12`

Returns a PKCS#12 bundle (key + leaf cert + chain). Leaf certs only.
**Requires `kek`**.

POST form:

| field          | constraints                          |
| -------------- | ------------------------------------ |
| `password`     | required, ≥ 1 char                   |
| `csrf_token`   | required                             |

Method is POST so the password isn't logged in URL or referrer headers.
Filename: `<sanitized-cn>.p12`.

Idempotent (§2.7.4): does not mutate state. No `form_token` required —
this is a read disguised as a POST.

---

## 8. Deploy

### 8.1 `POST /certs/{id}/deploy/new`, `POST /certs/{id}/deploy/{tid}/edit`

Configure or update a deploy target. Does **not** require `kek` — this is
metadata, the actual file write happens at run time.

POST form:

| field             | constraints                                                                |
| ----------------- | -------------------------------------------------------------------------- |
| `name`            | required; e.g., `nginx`, `haproxy`, `backup`                               |
| `cert_path`       | required; absolute path inside the container                               |
| `key_path`        | required; absolute path inside the container                               |
| `chain_path`      | optional; if set, write `fullchain.pem` here                               |
| `mode`            | required; octal e.g. `0640`                                                |
| `owner`, `group`  | optional; numeric uid/gid or names available inside the container          |
| `post_command`    | optional; absolute path to a binary or a quoted command                    |
| `auto_on_rotate`  | checkbox; `1` if checked                                                   |
| `form_token`      | required; from the rendered form (§2.7.1)                                  |
| `csrf_token`      | required                                                                   |

Validation: paths must be absolute; if either of `owner`/`group` resolves
fail at run time the target run will record `failed` (validation does not
attempt to resolve). Success → **303 → `/certs/{id}`**.

Form-token gated (§2.7.1). For *create*: replay returns 303 to the same
target that was created on first submission. For *edit*: replay returns
303 to the cert detail page; the row state is the same either way (full
replace).

### 8.2 `POST /certs/{id}/deploy/{tid}/delete`

Removes a target row. **303 → `/certs/{id}`**.

Idempotent (§2.7.2): returns 303 even if the target does not exist —
deletion is an "ensure not present" operation.

### 8.3 `POST /certs/{id}/deploy/{tid}/run`, `POST /certs/{id}/deploy`

Run a single target or all targets. Requires **`kek`** because the cert's
private key is decrypted to write `key.pem`. Each target run records:

- `last_deployed_at` (timestamp)
- `last_deployed_serial` (the cert serial that was written)
- `last_status` (`ok` \| `failed` \| `stale`)
- `last_error` (string; empty on `ok`)

The handler runs targets sequentially; if any fails, the rest still run.
**303 → `/certs/{id}`** regardless of per-target outcome — the page surfaces
each target's status.

Idempotent at the file level (§2.7.3): the cert/key files are written via
write-temp-then-atomic-rename, so a retry produces identical bytes. The
`post_command` may run more than once on retry — operators must use reload
commands that are themselves safe to invoke twice (the standard ones —
`nginx -s reload`, `systemctl reload caddy` — are).

---

## 9. Public endpoints

### 9.1 `GET /crl/{issuer-id}.crl`

Public, unauthenticated. **No CSRF, no session.**

Behaviour:

| Condition                                                       | Status | Body                | Headers                                                 |
| --------------------------------------------------------------- | ------ | ------------------- | ------------------------------------------------------- |
| Cached CRL exists and `next_update > now`                       | 200    | latest cached DER   | `Content-Type: application/pkix-crl`                    |
| Cached CRL stale and app **unlocked**                           | 200    | freshly-signed DER  | `Content-Type: application/pkix-crl`                    |
| Cached CRL stale and app **locked**                             | 200    | stale cached DER    | `Content-Type: application/pkix-crl` + `Warning: 110 - "CRL past nextUpdate; homepki is locked"` |
| `{issuer-id}` does not exist or has no CRL row                  | 404    | `crl not found`     | `Content-Type: text/plain`                              |
| Issuer exists but no CRL DER could be served (should not happen) | 503   | `crl unavailable`   | `Retry-After: 30`                                       |

The 200-with-stale-DER-when-locked decision and its rationale are documented
in [LIFECYCLE.md §6.5](LIFECYCLE.md#65-the-public-endpoint-and-the-lock-state).

The CRL endpoint is the only place homepki returns DER without an
`attachment` Content-Disposition — clients fetching it with `curl` see raw
bytes, which is conventional for `application/pkix-crl`.

### 9.2 `GET /healthz`

Returns **200** with body `ok` if the SQLite file is reachable. **503** with
body `db unavailable` if not. Does **not** check lock state — a locked-but-
running app is healthy.

### 9.3 `GET /static/*`

Serves embedded static assets (`htmx.min.js`, `pico.css`, etc.) from the
binary's `embed.FS`. `Cache-Control: public, max-age=31536000, immutable`
because asset paths include a content hash.

---

## 10. htmx integration

Several pages mount htmx for partial updates (filter changes on `/`,
inline form errors on issuance, deploy-target table refresh after run).
Conventions:

- The handler inspects `HX-Request: true` to decide between full-page and
  fragment rendering. The same URL serves both.
- After a successful POST that mutates state, the handler sets `HX-Trigger`
  for a small set of well-known events (`certs:changed`, `deploy:ran`) so
  that other components can refresh themselves without reloading the page.
- The handler may set `HX-Redirect: <url>` instead of returning a 303 when
  the request was an htmx swap that should escape to a full page nav.

---

## 11. Versioning

There is no formal API version in v1. The contract is "what this doc
describes for the version of homepki you're running". If a future v2 needs
breaking changes (e.g., a JSON API), it will be added at `/api/v2/...`
alongside the current routes.
