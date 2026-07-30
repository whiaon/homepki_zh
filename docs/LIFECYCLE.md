# homepki — Certificate Lifecycle

Companion to [SPEC.md](SPEC.md). SPEC describes *what* homepki is; this document
describes *how* the private key material, the certificate records, and the CRLs
behave across their full lifetime — from first-run setup through rotation,
revocation, and audit.

This doc is the source of truth for: locking, key encryption, storage layout,
rotation, revocation, and CRL handling. The HTTP wire form of every operation
described here (paths, methods, status codes, request/response shapes) is
documented in [API.md](API.md). If something here conflicts with SPEC.md, this
document wins for the areas it covers and SPEC.md should be updated.

---

## 1. Locking and unlocking

The app holds a single in-memory secret called the **KEK** (Key Encryption
Key). All private-key material on disk is encrypted under per-cert DEKs; the
DEKs are wrapped under the KEK. No KEK in memory ⇒ no private-key operations
possible.

Lock state is **process-global, not per-CA**. v1 has one operator and one
passphrase; modelling per-CA secrets adds significant complexity (multi-prompt
issuance flows, per-CA verifiers) for no real isolation benefit on a single-op
host.

### 1.1 First-run setup

On startup, the app checks `settings` for a `passphrase_verifier` row. If
absent, the operator is funnelled to the first-run setup flow (see
[API.md §4.1](API.md#41-get-setup-post-setup) for the HTTP form).

Setup requires the operator to enter and confirm a passphrase, then:

1. Generate `kdf_salt` (16 random bytes from `crypto/rand`).
2. Persist `kdf_params`: `{algo: "argon2id", time: 3, memory_kib: 65536, threads: 2, key_len: 32, version: 0x13}` as JSON.
3. Derive KEK = `argon2id(passphrase, kdf_salt, kdf_params)`.
4. Compute `verifier = HMAC-SHA256(KEK, "homepki/verify/v1")`. Persist it.
5. Hold KEK in memory. App is now unlocked.

The passphrase itself is **never** persisted in any form. The verifier is a
constant-string MAC under KEK, used purely to detect a wrong passphrase on
unlock without exposing key material.

**Minimum passphrase length: 12 characters.** No other complexity rules.
Length is what matters; complexity rules push users to predictable patterns.
Setup form rejects shorter passphrases client-side and server-side.

### 1.2 Unlock

The unlock action takes a passphrase from the operator. The handler:

1. Loads `kdf_salt`, `kdf_params`, `verifier` from settings.
2. Derives candidate KEK with the stored params.
3. Computes candidate verifier and compares with `subtle.ConstantTimeCompare`.
4. If equal: install KEK in memory, set unlocked=true, redirect to the main view.
5. If not: zero the candidate KEK, increment in-memory failure counter, return
   error. After 5 failures within 60s, sleep 2s on subsequent attempts (linear
   backoff, capped at 30s). No persistent lockout — restart clears counters.

### 1.3 Lock

The lock action zeros the KEK byte slice (explicit `for i := range kek { kek[i]
= 0 }`), nils the reference, sets unlocked=false. After this point any handler
that needs key material rejects the request without touching DB state — the
HTTP encoding of "locked" is in [API.md §2.5](API.md#25-status-codes-used).

### 1.4 Auto-lock

Idle-based auto-lock. **Default: off.** Configurable via `CM_AUTO_LOCK_MINUTES`
env var (e.g. `30`); zero or unset means disabled. "Idle" = no successful
authenticated request in N minutes. When auto-lock fires, the KEK is zeroed
exactly as manual lock. Background tasks (CRL regen, scheduled rotation)
reset the idle timer if they ran while unlocked.

For unattended deployments where `CM_PASSPHRASE` is set, auto-lock is forced
off — the app would just unlock itself again from env on next request.

### 1.5 Unattended unlock (`CM_PASSPHRASE`)

If `CM_PASSPHRASE` is set at startup, the app derives the KEK from it
immediately after migrations run, verifies it against the stored verifier, and
holds it in memory. The env var is then read from `os.Getenv` once and the
process does not retain the plaintext (Go strings are immutable so we can't
zero them, but they live only on the goroutine stack briefly).

This trades passphrase secrecy for availability: the passphrase is now visible
in `/proc/<pid>/environ`, the docker inspect output, and any orchestrator's
secret store. Document this trade-off explicitly. The recommended pattern is
Docker secrets / Compose `secrets:` mounting a file, then a small entrypoint
that exports `CM_PASSPHRASE` from the file before exec.

### 1.6 Passphrase rotation

The passphrase-rotation action takes `current` and `new`. Steps, all inside
one SQL transaction:

1. Verify `current` against the stored verifier.
2. Derive KEK_new from `new` with a freshly-generated salt and the current
   default params.
3. For each row in `certificates`, decrypt `wrapped_dek` with KEK_old and
   re-encrypt with KEK_new. **The encrypted private-key ciphertext is not
   touched** — only the wrapper changes. This is why the design uses two
   levels.
4. Compute new verifier under KEK_new.
5. Update `settings` (`kdf_salt`, `kdf_params`, `passphrase_verifier`).
6. Replace the in-memory KEK with KEK_new; zero KEK_old.

If the transaction fails midway, roll back; the operator's old passphrase
still works.

### 1.7 What requires unlocked state

| Operation                                  | Needs unlock? | Reason                                  |
| ------------------------------------------ | ------------- | --------------------------------------- |
| List/view cert metadata                    | no            | DER is stored unencrypted               |
| Download `cert.pem`, `chain.pem`, `fullchain.pem` | no    | Built from stored DER + parents         |
| Download `key.pem`                         | **yes**       | Must decrypt DEK then key               |
| Download `bundle.p12`                      | **yes**       | Bundle contains the key                 |
| Issue new cert (root, intermediate, leaf)  | **yes**       | Must sign with parent CA's key          |
| Rotate                                     | **yes**       | Same as issue                           |
| Revoke                                     | **yes**       | CRL signing happens immediately         |
| Deploy (run a target)                      | **yes**       | Writes `key.pem` to a path              |
| Serve cached CRL DER on the public endpoint | no            | DER is in DB, just bytes                |
| Regenerate CRL (on revoke or stale)         | **yes**       | New CRL must be signed                  |
| Liveness check                              | no            | Process liveness only                   |

Locked-state behaviour for the public CRL endpoint is detailed in §6.5; for
the HTTP encoding of "needs unlock" rejections see [API.md §2.6](API.md#26-lock-state).

---

## 2. Key encryption

Two layers of AEAD, both using AES-256-GCM with `crypto/rand` for nonces and
keys.

### 2.1 Layered design (KEK → DEK → key)

```
passphrase  --Argon2id-->  KEK  (32B, in memory only)
                             |
                             v wraps via AES-256-GCM
                          wrapped_dek (in DB)
                             |
                             v unwraps to
                          DEK  (32B, ephemeral per operation)
                             |
                             v decrypts via AES-256-GCM
                          PKCS#8 DER private key (ephemeral)
```

A **separate DEK per certificate** means:

- Passphrase rotation re-wraps N small DEKs, not N (potentially large)
  ciphertexts.
- A leaked DEK compromises one cert's key, not all.
- We can later add per-cert "external KEK" sources (KMS, hardware tokens) by
  swapping the wrap layer without touching the inner ciphertext.

### 2.2 Algorithm parameters

**KDF (passphrase → KEK):** Argon2id, `time=3, memory=64MiB, threads=2,
key_len=32`. Salt is 16 random bytes per install, stored in `settings`. KDF
params are stored alongside the salt as JSON so we can change defaults
without breaking existing installs (an install always uses the params it was
created with; we add a one-shot upgrade path later if defaults change
materially).

**KEK wraps DEK:** AES-256-GCM. 12-byte random nonce per wrap. AAD =
`"homepki/dek/v1|" || cert_id`. Output stored as `(dek_nonce, wrapped_dek)`.

**DEK encrypts key plaintext:** AES-256-GCM. 12-byte random nonce per
encryption. AAD = `"homepki/key/v1|" || cert_id`. Output stored as
`(cipher_nonce, ciphertext)`.

The `cert_id` in AAD binds the ciphertext to its DB row — an attacker who
can write to the DB can't move a ciphertext from one row to another to trick
us into decrypting the wrong cert's key.

### 2.3 Plaintext key serialization

Before encryption, the private key is marshalled as **PKCS#8 DER** via
`x509.MarshalPKCS8PrivateKey`. This handles RSA / ECDSA / Ed25519 uniformly
and is what `key.pem` exports too (PEM-armored PKCS#8).

### 2.4 Supported key algorithms

| `key_algo`  | `key_algo_params`        | Notes                                     |
| ----------- | ------------------------ | ----------------------------------------- |
| `rsa`       | `2048` / `3072` / `4096` | Default for roots: 4096                   |
| `ecdsa`     | `P-256` / `P-384`        | Default for intermediates and leaves: P-256 |
| `ed25519`   | (none)                   | Allowed; flag in UI that some TLS stacks reject Ed25519 server certs |

P-521, RSA <2048, and any non-FIPS curves are rejected at issuance.

### 2.5 Memory hygiene

- KEK is held in a `[]byte` and zeroed on lock (per §1.3).
- DEK is allocated, used, zeroed within the request handler — never returned
  up the call stack. Helper: `func withDEK(...) error` takes a callback so
  the defer-zero is guaranteed.
- Decrypted PKCS#8 plaintext: same callback pattern via `withPrivateKey`.
- Go strings cannot be zeroed; passphrases are accepted as `[]byte` from form
  values (Go's `request.FormValue` returns string, so we copy to a byte slice
  ASAP and zero the byte slice; the original string buffer remains until GC).

We do **not** call `mlockall` or use `syscall.Mlock` in v1. Documenting that
swap is enabled on the host means encrypted material may briefly be on swap.
For a home/internal-PKI threat model this is acceptable; we'll add an
optional mlock pass later if needed.

### 2.6 Random sources

All randomness — DEKs, nonces, KDF salts, certificate serial numbers — comes
from `crypto/rand.Reader`. There is no fallback; if `crypto/rand` fails the
operation aborts.

---

## 3. Data handling

The persistence layer (database choice, file layout, full schema, pragmas,
migrations, backup) is documented in [STORAGE.md](STORAGE.md). This section
covers only the lifecycle-relevant aspects: which fields hold encrypted
material, and how downloads are rendered from stored state.

### 3.1 The encryption boundary

Cert metadata and key material live in two tables, joined on `cert_id`. The
split is structural, not behavioural — it exists so that the v2 cold-root
design (see [COLD_ROOTS.md](COLD_ROOTS.md)) can later relocate root-tier
key rows to a separate file. v1 keeps everything in `homepki.db`.

In `certificates` ([STORAGE.md §5.3](STORAGE.md#53-certificates)):

| Field group                                                   | Encrypted? | Notes                |
| ------------------------------------------------------------- | ---------- | -------------------- |
| `der_cert`                                                    | no         | Public cert DER      |
| Subject DN, SANs, validity, serial, fingerprint, status, etc. | no         | Public metadata      |

In `cert_keys` ([STORAGE.md §5.4](STORAGE.md#54-cert_keys)):

| Field group                       | Encrypted? | Notes                                  |
| --------------------------------- | ---------- | -------------------------------------- |
| `wrapped_dek` + `dek_nonce`       | yes (KEK)  | DEK protecting this cert's private key |
| `ciphertext` + `cipher_nonce`     | yes (DEK)  | PKCS#8 DER private key                 |
| `kek_tier`                        | no         | `'main'` in v1; selects which KEK wrapped the DEK |

In `crls`: nothing encrypted — CRLs are public artifacts.

In `settings`: `passphrase_verifier`, `kdf_salt`, `kdf_params` are all
non-secret on their own (the verifier is a MAC over a constant string; salt
and params are inputs to the KDF). Compromising the DB still requires
brute-forcing the passphrase against `verifier` to derive KEK, then unwrap
DEKs, then decrypt keys.

There are **no `.pem` or `.key` files** in the data directory. The app
writes private-key bytes to disk only via an explicit Deploy target (an
operator-configured path, typically a bind mount to a host directory
consumed by nginx/Caddy/etc.).

### 3.2 PEM rendering on download

PEM responses are built in-memory from DB BLOBs:

- `cert.pem` = `pem.Encode("CERTIFICATE", der_cert)`.
- `chain.pem` = walk `parent_id` chain from this cert (exclusive) up to (but
  excluding) the self-signed root, concatenate.
- `fullchain.pem` = this cert's PEM + `chain.pem`. (Leaves only.)
- `key.pem` = decrypt → marshal PKCS#8 → `pem.Encode("PRIVATE KEY", ...)`.
  The plaintext byte slice is zeroed after writing the response.
- `bundle.p12` = `pkcs12.Modern.Encode(key, leafCert, chainCerts, password)`.
  Password is supplied by the operator on the request (kept off the URL — see
  [API.md §7.5](API.md#75-post-certsidbundlep12)). Plaintext key zeroed
  afterward.

---

## 4. Rotation

### 4.1 Trigger

The operator triggers a rotation from the cert's detail page. The form is
pre-populated with the old cert's fields (CN, SANs, key algorithm and params,
validity duration) and may be adjusted before submitting. HTTP wire form is
in [API.md §6.5](API.md#65-post-certsidrotate).

### 4.2 Effect on the old cert

The old cert is **not deleted, not modified except for status/linking
fields**. Specifically:

- `status` → `superseded`.
- `replaced_by_id` → new cert's `id`.
- `der_cert`, `wrapped_dek`, `ciphertext`, etc. all remain in place.
- The cert remains downloadable (`cert.pem`, `key.pem`, `fullchain.pem`,
  `p12`) for as long as the row exists.
- It is **not added to the CRL** by virtue of being superseded. Rotation is
  not revocation. If you also want to revoke (e.g., key compromise was the
  reason for rotating), do that as a separate step.

### 4.3 Effect on the new cert

- Fresh keypair, fresh serial number (cryptographically-random 159 bits then
  upper bit cleared per RFC 5280 §4.1.2.2).
- `replaces_id` → old cert's `id`.
- `status` → `active`.
- `not_before` = now − 60s (clock skew margin).
- `not_after` = now + (operator-chosen duration; defaults: **3 months for
  leaves, 5 years for intermediates, 10 years for roots**). Operator may
  override at issuance.
- Same SANs unless edited.
- CRL DP extension uses the same issuer URL as the old cert (issuer hasn't
  changed).
- **Deploy targets are inherited.** Every `deploy_targets` row on the old
  cert is copied onto the new one with a fresh row `id`, the same
  configuration (paths, mode, owner/group, post-command, `auto_on_rotate`),
  and the last-run columns carried over verbatim — those describe what is
  currently sitting at those paths on disk, which rotation does not change,
  so the UI shows `stale` until the successor is actually deployed. The old
  cert keeps its own target rows as history; they are never re-run by the
  rotation.

The whole rotation is one DB transaction: either both rows reach their final
state or nothing changes.

### 4.4 Auto-deploy

If the new cert has any inherited deploy targets with `auto_on_rotate=true`,
those targets run immediately after the transaction commits, writing the new
cert. The copies are what run — the old cert's rows are left alone. Each
target's outcome is recorded as `last_status` (`ok`/`failed`) with a
timestamp. A target failure does **not** roll back the rotation — the new
cert exists, the old is superseded, the operator just sees a red status on
the deploy and can retry or fix manually.

### 4.5 Rotating a CA

Rotating a root or intermediate produces a new CA cert with a **new key**.
This means:

- All existing certs issued under the old CA remain valid (they were signed
  by the old CA's still-existing key). Their CRL DP still points to the old
  CA's CRL (which is still served — the row is still there).
- New issuances under this CA must use the new key going forward. UI should
  default the parent picker to the active version after rotation.
- The old CA stays `superseded`. Trust stores need to add the new CA to
  validate certs issued after rotation; the old CA can be removed once all
  its issued certs have themselves been rotated or expired.

The operator can also choose to **revoke** the old CA after rotation, which
adds it to its own parent's CRL — useful in a key-compromise scenario but
otherwise not needed.

### 4.6 No garbage collection in v1

Superseded rows are never auto-deleted. Disk cost is small (a few KB per
cert). A future "forget" action could hard-delete an expired+superseded cert
if the operator wants to prune; out of scope here.

---

## 5. Revocation

### 5.1 Trigger

The operator submits a revocation with an RFC 5280 reason code (HTTP wire
form: [API.md §6.6](API.md#66-post-certsidrevoke)).

### 5.2 Supported reasons

| Code | Name                  | Supported in v1 |
| ---- | --------------------- | --------------- |
| 0    | unspecified           | yes             |
| 1    | keyCompromise         | yes             |
| 2    | cACompromise          | yes (CAs only)  |
| 3    | affiliationChanged    | yes             |
| 4    | superseded            | yes             |
| 5    | cessationOfOperation  | yes             |
| 6    | certificateHold       | **no**          |
| 8    | removeFromCRL         | **no**          |
| 9    | privilegeWithdrawn    | yes             |
| 10   | aACompromise          | yes (CAs only)  |

Hold (6) and removeFromCRL (8) are excluded because they introduce reversible
revocation, which complicates CRL number monotonicity guarantees and the
status state machine for marginal benefit on a single-operator PKI. The
current state machine is one-way:

```
active ──revoke──▶ revoked   (terminal)
active ──rotate──▶ superseded (terminal)
active ──time   ──▶ expired   (derived; not a stored status — see §5.5)
```

### 5.3 Effect on the cert row

Inside one DB transaction:

1. `status` → `revoked`, `revoked_at` → now, `revocation_reason` → code.
2. Regenerate the CRL of this cert's **direct parent (issuer)**. See §6.3.
3. Commit.

The cert's `der_cert`, `ciphertext`, `wrapped_dek` are **kept**. Operators
may still download `cert.pem`/`key.pem` for forensics. The deploy action is
disabled in the UI; if a deploy target had `auto_on_rotate=true` it does
*not* fire on revoke (revocation isn't a rotation).

### 5.4 Revoking a CA

Revoking an intermediate or root CA:

- The CA row goes `revoked`.
- The CA is added to **its own parent's CRL** (the root's CRL, if revoking an
  intermediate). For revoking a root there is no parent — the root's
  revocation is signaled by removing it from trust stores out-of-band, plus
  marking it `revoked` in homepki so the UI shows the state.
- Children (intermediates' leaves, root's intermediates) are **not
  automatically revoked**. Their `status` stays `active`. A derived state
  (computed in queries / shown in UI) flags them as "issuer-revoked":
  technically still valid bytes, but unverifiable by any client that fetches
  the parent's CRL. The operator can choose to bulk-revoke them as a
  follow-up action; the UI surfaces a one-click "revoke all 6 children"
  button on the CA's detail page.
- The CA's own CRL (its children's CRL) is **not** regenerated by this
  action — the children's status hasn't changed.

We don't auto-cascade because the operator's intent matters: was this a
key-compromise revocation (cascade everything) or a cleanup-of-an-unused-CA
(don't touch the long-tail of leaves)? Forcing a deliberate second action
keeps the audit trail honest.

### 5.5 Expiry

Expiry is **derived** (`not_after < now()`), not stored as a `status` value.
Reasons:

- An expired cert can become "valid again" in the UI sense if you wind back
  the system clock for testing — storing it as a status would lie.
- It frees us from a periodic background job that flips status on the second
  it expires.
- Listing queries compute the effective state as: `if status='revoked' →
  revoked; elif status='superseded' → superseded; elif now > not_after →
  expired; else → active` and that's what the UI shows.

Expired certs are **not** added to the CRL. RFC 5280 §3.3 explicitly allows
removing expired entries from a CRL because clients won't accept them
anyway; we go further and never put them on in the first place.

---

## 6. CRL handling

### 6.1 One CRL per CA

Every CA — root and intermediate — has its own CRL. The CRL of CA `X`
contains revocation entries for the certs whose `parent_id = X.id` and
`status = revoked`. Leaves don't have CRLs (they don't issue anything).

### 6.2 Initial CRL on CA creation

When a new CA is issued, a fresh empty CRL with `crl_number = 1` is generated
and stored immediately. Clients fetching the CA's CRL right after issuance
get a valid (empty) CRL rather than a 404 — important for clients that treat
404 as "indeterminate" rather than "no revocations".

### 6.3 Regeneration triggers

A CRL is regenerated when any of the following happens:

| Trigger                                  | Eager or lazy? |
| ---------------------------------------- | -------------- |
| A child cert is revoked                  | eager (inside the revoke transaction) |
| `next_update` has passed at request time | lazy (regenerate before serving)      |
| Operator clicks "regenerate CRL" on UI   | eager                                 |

There is no background scheduler in v1.

Eager regeneration on revoke means revoke needs unlock state (already noted
in §1.7). Lazy regeneration on the public endpoint means the endpoint can
trigger a sign operation — which needs unlock state. See §6.5 for what
happens when locked.

### 6.4 Regeneration steps

For issuer `I`:

1. Inside a transaction:
   - Read `max(crl_number)` for `I`. Next number = max + 1. (Strictly
     monotonic per RFC 5280 §5.2.3.)
   - Select all rows from `certificates` where `parent_id = I.id` AND
     `status = 'revoked'` AND `not_after > now()` (skip expired per §5.5).
   - Compute `this_update = now − 60s`, `next_update = now + 7d`.
2. Load `I`'s private key (decrypt via KEK→DEK).
3. `der, _ := x509.CreateRevocationList(rand.Reader, &template, I.cert, I.key)`
   where `template` includes:
   - `Number` = next CRL number
   - `ThisUpdate`, `NextUpdate`
   - `RevokedCertificateEntries`: for each revoked cert, `{SerialNumber,
     RevocationTime: revoked_at, ReasonCode}`.
4. Insert a new row in `crls` with `(issuer_cert_id=I.id, crl_number=next,
   this_update, next_update, der, updated_at=now)`. Old rows are kept (audit
   trail; clients with cached CRL numbers can still validate).
5. Zero the decrypted issuer key in memory.

### 6.5 The public endpoint and the lock state

The CRL endpoint is **public** (unauthenticated) and serves the cached DER.
Behavioural policy:

| State                                                       | What we serve                                  |
| ----------------------------------------------------------- | ---------------------------------------------- |
| Cached CRL exists and `next_update > now`                   | the cached DER, as-is                          |
| Cached CRL stale (`next_update ≤ now`) and app **unlocked** | regenerate per §6.4, then serve fresh DER      |
| Cached CRL stale and app **locked**                         | serve the stale cached DER, signal "stale" out-of-band; log a warning |
| No CRL row exists for this issuer                           | error response (this should not happen — see §6.2) |

Rationale for serving stale-when-locked: clients that strictly enforce CRL
freshness will reject the cert anyway, which is the correct behaviour for a
locked PKI; clients that are lenient still get a usable list of revocations
that's only off by however long the operator has been away. This beats
failing the endpoint entirely (clients break) or auto-unlocking (requires
storing the passphrase, defeating the lock).

The exact wire encoding of these responses (status codes, the stale-warning
header, content type) is in [API.md §9.1](API.md#91-get-crlissuer-idcrl).

### 6.6 CRL Distribution Point baked into issued certs

At issuance time, every cert (CA or leaf) has its `CRL Distribution Points`
extension set to:

```
URI: <CRL_BASE_URL>/crl/<parent-id>.crl
```

Where `<parent-id>` is the **parent CA's** UUID. This is the URL clients
verifying *this* cert will fetch. `CRL_BASE_URL` is read from env at
issuance and snapshotted; later changes to `CRL_BASE_URL` do not retroactively
edit already-issued certs (they can't — the cert is signed). If you change
`CRL_BASE_URL`, plan to re-issue (rotate) anything already in the field, or
maintain a redirect from the old URL.

Roots have no CRL DP extension on themselves (they're the trust anchor;
nothing's verifying the root via CRL).

### 6.7 CRL contents and extensions

Each CRL DER includes:

- **Issuer name**: exactly the issuer cert's subject DN.
- **`thisUpdate`, `nextUpdate`**: per §6.3.
- **CRL Number** extension (OID 2.5.29.20): our `crl_number`. Required
  monotonicity per RFC 5280 §5.2.3.
- **Authority Key Identifier** extension (OID 2.5.29.35): matches the
  issuer's Subject Key Identifier so clients can match CRL → issuer cert
  unambiguously when the issuer is rotated.
- **Per-entry CRL Reason Code** extension (OID 2.5.29.21): the reason from
  revocation, except for `unspecified` which we omit per RFC 5280 §5.3.1.

### 6.8 Audit / history

All historical CRL DERs are kept in the `crls` table indefinitely (PK is
`(issuer_cert_id, crl_number)`). Operator can inspect old CRLs from the
CA's CRL-history page (HTTP wire form: [API.md §5.3](API.md#53-get-certsidcrls)).
No GC in v1.

---

## 7. Imports

Roots minted offline or by another tool can be registered inside homepki
through `POST /certs/import/root` (HTTP wire form: [API.md §6.7](API.md#67-post-certsimportroot)).
Scope is intentionally roots only.

### 7.1 What gets stored

The import flow takes a self-signed cert (PEM) and its matching private
key (PKCS#8 PEM). The key is sealed under the in-memory KEK with the
same two-tier wrap as homepki-generated keys (see §2.1) — same AAD
binding, same column layout in `cert_keys`. The cert row carries
`source = 'imported'` to distinguish it from homepki-issued rows; the
dashboard surfaces an "imported" pill so the operator can tell at a
glance.

### 7.2 What's enforced at import time

- Subject DN must equal Issuer DN (self-signed).
- Signature must verify under the cert's own public key.
- `BasicConstraints CA=true`.
- Public key must match the supplied private key.
- PKCS#8 only for the key — legacy `RSA PRIVATE KEY` /
  `EC PRIVATE KEY` blocks are rejected with a hint pointing at
  `openssl pkcs8 -topk8`.
- Expired roots are accepted but flagged on the dashboard via the
  derived `expired` status (§5.5).

Re-uploading the same cert is idempotent: the handler resolves to the
existing row (matched by SHA-256 fingerprint) instead of inserting a
duplicate.

### 7.3 What happens after import

The imported row behaves like any homepki-issued CA:

- Children issued via `POST /certs/new/{intermediate,leaf}` under the
  imported parent are **homepki-signed**, get homepki's CRL
  Distribution Point baked in (§6.6), and revoke / CRL-regen flows
  work end to end.
- An empty initial CRL signed by the imported key is written at
  import time so `GET /crl/{id}.crl` returns 200 immediately
  (mirrors §6.2) — but only when the imported cert carries the
  `cRLSign` KeyUsage bit. Older roots minted without `cRLSign` are
  still accepted (see §7.5); they simply have no CRL endpoint, and
  revoking children under them records the transition without a CRL
  update (the same out-of-band model as root revocation in §5.4).
- The imported root itself can be rotated; the successor is a
  homepki-issued cert with the standard `replaces_id` / `replaced_by_id`
  link. Over time, rotation naturally migrates the install away from
  imported state.

### 7.4 What homepki cannot do for imported roots

The CRL DP extension in any cert is part of the signed body; we can't
change it without invalidating the issuer's signature. So:

- The imported root carries whatever DP it was minted with (often none
  for self-signed roots; sometimes one pointing at the original issuer
  infrastructure). Homepki doesn't touch it.
- Pre-existing children of the imported root that were issued
  *before* the import — not visible to homepki — keep their original
  DPs. Homepki's CRL is only consulted for those children if a
  verifier is configured out-of-band.

This is why import is roots-only in v1: importing leaves or
intermediates would inherit a baked-in DP that points away from
homepki, defeating the revocation flow. Roots avoid the problem
because new children flow through homepki's signing path.

### 7.5 Imported roots without `cRLSign`

RFC 5280 §4.2.1.3 requires the `cRLSign` KeyUsage bit on any cert that
signs a CRL — and Go's `x509.CreateRevocationList` enforces it. Older
or constrained PKIs sometimes mint roots without that bit; reminting
the cert to add it would, by definition, reissue the root and defeat
the point of import (the operator brought a cert they specifically
want to keep, not a placeholder for a fresh one).

Homepki accepts these roots and adapts the surrounding flows:

- **Import** writes the cert + sealed key but **skips the initial CRL
  row**. `GET /crl/{id}.crl` returns 404 — there is no CRL to serve,
  and the operator already accepted that limitation by importing a
  cert without `cRLSign`.
- **The dashboard hides the CRL download / history links** for these
  CAs (both on the index row and the detail page), and the detail
  page surfaces a short note explaining why.
- **Revoking a child** of such a CA marks the child `revoked` in the
  database and logs that the parent's CRL was not regenerated — the
  HTTP response is still a normal 303 to the child's detail page.
  Revocation distribution is the operator's responsibility (typically
  trust-store removal, same as for root revocation per §5.4).
- **Rotation** of the imported root produces a homepki-issued
  successor with `cRLSign` set and a working CRL endpoint, so the
  steady state migrates away from the no-CRL constraint as soon as
  the operator chooses to rotate.

---

## Open decisions

1. **`CM_PASSPHRASE` doc tone** (§1.5) — should the README warn loudly that
   it's the easy-but-less-secure mode, or treat it as the standard production
   path?
2. **Bulk revoke children of a revoked CA** (§5.4) — UI button proposed; is a
   one-click "cascade revoke" too footgun-shaped, vs. forcing manual?
