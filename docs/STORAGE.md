# homepki — Storage

> Documents the persistence layer: database choice, file layout, schema,
> migrations, transactions, and backup. Companion docs:
>
> - [LIFECYCLE.md](LIFECYCLE.md) — cert/key/CRL lifecycle semantics; what
>   each column *means* and when it changes. This doc says how those columns
>   are *stored*.
> - [API.md](API.md) — HTTP wire form. Two tables documented here
>   (`idempotency_tokens`, sessions cookie format) directly back the
>   request-handling rules in API.md §2.

---

## 1. Database

### 1.1 Choice: SQLite via modernc

- **Driver:** [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite),
  a pure-Go translation of SQLite. No CGO ⇒ `CGO_ENABLED=0` ⇒ static binary
  in a `scratch` image.
- **Mode:** WAL — concurrent reads while one writer is active. The public
  CRL endpoint must remain responsive while a long-running issuance is in
  flight.
- **Single-writer constraint** of SQLite is acceptable for a single-operator
  workload. There is no horizontal scaling concern in v1.

### 1.2 Why not...

- **Postgres:** deployment complexity not justified — operator now manages a
  separate service, credentials, backups. SQLite hits the spec's
  single-binary, single-volume goal.
- **BoltDB / Badger:** we want ad-hoc filtering (status, expiry, parent) and
  joins (cert ↔ CRLs ↔ deploy targets); SQL is the right tool.
- **Flat PEM/key files on disk:** would require either plaintext keys (no)
  or a parallel encrypted-file format reinventing what we get from SQLite
  blobs + AEAD. The encryption boundary stays clean inside one transactional
  store.

---

## 2. File layout

```
$CM_DATA_DIR/
  homepki.db          # SQLite main file
  homepki.db-wal      # WAL (created at runtime by SQLite)
  homepki.db-shm      # WAL shared-memory file
```

No PEM files, no key files, no separate secrets file. Backup = copy
`homepki.db` (with the WAL checkpointed first, see §8). Restore = drop the
file in place.

**Permissions:** the data directory should be `0700` and the DB file `0600`,
both owned by the user the homepki container runs as. The Dockerfile sets
the runtime user to a non-root uid so that even a write-anywhere bug can't
escape the data directory.

---

## 3. Connection management

### 3.1 Pragmas

Set on every connection open, before any query:

| pragma            | value     | reason                                                   |
| ----------------- | --------- | -------------------------------------------------------- |
| `journal_mode`    | `WAL`     | concurrent reads during writes                           |
| `synchronous`     | `NORMAL`  | fsync at WAL checkpoint; fast enough for our write rate  |
| `foreign_keys`    | `ON`      | enforce `parent_id`, `cert_id`, etc.                     |
| `busy_timeout`    | `5000`    | wait up to 5s on contention before returning `SQLITE_BUSY` |
| `temp_store`      | `MEMORY`  | keep temp tables (sort spillage, etc.) in RAM            |
| `cache_size`      | `-20000`  | ~20 MiB page cache (negative ⇒ kibibytes)                |

### 3.2 Connection pool

`*sql.DB` is configured with the default pool. Reads and writes share the
pool; SQLite serializes writes internally and `busy_timeout` smooths over
the rare contention. We do **not** maintain separate read/write pools in
v1 — single-operator load doesn't justify the complexity.

### 3.3 Statement preparation

Hot-path queries (cert list, single cert load, CRL fetch) are prepared
once at startup and reused. Cold queries (issuance, migrations) use
ad-hoc `db.Exec`/`db.Query`.

### 3.4 SQL → Go via sqlc

Queries live as `.sql` files under `internal/store/queries/` with
[sqlc](https://sqlc.dev) annotations. The generator produces typed Go
in `internal/store/storedb/` (committed). Per-table wrappers in
`internal/store/` translate between the generated row types and the
package's domain types — JSON columns, INTEGER↔bool, nullable
conversions, sentinel errors.

The schema migration runner is the one exception: it bootstraps the
`schema_migrations` table itself and runs arbitrary migration DDL,
neither of which sqlc can know about at build time.

---

## 4. Schema migrations

### 4.1 Mechanism

- Migration files live at `migrations/NNNN_<description>.up.sql`, four-digit
  zero-padded sequence.
- `//go:embed migrations/*.sql` bundles them into the binary.
- Startup runs an in-process runner (~40 LOC):
  1. Ensure `schema_migrations` exists.
  2. List embedded files, sort by sequence.
  3. For each file whose `version` is not yet recorded, exec the SQL inside
     a transaction; on success insert the row.
  4. Stop on first failure with a clear error referencing the file name.

### 4.2 No down migrations

Down migrations encourage destructive recovery patterns. We're forward-only:
if a migration was wrong, write `NNNN_fix_thing.up.sql` that compensates.
This also means the embedded files form an append-only history that mirrors
the production schema over time.

### 4.3 Migration content rules

- Each file is one logical change (one new table, one column add, one index).
- Schema-only — no data backfills mixed in. Backfills, if needed, go in a
  separate file labelled `NNNN_backfill_<thing>.up.sql`.
- Use `IF NOT EXISTS` defensively only for `CREATE INDEX` (idempotent
  retries on partial failures); for tables, prefer fresh-create + fail-loud.

---

## 5. Tables

All `DATETIME` columns store ISO-8601 UTC text (SQLite's recommended
representation for this driver). All UUID columns store the canonical
hyphenated 36-char form. All `BLOB` columns store raw bytes (no base64
wrapping).

### 5.1 `schema_migrations`

Tracks applied migrations. Owned by the runner.

| column        | type     | notes |
| ------------- | -------- | ----- |
| `version`     | INTEGER  | PK; the `NNNN` from the file name |
| `applied_at`  | DATETIME |       |

### 5.2 `settings`

App-wide key/value store. Used for: passphrase verifier, KDF salt and
parameters, CRL base URL snapshot.

| column        | type     | notes |
| ------------- | -------- | ----- |
| `key`         | TEXT     | PK    |
| `value`       | BLOB     | scalar or JSON, depending on key |
| `updated_at`  | DATETIME |       |

Keys used by v1:

| key                     | type           | source                    |
| ----------------------- | -------------- | ------------------------- |
| `passphrase_verifier`   | BLOB (32B HMAC) | LIFECYCLE.md §1.1         |
| `kdf_salt`              | BLOB (16B)     | LIFECYCLE.md §1.1         |
| `kdf_params`            | TEXT (JSON)    | LIFECYCLE.md §1.1         |
| `crl_base_url`          | TEXT           | snapshot of `CRL_BASE_URL` env at first cert issuance; used to detect drift |

### 5.3 `certificates`

The main table. Holds every cert this PKI has ever issued (active,
revoked, superseded, expired — never deleted in v1).

| column                  | type            | notes |
| ----------------------- | --------------- | ----- |
| `id`                    | TEXT (UUID)     | PK; embedded in CRL DP URL |
| `type`                  | TEXT            | `root_ca` \| `intermediate_ca` \| `leaf` |
| `parent_id`             | TEXT NULL       | FK → `certificates.id`; NULL for roots |
| `serial_number`         | TEXT            | hex string; 20-byte serials would overflow INTEGER |
| `subject_cn`            | TEXT            |       |
| `subject_o`             | TEXT NULL       |       |
| `subject_ou`            | TEXT NULL       |       |
| `subject_l`             | TEXT NULL       |       |
| `subject_st`            | TEXT NULL       |       |
| `subject_c`             | TEXT NULL       |       |
| `san_dns`               | TEXT (JSON arr) | empty array for non-leaf |
| `san_ip`                | TEXT (JSON arr) | empty array for non-leaf |
| `is_ca`                 | INTEGER (bool)  | basicConstraints CA flag |
| `path_len_constraint`   | INTEGER NULL    | basicConstraints pathLen |
| `key_algo`              | TEXT            | `rsa` \| `ecdsa` \| `ed25519` |
| `key_algo_params`       | TEXT            | bits or curve name |
| `key_usage`             | TEXT (JSON arr) |       |
| `ext_key_usage`         | TEXT (JSON arr) |       |
| `not_before`            | DATETIME        |       |
| `not_after`             | DATETIME        |       |
| `der_cert`              | BLOB            | DER-encoded cert; render PEM on download |
| `fingerprint_sha256`    | TEXT            | hex of SHA-256(DER) |
| `status`                | TEXT            | `active` \| `revoked` \| `superseded` (expired is derived; LIFECYCLE.md §5.5) |
| `revoked_at`            | DATETIME NULL   |       |
| `revocation_reason`     | INTEGER NULL    | RFC 5280 reason code |
| `replaces_id`           | TEXT NULL       | FK → `certificates.id`; rotation chain |
| `replaced_by_id`        | TEXT NULL       | FK → `certificates.id`; rotation chain |
| `created_at`            | DATETIME        |       |
| `source`                | TEXT            | `issued` (homepki minted the cert) \| `imported` (operator brought their own root via `POST /certs/import/root`). Default `issued`. |

**Constraints:**

- `UNIQUE(parent_id, serial_number)` — RFC 5280 §4.1.2.2 requires uniqueness per issuer.
- FK on `parent_id`, `replaces_id`, `replaced_by_id` (all → `certificates.id`).

**Indexes:**

- `idx_certificates_parent_status` on `(parent_id, status)` — feeds CRL
  regeneration ("revoked children of issuer X") and the leaf list per CA.
- `idx_certificates_not_after` on `(not_after)` — feeds the expiring-soon
  filter on the main view.
- `idx_certificates_fingerprint` on `(fingerprint_sha256)` — for search by
  fingerprint.

Encrypted private-key material is **not** here — see §5.4 (`cert_keys`).

### 5.4 `cert_keys`

Encrypted private-key material, one row per cert. Split out from
`certificates` so the v2 cold-root design (see [COLD_ROOTS.md](COLD_ROOTS.md))
can relocate root-tier rows to a separate database file without altering the
main schema. v1 keeps every row in this same file.

| column         | type        | notes                                    |
| -------------- | ----------- | ---------------------------------------- |
| `cert_id`      | TEXT        | PK; FK → `certificates.id`               |
| `kek_tier`     | TEXT        | `'main'` (default). v2 introduces `'root'`. |
| `wrapped_dek`  | BLOB        | DEK wrapped under the tier's KEK; LIFECYCLE.md §2 |
| `dek_nonce`    | BLOB (12B)  | nonce for the DEK wrap                   |
| `cipher_nonce` | BLOB (12B)  | nonce for the key encryption             |
| `ciphertext`   | BLOB        | PKCS#8 DER private key, AEAD-encrypted under DEK |
| `created_at`   | DATETIME    |                                          |

**Constraints:**

- FK on `cert_id` with `ON DELETE CASCADE` — cleaning up a cert row also
  removes its key material atomically.
- `CHECK (kek_tier IN ('main', 'root'))` — open enum; in v1 only `'main'`
  is ever written.

**Indexes:** none beyond the PK; lookups are always by `cert_id`.

**Why this split exists in v1.** The two-tier encryption model in
[COLD_ROOTS.md](COLD_ROOTS.md) needs to relocate root-cert key rows to a
separately-encrypted, removable `roots.db` file. Splitting the table now
means that v2 doesn't have to touch the `certificates` schema or migrate
encrypted blobs around — it only needs to move the `cert_keys` rows whose
`kek_tier = 'root'` to the new file. Code paths that load a cert's key are
written from day one as a separate query, so the v2 change is purely
"which DB do I open for the lookup, based on tier".

### 5.5 `crls`

One row per CRL ever issued. Old CRLs are kept for audit and for clients
with stale caches.

| column            | type        | notes |
| ----------------- | ----------- | ----- |
| `issuer_cert_id`  | TEXT        | PK part 1; FK → `certificates.id` |
| `crl_number`      | INTEGER     | PK part 2; strictly monotonic per issuer (LIFECYCLE.md §6.4) |
| `this_update`     | DATETIME    |       |
| `next_update`     | DATETIME    |       |
| `der`             | BLOB        | signed CRL bytes |
| `updated_at`      | DATETIME    |       |

**Indexes:**

- `idx_crls_issuer_latest` on `(issuer_cert_id, crl_number DESC)` — feeds
  "give me the latest CRL for this issuer" (the public endpoint's hot path).

### 5.6 `deploy_targets`

Per-leaf-cert deploy configuration. Tracks where files are written and the
result of the last run.

| column                   | type            | notes |
| ------------------------ | --------------- | ----- |
| `id`                     | TEXT (UUID)     | PK    |
| `cert_id`                | TEXT            | FK → `certificates.id`; leaf certs only |
| `name`                   | TEXT            | operator-given, e.g. `nginx`, `haproxy` |
| `cert_path`              | TEXT            | absolute path inside container |
| `key_path`               | TEXT            | absolute path inside container |
| `chain_path`             | TEXT NULL       | optional; if set, write `fullchain.pem` here |
| `mode`                   | TEXT            | octal as text, e.g. `0640` |
| `owner`                  | TEXT NULL       | uid or username |
| `group`                  | TEXT NULL       | gid or group name |
| `post_command`           | TEXT NULL       | reload command, e.g. `nginx -s reload` |
| `auto_on_rotate`         | INTEGER (bool)  |       |
| `last_deployed_at`       | DATETIME NULL   |       |
| `last_deployed_serial`   | TEXT NULL       | the cert serial that was written |
| `last_status`            | TEXT NULL       | `ok` \| `failed` \| `stale` |
| `last_error`             | TEXT NULL       |       |
| `created_at`             | DATETIME        |       |

**Constraints:**

- `UNIQUE(cert_id, name)` — operator can't have two targets with the same
  name on one cert.
- FK on `cert_id` with `ON DELETE CASCADE` — if a cert row is ever
  hard-deleted (out of scope in v1, but the schema is ready), its targets
  go too.

Targets belong to a single cert row, so a rotation copies them onto the
successor inside the rotation transaction (new `id`, same configuration,
last-run columns carried over) — see [LIFECYCLE.md §4.3](LIFECYCLE.md#43-effect-on-the-new-cert).

**Indexes:**

- `idx_deploy_targets_cert_id` on `(cert_id)` — feeds the cert detail page.

The `last_status = 'stale'` value is **not** written by the deploy runner;
it's derived in the UI when `last_deployed_serial != cert.serial_number`.
Stored only as `ok` or `failed`.

### 5.7 `idempotency_tokens`

Backs the form-token replay protection in API.md §2.7.1. Survives process
restarts, so an in-flight form submission across a restart still
deduplicates correctly.

| column        | type          | notes |
| ------------- | ------------- | ----- |
| `token`       | TEXT          | PK; 64 hex chars (32 random bytes) |
| `created_at`  | DATETIME      | when the form was rendered |
| `used_at`     | DATETIME NULL | populated on the first POST that consumes the token |
| `result_url`  | TEXT NULL     | populated atomically with `used_at`; the redirect target for replays |
| `expires_at`  | DATETIME      | `created_at + 24h` |

**Indexes:**

- `idx_idempotency_expires_at` on `(expires_at)` — feeds the cleanup sweep.

**Cleanup:** two-pronged.
- *Lazy:* every token lookup also deletes any rows where `expires_at < now`
  (single statement in the same transaction).
- *Sweep:* a goroutine runs `DELETE FROM idempotency_tokens WHERE expires_at
  < now` every hour, capping growth in case nobody loads forms for a while.

---

## 6. Sessions

Sessions are **not** stored in the database. Instead the session cookie is
self-contained:

```
Cookie name : session
Value       : base64url( payload || HMAC-SHA256(server_secret, payload) )
Payload     : JSON { "iat": <unix>, "exp": <unix>, "v": 1 }
Attributes  : HttpOnly; SameSite=Lax; Path=/; Secure (when served over HTTPS)
TTL         : 24h
```

`server_secret` is derived from the KEK at unlock time (`HKDF(KEK,
"homepki/session-cookie/v1")`), so:

- Sessions implicitly become invalid when the app is locked: no KEK ⇒ no
  `server_secret` ⇒ HMAC verification fails ⇒ user is bounced to `/unlock`.
- A passphrase rotation invalidates all sessions because KEK changed.
- A process restart that auto-unlocks via `CM_PASSPHRASE` derives the same
  KEK (same passphrase + same salt), so existing session cookies keep working
  across restarts.

This avoids an extra table and an extra storage concern. The cost is that
we can't implement "log out everywhere" without doing a passphrase
rotation, which is acceptable for v1.

---

## 7. Transactions

A transaction wraps every operation that mutates more than one row, plus
every form-token consumption. Required transactions:

| operation                              | transactional scope |
| -------------------------------------- | ------------------- |
| Issue cert (any type)                  | `idempotency_tokens` mark used → insert `certificates` row → insert `cert_keys` row → if CA, insert initial `crls` row |
| Rotate                                 | `idempotency_tokens` mark used → insert new `certificates` row → insert new `cert_keys` row → update old `certificates` row (`status`, `replaced_by_id`) → set new row's `replaces_id` → copy old row's `deploy_targets` onto the new cert |
| Revoke                                 | update `certificates` row → insert new `crls` row (regenerated) |
| Passphrase rotation                    | `idempotency_tokens` mark used → re-wrap all DEKs → update `settings` |
| Deploy target create/edit              | `idempotency_tokens` mark used → insert/update `deploy_targets` row |
| Migration                              | one transaction per file |

Transactions use SQLite's default `DEFERRED` mode (acquire write lock on
first write). The runner upgrades to `IMMEDIATE` for the few cases where
we want to fail fast on contention (passphrase rotation, large bulk
operations) — none in v1 yet.

---

## 8. Backup and restore

### 8.1 Backup

Two supported approaches:

- **Hot:** `VACUUM INTO '/path/to/backup.db'` produces a consistent
  snapshot without stopping the app. Safe to run from a sidecar or cron.
- **Cold:** stop the app, copy `homepki.db` plus any present `.db-wal` and
  `.db-shm` files (or run a `PRAGMA wal_checkpoint(FULL)` before copy and
  skip the WAL).

The backup file is a normal SQLite database; you can open it with `sqlite3`
to inspect.

### 8.2 Restore

1. Stop the app.
2. Move the existing `$CM_DATA_DIR/homepki.db*` aside (don't delete until
   verified).
3. Place the backup at `$CM_DATA_DIR/homepki.db`.
4. Remove any leftover `.db-wal` and `.db-shm` from the backup-source
   environment (they're tied to the original WAL state and shouldn't
   travel).
5. Start the app. It will run any pending migrations.
6. Unlock with the passphrase that was current when the backup was taken.

### 8.3 Encryption considerations

The DB file contains encrypted private-key material. Backups are safe to
store on untrusted media: the keys are AEAD-encrypted under DEKs, themselves
wrapped under a KEK derived from the passphrase. Anyone who steals the
backup must also brute-force the passphrase to recover keys.

If the operator forgets the passphrase, **the keys cannot be recovered.**
There is no escrow in v1.

### 8.4 Schema-version skew

If you restore a backup taken with an older schema into a newer binary,
migrations run on startup and the data is upgraded forward. The reverse
(newer backup, older binary) is not supported — there are no down
migrations and the binary will refuse to start if `schema_migrations`
contains versions it doesn't know.

---

## 9. Retention

| table                  | retention                                            |
| ---------------------- | ---------------------------------------------------- |
| `schema_migrations`    | forever                                              |
| `settings`             | forever                                              |
| `certificates`         | forever; no auto-delete in v1 even for revoked / superseded / expired rows |
| `cert_keys`            | forever; tied to `certificates` via `ON DELETE CASCADE`            |
| `crls`                 | forever; old CRLs may still be useful to clients with stale caches |
| `deploy_targets`       | until explicitly deleted by operator                 |
| `idempotency_tokens`   | 24h; lazy + periodic cleanup (§5.6)                  |

A future "forget" action could hard-delete an expired+superseded cert if
the operator wants to prune (per LIFECYCLE.md §4.6); out of scope here.
The schema is ready for it (`ON DELETE CASCADE` from `deploy_targets`).

---

## 10. Concurrency and consistency

### 10.1 Reader/writer coexistence

WAL mode means readers don't block the single writer and vice versa.
Concrete implications:

- The public CRL endpoint can serve a cached DER while issuance is signing
  a new cert in another transaction.
- Long-running operations (passphrase rotation, which re-wraps every DEK)
  hold the write lock for the duration; concurrent issuance attempts hit
  `busy_timeout` (5s) and either complete after the rotation finishes or
  fail with `SQLITE_BUSY` (rare).

### 10.2 Crash safety

`synchronous = NORMAL` + WAL gives durability at every checkpoint, not
every commit. The window of possible loss on power failure is one
checkpoint interval (default ~1000 pages / ~4 MB of writes). For our
workload that's a handful of issuances at most. Acceptable.

For higher durability the operator can set `synchronous = FULL` via a
custom pragma override, at the cost of a fsync per commit. Not exposed as
a config knob in v1.

### 10.3 No application-level row locking

We do not use `SELECT ... FOR UPDATE` (SQLite doesn't support it) or
advisory locks. Consistency comes from:

- Transactions for multi-row operations (§7).
- `UNIQUE` constraints catching duplicate-creation races.
- Form tokens (§5.6) catching duplicate-submission races.
