# For Your Eyes Only

## AES Client-Side Vault

A single-file PHP + HTML + JavaScript application that encrypts text in the browser, stores the ciphertext on a server, and allows one-off retrieval and local decryption. The server never sees the plaintext or the raw secret.

---

## Overview

The application has three responsibilities, all handled by one file (`encrypt.php`):

1. **Serve the client UI** — an HTML page with two tabs: *Encrypt & store* and *Retrieve & decrypt*.
2. **Store encrypted payloads** — accept a JSON POST containing an AES-GCM ciphertext (base64) and a SHA-256 validation hash, persist them in SQLite, and return a unique reference ID.
3. **Retrieve encrypted payloads (one-off)** — accept a reference ID and secret, verify the secret by recomputing the hash, and if correct, delete the record and return the ciphertext. The client decrypts locally.

The server's role is deliberately limited: **it never decrypts**. It only stores ciphertext, validates that a caller knows the secret, and hands the ciphertext back.

---

## Features

- **Client-side AES-256-GCM encryption** using the Web Crypto API.
- **SHA-256 key derivation** from a random 32-character alphanumeric secret.
- **SHA-256 validation hash** computed as `SHA-256(secret + encrypted_base64)`.
- **One-off retrieval semantics**: the DB row is deleted atomically inside a transaction upon successful secret validation. A wrong secret preserves the record so the user can retry.
- **30-day retention**: un-retrieved payloads are automatically purged by a deterministic time-based GC.
- **Per-IP rate limiting** persisted in SQLite, with a fixed-window counter and atomic increments.
- **Client-side pacing** (`guardedSubmit`) to prevent accidental double-submits.
- **Security headers**: CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`.
- **XSS-safe rendering**: the decrypted plaintext is written via `textContent`, never `innerHTML`.
- **Configurable endpoints**: same file serves both the UI and the API.

---

## Requirements

- **PHP 7.0+** (tested on PHP 7.0.33; the code avoids PHP 8-only syntax).
- **PDO SQLite driver** (`pdo_sqlite` extension enabled).
- **OpenSSL** extension (only needed if you extend the script; the current version does not use it server-side).
- **A writable directory** for the SQLite database and the rate-limit log.
- **HTTPS** in production. The one-off URLs and secrets should never travel in cleartext.
- **A modern browser** with Web Crypto API support (Chrome 37+, Firefox 34+, Safari 11+, Edge 79+).

---

## Installation

1. **Copy the file** to a directory served by PHP:

   ```
   /var/www/html/encrypt.php
   ```

2. **Ensure the directory is writable** by the PHP user (typically `www-data` on Debian/Ubuntu, `nginx` on RHEL/CentOS):

   ```bash
   chown www-data:www-data /var/www/html/
   chmod 750 /var/www/html/
   ```

   The script creates its own files (`payloads.sqlite`, `ratelimit.log`) with restrictive permissions on first run.

3. **Verify the SQLite driver is available**:

   ```bash
   php -m | grep -i pdo_sqlite
   ```

   If nothing is printed, install and enable `pdo_sqlite` for your PHP version.

4. **Open the page** in a browser:

   ```
   https://example.com/encrypt.php
   ```

   The first request creates `payloads.sqlite` and initializes the schema.

5. **Set up a cron job** (optional but recommended) to enforce GC even during idle periods:

   ```cron
   */5 * * * * sqlite3 /var/www/html/payloads.sqlite \
     "DELETE FROM payloads WHERE created_at < strftime('%s','now') - 2592000;"
   ```

   The PHP-level GC still runs opportunistically on incoming requests, so this is a belt-and-suspenders addition.

---

## Usage

### Encrypt & store

1. Open the page. The **Encrypt & store** tab is active by default.
2. Type your message in the textarea (max 1000 characters).
3. A random 32-character secret appears in the key box. **Copy it** — you'll need it to decrypt.
   - Use **📋 Copy secret** to copy it to the clipboard.
   - Use **🔄 Generate new secret** if you want a different one before encrypting.
4. Click **🔒 Encrypt & store with this secret**.
5. The server returns a reference ID and a URL. Both are displayed in the yellow result box.
6. Save the **reference ID** and the **secret** — the secret is the only way to decrypt, and it cannot be recovered.

### Retrieve & decrypt

1. Switch to the **Retrieve & decrypt** tab.
2. Paste the **reference ID** (32 hex characters).
3. Paste the **secret**.
4. Click **🔥 Retrieve, decrypt & destroy**.
5. If the secret is correct:
   - The server deletes the record and returns the ciphertext.
   - The browser verifies the hash locally and decrypts the payload.
   - The plaintext appears in the decrypted-message box.
   - A red banner confirms the record was destroyed and the reference ID is now unusable.
6. If the secret is wrong:
   - The server returns a generic "invalid" error.
   - The record is **not** deleted — you can retry with the correct secret.

### URL shortcut

If the URL contains `?id=<reference_id>`, the retrieve tab opens automatically with the reference ID pre-filled. You still need to paste the secret.

```
https://example.com/encrypt.php?id=9f3a1c2b4d5e6f708192a3b4c5d6e7f8
```

---

## API Reference

All API endpoints return JSON. The base path is the same as the UI page.

### `POST encrypt.php` — store a payload

**Request body:**
```json
{
  "encrypted": "base64-encoded-ciphertext",
  "validation_hash": "64-character-hex-sha256"
}
```

**Success response (200):**
```json
{
  "success": true,
  "reference_id": "9f3a1c2b4d5e6f708192a3b4c5d6e7f8",
  "url": "https://example.com/encrypt.php?id=9f3a1c2b4d5e6f708192a3b4c5d6e7f8",
  "one_off": true,
  "expires_in": 2592000
}
```

**Errors:**
- `400` — invalid base64, invalid hash format, or malformed JSON.
- `413` — request body exceeds `MAX_JSON_BODY` (32 KB).
- `429` — rate limit exceeded (`Retry-After` header included).
- `500` — database unavailable or insert failed.

### `POST encrypt.php?action=retrieve` — retrieve & destroy

**Request body:**
```json
{
  "reference_id": "9f3a1c2b4d5e6f708192a3b4c5d6e7f8",
  "secret": "Abc123Xyz789Def456Ghi012Jkl345"
}
```

**Success response (200):**
```json
{
  "success": true,
  "reference_id": "9f3a1c2b4d5e6f708192a3b4c5d6e7f8",
  "encrypted": "base64-encoded-ciphertext",
  "validation_hash": "64-character-hex-sha256",
  "consumed": true
}
```

**Errors:**
- `400` — invalid reference ID format or missing secret.
- `401` — invalid reference ID or wrong secret (record preserved).
- `429` — rate limit exceeded.
- `500` — database error during retrieval.

---

## Architecture

### Cryptographic flow

```
                         Browser                                Server
                    ─────────────────────────────────────────────────────────

  Plaintext ──┐
              │
              ▼
        ┌───────────┐
        │  AES-GCM  │ ◄─── derived key = SHA-256(secret)
        └───────────┘
              │
              ▼
    IV(12) || ciphertext || tag(16) ──base64──► POST ──► store in SQLite
                                                          (encrypted, hash)
                                                                 │
                                                                 │ reference_id
                                                                 ▼
                                                            returned to user

  ───────────────────────── later ─────────────────────────

    reference_id + secret ──POST──► validate:
                                       SHA-256(secret + encrypted) == stored_hash?
                                       │
                                       ├── yes ──► DELETE row, return ciphertext
                                       │
                                       └── no  ──► 401, keep row

    ciphertext ──► verify hash locally ──► AES-GCM decrypt ──► plaintext
```

### Database schema

```sql
CREATE TABLE payloads (
    reference_id    TEXT PRIMARY KEY,
    encrypted       TEXT NOT NULL,
    validation_hash TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE INDEX idx_payloads_created_at ON payloads(created_at);

CREATE TABLE rate_limits (
    bucket    TEXT    NOT NULL,
    window_ts INTEGER NOT NULL,
    hits      INTEGER NOT NULL,
    PRIMARY KEY (bucket, window_ts)
);

CREATE TABLE _meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
```

### Files created at runtime

| File | Purpose | Permissions |
|---|---|---|
| `payloads.sqlite` | Stores payloads, rate limits, and meta state | `0600` |
| `payloads.sqlite-wal` | SQLite write-ahead log | `0600` |
| `payloads.sqlite-shm` | SQLite shared memory file | `0600` |
| `ratelimit.log` | Appended log of rate-limit events | default umask |

---

## Configuration

All tunables are defined as PHP constants at the top of the file. Key ones:

| Constant | Default | Purpose |
|---|---|---|
| `DB_PATH` | `__DIR__ . '/payloads.sqlite'` | SQLite database location |
| `RATELIMIT_LOG` | `__DIR__ . '/ratelimit.log'` | Rate-limit event log |
| `MAX_ENCRYPTED_B64` | `16384` | Max size of base64 ciphertext accepted |
| `MAX_JSON_BODY` | `32768` | Max size of the entire JSON body |
| `REF_ID_LEN` | `32` | Reference ID length in hex characters (16 random bytes) |
| `SECRET_MAX_LEN` | `128` | Max secret length accepted |
| `RL_STORE_MAX` | `20` | Store writes allowed per window |
| `RL_STORE_WINDOW` | `600` | Store rate-limit window in seconds |
| `RL_RETRIEVE_MAX` | `30` | Retrieve reads allowed per window |
| `RL_RETRIEVE_WINDOW` | `300` | Retrieve rate-limit window in seconds |
| `RL_RETENTION` | `3600` | How long rate-limit rows are kept |
| `PAYLOAD_RETENTION` | `30 * 86400` | Un-retrieved payload retention (30 days) |
| `GC_INTERVAL` | `300` | Minimum seconds between GC runs |

---

## Security Notes

### What is protected

- **Server never sees plaintext.** Encryption and decryption happen entirely in the browser.
- **Server never sees the raw secret in a usable form for decryption.** It only receives the secret transiently during retrieval, computes a SHA-256 hash, compares it in constant time, and discards it.
- **Constant-time hash comparison** (`hash_equals`) prevents timing attacks on the secret check.
- **One-off semantics enforced transactionally.** A race between two concurrent retrievals cannot result in two successes.
- **XSS-safe plaintext rendering.** Decrypted content is written with `textContent`, never `innerHTML`.
- **CSP + related headers** restrict script sources, connection targets, framing, and MIME sniffing.
- **Per-IP rate limiting** with 429 responses and `Retry-After`.
- **Generic error messages** for retrieval failures, so an attacker cannot enumerate valid reference IDs.
- **Restrictive file permissions** on the database (`0600`).

### What is not protected (by design or by omission)

- **Rate limiting is per-IP.** An attacker with many IPs can bypass it. This is *not* a serious risk for the secret-brute-force vector because the secret has ~190 bits of entropy, but it matters for volumetric abuse.
- **No authentication.** Anyone who has the reference ID and secret can retrieve the payload. That is the intended trust model.
- **No expiry enforcement by the client.** The server purges after 30 days, but the UI does not display a countdown.
- **No CSRF tokens.** The API is stateless and does not use cookies, so CSRF is not applicable here — but be aware if you later add cookie-based features.
- **No audit log for successful retrievals.** Only rate-limit events are logged.
- **`script-src 'unsafe-inline'` is still in the CSP** (see the note below).

### Recommended additional hardening

1. **Move the inline `<script>` to an external `app.js`** and change CSP to `script-src 'self'`. This is the single highest-value hardening step and closes the XSS gap even if a future `innerHTML` sink is accidentally introduced.
2. **Serve everything over HTTPS only**, with HSTS. Add:
   ```
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   ```
3. **Set up `fail2ban` or a WAF** in front of the endpoint to block IPs that repeatedly trigger 429s.
4. **Back up `payloads.sqlite`** if the payloads are valuable. The current script has no backup mechanism.

---

## Troubleshooting

### "Database unavailable" on every request

- Verify `pdo_sqlite` is enabled: `php -m | grep pdo_sqlite`.
- Check that the PHP user has write access to the directory containing `encrypt.php`.
- Check the PHP error log for the underlying PDO exception.

### "Invalid reference ID or secret" even though the secret is correct

- Confirm the secret has no leading/trailing whitespace (the UI does not trim it).
- Confirm the reference ID is exactly 32 lowercase hex characters.
- If the record was created more than 30 days ago and never retrieved, the GC may have purged it.

### The URL opens but the reference ID field is empty

- The `?id=` parameter must match `/^[a-f0-9]{32}$/`. Check for URL-encoding artifacts or truncation.

### Rate limit triggered unexpectedly during testing

- Check `ratelimit.log` to see the hits and window.
- For local development, temporarily raise `RL_STORE_MAX` and `RL_RETRIEVE_MAX` in the config block.

### SQLite "database is locked" errors under load

- The script enables WAL mode and sets `busy_timeout = 3000`. If you still see lock errors, consider moving to PostgreSQL or MySQL for high-traffic deployments.

---

## Development Notes

### Why SQLite?

SQLite is ideal for a single-file demo: zero configuration, no separate service, and adequate performance for moderate traffic. It becomes a bottleneck if:

- You expect more than a few writes per second sustained.
- You need multi-node horizontal scaling.
- You need replication or failover.

For production use beyond a demo, migrate to PostgreSQL or MySQL. The `PDO` abstraction makes this straightforward — the queries are portable except for the `ON CONFLICT ... DO UPDATE` clauses, which you'd replace with each engine's native upsert.

### Why AES-GCM?

AES-GCM provides both confidentiality and integrity (authentication tag). A tampered ciphertext fails decryption. It's the recommended mode for symmetric encryption in modern applications and is directly supported by the Web Crypto API.

### Why SHA-256 for key derivation?

Because the secret is a 32-character alphanumeric string generated by `crypto.getRandomValues`, it already has ~190 bits of entropy. A simple hash is sufficient to produce a uniformly-distributed 256-bit AES key; no password-based KDF (PBKDF2, scrypt, Argon2) is needed. If you ever change the secret source to human-memorable passwords, replace SHA-256 with PBKDF2 or Argon2.

### Why the validation hash?

The hash `SHA-256(secret + encrypted_base64)` serves two purposes:

1. **Server-side secret check without decryption.** The server can verify the caller knows the secret without ever holding the plaintext.
2. **Client-side integrity check.** After retrieval, the client recomputes the hash and compares it with the stored one. A mismatch aborts decryption.

The hash is **not** a substitute for the AES-GCM authentication tag — it's an additional layer that lets the server participate in the trust decision without decrypting.

---

## License

This project is provided as-is, without warranty of any kind. You are free to use, modify, and redistribute it under the terms of the MIT License or any compatible license of your choice.

---

## Footnote

> **⚠️ Demonstration purposes only.**
>
> This project was written as a demonstration of a client-side encryption workflow combined with a server-side one-off retrieval mechanism. While it incorporates several security best practices — client-side AES-GCM encryption, constant-time hash comparison, atomic one-off deletion, rate limiting, security headers, and XSS-safe rendering — **it has not been audited, penetration-tested, or hardened for production use.**
>
> Deploying it in a production environment would require at minimum:
>
> - A formal security review of the cryptographic design and its implementation.
> - Migration from SQLite to a production-grade database with proper backups and replication.
> - Removal of `'unsafe-inline'` from the CSP by externalizing the JavaScript.
> - Robust monitoring, alerting, and log aggregation for rate-limit events and database errors.
> - A business continuity plan for lost secrets, purged records, and disaster recovery.
> - Compliance review if the payloads may contain personal data (GDPR, CCPA, HIPAA, etc.).
>
> **Use this code as a learning reference or a starting point, not as a finished product.**