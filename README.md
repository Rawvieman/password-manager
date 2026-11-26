# Password Manager

Zero-knowledge vault: the server stores only ciphertext and OPAQUE records, the browser extension holds the only key. This README is the project specification: Sections 1–9 define the protocol, Sections 10–12 define the implementation. Keep them in sync.

Shares its authentication and key-wrapping design with sahi-chap. Where this spec says "same as sahi-chap" the construction is identical apart from the `pm/` label strings.

**Scope for v1:** registration, unlock, lock, vault items (logins only), sync across devices, autofill on click, password generator, master-password change, mnemonic recovery. Out of scope: offline unlock, sharing between users, organisations, TOTP, attachments, non-Chrome browsers, mobile.

---

## 1. Goals and threat model

### Goals

1. The server cannot read any vault item, ever. Not with the database, not with the OPAQUE server keys, not with both plus unlimited compute against a strong master password.
2. A stolen database reveals no passwords, no vault keys, and nothing that permits an offline guess at the master password.
3. Autofill only ever offers credentials for the exact origin the page is on.
4. Master password can change without re-encrypting the vault.
5. Vault is recoverable from a 24-word mnemonic alone.
6. Two devices editing the same vault never silently lose a write.

### Threats defended against

- Database compromise, including OPAQUE records and all ciphertext.
- Malicious or compromised server operator.
- Stolen session token (yields ciphertext only).
- Phishing pages that imitate a login form on a look-alike origin.
- Page scripts attempting to read what the extension injects.

### Threats NOT defended against

- Compromised browser, OS, or another extension with debugging privileges. No vault survives a keylogger.
- Full server compromise plus a weak master password. OPAQUE removes the offline attack from stolen data, but an attacker holding the OPRF key and `wrapped_vk` can run Argon2id guesses. Security then equals password strength under Argon2id, the same floor as every password manager.
- Browser memory forensics while unlocked.

---

## 2. Primitives

Same as sahi-chap: OPAQUE (RFC 9807, ristretto255-SHA512, Argon2id KSF), HKDF-SHA256, XChaCha20-Poly1305, SHA-256, BIP39 24 words, Ed25519 (recovery proof only). RFC 8785 canonical JSON is not needed; nothing is signed except a nonce.

All HKDF `info` strings and AEAD associated data are prefixed with `pm/` and versioned.

---

## 3. Key material

### Per user

| Name | Where | Description |
|---|---|---|
| `vk` | client only, `chrome.storage.session` while unlocked | 32 random bytes. The vault key. Encrypts every item directly. |
| `mnemonic` | shown once at registration | `BIP39.encode(vk)`. The recovery credential. |
| `rsk`, `rpk` | derived from `vk` | Ed25519 keypair, `seed = HKDF(vk, info = "pm/recovery-key/v1")`. `rpk` stored on server. Proves possession of `vk` during recovery without revealing it. |
| `ek_pw` | client only, during unlock | OPAQUE export_key from the master password. Stable until the password changes. |
| `KEK` | client only, transient | `HKDF(ikm = ek_pw, salt = "", info = "pm/vk-wrap/v1", L = 32)` |
| `wrapped_vk` | server | `nonce(24) ‖ AEAD(KEK, nonce, vk, ad = "pm/vk/v1" ‖ user_id)` |

No PIN. sahi-chap needs a per-operation PIN because each signature is a legal act; a vault unlock is one act per session, so the master password alone gates it. A device-local quick-unlock PIN is reserved for v2.

### Per item

```
item_plain   = { name, username, password, urls: [origin, ...], notes, updated_at }   (JSON)
item_blob    = nonce(24) ‖ AEAD(vk, nonce, item_plain, ad = "pm/item/v1" ‖ user_id ‖ item_id)
```

Items are encrypted individually, not as one vault blob, so sync and conflicts are per item.

### Per server

OPAQUE server setup (OPRF seed, AKE keys) in KMS, separate from the database. Nothing else; the server signs nothing.

### Server-stored user record

```
user_id
opaque_record
rpk
wrapped_vk
created_at
```

Items table: `item_id, user_id, version, blob, deleted, server_seq`. `server_seq` is a per-user monotonic counter bumped on every write; it is the sync cursor.

---

## 4. Flows

All cryptography runs in the client. The server receives OPAQUE messages, ciphertexts, `rpk`, and signatures.

### 4.1 Registration

1. Client generates `vk`, derives `rpk`, displays mnemonic. User confirms backup by re-entering 3 random words.
2. OPAQUE registration with master password → server stores `opaque_record`; client holds `ek_pw`.
3. Client computes `KEK`, `wrapped_vk`. Sends `rpk`, `wrapped_vk`. Server stores in one transaction.
4. Client is now unlocked (Section 4.2 step 4).

### 4.2 Unlock

1. OPAQUE login with master password → `ek_pw`. Server issues a bearer session token.
2. Client fetches `wrapped_vk`, computes `KEK`, unwraps `vk`. Zeros `ek_pw`, `KEK`.
3. Lockout: server counts OPAQUE KE1 initiations per user (not failures, which the server cannot see): 10 in 15 min → 15 min lock, 20 → 1 h. Returns generic failure.
4. `vk` and the session token go into `chrome.storage.session` (memory-only, cleared on browser exit, `accessLevel: TRUSTED_CONTEXTS`). Client runs an initial sync.

Unlock requires the server. Offline unlock would need a device-local Argon2id cache of `vk`, which is an offline-attackable blob; deferred to v2 as an explicit opt-in.

### 4.3 Lock

Clear `chrome.storage.session`. Triggered by: user action, `chrome.alarms` idle timer (default 15 min, configurable), browser exit (automatic). Locked state holds only the ciphertext cache in `chrome.storage.local`.

### 4.4 Sync

Server is the source of truth for ciphertext; it never merges.

- **Pull:** `GET /items?since=<server_seq>` returns every item with a higher `server_seq`, tombstones included. Client decrypts, replaces local copies, stores the new cursor.
- **Push:** `PUT /items/{item_id}` with `{ version, blob }`. Server accepts only if `version == stored.version + 1` (or `version == 1` for a new id), stores, bumps `server_seq`. Otherwise `409` with the current `{ version, blob }`.
- **Conflict:** on `409` the client decrypts both, keeps the one with the later `updated_at`, re-encrypts with `version = current + 1`, retries once. The losing version is kept locally as a "previous value" the user can restore. No write is silently dropped.
- **Delete:** `PUT` with `deleted: true` and an empty blob. Tombstones are kept for 90 days.

Pull before every push. Pull on unlock, on `chrome.alarms` every 5 min while unlocked, and after every local write.

### 4.5 Autofill

1. Content script on every page detects login forms (`input[type=password]` plus its nearest username field). It injects nothing until the user clicks the extension's icon in the field or the toolbar.
2. Content script sends `{ origin }` to the service worker. `origin` is `scheme://host:port`, exact.
3. Service worker, if unlocked, returns `{ item_id, name, username }` for items whose `urls` contain that exact origin. Never the password.
4. User picks an entry in the extension UI. Only then does the service worker send the password to the content script, which fills the two fields and dispatches `input` events.

Exact-origin matching is the phishing defence. Subdomain and eTLD+1 matching are v2, opt-in per item.

### 4.6 Password generator

`crypto.getRandomValues` with rejection sampling over the chosen alphabet. Default 20 characters, all classes. Runs in the popup; nothing to specify.

### 4.7 Master password change

1. Unlocked, so `vk` is in session storage.
2. OPAQUE registration with the new password → `ek_pw_new`. Compute `KEK_new`, re-wrap `vk`.
3. Send new `opaque_record` and `wrapped_vk`; server replaces both atomically and invalidates all other sessions.

Items untouched: `vk` did not change.

### 4.8 Recovery (master password forgotten)

1. User enters mnemonic → `vk` → `rsk`, `rpk`.
2. Server issues `recovery_nonce`. Client returns `Ed25519.sign(rsk, "pm/recovery/v1" ‖ recovery_nonce ‖ user_id)`. Server verifies against stored `rpk` (`verify_strict`).
3. OPAQUE registration with new password → `ek_pw`. Re-wrap `vk`.
4. Server replaces `opaque_record` and `wrapped_vk`, invalidates all sessions, logs a recovery event.

Vault unchanged. Rate limit: 5 recovery attempts per user per hour.

### 4.9 Vault key rotation (mnemonic leaked)

Unlocked only. Client generates `vk_new`, shows the new mnemonic, re-encrypts every item under `vk_new` with `version + 1`, re-wraps under the current `KEK`, derives `rpk_new`. Pushes items first, then `{ wrapped_vk, rpk }` last, so an interrupted rotation leaves the old key fully valid. Vaults are small (hundreds of items); this is a loop, not a protocol.

---

## 5. Extension architecture (Chrome MV3)

| Context | Holds | Does |
|---|---|---|
| Popup / options page | `ek_pw`, `KEK` transiently | OPAQUE client, Argon2id (WASM), unwrap, UI. Runs the whole unlock so a service-worker kill mid-Argon2 cannot happen. Hands `vk` to session storage, then zeros everything. |
| Service worker | nothing in variables | Reads `vk` from `chrome.storage.session` on each request. Sync, item encrypt/decrypt, autofill matching, lock alarm. May be killed and restarted at any time; all state is in storage. |
| Content script | nothing | Form detection, fill on instruction. Isolated world; no access to `vk`. |
| `chrome.storage.session` | `vk`, session token, cursor | Memory-only. Cleared on lock and on browser exit. |
| `chrome.storage.local` | item ciphertext cache, settings | Survives restart; useless without `vk`. |

Message passing between contexts uses `chrome.runtime.sendMessage`. The service worker validates `sender.id` equals the extension's own id on every message, and the autofill reply path validates `sender.tab` and `sender.origin`.

Permissions: `storage`, `alarms`, `activeTab`, `scripting`; `host_permissions` for the API origin only. Content script registered for `<all_urls>` but inert until clicked.

---

## 6. Message authentication

| Where | Mechanism |
|---|---|
| Session requests | Bearer token over TLS |
| `wrapped_vk`, item blobs | AEAD tag with `user_id` (and `item_id`) as associated data |
| Recovery | Ed25519 over a server nonce |
| Sync ordering | Server-side `version` check, `server_seq` cursor |

---

## 7. Operational requirements

- OPAQUE server setup in KMS, backed up like a CA key: losing it makes every `wrapped_vk` undecryptable and forces every user through mnemonic recovery.
- KE1 counters incremented atomically.
- All OPAQUE failures identical in timing and message.
- Item blobs capped at 64 KiB; vault capped at 10,000 items per user.
- Tombstone purge after 90 days.

---

## 8. Reserved for later versions

- Offline unlock via device-local Argon2id cache (opt-in).
- Device-local quick-unlock PIN.
- Subdomain / eTLD+1 URL matching.
- TOTP, secure notes, cards, attachments.
- Sharing via per-item keys wrapped to recipients' public keys.
- Firefox (MV3 differences in `storage.session`), mobile.
- WebAuthn PRF as an alternative to the master password.

---

## 9. Why these choices

- **Items encrypted individually under `vk`:** per-item sync and conflicts; a one-blob vault makes every concurrent edit a whole-vault conflict.
- **`vk` directly as the item key, no per-item keys:** per-item keys only pay off for sharing, which is v2. Rotation is a loop over a small vault.
- **OPAQUE, so no salted hash and no client-side KDF of the vault key from the password:** the server holds nothing offline-attackable, unlike the standard "PBKDF2 the master password, store the verifier" design.
- **Recovery keypair derived from `vk`:** proves possession of the mnemonic without transmitting it, and costs nothing extra to store.
- **Version check on the server, merge on the client:** the server cannot merge ciphertext, and a version check is the smallest thing that guarantees no lost write.
- **Unlock in the popup, not the service worker:** MV3 service workers are killed after 30 s idle; Argon2id at memory-constrained settings takes about 1 s in WASM, which is fine, but a kill mid-OPAQUE leaves half-state. The popup lives as long as the user looks at it.
- **No offline unlock in v1:** every offline design stores something Argon2id-attackable on the device. Making that an explicit opt-in later is better than shipping it silently.

---

## 10. Technology stack

| Layer | Choice |
|---|---|
| Server | Rust, Axum, Tokio, `sqlx` + PostgreSQL |
| Extension | Vite + `@crxjs/vite-plugin` + React + TypeScript, Manifest V3 |
| Client SDK | TypeScript package, shared by the extension and any future web client |

### Cryptography libraries

Rust: `opaque-ke` 4.0 (pinned to the version `@serenity-kit/opaque` is built from), `ed25519-dalek` (recovery verify), `argon2`, `zeroize`, `thiserror`, `tracing`.

TypeScript: `@serenity-kit/opaque` 1.1.0, `@noble/ed25519`, `@noble/ciphers`, `@noble/hashes`, `@scure/bip39`.

### Cross-language constraints

1. **OPAQUE suite must match exactly.** Proven in sahi-chap: ristretto255, `TripleDh<Ristretto255, Sha512>`, base64url-no-pad, server `Ksf = Identity`, client picks Argon2id `memory-constrained`. Copy the spike as the first integration test.
2. **The server never decrypts anything.** Rust code treats `wrapped_vk` and item blobs as opaque bytes. No shared canonical encoding, no test vectors needed: the only cross-language check beyond OPAQUE is the recovery signature.

### Client code rule

All key material lives in `packages/sdk` with the surface `register`, `unlock`, `changePassword`, `recover`, `rotateVaultKey`, `encryptItem`, `decryptItem`. React components and the service worker call these and never touch `ek_pw`, `KEK`, or raw `vk` bytes outside a `withVaultKey(fn)` scope that zeros afterwards.

---

## 11. Repository layout

```
password-manager/
  Cargo.toml              cargo workspace
  package.json            pnpm workspace root
  pnpm-workspace.yaml     packages: apps/*, packages/*
  justfile                dev, test, migrate
  crates/
    pm-server/        Axum + sqlx: OPAQUE, sessions, lockout, items, recovery
  apps/
    extension/            Vite + CRXJS: popup, service worker, content script
  packages/
    sdk/                  TS: OPAQUE client, vk/mnemonic, wrap, item crypto, recovery keypair
  migrations/             sqlx migrations
  docker-compose.yml      postgres for local dev
  README.md               this file
```

### CI

1. `cargo test --workspace`
2. `pnpm test`
3. Postgres + `pm-server`, then: OPAQUE round trip, register → unlock → put item → pull from a second session → conflict → recover.

Job 3 is the gate.

---

## 12. Build order

0. Copy the OPAQUE spike from sahi-chap (server binary + TS driver). Passes on day one.
1. `packages/sdk` crypto: `vk`, mnemonic, wrap/unwrap, `encryptItem`/`decryptItem`, recovery keypair. Unit tests with fixed keys.
2. `pm-server`: OPAQUE register/unlock, KE1 lockout, bearer sessions, `wrapped_vk` + `rpk` storage. Spike becomes the integration test.
3. Items endpoints with `version` and `server_seq`. Integration test for the conflict path.
4. `apps/extension`: popup with register/unlock/lock, vault list, add/edit/delete, generator, sync.
5. Content script + autofill.
6. Password change, recovery, vault key rotation.
