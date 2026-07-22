# Architecture

## 1. Source files

| File | Responsibility |
|---|---|
| `crypto.rs` | Crypto Core — all cryptographic operations |
| `format.rs` | Format + Storage — serialization, parsing, atomic write | 
|`cli.rs` | CLI + Vault Service — REPL, session state, orchestration |
| `main.rs` | Entry point |

## 2. Module responsibilities

### crypto.rs (Crypto Core)
Handles all cryptographic operations. Has no I/O — never reads
or writes files, never interacts with the user.

Public API:
- `initcryptofirst(password)` — generates salt, DEK, wrapped_dek,
  header_mac_key. Called during `init`, before Format builds
  the canonical header.
- `initcryptosecond(dek, header_mac_key, canonical_header, body)`
  — computes header_mac and encrypts body. Called during `init`
  and `changepass`/`upgrade-kdf`, after Format builds the canonical
  header.
- `opencrypto(...)` — full open pipeline: derives keys, verifies
  header_mac using constant-time comparison, unwraps DEK,
  decrypts body.
- `savecrypto(dek, canonical_header, header_mac, body)` — 
  re-encrypts body with a fresh nonce. Called after any modification
  to records (add, edit, rm, attach, import).
- `changecryptofirst(old_password, new_password, ...)` — verifies
  old password, unwraps DEK, derives new keys, produces new
  wrapped_dek. Called during `changepass`.
  - `upgradekdf(password, ...)` — identical to changecryptofirst
  but old_password == new_password. Strengthens Argon2id parameters
  without changing the password.
- `verifycrypto(password, ...)` — verifies password and header
  integrity without decrypting body or opening a session.
  Called during `verify --with-password`.

### format.rs (Format + Storage)
- Parses and serializes the binary vault header
- Serializes and deserializes vault body using CBOR
- Builds canonical_header (bytes 0..99) from header fields
- Atomic file write (write-temp + fsync + rename)
- `verify_structure` — checks magic bytes, version, field lengths
  without a password

### cli.rs (CLI + Vault Service)
- Argument and REPL command parsing (clap)
- `Session` struct — holds open session state:
  DEK, canonical_header, header_mac, decrypted records in memory
- `Session::save` — orchestrates body re-encryption and atomic write
- `parse_file` — extracts header fields from raw file bytes
- `apply_rekey` — orchestrates changepass and upgrade-kdf pipeline
- Interactive password input without echo (rpassword)
- Clipboard handling (clip.exe, F-18)

### main.rs (Entry point)
- Initializes the application and calls `cli::run()`

## 3. Module boundaries

| Module | Never does |
|---|---|
| `crypto.rs` | No I/O, never sees raw file bytes, never parses header |
| `format.rs` | Never performs cryptographic operations |
| `cli.rs`| Never implements cryptographic primitives |
  
