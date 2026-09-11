# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust CLI application that authenticates with Bitwarden/Vaultwarden servers and accesses vault items. The application uses a hybrid approach: leveraging the official Bitwarden Rust SDK (v2.0.0) for cryptography and making direct API calls for authentication and vault access.

**Why manual API calls?** The Bitwarden Rust SDK v2.0.0 has a bug in the authentication flow that causes a panic when the API returns a refresh token (which it always does). By bypassing the SDK's authentication and directly calling the Bitwarden REST API, we work around this limitation while still using the SDK's excellent cryptography primitives.

## Development Commands

### Building
```bash
cargo build          # Debug build
cargo build --release # Release build
```

### Running
```bash
# With no subcommand, `bw` just prints help.
cargo run -- --help

# Explicit login: prompts for master password + OTP, caches session in the OS keychain.
cargo run -- --email user@example.com login

# Subsequent commands reuse the cached session (auto-refreshing access tokens as needed).
cargo run -- --email user@example.com list
cargo run -- --email user@example.com search github
cargo run -- --email user@example.com get <uuid>/password
cargo run -- --email user@example.com sync    # force-refresh the vault cache
cargo run -- --email user@example.com logout  # clear session + vault cache

# Email can also come from BW_USERNAME.
export BW_USERNAME=user@example.com
cargo run -- login
```

Any command that needs the vault will silently trigger a full login prompt if
no session is cached — running `bw login` first just makes that step explicit.

### Testing
```bash
cargo test           # Run all tests
cargo test test_name # Run specific test
```

### Linting and Formatting
```bash
cargo clippy         # Run linter
cargo fmt            # Format code
cargo fmt -- --check # Check formatting without modifying
```

## Architecture

### Module Structure

- **main.rs**: Application entry point.
  - Dispatches subcommands (`login`, `list`, `search`, `get`, `sync`, `logout`)
  - Interactive input helpers (`input()` — trims whitespace, `password()` — hidden input)
  - `acquire_session()` handles the "reuse cached session, refresh access token, or full login" logic
  - Uses `anyhow::Result` at the top level; adds `.context()` at each fallible boundary

- **lib.rs**: Module declarations.

- **args.rs**: CLI argument parsing using `clap`.
  - `Args` struct with `email`, `two_factor` (defaults to `authenticator`), `api_url`, `identity_url`, `session_timeout`
  - `Command` subcommand enum: `Login`, `List`, `Search`, `Get`, `Sync`, `Logout`
  - Supports environment variable `BW_USERNAME` for email
  - Default URLs point to production Bitwarden servers

- **two_factor_mapping.rs**: `TwoFactor` enum implementing `clap::ValueEnum`.
  - `to_provider_id()` returns the integer ID expected by the Bitwarden API

- **auth.rs**: Authentication via direct API calls. Returns `Result<_, AuthError>`.
  - `prelogin()`: fetches KDF parameters from `/accounts/prelogin/password`
  - `authenticate_password()`: password + 2FA auth against `/connect/token`
  - `refresh_access_token()`: uses the stored refresh token to renew an expired access token
  - `AuthError` variants: `Http`, `Api { context, status, body }`, `Parse { context, source, body }`, `AuthFailed`, `MissingKey`

- **crypto.rs**: Cryptographic operations using `bitwarden-crypto`. Returns `Result<_, CryptoError>`.
  - `derive_master_key()`, `hash_password()`
  - `decrypt_user_key()`, `decrypt_cipher_key()`
  - `decrypt_string()`, `decrypt_optional_string()`

- **vault.rs**: Vault operations via direct API calls. Returns `Result<_, VaultError>`.
  - `fetch_vault()`: pulls the encrypted vault from `/sync`
  - `cipher_key()`, `decrypt_cipher()`: honour per-cipher keys when set, fall back to the user key
  - `VaultError` wraps `reqwest::Error`, an `Api { status, body }` variant, and `CryptoError`

- **session.rs**: Persistent session + vault caching. Returns `Result<_, SessionError>`.
  - `load_session` / `save_session` / `clear_session`: session tokens + base64-encoded user key stored in the OS keychain via the `keyring` crate
  - `load_vault_cache` / `save_vault_cache` / `clear_vault_cache`: encrypted vault cached at `~/.config/bw-rs/vault_cache.json` (mode 0600)
  - `load_or_create_device_id`: persistent per-install device UUID at `~/.config/bw-rs/device_id`
  - `SessionData::is_valid` (idle timeout) and `access_token_expired` (30s safety margin) drive the refresh logic in `acquire_session`
  - `SessionError` variants: `HomeNotSet`, `InvalidKey`, plus `#[from]` wrappers for `io::Error`, `keyring::Error`, `serde_json::Error`, `base64::DecodeError`

### Error Handling

- **Libraries** (`auth.rs`, `vault.rs`, `session.rs`) define per-module error enums with `thiserror`. Each enum uses `#[from]` for common transitive errors and adds domain-specific variants (`AuthError::MissingKey`, `VaultError::MissingName`, `SessionError::HomeNotSet`, etc.) so callers can match on the error kind.
- **The application layer** (`main.rs`) uses `anyhow::Result` and adds `.context(...)` / `bail!` / `anyhow!` at boundaries — thiserror errors bubble up naturally via `?`.
- **Clippy lints in `Cargo.toml`** deny `unwrap_used` and `panic`, warn on `expect_used`, and deny the `pedantic` group. Prefer `?` + `.context(...)` over `unwrap()` / `expect()` / `unreachable!()`.

### Key Dependencies

- **bitwarden** (v2.0.0): Official SDK — currently only pulled in for its `secrets` feature; not used on the auth/sync path
- **bitwarden-crypto** (v2.0.0): Cryptographic primitives for key derivation and decryption
- **bitwarden-api-api** (v2.0.0): Type definitions for API response models (`SyncResponseModel`, `CipherDetailsResponseModel`)
- **clap** (v4.6.1): CLI argument parsing with `derive` and `env` features
- **tokio** (v1.52.3): Async runtime with full feature set
- **tracing/tracing-subscriber**: Structured logging controlled by `RUST_LOG`
- **reqwest** (v0.12): HTTP client for direct API calls with `rustls-tls`
- **keyring** (v3): OS-native credential storage for the cached session
- **base64** (v0.23): Base64-encodes the user key for keychain storage
- **thiserror** (v2): Per-module typed error enums in `auth.rs`, `vault.rs`, `session.rs`
- **anyhow** (v1): Top-level error type in `main.rs`
- **uuid** (v1.23.1): UUIDs for the persistent device identifier
- **rpassword** (v7.5): Hidden master-password input
- **serde/serde_json** (v1.0): JSON serialization

### Command Dispatch

`main.rs` runs this flow:

1. Parse CLI arguments.
2. If no subcommand → print help and exit. No session, no vault fetch.
3. If `logout` → clear the keychain entry and the on-disk vault cache. Exit.
4. Otherwise call `acquire_session()` (details below).
5. If `login` → session is cached; print confirmation and exit.
6. If `sync` → force a fresh vault fetch, save to cache, print item count.
7. Otherwise (`list`, `search`, `get`) → use the cached vault if fresh, else fetch and cache. Then run the command.

### Session Lifecycle (`acquire_session`)

1. `session::load_session(email)` reads the OS keychain.
2. If a session exists and `is_valid(session_timeout)` (idle timeout in minutes):
   - If `access_token_expired()`, try `auth::refresh_access_token(refresh_token, …)`.
   - On refresh failure, or if there's no refresh token, fall through to a full login.
   - Otherwise touch `last_used_at`, resave, and return.
3. Otherwise (no session or expired) run `full_auth()`.

### `full_auth` (fresh login)

1. Prompt for master password (`rpassword`, hidden) and OTP token if 2FA is set.
2. `auth::prelogin()` → KDF parameters.
3. `crypto::derive_master_key()` + `crypto::hash_password()`.
4. `auth::authenticate_password()` → `POST /identity/connect/token`. Returns access token, refresh token, encrypted user key.
5. `crypto::decrypt_user_key()` unwraps the user key using the master key.
6. Return `SessionData` (persisted by the caller via `session::save_session`).

### Hybrid Approach: SDK + Direct API

This application uses a hybrid architecture:

**Using the SDK:**
- KDF parameter retrieval (`prelogin`)
- Cryptographic operations (key derivation, decryption) via `bitwarden-crypto`
- Type definitions for API models via `bitwarden-api-api`

**Using direct API calls:**
- Authentication (`POST /identity/connect/token`)
- Vault synchronization (`GET /api/sync`)

**Why?** The SDK's authentication flow has a bug (panics on refresh token in response), but its cryptography is solid. By calling the REST API directly for auth/sync and using the SDK for crypto, we get the best of both worlds.

### Current Limitations

- Only the personal vault is exposed; org-owned ciphers are filtered out of `list` / `search` / `get`.
- No vault write operations (read-only).
- No 2FA methods beyond authenticator are actually wired through the interactive prompt (the CLI accepts `--two-factor <method>` but only `authenticator` triggers the OTP prompt).

### Background: SDK Authentication Bug (Worked Around)

**SDK Bug - Panic after successful authentication (v2.0.0)**

The Bitwarden Rust SDK v2.0.0 has a bug in `bitwarden-core/src/auth/login/password.rs` at line 149:
```
thread 'main' panicked at bitwarden-core-2.0.0/src/auth/login/password.rs:149:17:
internal error: entered unreachable code: Got a `refresh_token` answer to a login request
```

**Root cause**: The Bitwarden API returns an `IdentityTokenResponse::Refreshed` variant during password login with 2FA, but the SDK has an `unreachable!()` macro for this case because developers assumed it would never happen. However, the API always returns both `access_token` and `refresh_token` immediately upon successful authentication.

**Our solution**: We bypass the SDK's `PasswordLoginRequest` entirely and make direct HTTP calls to `/identity/connect/token`. This gives us full control over response handling while still using the SDK's excellent cryptographic primitives for key derivation and decryption.

**Upstream fix needed**: This bug should be reported at https://github.com/bitwarden/sdk/issues
