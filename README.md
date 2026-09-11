# bw — Rust Bitwarden CLI

A drop-in replacement for the [official Bitwarden CLI][official-cli] (which is
written in TypeScript and shipped as a Node.js app). This is a small,
single-binary Rust rewrite covering the read-side subcommands most day-to-day
workflows need: `login`, `list`, `search`, `get`, `sync`, `logout`.

It authenticates against Bitwarden/Vaultwarden and reads vault items, using
`bitwarden-crypto` for the cryptography and talking directly to the REST API
for authentication and vault sync (the Rust SDK's password login panics on the
`refresh_token` response — see [SDK bug](#background-sdk-bug)).

Not (yet) a full replacement: no vault writes, no attachment handling, no
organization/collection management. If you need those, use the official CLI.

[official-cli]: https://github.com/bitwarden/clients/tree/main/apps/cli

## Install

```bash
cargo build --release
# binary lands in target/release/bw
```

## Usage

```bash
bw --email you@example.com <subcommand>
# or
export BW_USERNAME=you@example.com
bw <subcommand>
```

Running `bw` with no subcommand prints help. Nothing happens until you invoke
one of:

| Subcommand | What it does |
| --- | --- |
| `login`  | Prompts for master password (+ OTP) and caches the session in the OS keychain. |
| `list`   | Prints `<uuid>  <name>` for every personal vault item. |
| `search <query>` | Case-insensitive substring match on decrypted item names. |
| `get <uuid>/<field>` | Prints a single field. Fields: `username`, `password`, `totp`, `notes`, `name`. |
| `sync`   | Force-refresh the on-disk vault cache. |
| `logout` | Clears the cached session and vault cache. |

Any subcommand that needs the vault will fall back to a full login prompt if
no valid session is cached — `bw login` just makes that step explicit.

### Options

- `--two-factor <method>` — one of `authenticator` (default), `email`, `duo`, `yubikey`, `u2f`, `remember`, `organization-duo`, `web-authn`. Only `authenticator` currently triggers the OTP prompt.
- `--api-url` / `--identity-url` — override the Bitwarden endpoints (defaults are the production servers).
- `--session-timeout <minutes>` — idle timeout for the cached session (default 15).

### Where state lives

- **Session** (access token, refresh token, encrypted user key): OS keychain via the `keyring` crate, service `bw-rs`.
- **Encrypted vault cache**: `~/.config/bw-rs/vault_cache.json` (mode 0600).
- **Device UUID**: `~/.config/bw-rs/device_id`.

`bw logout` clears the first two.

## Development

See [CLAUDE.md](CLAUDE.md) for module layout, error-handling architecture, and
the login-flow details.

```bash
cargo build
cargo clippy --all-targets -- -D warnings
cargo fmt
```

The `Cargo.toml` clippy config denies `unwrap_used`, `panic`, and the
`pedantic` group; use `?` with `anyhow::Context` (in `main.rs`) or a per-module
`thiserror` enum (in the library modules) instead.

## <a id="background-sdk-bug"></a>Background: SDK Bug (Worked Around)

The Bitwarden Rust SDK v2.0.0 panics after a successful password login because
the API always returns an `IdentityTokenResponse::Refreshed` variant that the
SDK marks `unreachable!()` at `bitwarden-core/src/auth/login/password.rs:149`.

This CLI bypasses the SDK's `PasswordLoginRequest` and calls
`/identity/connect/token` directly (see `src/auth.rs`), while still using
`bitwarden-crypto` for key derivation and decryption.

Upstream: <https://github.com/bitwarden/sdk/issues>
