use anyhow::{Context, Result, anyhow, bail};
use bitwarden_api_api::models::CipherDetailsResponseModel;
use bitwarden_crypto::{Kdf, SymmetricCryptoKey};
use clap::{CommandFactory, Parser};
use std::io::{self, Write, stdin, stdout};
use std::num::NonZero;
use thiserror::Error;
use tracing::info;
use zeroize::Zeroizing;

use lib::{
    args::{Args, Command, DeviceAction},
    auth, crypto,
    session::{self, SessionData},
    two_factor_mapping::TwoFactor,
    vault,
};

#[derive(Debug, Error)]
pub enum InputError {
    #[error("Incorrect input")]
    IncorrectInput(#[from] io::Error),
}

fn input(label: &str) -> Result<String, InputError> {
    let mut s = String::new();
    print!("{label}: ");
    let _ = stdout().flush();
    stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn password(label: &str) -> Result<Zeroizing<String>, InputError> {
    print!("{label}: ");
    let _ = stdout().flush();
    let config = rpassword::ConfigBuilder::new()
        .password_feedback_mask('*')
        .build();

    let password = rpassword::read_password_with_config(config)?;
    Ok(Zeroizing::new(password))
}

/// Full password + 2FA auth flow. Returns a fresh `SessionData` ready to save.
async fn full_auth(
    args: &Args,
    email: &str,
    identity_url: &str,
    device_id: &str,
) -> Result<SessionData> {
    let master_password = password("Master Password")?;
    let otp_token = if args.two_factor == TwoFactor::Authenticator {
        Some(input("2FA Token (OTP)")?)
    } else {
        None
    };

    info!("Getting KDF parameters...");
    let prelogin_response = auth::prelogin(email, identity_url)
        .await
        .context("prelogin")?;

    let iterations =
        u32::try_from(prelogin_response.kdf_iterations).context("KDF iterations out of range")?;
    let kdf = match prelogin_response.kdf {
        0 => Kdf::PBKDF2 {
            iterations: NonZero::new(iterations).context("KDF iterations must be non-zero")?,
        },
        1 => Kdf::Argon2id {
            iterations: NonZero::new(iterations).context("KDF iterations must be non-zero")?,
            memory: NonZero::new(
                u32::try_from(prelogin_response.kdf_memory.unwrap_or(19456))
                    .context("KDF memory out of range")?,
            )
            .context("KDF memory must be non-zero")?,
            parallelism: NonZero::new(
                u32::try_from(prelogin_response.kdf_parallelism.unwrap_or(2))
                    .context("KDF parallelism out of range")?,
            )
            .context("KDF parallelism must be non-zero")?,
        },
        other => bail!("Unsupported KDF type: {other}"),
    };

    let master_key =
        crypto::derive_master_key(&master_password, email, &kdf).context("deriving master key")?;
    let password_hash = Zeroizing::new(
        crypto::hash_password(&master_password, email, &kdf).context("hashing master password")?,
    );

    let two_factor_provider = Some(args.two_factor.to_provider_id());
    let auth_result = auth::authenticate_password(
        email,
        &password_hash,
        otp_token.as_deref(),
        two_factor_provider,
        identity_url,
        device_id,
    )
    .await
    .context("password authentication")?;

    let user_key = crypto::decrypt_user_key(&auth_result.encrypted_user_key, &master_key)
        .context("decrypting user key")?;

    SessionData::from_parts(
        email,
        auth_result.access_token,
        auth_result.refresh_token,
        u64::from(auth_result.expires_in),
        &user_key,
    )
    .context("building session data")
}

/// Resolve to a live (`access_token`, `user_key`) pair, either from a stored session
/// (refreshing the `access_token` if needed) or by prompting for full re-auth.
async fn acquire_session(
    args: &Args,
    email: &str,
    identity_url: &str,
    device_id: &str,
) -> Result<(String, SymmetricCryptoKey)> {
    if let Some(mut stored) = session::load_session(email).context("loading stored session")? {
        if stored
            .is_valid(args.session_timeout)
            .context("checking session validity")?
        {
            if stored
                .access_token_expired()
                .context("checking access token expiry")?
            {
                if let Some(rt) = stored.refresh_token.clone() {
                    match auth::refresh_access_token(&rt, identity_url, device_id).await {
                        Ok(refreshed) => {
                            info!("Access token refreshed");
                            stored.access_token = refreshed.access_token;
                            if refreshed.refresh_token.is_some() {
                                stored.refresh_token = refreshed.refresh_token;
                            }
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .context("reading system clock")?
                                .as_secs();
                            stored.access_token_expires_at = now + u64::from(refreshed.expires_in);
                        }
                        Err(e) => {
                            eprintln!("Session refresh failed ({e}), falling back to full login");
                            let fresh = full_auth(args, email, identity_url, device_id).await?;
                            session::save_session(&fresh).context("saving session")?;
                            let key = fresh.user_key().context("decoding user key")?;
                            return Ok((fresh.access_token, key));
                        }
                    }
                } else {
                    let fresh = full_auth(args, email, identity_url, device_id).await?;
                    session::save_session(&fresh).context("saving session")?;
                    let key = fresh.user_key().context("decoding user key")?;
                    return Ok((fresh.access_token, key));
                }
            }
            let key = stored.user_key().context("decoding stored user key")?;
            stored.touch().context("touching session timestamp")?;
            session::save_session(&stored).context("saving session")?;
            return Ok((stored.access_token, key));
        }
        info!(
            "Stored session expired (idle timeout {}m)",
            args.session_timeout
        );
    }

    let fresh = full_auth(args, email, identity_url, device_id).await?;
    session::save_session(&fresh).context("saving session")?;
    let key = fresh.user_key().context("decoding user key")?;
    Ok((fresh.access_token, key))
}

/// Loads the vault: force-fetch on `Sync`, use a fresh cache when available,
/// otherwise fetch and cache.
async fn resolve_ciphers(
    args: &Args,
    email: &str,
    api_url: &str,
    access_token: &str,
    force_sync: bool,
) -> Result<Vec<CipherDetailsResponseModel>> {
    if !force_sync
        && let Some(cache) = session::load_vault_cache(email).context("loading vault cache")?
        && cache
            .is_fresh(email, args.session_timeout)
            .context("checking vault cache freshness")?
    {
        info!("Using cached vault ({} items)", cache.ciphers.len());
        return Ok(cache.ciphers);
    }

    info!(
        "{}",
        if force_sync {
            "Force-refreshing vault cache..."
        } else {
            "Fetching vault..."
        }
    );
    let sync_data = vault::fetch_vault(api_url, access_token)
        .await
        .context("fetching vault")?;
    let ciphers = sync_data.ciphers.unwrap_or_default();
    session::save_vault_cache(email, &ciphers).context("saving vault cache")?;
    Ok(ciphers)
}

/// Returns `(id, decrypted_name)` for a cipher, or `None` if the name is
/// missing or any step of decryption fails. Used by `list` and `search`, which
/// silently skip such items.
fn cipher_id_name(
    cipher: &CipherDetailsResponseModel,
    user_key: &SymmetricCryptoKey,
) -> Option<(String, String)> {
    let enc_name = cipher.name.as_ref()?;
    let per_cipher_key = vault::cipher_key(cipher, user_key).ok()?;
    let key = per_cipher_key.as_ref().unwrap_or(user_key);
    let name = crypto::decrypt_string(enc_name, key).ok()?;
    let id = cipher.id.map_or_else(|| "-".to_string(), |u| u.to_string());
    Some((id, name))
}

fn run_get(
    ciphers: &[CipherDetailsResponseModel],
    user_key: &SymmetricCryptoKey,
    query: &str,
) -> Result<()> {
    let (id_str, field) = query
        .split_once('/')
        .ok_or_else(|| anyhow!("Query must be <id>/<field>"))?;
    let target_id: uuid::Uuid = id_str
        .parse()
        .with_context(|| format!("Invalid item id: {id_str}"))?;

    let cipher = ciphers
        .iter()
        .find(|c| c.id == Some(target_id))
        .ok_or_else(|| anyhow!("No item with id {target_id}"))?;

    let decrypted = vault::decrypt_cipher(cipher, user_key)
        .with_context(|| format!("decrypting item {target_id}"))?;
    let value = match field {
        "username" => decrypted.username,
        "password" => decrypted.password,
        "totp" => decrypted.totp,
        "notes" => decrypted.notes,
        "name" => Some(decrypted.name),
        other => bail!("Unknown field: {other}"),
    };
    if let Some(v) = value {
        println!("{v}");
    } else {
        eprintln!("Field '{field}' is empty on this item");
        std::process::exit(1);
    }
    Ok(())
}

fn run_list(personal: &[&CipherDetailsResponseModel], user_key: &SymmetricCryptoKey) {
    for cipher in personal {
        if let Some((id, name)) = cipher_id_name(cipher, user_key) {
            println!("{id}  {name}");
        }
    }
}

fn run_search(
    personal: &[&CipherDetailsResponseModel],
    user_key: &SymmetricCryptoKey,
    query: &str,
) {
    let q = query.to_lowercase();
    let mut found = 0;
    for cipher in personal {
        if let Some((id, name)) = cipher_id_name(cipher, user_key)
            && name.to_lowercase().contains(&q)
        {
            println!("{id}  {name}");
            found += 1;
        }
    }
    if found == 0 {
        eprintln!("No matches for '{query}'");
        std::process::exit(1);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let mut cmd = Args::command();
    let args = Args::parse();

    let Some(command) = args.command.as_ref() else {
        cmd.print_help().context("printing help")?;
        return Ok(());
    };

    let email = args.email.trim().to_lowercase();

    if let Command::Device { action } = command {
        match action {
            DeviceAction::Rotate => {
                let new_id = session::rotate_device_id().context("rotating device id")?;
                println!("Device id rotated: {new_id}");
            }
        }
        return Ok(());
    }

    if matches!(command, Command::Logout) {
        if let Some(stored) = session::load_session(&email).context("loading stored session")?
            && let Some(rt) = stored.refresh_token.as_deref()
            && let Err(e) = auth::revoke_refresh_token(rt, &args.identity_url).await
        {
            eprintln!("Warning: server-side revocation failed: {e}");
        }
        session::clear_session(&email).context("clearing session")?;
        session::clear_vault_cache(&email).context("clearing vault cache")?;
        println!("Session cleared for {email}");
        return Ok(());
    }

    let device_id = session::load_or_create_device_id().context("loading device id")?;
    let (access_token, user_key) =
        acquire_session(&args, &email, &args.identity_url, &device_id).await?;

    if matches!(command, Command::Login) {
        println!("Logged in as {email}");
        return Ok(());
    }

    let force_sync = matches!(command, Command::Sync);
    let ciphers = resolve_ciphers(&args, &email, &args.api_url, &access_token, force_sync).await?;
    let personal: Vec<_> = ciphers
        .iter()
        .filter(|c| c.organization_id.is_none())
        .collect();

    match command {
        Command::Get { query } => run_get(&ciphers, &user_key, query)?,
        Command::List => run_list(&personal, &user_key),
        Command::Search { query } => run_search(&personal, &user_key, query),
        Command::Sync => println!("Vault cache refreshed ({} items)", ciphers.len()),
        Command::Login | Command::Logout | Command::Device { .. } => bail!("handled earlier"),
    }

    Ok(())
}
