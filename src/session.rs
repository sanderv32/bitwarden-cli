use base64::Engine;
use bitwarden_api_api::models::CipherDetailsResponseModel;
use bitwarden_crypto::{BitwardenLegacyKeyBytes, SymmetricCryptoKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

const KEYRING_SERVICE: &str = "bw-rs";

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("HOME environment variable not set")]
    HomeNotSet,
    #[error("stored user key is invalid: {0}")]
    InvalidKey(String),
    #[error("system clock error: {0}")]
    Clock(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

fn config_dir() -> Result<PathBuf, SessionError> {
    let home = std::env::var("HOME").map_err(|_| SessionError::HomeNotSet)?;
    let dir = PathBuf::from(home).join(".config").join("bw-rs");
    fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// Writes bytes to `path`, creating it with mode 0600 on Unix and forcing 0600
/// on already-existing files. Non-Unix targets get the default filesystem perms.
fn write_private(path: &Path, contents: &[u8]) -> Result<(), SessionError> {
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    file.write_all(contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn now_unix() -> Result<u64, SessionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| SessionError::Clock(e.to_string()))
}

/// Returns a stable device UUID, creating and persisting one on first use.
///
/// The device id is written to `~/.config/bw-rs/device_id` (mode 0600) and
/// reused across runs. Bitwarden treats this value as an anti-fuzzing signal
/// for 2FA-bypass detection, so it is sensitive: if the file leaks, an
/// attacker can impersonate the same "device." Use [`rotate_device_id`] to
/// generate a fresh one.
///
/// # Errors
/// Returns an error if the config directory cannot be created or the device id
/// file cannot be written.
pub fn load_or_create_device_id() -> Result<String, SessionError> {
    let path = config_dir()?.join("device_id");
    if let Ok(existing) = fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if Uuid::parse_str(trimmed).is_ok() {
            return Ok(trimmed.to_string());
        }
    }
    let new_id = Uuid::new_v4().to_string();
    write_private(&path, new_id.as_bytes())?;
    Ok(new_id)
}

/// Generates a fresh device UUID, overwriting the persisted one. Returns the
/// new id.
///
/// # Errors
/// Returns an error if the config directory cannot be created or the device id
/// file cannot be written.
pub fn rotate_device_id() -> Result<String, SessionError> {
    let path = config_dir()?.join("device_id");
    let new_id = Uuid::new_v4().to_string();
    write_private(&path, new_id.as_bytes())?;
    Ok(new_id)
}

/// Session data persisted in the OS keychain between runs.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionData {
    pub email: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    /// Unix seconds when the `access_token` expires (Bitwarden default: 1h after issue).
    pub access_token_expires_at: u64,
    /// Unix seconds of the last successful use of this session.
    pub last_used_at: u64,
    /// Base64-encoded 64-byte `SymmetricCryptoKey` (the user key).
    pub user_key_b64: String,
}

impl SessionData {
    /// # Errors
    /// Returns an error if the stored key cannot be base64-decoded or converted
    /// into a `SymmetricCryptoKey`.
    pub fn user_key(&self) -> Result<SymmetricCryptoKey, SessionError> {
        let bytes = base64::engine::general_purpose::STANDARD.decode(&self.user_key_b64)?;
        SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(bytes))
            .map_err(|e| SessionError::InvalidKey(e.to_string()))
    }

    /// # Errors
    /// Returns an error if the system clock cannot be read.
    pub fn from_parts(
        email: &str,
        access_token: String,
        refresh_token: Option<String>,
        expires_in_seconds: u64,
        user_key: &SymmetricCryptoKey,
    ) -> Result<Self, SessionError> {
        let bytes = user_key.to_encoded();
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
        let now = now_unix()?;
        Ok(Self {
            email: email.to_string(),
            access_token,
            refresh_token,
            access_token_expires_at: now + expires_in_seconds,
            last_used_at: now,
            user_key_b64: b64,
        })
    }

    /// Idle-timeout check: session is valid if last use was within `timeout_minutes`.
    ///
    /// # Errors
    /// Returns an error if the system clock cannot be read.
    pub fn is_valid(&self, timeout_minutes: u64) -> Result<bool, SessionError> {
        let elapsed = now_unix()?.saturating_sub(self.last_used_at);
        Ok(elapsed < timeout_minutes.saturating_mul(60))
    }

    /// True if the Bitwarden `access_token` has expired (30s safety margin).
    ///
    /// # Errors
    /// Returns an error if the system clock cannot be read.
    pub fn access_token_expired(&self) -> Result<bool, SessionError> {
        Ok(now_unix()? + 30 >= self.access_token_expires_at)
    }

    /// # Errors
    /// Returns an error if the system clock cannot be read.
    pub fn touch(&mut self) -> Result<(), SessionError> {
        self.last_used_at = now_unix()?;
        Ok(())
    }
}

fn entry(email: &str) -> Result<keyring::Entry, SessionError> {
    Ok(keyring::Entry::new(KEYRING_SERVICE, email)?)
}

/// # Errors
/// Returns an error if the keyring cannot be accessed or the stored session
/// JSON cannot be parsed.
pub fn load_session(email: &str) -> Result<Option<SessionData>, SessionError> {
    match entry(email)?.get_password() {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// # Errors
/// Returns an error if the session cannot be serialized or written to the
/// keyring.
pub fn save_session(session: &SessionData) -> Result<(), SessionError> {
    let json = serde_json::to_string(session)?;
    entry(&session.email)?.set_password(&json)?;
    Ok(())
}

/// # Errors
/// Returns an error if the keyring entry cannot be opened or deleted for a
/// reason other than "no entry".
pub fn clear_session(email: &str) -> Result<(), SessionError> {
    match entry(email)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// On-disk cache of the encrypted vault. Cipher fields are still Bitwarden-encrypted;
/// only metadata (IDs, timestamps, item count) is exposed by the cache file.
#[derive(Serialize, Deserialize)]
pub struct VaultCache {
    pub email: String,
    pub cached_at: u64,
    pub ciphers: Vec<CipherDetailsResponseModel>,
}

impl VaultCache {
    /// # Errors
    /// Returns an error if the system clock cannot be read.
    pub fn is_fresh(&self, email: &str, ttl_minutes: u64) -> Result<bool, SessionError> {
        if self.email != email {
            return Ok(false);
        }
        let elapsed = now_unix()?.saturating_sub(self.cached_at);
        Ok(elapsed < ttl_minutes.saturating_mul(60))
    }
}

fn vault_cache_path(email: &str) -> Result<PathBuf, SessionError> {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(email.as_bytes());
    let mut suffix = String::with_capacity(8);
    for byte in &digest[..4] {
        use std::fmt::Write;
        let _ = write!(&mut suffix, "{byte:02x}");
    }
    Ok(config_dir()?.join(format!("vault_cache_{suffix}.json")))
}

/// # Errors
/// Returns an error if the cache path cannot be resolved, the file cannot be
/// read for a reason other than "not found", or the contents cannot be parsed.
pub fn load_vault_cache(email: &str) -> Result<Option<VaultCache>, SessionError> {
    let path = vault_cache_path(email)?;
    match fs::read_to_string(&path) {
        Ok(json) => Ok(Some(serde_json::from_str(&json)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// # Errors
/// Returns an error if the cache cannot be serialized or written to disk.
pub fn save_vault_cache(
    email: &str,
    ciphers: &[CipherDetailsResponseModel],
) -> Result<(), SessionError> {
    let cache = VaultCache {
        email: email.to_string(),
        cached_at: now_unix()?,
        ciphers: ciphers.to_vec(),
    };
    let json = serde_json::to_string(&cache)?;
    write_private(&vault_cache_path(email)?, json.as_bytes())?;
    Ok(())
}

/// # Errors
/// Returns an error if the cache path cannot be resolved or the file cannot be
/// removed for a reason other than "not found".
pub fn clear_vault_cache(email: &str) -> Result<(), SessionError> {
    let path = vault_cache_path(email)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
