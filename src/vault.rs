use crate::crypto;
use bitwarden_api_api::models::{CipherDetailsResponseModel, SyncResponseModel};
use bitwarden_crypto::{CryptoError, SymmetricCryptoKey};
use reqwest::StatusCode;
use thiserror::Error;

const MAX_SYNC_BYTES: u64 = 50 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("sync API failed ({status}): {body}")]
    Api { status: StatusCode, body: String },
    #[error("sync response body too large: {0} bytes (max {MAX_SYNC_BYTES})")]
    BodyTooLarge(u64),
    #[error("failed to parse sync response: {0}")]
    Parse(#[from] serde_json::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("cipher has no name")]
    MissingName,
}

/// Fetches vault data from the Bitwarden sync endpoint
///
/// # Errors
/// Returns an error if the HTTP request fails, the server returns a non-success
/// status, or the response body cannot be parsed as a `SyncResponseModel`.
pub async fn fetch_vault(
    api_url: &str,
    access_token: &str,
) -> Result<SyncResponseModel, VaultError> {
    let client = reqwest::Client::new();
    let url = format!("{api_url}/sync");

    tracing::debug!("GET {}", url);

    let response = client
        .get(&url)
        .bearer_auth(access_token)
        .header("Content-Type", "application/json")
        .send()
        .await?;

    let status = response.status();

    tracing::debug!("sync status={}", status);

    if !status.is_success() {
        let body = response.text().await?;
        return Err(VaultError::Api { status, body });
    }

    if let Some(len) = response.content_length()
        && len > MAX_SYNC_BYTES
    {
        return Err(VaultError::BodyTooLarge(len));
    }

    let bytes = response.bytes().await?;
    if bytes.len() as u64 > MAX_SYNC_BYTES {
        return Err(VaultError::BodyTooLarge(bytes.len() as u64));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Decrypted cipher data for display
#[derive(Debug)]
pub struct DecryptedCipher {
    pub id: Option<String>,
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub notes: Option<String>,
    pub totp: Option<String>,
}

/// Returns the per-cipher key if `cipher.key` is set, otherwise None.
/// Callers should fall back to `user_key` when this returns None.
///
/// # Errors
/// Returns an error if the per-cipher key is present but cannot be decrypted.
pub fn cipher_key(
    cipher: &CipherDetailsResponseModel,
    user_key: &SymmetricCryptoKey,
) -> Result<Option<SymmetricCryptoKey>, CryptoError> {
    cipher
        .key
        .as_deref()
        .map(|k| crypto::decrypt_cipher_key(k, user_key))
        .transpose()
}

/// Decrypts a cipher's login fields. Honors the per-cipher key at `cipher.key` if set.
///
/// # Errors
/// Returns an error if the per-cipher key cannot be derived, the cipher has no
/// name, or any field decryption fails.
pub fn decrypt_cipher(
    cipher: &CipherDetailsResponseModel,
    user_key: &SymmetricCryptoKey,
) -> Result<DecryptedCipher, VaultError> {
    let cipher_key = cipher_key(cipher, user_key)?;
    let key = cipher_key.as_ref().unwrap_or(user_key);

    let name = cipher.name.as_ref().ok_or(VaultError::MissingName)?;
    let decrypted_name = crypto::decrypt_string(name, key)?;

    let mut username = None;
    let mut password = None;
    let mut totp = None;

    if let Some(login) = &cipher.login {
        username = crypto::decrypt_optional_string(&login.username, key)?;
        password = crypto::decrypt_optional_string(&login.password, key)?;
        totp = crypto::decrypt_optional_string(&login.totp, key)?;
    }

    let notes = crypto::decrypt_optional_string(&cipher.notes, key)?;

    Ok(DecryptedCipher {
        id: cipher.id.map(|id| id.to_string()),
        name: decrypted_name,
        username,
        password,
        notes,
        totp,
    })
}

/// Searches for ciphers by name (case-insensitive)
#[must_use]
pub fn search_ciphers(
    ciphers: &[CipherDetailsResponseModel],
    query: &str,
    user_key: &SymmetricCryptoKey,
) -> Vec<DecryptedCipher> {
    let query_lower = query.to_lowercase();
    let mut results = Vec::new();

    for cipher in ciphers {
        if let Some(encrypted_name) = &cipher.name
            && let Ok(name) = crypto::decrypt_string(encrypted_name, user_key)
            && name.to_lowercase().contains(&query_lower)
            && let Ok(decrypted) = decrypt_cipher(cipher, user_key)
        {
            results.push(decrypted);
        }
    }

    results
}
