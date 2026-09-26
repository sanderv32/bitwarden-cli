use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("{context} failed ({status}): {body}")]
    Api {
        context: &'static str,
        status: StatusCode,
        body: String,
    },
    #[error("failed to parse {context} response: {source}\nbody: {body}")]
    Parse {
        context: &'static str,
        #[source]
        source: serde_json::Error,
        body: String,
    },
    #[error("authentication error: {0}")]
    AuthFailed(String),
    #[error("server did not return encryption key")]
    MissingKey,
}

/// Prelogin request body
#[derive(Debug, Serialize)]
struct PreloginRequest {
    email: String,
}

/// Prelogin response from /identity/accounts/prelogin/password
#[derive(Debug, Deserialize)]
pub struct PreloginResponse {
    pub kdf: i32,
    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: i32,
    #[serde(rename = "kdfMemory")]
    pub kdf_memory: Option<i32>,
    #[serde(rename = "kdfParallelism")]
    pub kdf_parallelism: Option<i32>,
}

/// Calls the prelogin endpoint to get KDF parameters
///
/// # Errors
/// Returns an error if the HTTP request fails, the server returns a non-success
/// status, or the response body cannot be parsed as a `PreloginResponse`.
pub async fn prelogin(email: &str, identity_url: &str) -> Result<PreloginResponse, AuthError> {
    let client = reqwest::Client::new();
    let url = format!("{identity_url}/accounts/prelogin/password");

    let request_body = PreloginRequest {
        email: email.to_string(),
    };

    tracing::debug!("POST {}", url);

    let response = client
        .post(&url)
        .json(&request_body)
        .header("Content-Type", "application/json")
        .send()
        .await?;

    let status = response.status();
    let response_text = response.text().await?;

    tracing::debug!("prelogin status={}", status);

    if !status.is_success() {
        return Err(AuthError::Api {
            context: "prelogin",
            status,
            body: response_text,
        });
    }

    serde_json::from_str(&response_text).map_err(|source| AuthError::Parse {
        context: "prelogin",
        source,
        body: response_text,
    })
}

/// Public key encryption key pair
#[derive(Debug, Deserialize)]
pub struct PublicKeyEncryptionKeyPair {
    #[serde(rename = "wrappedPrivateKey")]
    pub wrapped_private_key: Option<String>,
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    #[serde(rename = "Object")]
    pub object: Option<String>,
}

/// Account keys containing encryption key pairs
#[derive(Debug, Deserialize)]
pub struct AccountKeys {
    #[serde(rename = "publicKeyEncryptionKeyPair")]
    pub public_key_encryption_key_pair: Option<PublicKeyEncryptionKeyPair>,
    #[serde(rename = "Object")]
    pub object: Option<String>,
}

/// Master password policy settings
#[derive(Debug, Deserialize)]
pub struct MasterPasswordPolicy {
    #[serde(rename = "Object")]
    pub object: Option<String>,
}

/// KDF configuration
#[derive(Debug, Deserialize)]
pub struct KdfConfig {
    #[serde(rename = "KdfType")]
    pub kdf_type: Option<i32>,
    #[serde(rename = "Iterations")]
    pub iterations: Option<i32>,
}

/// Master password unlock options
#[derive(Debug, Deserialize)]
pub struct MasterPasswordUnlock {
    #[serde(rename = "Kdf")]
    pub kdf: Option<KdfConfig>,
    #[serde(rename = "MasterKeyEncryptedUserKey")]
    pub master_key_encrypted_user_key: Option<String>,
    #[serde(rename = "Salt")]
    pub salt: Option<String>,
}

/// User decryption options
#[derive(Debug, Deserialize)]
pub struct UserDecryptionOptions {
    #[serde(rename = "HasMasterPassword")]
    pub has_master_password: Option<bool>,
    #[serde(rename = "MasterPasswordUnlock")]
    pub master_password_unlock: Option<MasterPasswordUnlock>,
    #[serde(rename = "Object")]
    pub object: Option<String>,
}

/// Authentication response from Bitwarden identity endpoint
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum IdentityResponse {
    Success {
        access_token: String,
        expires_in: u32,
        token_type: String,
        refresh_token: Option<String>,
        scope: Option<String>,
        #[serde(rename = "Key")]
        key: Option<String>,
        #[serde(rename = "PrivateKey")]
        private_key: Option<String>,
        #[serde(rename = "AccountKeys")]
        account_keys: Option<Box<AccountKeys>>,
        #[serde(rename = "MasterPasswordPolicy")]
        master_password_policy: Option<MasterPasswordPolicy>,
        #[serde(rename = "UserDecryptionOptions")]
        user_decryption_options: Option<Box<UserDecryptionOptions>>,
        #[serde(rename = "Kdf")]
        kdf: Option<i32>,
        #[serde(rename = "KdfIterations")]
        kdf_iterations: Option<i32>,
        #[serde(rename = "KdfMemory")]
        kdf_memory: Option<i32>,
        #[serde(rename = "KdfParallelism")]
        kdf_parallelism: Option<i32>,
        #[serde(rename = "ResetMasterPassword")]
        reset_master_password: Option<bool>,
        #[serde(rename = "ForcePasswordReset")]
        force_password_reset: Option<bool>,
    },
    Error {
        error: String,
        error_description: String,
        #[serde(rename = "TwoFactorProviders")]
        two_factor_providers: Option<Vec<i32>>,
    },
}

/// Complete authentication result with tokens and keys
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u32,
    pub encrypted_user_key: String,
    pub encrypted_private_key: Option<String>,
}

/// Result of refreshing an access token via the `refresh_token` grant.
#[derive(Debug, Clone)]
pub struct RefreshResult {
    pub access_token: String,
    /// Bitwarden rotates the refresh token; the new one (if returned) should replace the stored one.
    pub refresh_token: Option<String>,
    pub expires_in: u32,
}

/// Authenticates with Bitwarden and returns tokens + encrypted keys
///
/// # Errors
/// Returns an error if the HTTP request fails, the server returns a non-success
/// status, the response cannot be parsed, the server reports an authentication
/// error, or the server response does not include an encryption key.
pub async fn authenticate_password(
    email: &str,
    password_hash: &str,
    two_factor_token: Option<&str>,
    two_factor_provider: Option<i32>,
    identity_url: &str,
    device_identifier: &str,
) -> Result<AuthResult, AuthError> {
    let client = reqwest::Client::new();

    let mut form = vec![
        ("grant_type", "password"),
        ("username", email),
        ("password", password_hash),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("deviceType", "10"),
        ("deviceIdentifier", device_identifier),
        ("deviceName", "firefox"),
    ];

    let token_str;
    let provider_str;
    let remember_str;

    if let Some(token) = two_factor_token {
        token_str = token.to_string();
        provider_str = two_factor_provider.unwrap_or(0).to_string();
        remember_str = "0".to_string();

        form.push(("twoFactorToken", &token_str));
        form.push(("twoFactorProvider", &provider_str));
        form.push(("twoFactorRemember", &remember_str));
    }

    let url = format!("{identity_url}/connect/token");

    tracing::debug!("POST {} (grant=password)", url);

    let response = client
        .post(&url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
        )
        .header("Accept", "application/json")
        .header("Accept-Language", "en-US,en;q=0.5")
        .header("Origin", "https://vault.bitwarden.com")
        .header("Referer", "https://vault.bitwarden.com/")
        .header("Device-Type", "10")
        .header("Bitwarden-Client-Name", "web")
        .header("Bitwarden-Client-Version", "2025.1.0")
        .form(&form)
        .send()
        .await?;

    let status = response.status();
    let response_text = response.text().await?;

    tracing::debug!("authentication status={}", status);

    if !status.is_success() {
        return Err(AuthError::Api {
            context: "authentication",
            status,
            body: response_text,
        });
    }

    let identity: IdentityResponse =
        serde_json::from_str(&response_text).map_err(|source| AuthError::Parse {
            context: "authentication",
            source,
            body: response_text,
        })?;

    match identity {
        IdentityResponse::Success {
            access_token,
            refresh_token,
            expires_in,
            key,
            private_key,
            ..
        } => {
            let encrypted_user_key = key.ok_or(AuthError::MissingKey)?;

            Ok(AuthResult {
                access_token,
                refresh_token,
                expires_in,
                encrypted_user_key,
                encrypted_private_key: private_key,
            })
        }
        IdentityResponse::Error {
            error_description, ..
        } => Err(AuthError::AuthFailed(error_description)),
    }
}

/// Refreshes an access token using the `refresh_token` grant. Does not require
/// the master password or 2FA.
///
/// # Errors
/// Returns an error if the HTTP request fails, the server returns a non-success
/// status, or the response body cannot be parsed.
pub async fn refresh_access_token(
    refresh_token: &str,
    identity_url: &str,
    device_identifier: &str,
) -> Result<RefreshResult, AuthError> {
    #[derive(Deserialize)]
    struct RefreshBody {
        access_token: String,
        expires_in: u32,
        refresh_token: Option<String>,
    }

    let client = reqwest::Client::new();
    let url = format!("{identity_url}/connect/token");

    let form = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", "web"),
        ("deviceIdentifier", device_identifier),
    ];

    tracing::debug!("POST {} (grant=refresh_token)", url);

    let response = client
        .post(&url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
        )
        .header("Accept", "application/json")
        .header("Origin", "https://vault.bitwarden.com")
        .header("Referer", "https://vault.bitwarden.com/")
        .header("Device-Type", "10")
        .header("Bitwarden-Client-Name", "web")
        .header("Bitwarden-Client-Version", "2025.1.0")
        .form(&form)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(AuthError::Api {
            context: "refresh",
            status,
            body,
        });
    }

    let parsed: RefreshBody = serde_json::from_str(&body).map_err(|source| AuthError::Parse {
        context: "refresh",
        source,
        body,
    })?;

    Ok(RefreshResult {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_in: parsed.expires_in,
    })
}

/// Revokes a refresh token on the identity server (`/connect/revocation`).
///
/// # Errors
/// Returns an error if the HTTP request fails or the server returns a non-success status.
pub async fn revoke_refresh_token(
    refresh_token: &str,
    identity_url: &str,
) -> Result<(), AuthError> {
    let client = reqwest::Client::new();
    let url = format!("{identity_url}/connect/revocation");

    let form = [
        ("client_id", "web"),
        ("token", refresh_token),
        ("token_type_hint", "refresh_token"),
    ];

    tracing::debug!("POST {}", url);

    let response = client
        .post(&url)
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await?;
        return Err(AuthError::Api {
            context: "revocation",
            status,
            body,
        });
    }

    tracing::debug!("revocation status={}", status);
    Ok(())
}
