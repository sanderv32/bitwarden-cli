use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, CryptoError, EncString, HashPurpose, Kdf, KeyDecryptable, MasterKey,
    SymmetricCryptoKey,
};
use std::str::FromStr;

/// Derives the master key from a password using KDF parameters
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn derive_master_key(password: &str, email: &str, kdf: &Kdf) -> Result<MasterKey, CryptoError> {
    MasterKey::derive(password, email, kdf)
}

/// Derives the master password hash for authentication
///
/// # Errors
/// Returns an error if master key derivation fails.
pub fn hash_password(password: &str, email: &str, kdf: &Kdf) -> Result<String, CryptoError> {
    let master_key = derive_master_key(password, email, kdf)?;
    let hash =
        master_key.derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization);
    Ok(hash.to_string())
}

/// Decrypts the user key from the encrypted key string using the master key
///
/// # Errors
/// Returns an error if the encrypted key cannot be parsed or decrypted.
pub fn decrypt_user_key(
    encrypted_user_key: &str,
    master_key: &MasterKey,
) -> Result<SymmetricCryptoKey, CryptoError> {
    let enc_string = EncString::from_str(encrypted_user_key)?;
    master_key.decrypt_user_key(enc_string)
}

/// Decrypts an encrypted string using the provided key
///
/// # Errors
/// Returns an error if the encrypted value cannot be parsed or decrypted.
pub fn decrypt_string(encrypted: &str, key: &SymmetricCryptoKey) -> Result<String, CryptoError> {
    let enc_string = EncString::from_str(encrypted)?;
    enc_string.decrypt_with_key(key)
}

/// Decrypts an encrypted per-cipher symmetric key using the user key
///
/// # Errors
/// Returns an error if the encrypted key cannot be parsed, decrypted, or
/// converted into a `SymmetricCryptoKey`.
pub fn decrypt_cipher_key(
    encrypted_key: &str,
    user_key: &SymmetricCryptoKey,
) -> Result<SymmetricCryptoKey, CryptoError> {
    let enc_string = EncString::from_str(encrypted_key)?;
    let bytes: Vec<u8> = enc_string.decrypt_with_key(user_key)?;
    SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(bytes))
        .map_err(|_| CryptoError::InvalidKey)
}

/// Decrypts an optional encrypted string
///
/// # Errors
/// Returns an error if the value is present and decryption fails.
pub fn decrypt_optional_string(
    encrypted: &Option<String>,
    key: &SymmetricCryptoKey,
) -> Result<Option<String>, CryptoError> {
    encrypted
        .as_ref()
        .map(|s| decrypt_string(s, key))
        .transpose()
}
