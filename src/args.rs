use crate::two_factor_mapping::TwoFactor;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long, env = "BW_USERNAME")]
    pub email: String,

    /// Only provide if your account has 2FA enabled
    #[arg(long, value_enum, default_value_t=TwoFactor::Authenticator)]
    pub two_factor: TwoFactor,

    #[arg(long, default_value = "https://api.bitwarden.com")]
    pub api_url: String,

    #[arg(long, default_value = "https://identity.bitwarden.com")]
    pub identity_url: String,

    /// Idle session timeout in minutes. Session expires after this many minutes of inactivity.
    #[arg(long, default_value_t = 15)]
    pub session_timeout: u64,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Authenticate and cache a session in the OS keychain.
    Login,
    /// List all vault items as "<id>  <name>" (one per line).
    List,
    /// Search vault items by name (case-insensitive substring). Prints "<id>  <name>" per match.
    Search { query: String },
    /// Get a field from a vault item. Format: <id>/<field>.
    /// Fields: username, password, totp, notes, name.
    Get { query: String },
    /// Clear the stored session from the OS keychain.
    Logout,
    /// Force-refresh the local vault cache from the server.
    Sync,
    /// Manage this install's persistent device identifier.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
}

#[derive(Subcommand)]
pub enum DeviceAction {
    /// Rotate the persistent device identifier. Existing sessions remain valid
    /// but future auth requests will present a new device UUID to the server.
    Rotate,
}
