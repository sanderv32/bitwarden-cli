use clap::ValueEnum;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum TwoFactor {
    Authenticator,
    Email,
    Duo,
    Yubikey,
    U2F,
    Remember,
    OrganizationDuo,
    WebAuthn,
}

impl TwoFactor {
    /// Converts to the integer value used by Bitwarden API
    #[must_use]
    pub fn to_provider_id(self) -> i32 {
        match self {
            TwoFactor::Authenticator => 0,
            TwoFactor::Email => 1,
            TwoFactor::Duo => 2,
            TwoFactor::Yubikey => 3,
            TwoFactor::U2F => 4,
            TwoFactor::Remember => 5,
            TwoFactor::OrganizationDuo => 6,
            TwoFactor::WebAuthn => 7,
        }
    }
}
