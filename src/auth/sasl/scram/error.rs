use core::fmt;

use crate::codec::stringprep::StringPrepError;

/// The errors a SCRAM server reports in its final message (the
/// `server-error-value` of RFC 5802 §7). A received value this module does
/// not know is `OtherError`, as RFC 5802 §7 asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SCRAMServerError {
    InvalidEncoding,
    ExtensionsNotSupported,
    InvalidProof,
    ChannelBindingsDontMatch,
    ServerDoesSupportChannelBinding,
    ChannelBindingNotSupported,
    UnsupportedChannelBindingType,
    UnknownUser,
    InvalidUsernameEncoding,
    NoResources,
    OtherError,
}

impl SCRAMServerError {
    pub const ALL: [SCRAMServerError; 11] = [
        SCRAMServerError::InvalidEncoding,
        SCRAMServerError::ExtensionsNotSupported,
        SCRAMServerError::InvalidProof,
        SCRAMServerError::ChannelBindingsDontMatch,
        SCRAMServerError::ServerDoesSupportChannelBinding,
        SCRAMServerError::ChannelBindingNotSupported,
        SCRAMServerError::UnsupportedChannelBindingType,
        SCRAMServerError::UnknownUser,
        SCRAMServerError::InvalidUsernameEncoding,
        SCRAMServerError::NoResources,
        SCRAMServerError::OtherError,
    ];

    /// The value of `e=`.
    pub const fn name(self) -> &'static str {
        match self {
            SCRAMServerError::InvalidEncoding => "invalid-encoding",
            SCRAMServerError::ExtensionsNotSupported => "extensions-not-supported",
            SCRAMServerError::InvalidProof => "invalid-proof",
            SCRAMServerError::ChannelBindingsDontMatch => "channel-bindings-dont-match",
            SCRAMServerError::ServerDoesSupportChannelBinding => "server-does-support-channel-binding",
            SCRAMServerError::ChannelBindingNotSupported => "channel-binding-not-supported",
            SCRAMServerError::UnsupportedChannelBindingType => "unsupported-channel-binding-type",
            SCRAMServerError::UnknownUser => "unknown-user",
            SCRAMServerError::InvalidUsernameEncoding => "invalid-username-encoding",
            SCRAMServerError::NoResources => "no-resources",
            SCRAMServerError::OtherError => "other-error",
        }
    }

    /// The error of the value `name`; `OtherError` for an unknown one.
    pub fn from_name(name: &str) -> SCRAMServerError {
        SCRAMServerError::ALL.into_iter().find(|error| error.name() == name).unwrap_or(SCRAMServerError::OtherError)
    }
}

/// Why a SCRAM exchange fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SCRAMError {
    /// The verdict of the server: what a server reports to the client (in
    /// a server-final-message with `e=`), and what a client receives.
    Server(SCRAMServerError),
    /// A message of the server the client cannot read.
    Format,
    /// A mandatory extension (`m=`) in a message of the server (RFC 5802 §5.1).
    Extension,
    /// The nonce of the server does not extend the nonce of the client.
    Nonce,
    /// An iteration count outside the configuration.
    Iterations,
    /// The server does not prove that it knows the key (ServerSignature).
    ServerSignature,
    /// A salted password cached for another salt or iteration count.
    Salt,
    /// The username or the password is refused by SASLprep.
    Prepare(StringPrepError),
    /// The random source failed.
    Random,
    /// A step called out of order, or after the exchange ended.
    State,
}

impl From<StringPrepError> for SCRAMError {
    fn from(error: StringPrepError) -> SCRAMError {
        SCRAMError::Prepare(error)
    }
}

impl fmt::Display for SCRAMError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SCRAMError::Server(error) => write!(formatter, "SCRAM server error: {}", error.name()),
            SCRAMError::Format => formatter.write_str("malformed SCRAM message"),
            SCRAMError::Extension => formatter.write_str("unsupported mandatory SCRAM extension"),
            SCRAMError::Nonce => formatter.write_str("the server nonce does not extend the client nonce"),
            SCRAMError::Iterations => formatter.write_str("iteration count outside the configuration"),
            SCRAMError::ServerSignature => formatter.write_str("the server signature does not verify"),
            SCRAMError::Salt => formatter.write_str("the cached salted password is for another salt"),
            SCRAMError::Prepare(error) => write!(formatter, "{error}"),
            SCRAMError::Random => formatter.write_str("the random source failed"),
            SCRAMError::State => formatter.write_str("SCRAM step out of order"),
        }
    }
}

impl core::error::Error for SCRAMError {}
