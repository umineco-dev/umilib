use core::fmt;

/// An error of DHCP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DHCPError {
    /// Bytes that are not a DHCP message or option.
    Malformed(&'static str),
    /// A message larger than it may be.
    TooLarge,
    /// What the call asks for is not possible now.
    State,
    /// A configuration that cannot work.
    Config,
    /// The source of randomness failed.
    Random,
}

impl fmt::Display for DHCPError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DHCPError::Malformed(reason) => write!(formatter, "a malformed DHCP message: {reason}"),
            DHCPError::TooLarge => formatter.write_str("a DHCP message too large"),
            DHCPError::State => formatter.write_str("not possible in this state"),
            DHCPError::Config => formatter.write_str("a DHCP configuration that cannot work"),
            DHCPError::Random => formatter.write_str("the source of randomness failed"),
        }
    }
}

impl core::error::Error for DHCPError {}
