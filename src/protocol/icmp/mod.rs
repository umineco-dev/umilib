//! The Internet Control Message Protocol: what both versions share — the
//! multi-part extensions of error messages (RFC 4884), the rate limit of
//! the errors a node originates and the error type — and each version in
//! [`v4`] (RFC 792) and [`v6`] (RFC 4443, with Neighbor Discovery of
//! RFC 4861).

mod error;
mod extension;
mod rate_limiter;

pub use error::ICMPError;
pub use extension::{ICMPExtensionObject, ICMPExtensionObjects, ICMPExtensions};
pub use rate_limiter::{ICMPRateLimitConfig, ICMPRateLimiter};

#[cfg(umilib_feature = "protocol-icmp-v4")]
pub mod v4;
#[cfg(umilib_feature = "protocol-icmp-v6")]
pub mod v6;
