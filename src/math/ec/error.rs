use core::fmt;

/// The failures of the elliptic curve operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ECError {
    /// An encoded point or scalar has the wrong length, a value not below its
    /// modulus, or a malformed prefix or sign.
    InvalidEncoding,
    /// The coordinates do not satisfy the equation of the curve, or a
    /// compressed coordinate has no square root.
    NotOnCurve,
    /// The point is not in the subgroup of prime order.
    NotInSubgroup,
    /// The point is the identity where it is not allowed (a public key).
    Identity,
}

impl fmt::Display for ECError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            ECError::InvalidEncoding => "the encoding is invalid",
            ECError::NotOnCurve => "the point is not on the curve",
            ECError::NotInSubgroup => "the point is not in the subgroup of prime order",
            ECError::Identity => "the point is the identity",
        })
    }
}

impl core::error::Error for ECError {}
