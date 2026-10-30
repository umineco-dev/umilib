use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{ExtensionValue, Time, X509Error};
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Integer, ASN1Time, ObjectIdentifier};

/// Defines an extension whose value is a non-negative INTEGER of any
/// length, kept as its contents octets.
macro_rules! number_extension {
    ($(#[$meta:meta])* $name:ident, $field:ident, $oid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name<'a> {
            /// The contents octets of the INTEGER (big-endian, in the fewest octets).
            pub $field: Cow<'a, [u8]>,
        }

        impl $name<'_> {
            /// RFC 5280 §5.2.3: CRL issuers do not use numbers longer than 20 octets.
            pub const MAXIMUM_LENGTH: usize = 20;

            pub fn from_u64(value: u64) -> $name<'static> {
                let mut content = Vec::new();
                ASN1Integer::encode_unsigned(&value.to_be_bytes(), &mut content);
                $name { $field: Cow::Owned(content) }
            }

            /// The number, if it fits in `u128`.
            pub fn as_u128(&self) -> Result<u128, X509Error> {
                Ok(ASN1Integer::new(&self.$field)?.as_u128()?)
            }

            pub fn into_owned(self) -> $name<'static> {
                $name { $field: Cow::Owned(self.$field.into_owned()) }
            }
        }

        impl<'a> ExtensionValue<'a> for $name<'a> {
            const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static($oid);

            /// Reads the number; numbers longer than 20 octets, which
            /// RFC 5280 asks users to handle, are accepted.
            fn decode(reader: &mut DERReader<'a>) -> Result<$name<'a>, X509Error> {
                let integer = reader.read_integer()?;
                if integer.is_negative() {
                    return Err(X509Error::InvalidExtension);
                }
                Ok($name { $field: Cow::Borrowed(integer.as_bytes()) })
            }

            fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
                let integer = ASN1Integer::new(&self.$field)?;
                if integer.is_negative() {
                    return Err(X509Error::InvalidExtension);
                }
                writer.write_integer(&integer);
                Ok(())
            }
        }
    };
}

number_extension!(
    /// The `CRLNumber` CRL extension (RFC 5280 §5.2.3): the sequence number of the CRL.
    CRLNumber,
    number,
    &[0x55, 0x1D, 20]
);

number_extension!(
    /// The `DeltaCRLIndicator` CRL extension (RFC 5280 §5.2.4): the number
    /// of the complete CRL that a delta CRL updates.
    DeltaCRLIndicator,
    base_crl_number,
    &[0x55, 0x1D, 27]
);

/// The `CRLReason` CRL entry extension (RFC 5280 §5.3.1): why the
/// certificate was revoked. Codes RFC 5280 does not define are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CRLReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}

impl CRLReason {
    pub const ALL: [CRLReason; 10] = [
        CRLReason::Unspecified,
        CRLReason::KeyCompromise,
        CRLReason::CACompromise,
        CRLReason::AffiliationChanged,
        CRLReason::Superseded,
        CRLReason::CessationOfOperation,
        CRLReason::CertificateHold,
        CRLReason::RemoveFromCRL,
        CRLReason::PrivilegeWithdrawn,
        CRLReason::AACompromise,
    ];

    pub fn from_code(code: i128) -> Option<CRLReason> {
        CRLReason::ALL.into_iter().find(|reason| *reason as i128 == code)
    }
}

impl ExtensionValue<'_> for CRLReason {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 21]);

    fn decode(reader: &mut DERReader<'_>) -> Result<CRLReason, X509Error> {
        let code = reader.read_enumerated()?.as_i128().map_err(|_| X509Error::InvalidExtension)?;
        CRLReason::from_code(code).ok_or(X509Error::InvalidExtension)
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        writer.write_enumerated(*self as i128);
        Ok(())
    }
}

/// The `InvalidityDate` CRL entry extension (RFC 5280 §5.3.2): when the
/// key is known or suspected to have been compromised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InvalidityDate {
    pub time: ASN1Time,
}

impl ExtensionValue<'_> for InvalidityDate {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 24]);

    /// Reads a GeneralizedTime without a fraction of a second, as RFC 5280
    /// §5.3.2 requires (§4.1.2.5.2).
    fn decode(reader: &mut DERReader<'_>) -> Result<InvalidityDate, X509Error> {
        Ok(InvalidityDate { time: Time::decode_generalized(reader)? })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        Time::encode_generalized(&self.time, writer)
    }
}

/// The `HoldInstructionCode` CRL entry extension (RFC 3280 §5.3.2, kept
/// in appendix A.2 of RFC 5280): what to do with a held certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HoldInstructionCode<'a> {
    pub instruction: ObjectIdentifier<'a>,
}

/// The hold instructions of ANSI X9.57, under `1.2.840.10040.2`. RFC 5280
/// appendix A.2 writes the arc as `{joint-iso-itu-t(2) member-body(2) ...}`,
/// but `member-body` is an arc of `iso(1)`: the registered identifiers,
/// which implementations use, begin with 1.
impl HoldInstructionCode<'_> {
    /// `id-holdinstruction-none`, deprecated.
    pub const NONE: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x02, 0x01]);
    /// `id-holdinstruction-callissuer`.
    pub const CALL_ISSUER: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x02, 0x02]);
    /// `id-holdinstruction-reject`.
    pub const REJECT: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0xCE, 0x38, 0x02, 0x03]);

    pub fn into_owned(self) -> HoldInstructionCode<'static> {
        HoldInstructionCode { instruction: self.instruction.into_owned() }
    }
}

impl<'a> ExtensionValue<'a> for HoldInstructionCode<'a> {
    const OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x55, 0x1D, 23]);

    fn decode(reader: &mut DERReader<'a>) -> Result<HoldInstructionCode<'a>, X509Error> {
        Ok(HoldInstructionCode { instruction: reader.read_object_identifier()? })
    }

    fn encode(&self, writer: &mut DERWriter) -> Result<(), X509Error> {
        writer.write_object_identifier(&self.instruction);
        Ok(())
    }
}
