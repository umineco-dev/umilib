use crate::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
use crate::hash::sha::v3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};
use crate::hash::{Digest, ExtendableOutput, XOFReader};

/// A hash function that pre-hashes the messages of HashML-DSA (FIPS 204
/// section 5.4) and HashSLH-DSA (FIPS 205 section 10.2): the DER encoding
/// of its object identifier and its digest, which for an XOF has the
/// length the standards fix (256 bits for SHAKE128, 512 for SHAKE256).
pub trait PreHash {
    /// The DER encoding of the object identifier, tag and length included.
    const OID: &'static [u8];
    /// The bytes of the digest.
    const OUTPUT_SIZE: usize;

    /// Writes the digest of `message` into `out` of [`PreHash::OUTPUT_SIZE`] bytes.
    fn pre_hash(message: &[u8], out: &mut [u8]);
}

/// Implements [`PreHash`] for hash functions of fixed output with the OID 2.16.840.1.101.3.4.2.`$arc`.
macro_rules! digest_pre_hash {
    ($($type:ty, $arc:literal, $size:literal;)*) => {
        $(
            impl PreHash for $type {
                const OID: &'static [u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, $arc];
                const OUTPUT_SIZE: usize = $size;

                fn pre_hash(message: &[u8], out: &mut [u8]) {
                    out.copy_from_slice(<$type>::digest(message).as_ref());
                }
            }
        )*
    };
}

digest_pre_hash! {
    SHA256, 0x01, 32;
    SHA384, 0x02, 48;
    SHA512, 0x03, 64;
    SHA224, 0x04, 28;
    SHA512_224, 0x05, 28;
    SHA512_256, 0x06, 32;
    SHA3_224, 0x07, 28;
    SHA3_256, 0x08, 32;
    SHA3_384, 0x09, 48;
    SHA3_512, 0x0A, 64;
}

/// Implements [`PreHash`] for an XOF with the OID 2.16.840.1.101.3.4.2.`$arc` and an output of `$size` bytes.
macro_rules! xof_pre_hash {
    ($($type:ty, $arc:literal, $size:literal;)*) => {
        $(
            impl PreHash for $type {
                const OID: &'static [u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, $arc];
                const OUTPUT_SIZE: usize = $size;

                fn pre_hash(message: &[u8], out: &mut [u8]) {
                    let mut function = <$type>::default();
                    function.update(message);
                    function.finalize_xof().read(out);
                }
            }
        )*
    };
}

xof_pre_hash! {
    SHAKE128, 0x0B, 32;
    SHAKE256, 0x0C, 64;
}
