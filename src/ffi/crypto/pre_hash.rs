use crate::crypto::PreHash;

/// An operation with a [`PreHash`] function chosen at run time.
pub trait PreHashCall {
    type Output;

    fn call<H: PreHash>(self) -> Self::Output;
}

/// The pre-hash functions of HashML-DSA and HashSLH-DSA, by the C type names
/// of their hash types; `None` for a name that is unknown.
pub struct PreHashRegistry;

impl PreHashRegistry {
    pub fn hash<V: PreHashCall>(name: &str, call: V) -> Option<V::Output> {
        use crate::hash::sha::v2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
        use crate::hash::sha::v3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};
        Some(match name {
            "umilib_hash_sha_v2_SHA224" => call.call::<SHA224>(),
            "umilib_hash_sha_v2_SHA256" => call.call::<SHA256>(),
            "umilib_hash_sha_v2_SHA384" => call.call::<SHA384>(),
            "umilib_hash_sha_v2_SHA512" => call.call::<SHA512>(),
            "umilib_hash_sha_v2_SHA512_224" => call.call::<SHA512_224>(),
            "umilib_hash_sha_v2_SHA512_256" => call.call::<SHA512_256>(),
            "umilib_hash_sha_v3_SHA3_224" => call.call::<SHA3_224>(),
            "umilib_hash_sha_v3_SHA3_256" => call.call::<SHA3_256>(),
            "umilib_hash_sha_v3_SHA3_384" => call.call::<SHA3_384>(),
            "umilib_hash_sha_v3_SHA3_512" => call.call::<SHA3_512>(),
            "umilib_hash_sha_v3_SHAKE128" => call.call::<SHAKE128>(),
            "umilib_hash_sha_v3_SHAKE256" => call.call::<SHAKE256>(),
            _ => return None,
        })
    }
}
