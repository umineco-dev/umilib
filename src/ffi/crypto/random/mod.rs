//! The C ABI of [`crate::crypto::random`].
//!
//! [`HMACDRBG<H>`](crate::crypto::random::HMACDRBG) and
//! [`HashDRBG<H>`](crate::crypto::random::HashDRBG) are exported as one type
//! each for every hash function of
//! [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms), chosen by the C
//! type name of the hash type, and [`CTRDRBG<C>`](crate::crypto::random::CTRDRBG)
//! as one type for every 128-bit block cipher of
//! [`ffi_block_ciphers!`](crate::ffi_block_ciphers), chosen by the C type
//! name of the cipher type. The [`Random`](crate::crypto::random::Random) interface is the `_fill`
//! function of each generator.

use crate::crypto::random::{DRBGConfig, RandomError};
use crate::ffi::{Definition, Function, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The statuses of [`RandomError`], one per variant.
pub struct RandomStatus;

impl RandomStatus {
    pub const ENTROPY_LENGTH: Status =
        Status::new(c"crypto.random", c"EntropyLength", c"the entropy input is shorter than the security strength");
    pub const REQUEST_LENGTH: Status =
        Status::new(c"crypto.random", c"RequestLength", c"the request exceeds the maximum request size");
    pub const RESEED_REQUIRED: Status =
        Status::new(c"crypto.random", c"ReseedRequired", c"the generator must be reseeded");
    pub const NONCE_LENGTH: Status = Status::new(
        c"crypto.random",
        c"NonceLength",
        c"the nonce with the entropy input is shorter than 3/2 of the security strength",
    );
    pub const INPUT_LENGTH: Status =
        Status::new(c"crypto.random", c"InputLength", c"an input is longer than 2^35 bits");
    pub const ENTROPY_SOURCE: Status = Status::new(c"crypto.random", c"EntropySource", c"the source of entropy failed");
    pub const UNINSTANTIATED: Status =
        Status::new(c"crypto.random", c"Uninstantiated", c"the generator was uninstantiated");
}

impl ToStatus for RandomError {
    fn to_status(&self) -> &'static Status {
        match self {
            RandomError::EntropyLength { .. } => &RandomStatus::ENTROPY_LENGTH,
            RandomError::RequestLength { .. } => &RandomStatus::REQUEST_LENGTH,
            RandomError::ReseedRequired => &RandomStatus::RESEED_REQUIRED,
            RandomError::NonceLength { .. } => &RandomStatus::NONCE_LENGTH,
            RandomError::InputLength { .. } => &RandomStatus::INPUT_LENGTH,
            RandomError::EntropySource => &RandomStatus::ENTROPY_SOURCE,
            RandomError::Uninstantiated => &RandomStatus::UNINSTANTIATED,
        }
    }
}

impl Value for DRBGConfig {
    const TYPE: Type = Type::Named("umilib_crypto_random_DRBGConfig");
}

/// Defines `$state` as `$generator<P>` for any primitive `P` (a hash
/// function or a block cipher) of a registry.
macro_rules! drbg_state {
    ($state:ident, $generator:ident; $($feature:literal $variant:ident => $type:path, $name:literal;)*) => {
        /// A generator over any primitive of its registry.
        #[derive(Debug)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum $state {
            $(
                #[cfg(umilib_feature = $feature)]
                $variant(crate::crypto::random::$generator<$type>),
            )*
        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl $state {
            /// Instantiates the generator over the primitive whose C type is named `primitive`;
            /// `None` if it is unknown or not enabled.
            pub fn with_config(
                primitive: &str,
                config: DRBGConfig,
                entropy: &[u8],
                nonce: &[u8],
                personalization: &[u8],
            ) -> Option<Result<$state, RandomError>> {
                match primitive {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(
                            <crate::crypto::random::$generator<$type> as crate::crypto::random::DRBG>::instantiate(config, entropy, nonce, personalization)
                                .map($state::$variant),
                        ),
                    )*
                    _ => None,
                }
            }

            pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), RandomError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $state::$variant(ref mut state) => crate::crypto::random::DRBG::reseed(state, entropy, additional),
                    )*
                }
            }

            pub fn generate(&mut self, out: &mut [u8], additional: &[u8]) -> Result<(), RandomError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $state::$variant(ref mut state) => crate::crypto::random::DRBG::generate(state, out, additional),
                    )*
                }
            }

            pub fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $state::$variant(ref mut state) => crate::crypto::random::Random::fill(state, out),
                    )*
                }
            }

            pub fn uninstantiate(&mut self) {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $state::$variant(ref mut state) => crate::crypto::random::DRBG::uninstantiate(state),
                    )*
                }
            }

            pub fn is_instantiated(&self) -> bool {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $state::$variant(ref state) => crate::crypto::random::DRBG::is_instantiated(state),
                    )*
                }
            }

            pub fn config(&self) -> DRBGConfig {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $state::$variant(ref state) => *crate::crypto::random::DRBG::config(state),
                    )*
                }
            }

            /// The security strength in bits.
            pub fn security_strength(&self) -> usize {
                match *self {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $state::$variant(_) => <crate::crypto::random::$generator<$type> as crate::crypto::random::DRBG>::SECURITY_STRENGTH,
                    )*
                }
            }
        }
    };
}

macro_rules! hmac_drbg_state {
    ($($line:tt)*) => {
        drbg_state!(HMACDRBGState, HMACDRBG; $($line)*);
    };
}

macro_rules! hash_drbg_state {
    ($($line:tt)*) => {
        drbg_state!(HashDRBGState, HashDRBG; $($line)*);
    };
}

macro_rules! ctr_drbg_state {
    ([16] $($feature:literal $variant:ident => $type:path, $name:literal;)* [8] $($rest:tt)*) => {
        drbg_state!(CTRDRBGState, CTRDRBG; $($feature $variant => $type, $name;)*);

        impl CTRDRBGState {
            /// Instantiates CTR_DRBG without the derivation function over the cipher whose C type is
            /// named `cipher`; `None` if it is unknown or not enabled.
            pub fn instantiate_without_derivation(
                cipher: &str,
                config: DRBGConfig,
                entropy: &[u8],
                personalization: &[u8],
            ) -> Option<Result<CTRDRBGState, RandomError>> {
                match cipher {
                    $(
                        #[cfg(umilib_feature = $feature)]
                        $name => Some(
                            crate::crypto::random::CTRDRBG::<$type>::instantiate_without_derivation(config, entropy, personalization)
                                .map(CTRDRBGState::$variant),
                        ),
                    )*
                    _ => {
                        let _ = (config, entropy, personalization);
                        None
                    }
                }
            }
        }
    };
}

crate::ffi_digest_algorithms!(hmac_drbg_state);
crate::ffi_digest_algorithms!(hash_drbg_state);
crate::ffi_block_ciphers!(ctr_drbg_state);

impl Value for HMACDRBGState {
    const TYPE: Type = Type::Named("umilib_crypto_random_HMACDRBG");
}

impl Value for HashDRBGState {
    const TYPE: Type = Type::Named("umilib_crypto_random_HashDRBG");
}

impl Value for CTRDRBGState {
    const TYPE: Type = Type::Named("umilib_crypto_random_CTRDRBG");
}

/// A source of random bytes of the C ABI: a generator handle of this module
/// with the C type name of its type, as the functions that generate keys
/// take it (`random` and `random_type`).
pub enum RandomSource<'a> {
    HMACDRBG(&'a mut HMACDRBGState),
    HashDRBG(&'a mut HashDRBGState),
    CTRDRBG(&'a mut CTRDRBGState),
}

impl<'a> RandomSource<'a> {
    /// The source of the handle `random` of the type whose C name is the
    /// UTF-8 text at `kind`; fails with InvalidArgument for another name.
    ///
    /// # Safety
    ///
    /// `random` must be null or a live handle of the named type, used by
    /// nothing else during the call, and `kind` readable text.
    pub unsafe fn from_handle(
        random: *mut core::ffi::c_void,
        kind: *const u8,
        kind_length: usize,
    ) -> Result<RandomSource<'a>, &'static Status> {
        // SAFETY: the caller passes readable text and a handle of the named type.
        let kind = unsafe { Pointer::text(kind, kind_length) }?;
        match kind {
            "umilib_crypto_random_HMACDRBG" => {
                Ok(RandomSource::HMACDRBG(unsafe { Pointer::reference_mut(random.cast()) }?))
            }
            "umilib_crypto_random_HashDRBG" => {
                Ok(RandomSource::HashDRBG(unsafe { Pointer::reference_mut(random.cast()) }?))
            }
            "umilib_crypto_random_CTRDRBG" => {
                Ok(RandomSource::CTRDRBG(unsafe { Pointer::reference_mut(random.cast()) }?))
            }
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

impl crate::crypto::random::Random for RandomSource<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError> {
        match self {
            RandomSource::HMACDRBG(state) => state.fill(out),
            RandomSource::HashDRBG(state) => state.fill(out),
            RandomSource::CTRDRBG(state) => state.fill(out),
        }
    }
}

/// Exports the functions of a generator `$state` over a `$kind` (a text)
/// named by the parameters `$primitive` and `$primitive_length`.
macro_rules! drbg_functions {
    ($state:ident, $prefix:literal, $primitive:ident, $primitive_length:ident, $kind:literal) => {
        crate::ffi_exports! {
            const FUNCTIONS;
            #[doc = concat!(" Instantiates the generator with the default limits over the ", $kind, " whose C type")]
            #[doc = concat!(" is named by the UTF-8 text at `", stringify!($primitive), "`, with the entropy input, the nonce and the")]
            #[doc = concat!(" personalization string; fails with InvalidArgument if that ", $kind, " is unknown or")]
            /// not enabled, with EntropyLength if the entropy input is shorter than the security
            /// strength, and with NonceLength if the nonce with it is shorter than 3/2 of it.
            pub unsafe extern "C" fn new = concat!($prefix, "_new"); ($primitive: *const u8, $primitive_length: usize, entropy: *const u8, entropy_length: usize, nonce: *const u8, nonce_length: usize, personalization: *const u8, personalization_length: usize, out: *mut *mut $state) -> *const Status {
                // SAFETY: forwarded with the same contract.
                unsafe { with_config($primitive, $primitive_length, &DRBGConfig::default(), entropy, entropy_length, nonce, nonce_length, personalization, personalization_length, out) }
            }

            /// Like `_new` with the limits `config`, clamped to SP 800-90A table 2.
            pub unsafe extern "C" fn with_config = concat!($prefix, "_with_config"); ($primitive: *const u8, $primitive_length: usize, config: *const DRBGConfig, entropy: *const u8, entropy_length: usize, nonce: *const u8, nonce_length: usize, personalization: *const u8, personalization_length: usize, out: *mut *mut $state) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes readable text, a readable structure, readable bytes and a writable pointer.
                    let primitive = unsafe { Pointer::text($primitive, $primitive_length) }?;
                    let config = unsafe { Pointer::reference(config) }?;
                    let entropy = unsafe { Pointer::slice(entropy, entropy_length) }?;
                    let nonce = unsafe { Pointer::slice(nonce, nonce_length) }?;
                    let personalization = unsafe { Pointer::slice(personalization, personalization_length) }?;
                    let state = $state::with_config(primitive, *config, entropy, nonce, personalization)
                        .ok_or(&Status::INVALID_ARGUMENT)?
                        .map_err(|error| error.to_status())?;
                    unsafe { Pointer::write_handle(out, state) }
                })())
            }

            /// Releases the generator, zeroizing it. Does nothing if `state` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (state: *mut $state) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { Pointer::free(state) }
            }

            /// Mixes the fresh entropy input and the optional additional input into the state.
            pub unsafe extern "C" fn reseed = concat!($prefix, "_reseed"); (state: *mut $state, entropy: *const u8, entropy_length: usize, additional: *const u8, additional_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and readable bytes.
                    let state = unsafe { Pointer::reference_mut(state) }?;
                    let entropy = unsafe { Pointer::slice(entropy, entropy_length) }?;
                    let additional = unsafe { Pointer::slice(additional, additional_length) }?;
                    state.reseed(entropy, additional).map_err(|error| error.to_status())
                })())
            }

            /// Fills the `out_length` bytes at `out` with one request, with the optional additional input,
            /// which must not overlap `out`.
            pub unsafe extern "C" fn generate = concat!($prefix, "_generate"); (state: *mut $state, out: *mut u8, out_length: usize, additional: *const u8, additional_length: usize) -> *const Status {
                Status::from_result((|| {
                    Pointer::check_disjoint(additional, additional_length, out, out_length)?;
                    // SAFETY: the caller passes a valid handle, a writable byte range and readable bytes.
                    let state = unsafe { Pointer::reference_mut(state) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    let additional = unsafe { Pointer::slice(additional, additional_length) }?;
                    state.generate(out, additional).map_err(|error| error.to_status())
                })())
            }

            /// Fills the `out_length` bytes at `out`, of any length, with requests of the maximum size.
            pub unsafe extern "C" fn fill = concat!($prefix, "_fill"); (state: *mut $state, out: *mut u8, out_length: usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable byte range.
                    let state = unsafe { Pointer::reference_mut(state) }?;
                    let out = unsafe { Pointer::slice_mut(out, out_length) }?;
                    state.fill(out).map_err(|error| error.to_status())
                })())
            }

            /// Erases the state; every later `_reseed`, `_generate` and `_fill` fails with Uninstantiated.
            pub unsafe extern "C" fn uninstantiate = concat!($prefix, "_uninstantiate"); (state: *mut $state) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    unsafe { Pointer::reference_mut(state) }?.uninstantiate();
                    Ok(())
                })())
            }

            /// Writes whether the generator is instantiated into `out`.
            pub unsafe extern "C" fn is_instantiated = concat!($prefix, "_is_instantiated"); (state: *const $state, out: *mut bool) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { Pointer::reference(state) }?;
                    unsafe { Pointer::write(out, state.is_instantiated()) }
                })())
            }

            /// Writes the limits of the generator into `out`.
            pub unsafe extern "C" fn config = concat!($prefix, "_config"); (state: *const $state, out: *mut DRBGConfig) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable structure.
                    let state = unsafe { Pointer::reference(state) }?;
                    unsafe { Pointer::write(out, state.config()) }
                })())
            }

            /// Writes the security strength in bits into `out`.
            pub unsafe extern "C" fn security_strength = concat!($prefix, "_security_strength"); (state: *const $state, out: *mut usize) -> *const Status {
                Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { Pointer::reference(state) }?;
                    unsafe { Pointer::write(out, state.security_strength()) }
                })())
            }
        }
    };
}

/// [`HMACDRBG`](crate::crypto::random::HMACDRBG).
pub mod hmac_drbg {
    use super::{DRBGConfig, HMACDRBGState, Pointer, Status, ToStatus};

    drbg_functions!(HMACDRBGState, "umilib_crypto_random_hmac_drbg", hash, hash_length, "hash function");
}

/// [`HashDRBG`](crate::crypto::random::HashDRBG).
pub mod hash_drbg {
    use super::{DRBGConfig, HashDRBGState, Pointer, Status, ToStatus};

    drbg_functions!(HashDRBGState, "umilib_crypto_random_hash_drbg", hash, hash_length, "hash function");
}

/// [`CTRDRBG`](crate::crypto::random::CTRDRBG).
pub mod ctr_drbg {
    use super::{CTRDRBGState, DRBGConfig, Pointer, Status, ToStatus};

    drbg_functions!(CTRDRBGState, "umilib_crypto_random_ctr_drbg", cipher, cipher_length, "128-bit block cipher");

    crate::ffi_functions! {
        const DERIVATION;
        /// Instantiates CTR_DRBG without the derivation function (SP 800-90A section 10.2.1.3.1) with
        /// the limits `config` over the 128-bit block cipher whose C type is named by the UTF-8 text at
        /// `cipher`: the entropy input has exactly seedlen bytes (16 and the key length) and the
        /// personalization string at most seedlen.
        pub unsafe extern "C" fn umilib_crypto_random_ctr_drbg_instantiate_without_derivation(cipher: *const u8, cipher_length: usize, config: *const DRBGConfig, entropy: *const u8, entropy_length: usize, personalization: *const u8, personalization_length: usize, out: *mut *mut CTRDRBGState) -> *const Status {
            Status::from_result((|| {
                // SAFETY: the caller passes readable text, a readable structure, readable bytes and a writable pointer.
                let cipher = unsafe { Pointer::text(cipher, cipher_length) }?;
                let config = unsafe { Pointer::reference(config) }?;
                let entropy = unsafe { Pointer::slice(entropy, entropy_length) }?;
                let personalization = unsafe { Pointer::slice(personalization, personalization_length) }?;
                let state = CTRDRBGState::instantiate_without_derivation(cipher, *config, entropy, personalization)
                    .ok_or(&Status::INVALID_ARGUMENT)?
                    .map_err(|error| error.to_status())?;
                unsafe { Pointer::write_handle(out, state) }
            })())
        }
    }

    /// The functions of CTR_DRBG, in declaration order.
    pub const ALL: &[crate::ffi::Function] =
        &crate::ffi::Function::concat::<{ FUNCTIONS.len() + DERIVATION.len() }>(&[FUNCTIONS, DERIVATION]);
}

crate::ffi_functions! {
    const CONFIG;
    /// Returns the limits of SP 800-90A table 2: 2^48 requests between reseeds, 2^16 bytes per request.
    pub unsafe extern "C" fn umilib_crypto_random_drbg_config_default() -> DRBGConfig {
        DRBGConfig::default()
    }

    /// Returns `config` with every limit within SP 800-90A table 2.
    pub unsafe extern "C" fn umilib_crypto_random_drbg_config_clamped(config: DRBGConfig) -> DRBGConfig {
        config.clamped()
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "random",
    definitions: &[
        Definition::Structure {
            name: "umilib_crypto_random_DRBGConfig",
            documentation: " The limits of a deterministic random bit generator.",
            fields: &[
                Parameter { name: "reseed_interval", value: <u64 as Value>::TYPE },
                Parameter { name: "maximum_request", value: <usize as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_crypto_random_HMACDRBG",
            documentation: " HMAC_DRBG (SP 800-90A) over a hash function chosen when it is instantiated.",
        },
        Definition::Opaque {
            name: "umilib_crypto_random_HashDRBG",
            documentation: " Hash_DRBG (SP 800-90A) over a hash function chosen when it is instantiated.",
        },
        Definition::Opaque {
            name: "umilib_crypto_random_CTRDRBG",
            documentation: " CTR_DRBG (SP 800-90A) over a 128-bit block cipher chosen when it is instantiated.",
        },
    ],
    functions: &Function::concat::<
        { CONFIG.len() + hmac_drbg::FUNCTIONS.len() + hash_drbg::FUNCTIONS.len() + ctr_drbg::ALL.len() },
    >(&[CONFIG, hmac_drbg::FUNCTIONS, hash_drbg::FUNCTIONS, ctr_drbg::ALL]),
    modules: &[],
};
