/// Defines `$name` as `$wrapper<P>` for every pseudorandom function `P` the C
/// ABI can name: HMAC over each hash function of the registry and CMAC over
/// a block cipher of either size, with the constructor `new(prf, primitive,
/// key, parameter)` and the listed methods delegated to `$wrapper`.
///
/// `prf` is the C type name of the PRF (`umilib_crypto_hmac_HMAC` or
/// `umilib_crypto_cmac_CMAC`) and `primitive` that of its hash function or
/// cipher; `$wrapper::new(prf, parameter)` builds the value. Called as
/// [`ffi_digest_algorithms!`](crate::ffi_digest_algorithms) callback through
/// a local macro that passes `@build $name, $wrapper, $parameter { methods }`
/// and the registry in braces.
#[macro_export]
macro_rules! ffi_prf_enum {
    (@build $name:ident, $wrapper:ident, $parameter:ty {
        $($(#[doc = $method_documentation:literal])* fn $method:ident(&self $(, $argument:ident: $argument_type:ty)*) -> $returns:ty;)*
    } $registry:tt) => {
        $crate::ffi_prf_enum!(@enum $name, $wrapper, $parameter, $registry);

        // The enum is empty when no PRF is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl $name {
            $(
                // `self` is passed along: each expansion has its own hygiene for it.
                $crate::ffi_prf_enum!(@method $name, self, [$(#[doc = $method_documentation])*] $method (&self $(, $argument: $argument_type)*) ($($argument),*) -> $returns, $registry);
            )*
        }
    };
    (@method $name:ident, $this:ident, [$($documentation:tt)*] $method:ident $parameters:tt $arguments:tt -> $returns:ty, {
        $($feature:literal $variant:ident => $type:path, $hash_name:literal;)*
    }) => {
        $($documentation)*
        pub fn $method $parameters -> $returns {
            match *$this {
                $(
                    #[cfg(all(umilib_feature = "crypto-hmac", umilib_feature = $feature))]
                    $name::$variant(ref inner) => inner.$method $arguments,
                )*
                #[cfg(umilib_feature = "crypto-cmac")]
                $name::CMAC128(ref inner) => inner.$method $arguments,
                #[cfg(umilib_feature = "crypto-cmac")]
                $name::CMAC64(ref inner) => inner.$method $arguments,
            }
        }
    };
    (@enum $name:ident, $wrapper:ident, $parameter:ty, {
        $($feature:literal $variant:ident => $type:path, $hash_name:literal;)*
    }) => {
        #[doc = concat!(" [`", stringify!($wrapper), "<P>`] for every pseudorandom function `P` of the C ABI.")]
        #[derive(Clone)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum $name {
            $(
                #[cfg(all(umilib_feature = "crypto-hmac", umilib_feature = $feature))]
                $variant($wrapper<$crate::crypto::hmac::HMAC<$type>>),
            )*
            #[cfg(umilib_feature = "crypto-cmac")]
            CMAC128($wrapper<$crate::crypto::cmac::CMAC<$crate::ffi::crypto::BlockCipher128>>),
            #[cfg(umilib_feature = "crypto-cmac")]
            CMAC64($wrapper<$crate::crypto::cmac::CMAC<$crate::ffi::crypto::BlockCipher64>>),
        }

        // The enum is empty when no PRF is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl $name {
            /// The value over the PRF whose C type is named `prf`, over the hash function or
            /// cipher whose C type is named `primitive`, keyed with `key`; fails with
            /// InvalidArgument if either is unknown or not enabled.
            pub fn new(prf: &str, primitive: &str, key: &[u8], parameter: $parameter) -> Result<$name, &'static $crate::ffi::Status> {
                match prf {
                    #[cfg(umilib_feature = "crypto-hmac")]
                    "umilib_crypto_hmac_HMAC" => match primitive {
                        $(
                            #[cfg(umilib_feature = $feature)]
                            $hash_name => $wrapper::new($crate::crypto::hmac::HMAC::<$type>::new(key), parameter)
                                .map($name::$variant)
                                .map_err(|error| $crate::ffi::ToStatus::to_status(&error)),
                        )*
                        _ => Err(&$crate::ffi::Status::INVALID_ARGUMENT),
                    },
                    #[cfg(umilib_feature = "crypto-cmac")]
                    "umilib_crypto_cmac_CMAC" => match $crate::ffi::crypto::BlockCipherChoice::new(primitive, key)? {
                        $crate::ffi::crypto::BlockCipherChoice::Block128(cipher) => {
                            $wrapper::new($crate::crypto::cmac::CMAC::new(cipher), parameter).map($name::CMAC128)
                        }
                        $crate::ffi::crypto::BlockCipherChoice::Block64(cipher) => {
                            $wrapper::new($crate::crypto::cmac::CMAC::new(cipher), parameter).map($name::CMAC64)
                        }
                    }
                    .map_err(|error| $crate::ffi::ToStatus::to_status(&error)),
                    _ => Err(&$crate::ffi::Status::INVALID_ARGUMENT),
                }
            }

        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}
