/// Defines exported C functions together with their manifest entries.
///
/// Every function is exported unmangled, and a constant (`FUNCTIONS`, or the
/// name given as `const NAME;` before the functions) lists their
/// [`Function`](crate::ffi::Function) descriptions in declaration order, so
/// the manifest can never disagree with the actual signatures.
///
/// ```ignore
/// umilib::ffi_functions! {
///     /// Adds two numbers.
///     pub unsafe extern "C" fn example_add(a: u32, b: u32) -> u32 {
///         a.wrapping_add(b)
///     }
/// }
/// ```
#[macro_export]
macro_rules! ffi_functions {
    (@returns) => {
        <() as $crate::ffi::Value>::TYPE
    };
    (@returns $returns:ty) => {
        <$returns as $crate::ffi::Value>::TYPE
    };
    ($(
        $(#[doc = $documentation:literal])*
        pub unsafe extern "C" fn $name:ident($($parameter:ident: $type:ty),* $(,)?) $(-> $returns:ty)? $body:block
    )*) => {
        $crate::ffi_functions! {
            const FUNCTIONS;
            $(
                $(#[doc = $documentation])*
                pub unsafe extern "C" fn $name($($parameter: $type),*) $(-> $returns)? $body
            )*
        }
    };
    (const $constant:ident; $(
        $(#[doc = $documentation:literal])*
        pub unsafe extern "C" fn $name:ident($($parameter:ident: $type:ty),* $(,)?) $(-> $returns:ty)? $body:block
    )*) => {
        $(
            $(#[doc = $documentation])*
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $name($($parameter: $type),*) $(-> $returns)? $body
        )*

        /// The functions exported by this module, in declaration order.
        pub const $constant: &[$crate::ffi::Function] = &[$(
            $crate::ffi::Function {
                name: stringify!($name),
                documentation: concat!($($documentation, "\n",)*),
                parameters: &[$(
                    $crate::ffi::Parameter {
                        name: stringify!($parameter),
                        value: <$type as $crate::ffi::Value>::TYPE,
                    },
                )*],
                returns: $crate::ffi_functions!(@returns $($returns)?),
            },
        )*];
    };
}

/// Like [`ffi_functions!`], but each function names its C symbol with an
/// expression, so macros can export the same function set for many types:
///
/// ```ignore
/// umilib::ffi_exports! {
///     const FUNCTIONS;
///     /// Adds two numbers.
///     pub unsafe extern "C" fn add = concat!("example", "_add") (a: u32, b: u32) -> u32 {
///         a.wrapping_add(b)
///     }
/// }
/// ```
///
/// The Rust names of the functions only need to be unique in their module.
#[macro_export]
macro_rules! ffi_exports {
    (const $constant:ident; $(
        $(#[doc = $documentation:expr])*
        pub unsafe extern "C" fn $name:ident = $symbol:expr; ($($parameter:ident: $type:ty),* $(,)?) $(-> $returns:ty)? $body:block
    )*) => {
        $(
            $(#[doc = $documentation])*
            #[unsafe(export_name = $symbol)]
            pub unsafe extern "C" fn $name($($parameter: $type),*) $(-> $returns)? $body
        )*

        /// The functions exported by this module, in declaration order.
        pub const $constant: &[$crate::ffi::Function] = &[$(
            $crate::ffi::Function {
                name: $symbol,
                documentation: concat!($($documentation, "\n",)*),
                parameters: &[$(
                    $crate::ffi::Parameter {
                        name: stringify!($parameter),
                        value: <$type as $crate::ffi::Value>::TYPE,
                    },
                )*],
                returns: $crate::ffi_functions!(@returns $($returns)?),
            },
        )*];
    };
}
