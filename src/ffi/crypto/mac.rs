use crate::crypto::MAC;

/// A MAC of the C ABI whose output size may be chosen at run time: the
/// functions of [`MAC`] with the tag written into a slice.
pub trait MACState: Clone {
    fn output_size(&self) -> usize;

    fn update(&mut self, data: &[u8]);

    /// Writes the tag into `out`, which has the output size.
    fn finalize_into(self, out: &mut [u8]);

    fn reset(&mut self);

    /// Whether `tag` is the tag of the message, compared in constant time.
    fn verify(self, tag: &[u8]) -> bool;
}

impl<M: MAC> MACState for M {
    fn output_size(&self) -> usize {
        M::OUTPUT_SIZE
    }

    fn update(&mut self, data: &[u8]) {
        MAC::update(self, data);
    }

    fn finalize_into(self, out: &mut [u8]) {
        out.copy_from_slice(self.finalize().as_ref());
    }

    fn reset(&mut self) {
        MAC::reset(self);
    }

    fn verify(self, tag: &[u8]) -> bool {
        MAC::verify(self, tag)
    }
}

/// Defines `$name` as an enum of MACs whose variants share the C ABI
/// (`Variant(Type),` for each), implementing [`MACState`] by delegation.
#[macro_export]
macro_rules! ffi_mac_enum {
    ($(#[$documentation:meta])* $name:ident { $($(#[$attribute:meta])* $variant:ident($type:ty),)* }) => {
        $(#[$documentation])*
        #[derive(Clone)]
        // The enum lives behind a handle: boxing the variants would add an allocation.
        #[allow(clippy::large_enum_variant)]
        pub enum $name {
            $($(#[$attribute])* $variant($type),)*
        }

        // The enum is empty when no algorithm of the registry is enabled, leaving the arguments unused.
        #[allow(unused_variables)]
        impl $crate::ffi::crypto::MACState for $name {
            fn output_size(&self) -> usize {
                match *self {
                    $($(#[$attribute])* $name::$variant(ref mac) => $crate::ffi::crypto::MACState::output_size(mac),)*
                }
            }

            fn update(&mut self, data: &[u8]) {
                match *self {
                    $($(#[$attribute])* $name::$variant(ref mut mac) => $crate::ffi::crypto::MACState::update(mac, data),)*
                }
            }

            fn finalize_into(self, out: &mut [u8]) {
                match self {
                    $($(#[$attribute])* $name::$variant(mac) => $crate::ffi::crypto::MACState::finalize_into(mac, out),)*
                }
            }

            fn reset(&mut self) {
                match *self {
                    $($(#[$attribute])* $name::$variant(ref mut mac) => $crate::ffi::crypto::MACState::reset(mac),)*
                }
            }

            fn verify(self, tag: &[u8]) -> bool {
                match self {
                    $($(#[$attribute])* $name::$variant(mac) => $crate::ffi::crypto::MACState::verify(mac, tag),)*
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

/// Exports the functions of a [`MACState`] type under `$prefix`, after its
/// constructors: `_free`, `_clone`, `_output_size`, `_update`, `_finalize`,
/// `_reset` and `_verify`.
#[macro_export]
macro_rules! ffi_mac {
    ($type:ty, $prefix:literal, $constant:ident) => {
        $crate::ffi_exports! {
            const $constant;
            /// Releases the state, zeroizing it. Does nothing if `state` is null.
            pub unsafe extern "C" fn free = concat!($prefix, "_free"); (state: *mut $type) {
                // SAFETY: the caller passes null or a handle created by this module.
                unsafe { $crate::ffi::Pointer::free(state) }
            }

            /// Writes a copy of `state` into `out`.
            pub unsafe extern "C" fn clone = concat!($prefix, "_clone"); (state: *const $type, out: *mut *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { $crate::ffi::Pointer::reference(state) }?;
                    unsafe { $crate::ffi::Pointer::write_handle(out, state.clone()) }
                })())
            }

            /// Writes the output size into `out`.
            pub unsafe extern "C" fn output_size = concat!($prefix, "_output_size"); (state: *const $type, out: *mut usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and a writable pointer.
                    let state = unsafe { $crate::ffi::Pointer::reference(state) }?;
                    unsafe { $crate::ffi::Pointer::write(out, $crate::ffi::crypto::MACState::output_size(state)) }
                })())
            }

            /// Adds the `length` bytes at `data` to the message.
            pub unsafe extern "C" fn update = concat!($prefix, "_update"); (state: *mut $type, data: *const u8, length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle and readable bytes.
                    let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                    $crate::ffi::crypto::MACState::update(state, unsafe { $crate::ffi::Pointer::slice(data, length) }?);
                    Ok(())
                })())
            }

            /// Writes the tag into the `out_length` bytes at `out`, which must be the output size, and
            /// releases the state. On failure the state is not released.
            pub unsafe extern "C" fn finalize = concat!($prefix, "_finalize"); (state: *mut $type, out: *mut u8, out_length: usize) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a writable byte range.
                    let out = unsafe { $crate::ffi::Pointer::slice_mut(out, out_length) }?;
                    let size = $crate::ffi::crypto::MACState::output_size(unsafe { $crate::ffi::Pointer::reference(state) }?);
                    if out.len() != size {
                        return Err($crate::ffi::ToStatus::to_status(&$crate::crypto::CryptoError::TagLength { length: out.len(), minimum: size, maximum: size }));
                    }
                    // SAFETY: the caller passes a handle created by this module and does not use it afterwards.
                    let state = unsafe { alloc::boxed::Box::from_raw(state) };
                    // From a copy, so that dropping the box zeroizes the state where it lives.
                    $crate::ffi::crypto::MACState::finalize_into((*state).clone(), out);
                    drop(state);
                    Ok(())
                })())
            }

            /// Returns to the state after the key.
            pub unsafe extern "C" fn reset = concat!($prefix, "_reset"); (state: *mut $type) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes a valid handle.
                    let state = unsafe { $crate::ffi::Pointer::reference_mut(state) }?;
                    $crate::ffi::crypto::MACState::reset(state);
                    Ok(())
                })())
            }

            /// Writes into `out` whether the `tag_length` bytes at `tag` are the tag of the message,
            /// compared in constant time, and releases the state. On failure the state is not released.
            pub unsafe extern "C" fn verify = concat!($prefix, "_verify"); (state: *mut $type, tag: *const u8, tag_length: usize, out: *mut bool) -> *const $crate::ffi::Status {
                $crate::ffi::Status::from_result((|| {
                    // SAFETY: the caller passes readable bytes, a writable pointer and a handle created by this module.
                    let tag = unsafe { $crate::ffi::Pointer::slice(tag, tag_length) }?;
                    unsafe { $crate::ffi::Pointer::reference(state) }?;
                    // Every check comes before the state is released, so a failure leaves it to the caller.
                    if out.is_null() {
                        return Err(&$crate::ffi::Status::NULL_POINTER);
                    }
                    let state = unsafe { alloc::boxed::Box::from_raw(state) };
                    let valid = $crate::ffi::crypto::MACState::verify((*state).clone(), tag);
                    drop(state);
                    unsafe { $crate::ffi::Pointer::write(out, valid) }
                })())
            }
        }
    };
}
