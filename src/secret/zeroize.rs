use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, compiler_fence};

/// Overwriting a value with zeros in a way the compiler does not remove.
pub trait Zeroize {
    /// Overwrites `self` with zeros.
    fn zeroize(&mut self);
}

macro_rules! zeroize {
    ($($type:ty),* $(,)?) => {
        $(
            impl Zeroize for $type {
                fn zeroize(&mut self) {
                    // SAFETY: `self` is a valid, aligned, exclusive reference.
                    unsafe { core::ptr::write_volatile(self, 0 as $type) };
                    compiler_fence(Ordering::SeqCst);
                }
            }
        )*
    };
}

zeroize!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

impl Zeroize for char {
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(self, '\0') };
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for bool {
    fn zeroize(&mut self) {
        // SAFETY: `self` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(self, false) };
        compiler_fence(Ordering::SeqCst);
    }
}

impl<T: Zeroize> Zeroize for [T] {
    fn zeroize(&mut self) {
        self.iter_mut().for_each(Zeroize::zeroize);
    }
}

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<T: Zeroize> Zeroize for Option<T> {
    /// Zeroizes the contained value and sets the option to `None`.
    fn zeroize(&mut self) {
        if let Some(value) = self {
            value.zeroize();
        }
        *self = None;
    }
}

impl<T: Zeroize> Zeroize for Vec<T> {
    /// Zeroizes every element and the unused capacity, then clears the vector.
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
        for element in self.spare_capacity_mut() {
            // SAFETY: `element` is a valid, aligned, exclusive reference; a
            // `MaybeUninit` may hold any bytes, including zeros.
            unsafe { core::ptr::write_volatile(element, core::mem::MaybeUninit::zeroed()) };
        }
        compiler_fence(Ordering::SeqCst);
        self.clear();
    }
}

impl Zeroize for String {
    /// Zeroizes the whole allocation, then clears the string.
    fn zeroize(&mut self) {
        // SAFETY: only zeros are written and the string is cleared afterwards,
        // so it never holds invalid UTF-8 when observed.
        unsafe { self.as_mut_vec() }.zeroize();
    }
}
