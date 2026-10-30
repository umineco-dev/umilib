use core::fmt;

use super::{Choice, ConstantTimeEq, Zeroize};

/// A value that is zeroized when dropped and never printed.
///
/// The value is reached only through [`Secret::expose`] and
/// [`Secret::expose_mut`], which makes every use of it visible in the code.
pub struct Secret<T: Zeroize> {
    value: T,
}

impl<T: Zeroize> Secret<T> {
    /// Takes ownership of `value`.
    pub const fn new(value: T) -> Secret<T> {
        Secret { value }
    }

    /// Borrows the secret value.
    pub fn expose(&self) -> &T {
        &self.value
    }

    /// Borrows the secret value mutably.
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.value
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Secret<T> {
        Secret::new(self.value.clone())
    }
}

impl<T: Zeroize + Default> Default for Secret<T> {
    fn default() -> Secret<T> {
        Secret::new(T::default())
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(..)")
    }
}

impl<T: Zeroize + ConstantTimeEq> ConstantTimeEq for Secret<T> {
    fn ct_eq(&self, other: &Secret<T>) -> Choice {
        self.value.ct_eq(&other.value)
    }
}

impl<T: Zeroize> From<T> for Secret<T> {
    fn from(value: T) -> Secret<T> {
        Secret::new(value)
    }
}
