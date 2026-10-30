use crate::secret::ConstantTimeEq;

/// A message authentication code over a byte stream.
pub trait MAC: Clone {
    const OUTPUT_SIZE: usize;
    /// A tag: `[u8; OUTPUT_SIZE]`.
    type Output: AsRef<[u8]> + AsMut<[u8]> + Clone + Copy + Eq + core::fmt::Debug;

    /// Adds `data` to the message.
    fn update(&mut self, data: &[u8]);

    /// The tag of the message; the state is consumed (and zeroized).
    fn finalize(self) -> Self::Output;

    /// Returns to the state after the key, for MACs that allow several
    /// messages under one key (Poly1305, a one-time MAC, does not).
    fn reset(&mut self);

    /// Whether `tag` is the tag of the message, compared in constant time.
    fn verify(self, tag: &[u8]) -> bool {
        let mut expected = self.finalize();
        let valid = expected.as_ref().ct_eq(tag).into_bool();
        crate::secret::Zeroize::zeroize(expected.as_mut());
        valid
    }
}

/// A [`MAC`] that is a pseudorandom function of the message under one key,
/// which may compute any number of outputs: the PRF that the key derivation
/// functions of SP 800-108 and RFC 7836 require (HMAC, CMAC). A one-time MAC
/// such as Poly1305 is not one.
pub trait PRF: MAC {}
