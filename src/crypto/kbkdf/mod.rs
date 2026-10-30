//! The key-based key derivation functions of NIST SP 800-108r1: counter,
//! feedback and double-pipeline modes over any keyed pseudorandom function.

use core::fmt;

use crate::crypto::{CryptoError, PRF};
use crate::secret::Zeroize;

/// Where the counter \[i\]_r goes in the input of each PRF invocation of the
/// feedback and double-pipeline modes (SP 800-108r1 sections 4.2 and 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KBKDFCounter {
    /// No counter: PRF(K(i-1) || fixed).
    Absent,
    /// PRF(\[i\] || K(i-1) || fixed).
    BeforeIteration,
    /// PRF(K(i-1) || \[i\] || fixed).
    AfterIteration,
    /// PRF(K(i-1) || fixed || \[i\]).
    AfterFixed,
}

/// KBKDF over the pseudorandom function `P`, a MAC keyed with K_IN (HMAC or
/// CMAC, section 5), with a counter of `r` = 8, 16, 24 or 32 bits.
///
/// The fixed input data (typically Label || 0x00 || Context || \[L\]_2,
/// section 5) is built by the caller, as protocols define it; the output
/// length L is the length of the output buffer. Each block of output is one
/// PRF invocation on a copy of the keyed `P`.
#[derive(Clone)]
pub struct KBKDF<P: PRF> {
    prf: P,
    counter_bytes: usize,
}

impl<P: PRF> KBKDF<P> {
    /// KBKDF with the keyed `prf` and a counter of `counter_bits` bits.
    pub fn new(prf: P, counter_bits: u32) -> Result<KBKDF<P>, CryptoError> {
        if !matches!(counter_bits, 8 | 16 | 24 | 32) {
            return Err(CryptoError::InvalidParameter);
        }
        Ok(KBKDF { prf, counter_bytes: counter_bits as usize / 8 })
    }

    /// The number of blocks of `length` bytes: n = ⌈L / h⌉, at most 2^r - 1
    /// with a counter and 2^32 - 1 without (sections 4.1 to 4.3).
    pub fn blocks(&self, length: usize, counter: bool) -> Result<usize, CryptoError> {
        let blocks = length.div_ceil(P::OUTPUT_SIZE) as u64;
        let bits = if counter { 8 * self.counter_bytes } else { 32 };
        if blocks > (1u64 << bits) - 1 {
            return Err(CryptoError::InputLength { length });
        }
        Ok(blocks as usize)
    }

    /// The big-endian counter \[i\]_r.
    pub fn counter_bytes(&self, index: usize) -> ([u8; 4], usize) {
        let bytes = (index as u32).to_be_bytes();
        (bytes, 4 - self.counter_bytes)
    }

    /// Counter mode (section 4.1): K(i) = PRF(K_IN, before || \[i\]_r || after);
    /// the counter may be before, after or inside the fixed input data.
    pub fn counter(&self, before: &[u8], after: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        self.blocks(out.len(), true)?;
        for (index, piece) in out.chunks_mut(P::OUTPUT_SIZE).enumerate() {
            let (counter, start) = self.counter_bytes(index + 1);
            let mut prf = self.prf.clone();
            prf.reset();
            prf.update(before);
            prf.update(&counter[start..]);
            prf.update(after);
            let mut block = prf.finalize();
            piece.copy_from_slice(&block.as_ref()[..piece.len()]);
            block.as_mut().zeroize();
        }
        Ok(())
    }

    /// One PRF invocation on the iteration value, the counter of `index` at `location`, and `fixed`.
    pub fn invoke(&self, iteration: &[u8], location: KBKDFCounter, index: usize, fixed: &[u8]) -> P::Output {
        let (counter, start) = self.counter_bytes(index);
        let counter = &counter[start..];
        let mut prf = self.prf.clone();
        prf.reset();
        if location == KBKDFCounter::BeforeIteration {
            prf.update(counter);
        }
        prf.update(iteration);
        if location == KBKDFCounter::AfterIteration {
            prf.update(counter);
        }
        prf.update(fixed);
        if location == KBKDFCounter::AfterFixed {
            prf.update(counter);
        }
        prf.finalize()
    }

    /// Feedback mode (section 4.2): K(0) = `iv` (possibly empty) and K(i) = PRF(K_IN, K(i-1), \[i\]_r, fixed).
    pub fn feedback(&self, iv: &[u8], fixed: &[u8], location: KBKDFCounter, out: &mut [u8]) -> Result<(), CryptoError> {
        self.blocks(out.len(), location != KBKDFCounter::Absent)?;
        let mut previous: Option<P::Output> = None;
        for (index, piece) in out.chunks_mut(P::OUTPUT_SIZE).enumerate() {
            let iteration = previous.as_ref().map_or(iv, |block| block.as_ref());
            let block = self.invoke(iteration, location, index + 1, fixed);
            piece.copy_from_slice(&block.as_ref()[..piece.len()]);
            if let Some(mut old) = previous.replace(block) {
                old.as_mut().zeroize();
            }
        }
        if let Some(mut last) = previous {
            last.as_mut().zeroize();
        }
        Ok(())
    }

    /// Double-pipeline mode (section 4.3): A(0) = `fixed`, A(i) = PRF(K_IN, A(i-1))
    /// and K(i) = PRF(K_IN, A(i), \[i\]_r, fixed).
    pub fn double_pipeline(&self, fixed: &[u8], location: KBKDFCounter, out: &mut [u8]) -> Result<(), CryptoError> {
        self.blocks(out.len(), location != KBKDFCounter::Absent)?;
        let mut a: Option<P::Output> = None;
        for (index, piece) in out.chunks_mut(P::OUTPUT_SIZE).enumerate() {
            let mut prf = self.prf.clone();
            prf.reset();
            prf.update(a.as_ref().map_or(fixed, |value| value.as_ref()));
            let next = prf.finalize();
            if let Some(mut old) = a.replace(next) {
                old.as_mut().zeroize();
            }
            let current = a.as_ref().expect("A(i) was just computed");
            let mut block = self.invoke(current.as_ref(), location, index + 1, fixed);
            piece.copy_from_slice(&block.as_ref()[..piece.len()]);
            block.as_mut().zeroize();
        }
        if let Some(mut last) = a {
            last.as_mut().zeroize();
        }
        Ok(())
    }
}

impl<P: PRF + Zeroize> Zeroize for KBKDF<P> {
    fn zeroize(&mut self) {
        self.prf.zeroize();
    }
}

impl<P: PRF> fmt::Debug for KBKDF<P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "KBKDF({}-bit counter, ..)", 8 * self.counter_bytes)
    }
}
