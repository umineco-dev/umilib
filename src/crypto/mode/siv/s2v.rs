use core::fmt;

use crate::crypto::BlockCipher;
use crate::crypto::cmac::CMAC;
use crate::secret::Zeroize;

/// S2V (RFC 5297 section 2.4): the pseudo-random function of a vector of
/// strings S1, ..., Sn over CMAC with the 128-bit block cipher `C`.
///
/// The components before the last are given to [`S2V::update`] one by one,
/// the last to [`S2V::finalize`]; the vector without components has its own
/// output, [`S2V::finalize_empty`]. The state after the key may be cloned to
/// compute several vectors without deriving the CMAC subkeys again.
#[derive(Clone)]
pub struct S2V<C: BlockCipher<Block = [u8; 16]>> {
    /// CMAC with the key and no message.
    cmac: CMAC<C>,
    /// The chaining value D.
    d: [u8; 16],
    components: usize,
}

impl<C: BlockCipher<Block = [u8; 16]>> S2V<C> {
    pub fn new(cipher: C) -> S2V<C> {
        let cmac = CMAC::new(cipher);
        let mut zero = cmac.clone();
        zero.update(&[0u8; 16]);
        let d = zero.finalize();
        S2V { cmac, d, components: 0 }
    }

    /// Adds a component that is not the last: D = dbl(D) xor CMAC(K, component).
    pub fn update(&mut self, component: &[u8]) {
        let mut cmac = self.cmac.clone();
        cmac.update(component);
        let mut value = cmac.finalize();
        CMAC::<C>::double(&mut self.d);
        for (byte, other) in self.d.iter_mut().zip(&value) {
            *byte ^= other;
        }
        value.zeroize();
        self.components += 1;
    }

    /// The output V of the vector that ends with `last`.
    pub fn finalize(mut self, last: &[u8]) -> [u8; 16] {
        let mut cmac = self.cmac.clone();
        let mut tail = [0u8; 16];
        if last.len() >= 16 {
            // T = Sn xorend D.
            let (head, end) = last.split_at(last.len() - 16);
            cmac.update(head);
            tail.copy_from_slice(end);
        } else {
            // T = dbl(D) xor pad(Sn).
            CMAC::<C>::double(&mut self.d);
            tail[..last.len()].copy_from_slice(last);
            tail[last.len()] = 0x80;
        }
        for (byte, other) in tail.iter_mut().zip(&self.d) {
            *byte ^= other;
        }
        cmac.update(&tail);
        tail.zeroize();
        cmac.finalize()
    }

    /// The output of the vector without components, `CMAC(K, <one>)`; `None`
    /// once a component has been added, since such a vector has a last one.
    pub fn finalize_empty(self) -> Option<[u8; 16]> {
        if self.components > 0 {
            return None;
        }
        let mut one = [0u8; 16];
        one[15] = 1;
        let mut cmac = self.cmac.clone();
        cmac.update(&one);
        Some(cmac.finalize())
    }

    /// The number of components added by [`S2V::update`].
    pub fn components(&self) -> usize {
        self.components
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Zeroize for S2V<C> {
    fn zeroize(&mut self) {
        self.cmac.zeroize();
        self.d.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> Drop for S2V<C> {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl<C: BlockCipher<Block = [u8; 16]>> fmt::Debug for S2V<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "S2V({} components, ..)", self.components)
    }
}
