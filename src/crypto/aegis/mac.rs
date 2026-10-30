use core::fmt;

use super::{AEGIS128XState, AEGIS256XState};
use crate::crypto::MAC;
use crate::secret::Zeroize;

macro_rules! aegis_mac {
    ($(#[$documentation:meta])* $name:ident, $state:ident, $key:literal, $buffer:literal) => {
        $(#[$documentation])*
        ///
        /// Unlike the AEAD, a (key, nonce) pair may authenticate several
        /// inputs; the tag must not serve as a hash or to derive keys
        /// (section 8). [`MAC::reset`] returns to the state after Init.
        #[derive(Clone)]
        pub struct $name<const D: usize, const TAG: usize> {
            initial: $state<D>,
            state: $state<D>,
            buffer: [u8; $buffer],
            buffered: usize,
            length: u64,
        }

        impl<const D: usize, const TAG: usize> $name<D, TAG> {
            const TAG_IS_VALID: () = assert!(TAG == 16 || TAG == 32, "AEGIS tags have 16 or 32 bytes");

            pub fn new(key: &[u8; $key], nonce: &[u8; $key]) -> $name<D, TAG> {
                #[allow(clippy::let_unit_value)]
                let () = $name::<D, TAG>::TAG_IS_VALID;
                let initial = $state::new(key, nonce);
                $name { state: initial.clone(), initial, buffer: [0; $buffer], buffered: 0, length: 0 }
            }

            /// Adds `data`, in blocks of the rate; a partial block waits for more data.
            pub fn update(&mut self, mut data: &[u8]) {
                let rate = $state::<D>::RATE;
                self.length += data.len() as u64;
                if self.buffered > 0 {
                    let take = (rate - self.buffered).min(data.len());
                    self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
                    self.buffered += take;
                    data = &data[take..];
                    if self.buffered < rate {
                        return;
                    }
                    let block = self.buffer;
                    self.state.absorb(&block[..rate]);
                    self.buffered = 0;
                }
                let whole = data.len() - data.len() % rate;
                for block in data[..whole].chunks_exact(rate) {
                    self.state.absorb(block);
                }
                self.buffer[..data.len() - whole].copy_from_slice(&data[whole..]);
                self.buffered = data.len() - whole;
            }

            /// The tag: the last block zero-padded, then FinalizeMac.
            pub fn finalize(mut self) -> [u8; TAG] {
                let rate = $state::<D>::RATE;
                if self.buffered > 0 {
                    self.buffer[self.buffered..rate].fill(0);
                    let block = self.buffer;
                    self.state.absorb(&block[..rate]);
                }
                let state = self.state.clone();
                let tag = state.finalize_mac(self.length);
                self.zeroize();
                tag
            }

            /// The tag of `data` under `key` and `nonce`.
            pub fn mac(key: &[u8; $key], nonce: &[u8; $key], data: &[u8]) -> [u8; TAG] {
                let mut mac = $name::<D, TAG>::new(key, nonce);
                mac.update(data);
                mac.finalize()
            }
        }

        impl<const D: usize, const TAG: usize> MAC for $name<D, TAG> {
            const OUTPUT_SIZE: usize = TAG;
            type Output = [u8; TAG];

            fn update(&mut self, data: &[u8]) {
                $name::update(self, data);
            }

            fn finalize(self) -> [u8; TAG] {
                $name::finalize(self)
            }

            fn reset(&mut self) {
                self.state = self.initial.clone();
                self.buffer.zeroize();
                self.buffered = 0;
                self.length = 0;
            }
        }

        impl<const D: usize, const TAG: usize> Zeroize for $name<D, TAG> {
            fn zeroize(&mut self) {
                self.initial.zeroize();
                self.state.zeroize();
                self.buffer.zeroize();
                self.buffered = 0;
                self.length = 0;
            }
        }

        impl<const D: usize, const TAG: usize> Drop for $name<D, TAG> {
            fn drop(&mut self) {
                self.buffer.zeroize();
            }
        }

        impl<const D: usize, const TAG: usize> fmt::Debug for $name<D, TAG> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "({} lanes, {}-byte tags, ..)"), D, TAG)
            }
        }
    };
}

aegis_mac!(
    /// AEGISMAC-128X with `D` lanes and tags of `TAG` bytes (sections 8.1 and 8.3); AEGISMAC-128L is `D = 1`.
    AEGISMAC128X, AEGIS128XState, 16, 128
);
aegis_mac!(
    /// AEGISMAC-256X with `D` lanes and tags of `TAG` bytes (sections 8.2 and 8.4); AEGISMAC-256 is `D = 1`.
    AEGISMAC256X, AEGIS256XState, 32, 64
);

/// AEGISMAC-128L (section 8.1).
pub type AEGISMAC128L<const TAG: usize> = AEGISMAC128X<1, TAG>;
/// AEGISMAC-256 (section 8.2).
pub type AEGISMAC256<const TAG: usize> = AEGISMAC256X<1, TAG>;
