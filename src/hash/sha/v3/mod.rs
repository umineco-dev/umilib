//! SHA-3 (FIPS 202) and the functions derived from it in SP 800-185.
//!
//! [`KeccakF1600`] is the permutation and [`Sponge`] the sponge construction
//! over it. The fixed-length hashes are [`SHA3_224`], [`SHA3_256`],
//! [`SHA3_384`] and [`SHA3_512`] (and [`Keccak256`] and friends, the padding
//! of the original Keccak submission that some protocols kept); the
//! extendable-output functions are [`SHAKE128`] and [`SHAKE256`]; SP 800-185
//! adds [`CSHAKE128`] and [`CSHAKE256`] with function names and
//! customization strings, [`TupleHash128`] and [`TupleHash256`] over
//! sequences of strings, and [`ParallelHash128`] and [`ParallelHash256`].

mod keccak;
mod sha3;
mod shake;
mod sp800185;

pub use keccak::{KeccakF1600, Sponge};
pub use sha3::{Keccak224, Keccak256, Keccak384, Keccak512, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
pub use shake::{SHAKE128, SHAKE256};
pub use sp800185::{CSHAKE128, CSHAKE256, ParallelHash128, ParallelHash256, SP800185, TupleHash128, TupleHash256};
