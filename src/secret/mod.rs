//! Handling of secret values: constant-time comparison and selection, and
//! zeroization of memory when a secret is no longer needed.
//!
//! Constant-time operations avoid branches and memory accesses that depend on
//! secret data. Rust and LLVM do not guarantee constant-time code generation, so
//! every [`Choice`] passes through [`core::hint::black_box`], which keeps the
//! optimizer from turning masks back into branches in practice. See
//! `.docs/constant-time.md` for the policy and its limits.

mod choice;
mod conditionally_selectable;
mod constant_time_eq;
mod constant_time_table;
mod data_independent_timing;
#[allow(clippy::module_inception)]
mod secret;
mod zeroize;

pub use choice::Choice;
pub use conditionally_selectable::ConditionallySelectable;
pub use constant_time_eq::ConstantTimeEq;
pub use constant_time_table::ConstantTimeTable;
pub use data_independent_timing::DataIndependentTiming;
pub use secret::Secret;
pub use zeroize::Zeroize;
