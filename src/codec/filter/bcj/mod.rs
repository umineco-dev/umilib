//! Branch/call/jump (BCJ) filters (.xz format specification, section
//! 5.3.2): the relative addresses of the branch, call and jump instructions
//! of executables are converted to absolute ones, which repeat more and so
//! compress better. One [`BCJFilter`] serves the eight architectures of the
//! format ([`BCJArchitecture`]); the conversions are those of XZ Utils.

mod architecture;
mod filter;

pub use architecture::BCJArchitecture;
pub use filter::BCJFilter;
