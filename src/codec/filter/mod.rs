//! Filters: reversible transformations that keep the size of data and make
//! it compress better ([`Filter`]): the Delta filter and the branch
//! converters of executables (BCJ) of .xz and .7z, and [`FilterChain`],
//! which runs several of them over a stream.

mod chain;
#[allow(clippy::module_inception)]
mod filter;

pub use chain::FilterChain;
pub use filter::Filter;

#[cfg(umilib_feature = "codec-filter-bcj")]
pub mod bcj;
#[cfg(umilib_feature = "codec-filter-delta")]
pub mod delta;
