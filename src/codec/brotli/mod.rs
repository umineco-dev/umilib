//! Brotli (RFC 7932): streams of meta-blocks of commands (insert lengths,
//! copy lengths and distances) and literals coded with prefix codes chosen
//! by block types and context models, with the static dictionary of the
//! format and its word transformations ([`BrotliCompressor`],
//! [`BrotliDecompressor`]), and the parts they are built from.
//!
//! The static dictionary is the one of RFC 7932 Appendix A, under the
//! license of its code (see the third-party notice in LICENSE).

mod block;
mod compressor;
mod config;
mod context_map;
mod decompressor;
mod distance;
mod format;
mod prefix;

pub use block::{BrotliBlockSwitch, BrotliCategory};
pub use compressor::{BrotliCompressor, BrotliLevel};
pub use config::{BrotliConfig, BrotliDecompressorConfig};
pub use context_map::{BrotliContextMap, BrotliContextMapPhase, BrotliContextMapReader};
pub use decompressor::{BrotliDecompressor, BrotliState};
pub use distance::BrotliDistances;
pub use format::{BrotliFormat, BrotliTransform, BrotliTransformKind};
pub use prefix::{BrotliPrefixCode, BrotliPrefixPhase, BrotliPrefixReader};
