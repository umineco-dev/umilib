//! LZ77: the shared parts of the LZ77 formats (the history of a decompressor,
//! [`LZ77Window`], and the match search of a compressor, [`LZ77MatchFinder`]),
//! and the triples of the original algorithm in a format of this library
//! ([`LZ77Format`]).

mod compressor;
mod config;
mod decompressor;
mod format;
mod match_finder;
mod window;

pub use compressor::LZ77Compressor;
pub use config::LZ77Config;
pub use decompressor::{LZ77Decompressor, LZ77State};
pub use format::LZ77Format;
pub use match_finder::{LZ77Match, LZ77MatchFinder, LZ77MatchFinderConfig};
pub use window::LZ77Window;
