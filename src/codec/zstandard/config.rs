use super::ZstandardDictionary;

/// The parameters of a [`ZstandardCompressor`](super::ZstandardCompressor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZstandardConfig {
    /// 1 to 19: the search ([`ZstandardLevel`](super::ZstandardLevel)) and,
    /// unless `window_log` is given, the window.
    pub level: u32,
    /// The base-2 logarithm of the window (10 to 30), if not the level's.
    pub window_log: Option<u32>,
    /// Whether the frame ends with the low 32 bits of the XXH64 of the data.
    pub content_checksum: bool,
    /// The size of the data, written in the header if given; finishing a
    /// stream of another size fails with `InvalidParameter`.
    pub content_size: Option<u64>,
    /// The dictionary: its content is the history before the data, and its
    /// identifier (if not 0) is written in the header.
    pub dictionary: Option<ZstandardDictionary>,
}

impl Default for ZstandardConfig {
    fn default() -> ZstandardConfig {
        ZstandardConfig { level: 3, window_log: None, content_checksum: true, content_size: None, dictionary: None }
    }
}

/// The limits of a [`ZstandardDecompressor`](super::ZstandardDecompressor).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZstandardDecompressorConfig {
    /// The largest window a frame may ask for (larger ones fail with
    /// `LimitExceeded`): 128 MiB by default, the default limit of the
    /// reference decoder; the history grows with the data up to it.
    pub maximum_window: u64,
    /// Whether the input is a series of frames (and skippable frames) that
    /// ends with it, as the zstd tool reads; otherwise one frame, after which
    /// the input is not consumed.
    pub multiple_frames: bool,
    /// The dictionary given to the frames that name its identifier (or
    /// every frame, for raw content).
    pub dictionary: Option<ZstandardDictionary>,
}

impl Default for ZstandardDecompressorConfig {
    fn default() -> ZstandardDecompressorConfig {
        ZstandardDecompressorConfig { maximum_window: 1 << 27, multiple_frames: true, dictionary: None }
    }
}
