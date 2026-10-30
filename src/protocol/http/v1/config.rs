use alloc::vec::Vec;
use core::time::Duration;

use crate::protocol::http::HTTPConfig;

/// The configuration of HTTP/1.1 connections; every limit and timeout can be changed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct H1Config {
    pub http: HTTPConfig,
    /// The scheme of the requests a server receives in origin-form: "http"
    /// by default, "https" over TLS (RFC 9112 §3.3).
    pub scheme: Vec<u8>,
    /// The most exchanges under way at once: the requests a server reads
    /// ahead of its responses, and those a client sends before their
    /// responses arrive (RFC 9112 §9.3.2): 16 by default.
    pub maximum_pipelined: usize,
    /// The longest line of a chunk's size and extensions (RFC 9112 §7.1.1): 4 KiB by default.
    pub maximum_chunk_line: usize,
    /// How long a connection stays open without an exchange under way: 60 s by default; `None` for ever.
    pub idle_timeout: Option<Duration>,
    /// How long the head of a message may take to arrive once it started,
    /// against peers that send it slowly: 30 s by default; `None` for ever.
    pub head_timeout: Option<Duration>,
    /// Whether a server sends 100 (Continue) when its application first
    /// reads the content of a request that expects it (RFC 9110 §10.1.1): on by default.
    pub continue_automatically: bool,
}

impl Default for H1Config {
    fn default() -> H1Config {
        H1Config {
            http: HTTPConfig::default(),
            scheme: b"http".to_vec(),
            maximum_pipelined: 16,
            maximum_chunk_line: 4 << 10,
            idle_timeout: Some(Duration::from_secs(60)),
            head_timeout: Some(Duration::from_secs(30)),
            continue_automatically: true,
        }
    }
}
