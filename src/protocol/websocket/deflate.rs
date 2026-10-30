use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::codec::deflate::{DeflateCompressor, DeflateConfig, DeflateDecompressor, DeflateDecompressorConfig};
use crate::codec::{Compressor, Decompressor, Flush};

/// The parameters of permessage-deflate (RFC 7692 §7.1): in an offer of a
/// client, or the response of a server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct WebSocketDeflateParameters {
    pub server_no_context_takeover: bool,
    pub client_no_context_takeover: bool,
    /// The LZ77 window of the server's compressor, 8 to 15.
    pub server_max_window_bits: Option<u8>,
    /// The client's: in an offer, `Some(None)` says that the client can
    /// take a limit without proposing one (§7.1.2.2).
    pub client_max_window_bits: Option<Option<u8>>,
}

impl WebSocketDeflateParameters {
    /// The extension's name in Sec-WebSocket-Extensions.
    pub const NAME: &'static str = "permessage-deflate";
    /// The bytes a compressed message's last block ends with, which the
    /// sender leaves out and the receiver adds back (RFC 7692 §7.2.1, §7.2.2).
    pub const TAIL: [u8; 4] = [0x00, 0x00, 0xFF, 0xFF];

    /// The parameters of an offer or a response, as (name, value) pairs
    /// with values unquoted; fails for one unknown, repeated, or of an
    /// invalid value (§7.1).
    pub fn parse(parameters: &[(String, Option<String>)]) -> Result<WebSocketDeflateParameters, &'static str> {
        let mut out = WebSocketDeflateParameters::default();
        let mut seen: Vec<&str> = Vec::new();
        let bits = |value: &Option<String>| -> Result<u8, &'static str> {
            let value = value.as_deref().ok_or("a window size without a value")?;
            // 1*DIGIT without leading zeros, 8 to 15 (§7.1.2.1).
            match value.parse::<u8>() {
                Ok(bits @ 8..=15) if !value.starts_with('0') => Ok(bits),
                _ => Err("a window size out of range"),
            }
        };
        for (name, value) in parameters {
            if seen.contains(&name.as_str()) {
                return Err("a parameter repeated");
            }
            seen.push(name);
            match name.as_str() {
                "server_no_context_takeover" | "client_no_context_takeover" => {
                    if value.is_some() {
                        return Err("a value for a flag");
                    }
                    if name == "server_no_context_takeover" {
                        out.server_no_context_takeover = true;
                    } else {
                        out.client_no_context_takeover = true;
                    }
                }
                "server_max_window_bits" => out.server_max_window_bits = Some(bits(value)?),
                "client_max_window_bits" => {
                    out.client_max_window_bits = Some(match value {
                        None => None,
                        Some(_) => Some(bits(value)?),
                    })
                }
                _ => return Err("an unknown parameter"),
            }
        }
        Ok(out)
    }

    /// The parameters as pairs, for Sec-WebSocket-Extensions.
    pub fn pairs(&self) -> Vec<(String, Option<String>)> {
        let mut pairs = Vec::new();
        if self.server_no_context_takeover {
            pairs.push((String::from("server_no_context_takeover"), None));
        }
        if self.client_no_context_takeover {
            pairs.push((String::from("client_no_context_takeover"), None));
        }
        if let Some(bits) = self.server_max_window_bits {
            pairs.push((String::from("server_max_window_bits"), Some(alloc::format!("{bits}"))));
        }
        if let Some(bits) = self.client_max_window_bits {
            pairs.push((String::from("client_max_window_bits"), bits.map(|bits| alloc::format!("{bits}"))));
        }
        pairs
    }

    /// A server's response to the client's `offer` (§7.1): the offer's
    /// limits, kept; a limit of the client's window only if it offered to
    /// take one.
    /// The parameters a client uses: those of the server's response, with
    /// the hints of its own `offer`, which hold even if the response does not
    /// repeat them: no context takeover, and a window of at most the bits it
    /// offered (§7.1.1.1, §7.1.2.2).
    pub fn with_hints(self, offer: &WebSocketDeflateParameters) -> WebSocketDeflateParameters {
        let client_max_window_bits = match offer.client_max_window_bits {
            Some(Some(hint)) => Some(Some(self.client_max_window_bits.flatten().map_or(hint, |bits| bits.min(hint)))),
            _ => self.client_max_window_bits,
        };
        WebSocketDeflateParameters {
            client_no_context_takeover: self.client_no_context_takeover || offer.client_no_context_takeover,
            client_max_window_bits,
            ..self
        }
    }

    pub fn accept(offer: &WebSocketDeflateParameters) -> WebSocketDeflateParameters {
        WebSocketDeflateParameters {
            server_no_context_takeover: offer.server_no_context_takeover,
            client_no_context_takeover: offer.client_no_context_takeover,
            server_max_window_bits: offer.server_max_window_bits,
            client_max_window_bits: match offer.client_max_window_bits {
                Some(Some(bits)) => Some(Some(bits)),
                _ => None,
            },
        }
    }

    /// Checks a server's `response` to the client's `offer` (§7.1.2.2):
    /// a limit of the client's window only if offered.
    pub fn check_response(
        offer: &WebSocketDeflateParameters,
        response: &WebSocketDeflateParameters,
    ) -> Result<(), &'static str> {
        if response.client_max_window_bits.is_some() && offer.client_max_window_bits.is_none() {
            return Err("a limit of the client's window it did not offer to take");
        }
        if response.client_max_window_bits == Some(None) {
            return Err("client_max_window_bits without a value in a response");
        }
        Ok(())
    }
}

/// The compression of messages of permessage-deflate (RFC 7692 §7.2) on
/// one connection: this end's compressor and the peer's decompressor, each
/// kept across messages unless its "no context takeover" is negotiated.
#[derive(Debug)]
pub struct WebSocketDeflate {
    pub parameters: WebSocketDeflateParameters,
    /// Whether this end is the client, which compresses with the client's parameters.
    pub client: bool,
    pub compressor: DeflateCompressor,
    pub decompressor: DeflateDecompressor,
}

impl WebSocketDeflate {
    pub fn new(
        parameters: WebSocketDeflateParameters,
        client: bool,
        level: u32,
    ) -> Result<WebSocketDeflate, &'static str> {
        let own_bits =
            if client { parameters.client_max_window_bits.flatten() } else { parameters.server_max_window_bits };
        let config = DeflateConfig { level, window_bits: u32::from(own_bits.unwrap_or(15)) };
        let compressor = DeflateCompressor::new(config).map_err(|_| "a compressor of these parameters")?;
        // The peer's window is at most 15 bits: a decompressor of 15 takes any.
        let decompressor =
            DeflateDecompressor::new(DeflateDecompressorConfig { window_bits: 15 }).map_err(|_| "a decompressor")?;
        Ok(WebSocketDeflate { parameters, client, compressor, decompressor })
    }

    /// Whether this end starts each message with a fresh compressor.
    pub fn resets_compressor(&self) -> bool {
        if self.client {
            self.parameters.client_no_context_takeover
        } else {
            self.parameters.server_no_context_takeover
        }
    }

    /// Whether the peer starts each of its messages afresh.
    pub fn resets_decompressor(&self) -> bool {
        if self.client {
            self.parameters.server_no_context_takeover
        } else {
            self.parameters.client_no_context_takeover
        }
    }

    /// The compressed payload of a message (§7.2.1): a sync flush, without its final 4 bytes.
    pub fn compress(&mut self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut out = Vec::new();
        let mut input = message;
        let mut chunk = vec![0u8; 16 << 10];
        loop {
            let progress =
                self.compressor.compress(input, &mut chunk, Flush::Sync).map_err(|_| "compression failed")?;
            input = &input[progress.consumed..];
            out.extend_from_slice(&chunk[..progress.produced]);
            if input.is_empty() && progress.produced < chunk.len() {
                break;
            }
        }
        if out.ends_with(&WebSocketDeflateParameters::TAIL) {
            out.truncate(out.len() - 4);
        }
        if self.resets_compressor() {
            self.compressor.reset();
        }
        Ok(out)
    }

    /// The message of a compressed payload (§7.2.2), at most `limit` bytes.
    pub fn decompress(&mut self, payload: &[u8], limit: usize) -> Result<Vec<u8>, &'static str> {
        let mut input: Vec<u8> = Vec::with_capacity(payload.len() + 4);
        input.extend_from_slice(payload);
        input.extend_from_slice(&WebSocketDeflateParameters::TAIL);
        let mut rest = &input[..];
        let mut out = Vec::new();
        let mut chunk = vec![0u8; 16 << 10];
        loop {
            let room = chunk.len().min(limit.saturating_sub(out.len()) + 1);
            let progress =
                self.decompressor.decompress(rest, &mut chunk[..room]).map_err(|_| "content that does not inflate")?;
            rest = &rest[progress.consumed..];
            out.extend_from_slice(&chunk[..progress.produced]);
            if out.len() > limit {
                return Err("a message larger than the limit");
            }
            if progress.finished {
                // A block with BFINAL: the next block follows at the next byte (§7.2.1, §7.2.3.4).
                self.decompressor.resume();
                if rest.is_empty() {
                    break;
                }
                continue;
            }
            if rest.is_empty() && progress.produced < room {
                break;
            }
        }
        if self.resets_decompressor() {
            self.decompressor.reset();
        }
        Ok(out)
    }
}
