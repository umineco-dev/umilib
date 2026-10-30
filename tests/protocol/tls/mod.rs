//! Tests of `umilib::protocol::tls` against the traces of RFC 8448 and the
//! rules of RFC 9846.

mod codec;
#[cfg(feature = "crypto-hpke")]
mod ech;
mod extensions;
pub mod handshake;
mod quic;
pub mod resumption;
mod rfc8448;
mod robustness;
mod v1_2;

use crate::{RFC, Vectors};

/// A value of the traces of RFC 8448: the section and step it belongs to
/// (such as `server}  derive secret "tls13 c hs traffic":`), its label
/// (such as "ClientHello" or "expanded") and its bytes.
pub struct TraceItem {
    pub section: String,
    pub step: String,
    pub label: String,
    pub bytes: Vec<u8>,
}

pub struct Trace;

impl Trace {
    pub const PATH: &'static str = "protocol/tls/rfc8448.txt";

    /// Every labelled value of RFC 8448 ("label (n octets):  hex..."), its
    /// hex gathered across lines and page breaks until it has n octets.
    pub fn items() -> Vec<TraceItem> {
        let text = Vectors::read(Trace::PATH);
        let (mut section, mut step) = (String::new(), String::new());
        let mut items: Vec<TraceItem> = Vec::new();
        let mut open: Option<(String, usize, String)> = None;
        for line in text.lines().filter(|line| !RFC::is_page_break(line)) {
            if let Some((label, length, hex)) = open.as_mut() {
                hex.push_str(line);
                if hex.split_whitespace().count() >= *length {
                    let bytes = Vectors::hex(&hex.split_whitespace().collect::<String>());
                    items.push(TraceItem { section: section.clone(), step: step.clone(), label: label.clone(), bytes });
                    open = None;
                }
                continue;
            }
            if line.chars().next().is_some_and(|c| c.is_ascii_digit()) && line.contains(".  ") {
                section = line.trim().to_string();
            } else if let Some(rest) = line.trim_start().strip_prefix('{') {
                step = rest.to_string();
            } else if let Some((head, hex)) = line.split_once(" octets):") {
                let Some((label, length)) = head.trim().rsplit_once(" (") else { continue };
                let length: usize = length.parse().unwrap();
                let first = hex.to_string();
                if first.split_whitespace().count() >= length {
                    let hex: String = first.split_whitespace().take(length).collect();
                    let bytes = if length == 0 { Vec::new() } else { Vectors::hex(&hex) };
                    items.push(TraceItem {
                        section: section.clone(),
                        step: step.clone(),
                        label: label.to_string(),
                        bytes,
                    });
                } else {
                    open = Some((label.to_string(), length, first));
                }
            }
        }
        items
    }
}

impl Trace {
    /// The bytes labelled `label` in the first step of `section` whose text
    /// contains `step`.
    pub fn find<'a>(items: &'a [TraceItem], section: &str, step: &str, label: &str) -> &'a [u8] {
        &items
            .iter()
            .find(|item| item.section.starts_with(section) && item.step.contains(step) && item.label == label)
            .unwrap_or_else(|| panic!("{section} {step} {label}"))
            .bytes
    }
}
