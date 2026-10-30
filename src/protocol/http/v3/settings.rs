use alloc::vec::Vec;

use crate::bytes::Reader;
use crate::protocol::quic::QUICVarint;

use super::{H3Error, H3ErrorCode};

/// The settings of one end (RFC 9114 §7.2.4.1, RFC 9204 §5, RFC 9220 §3),
/// each with its initial value until SETTINGS changes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct H3Settings {
    pub qpack_max_table_capacity: u64,
    /// `None` for no limit, as initially.
    pub max_field_section_size: Option<u64>,
    pub qpack_blocked_streams: u64,
    pub enable_connect_protocol: bool,
}

impl H3Settings {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;

    /// The settings of a SETTINGS frame's payload. Fails with
    /// H3_SETTINGS_ERROR for identifiers of HTTP/2 that HTTP/3 reserves
    /// (§7.2.4.1), a repeated identifier, or a flag other than 0 and 1;
    /// H3_FRAME_ERROR for a payload cut short. Unknown identifiers are ignored.
    pub fn decode(payload: &[u8]) -> Result<H3Settings, H3Error> {
        let error = |reason| H3Error::connection(H3ErrorCode::SETTINGS_ERROR, reason);
        let mut reader = Reader::new(payload);
        let mut settings = H3Settings::default();
        let mut seen = Vec::new();
        while !reader.is_empty() {
            let cut = |_| H3Error::connection(H3ErrorCode::FRAME_ERROR, "SETTINGS cut short");
            let id = QUICVarint::read(&mut reader).map_err(cut)?;
            let value = QUICVarint::read(&mut reader).map_err(cut)?;
            if seen.contains(&id) {
                return Err(error("a setting repeated"));
            }
            seen.push(id);
            match id {
                0x02..=0x05 => return Err(error("a setting of HTTP/2")),
                H3Settings::QPACK_MAX_TABLE_CAPACITY => settings.qpack_max_table_capacity = value,
                H3Settings::MAX_FIELD_SECTION_SIZE => settings.max_field_section_size = Some(value),
                H3Settings::QPACK_BLOCKED_STREAMS => settings.qpack_blocked_streams = value,
                H3Settings::ENABLE_CONNECT_PROTOCOL => {
                    settings.enable_connect_protocol = match value {
                        0 => false,
                        1 => true,
                        _ => return Err(error("SETTINGS_ENABLE_CONNECT_PROTOCOL above 1")),
                    }
                }
                _ => {}
            }
        }
        Ok(settings)
    }

    /// The payload of a SETTINGS frame of these settings, those of their
    /// initial value left out, and a reserved one (0x1f × `grease` + 0x21)
    /// if given, as endpoints should send (§7.2.4.1).
    pub fn encode(&self, grease: Option<u64>, out: &mut Vec<u8>) {
        let mut write = |id: u64, value: u64| {
            let _ = QUICVarint::write(out, id);
            let _ = QUICVarint::write(out, value);
        };
        if self.qpack_max_table_capacity != 0 {
            write(H3Settings::QPACK_MAX_TABLE_CAPACITY, self.qpack_max_table_capacity);
        }
        if let Some(size) = self.max_field_section_size {
            write(H3Settings::MAX_FIELD_SECTION_SIZE, size);
        }
        if self.qpack_blocked_streams != 0 {
            write(H3Settings::QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams);
        }
        if self.enable_connect_protocol {
            write(H3Settings::ENABLE_CONNECT_PROTOCOL, 1);
        }
        if let Some(n) = grease {
            write(0x1F * n + 0x21, n);
        }
    }
}
