use alloc::vec::Vec;

use super::{H2Error, H2ErrorCode};

/// The identifier of a setting (RFC 9113 §6.5.2, RFC 8441 §3, RFC 9218 §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct H2SettingID(pub u16);

impl H2SettingID {
    pub const HEADER_TABLE_SIZE: H2SettingID = H2SettingID(0x1);
    pub const ENABLE_PUSH: H2SettingID = H2SettingID(0x2);
    pub const MAX_CONCURRENT_STREAMS: H2SettingID = H2SettingID(0x3);
    pub const INITIAL_WINDOW_SIZE: H2SettingID = H2SettingID(0x4);
    pub const MAX_FRAME_SIZE: H2SettingID = H2SettingID(0x5);
    pub const MAX_HEADER_LIST_SIZE: H2SettingID = H2SettingID(0x6);
    pub const ENABLE_CONNECT_PROTOCOL: H2SettingID = H2SettingID(0x8);
    pub const NO_RFC7540_PRIORITIES: H2SettingID = H2SettingID(0x9);
}

/// The settings of one end (RFC 9113 §6.5.2), each with its initial value
/// until a SETTINGS frame changes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct H2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    /// `None` for no limit, as initially.
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    /// `None` for no limit, as initially.
    pub max_header_list_size: Option<u32>,
    pub enable_connect_protocol: bool,
    pub no_rfc7540_priorities: bool,
}

impl Default for H2Settings {
    fn default() -> H2Settings {
        H2Settings {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: H2Settings::DEFAULT_WINDOW,
            max_frame_size: H2Settings::MINIMUM_FRAME_SIZE,
            max_header_list_size: None,
            enable_connect_protocol: false,
            no_rfc7540_priorities: false,
        }
    }
}

impl H2Settings {
    /// The initial flow-control window (RFC 9113 §6.9.2).
    pub const DEFAULT_WINDOW: u32 = 65_535;
    /// The largest window: 2^31 - 1 (RFC 9113 §6.9.1).
    pub const MAXIMUM_WINDOW: u32 = (1 << 31) - 1;
    /// The bounds of SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2).
    pub const MINIMUM_FRAME_SIZE: u32 = 1 << 14;
    pub const MAXIMUM_FRAME_SIZE: u32 = (1 << 24) - 1;

    /// Applies a setting the peer sent (RFC 9113 §6.5.2, RFC 8441 §3, RFC
    /// 9218 §2.1); unknown ones are ignored. Fails for values out of range
    /// and for turning extended CONNECT off once on.
    pub fn apply(&mut self, id: H2SettingID, value: u32) -> Result<(), H2Error> {
        let flag = |value: u32| match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(H2Error::protocol("a setting of a flag above 1")),
        };
        match id {
            H2SettingID::HEADER_TABLE_SIZE => self.header_table_size = value,
            H2SettingID::ENABLE_PUSH => self.enable_push = flag(value)?,
            H2SettingID::MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = Some(value),
            H2SettingID::INITIAL_WINDOW_SIZE => {
                if value > H2Settings::MAXIMUM_WINDOW {
                    return Err(H2Error::connection(
                        H2ErrorCode::FLOW_CONTROL_ERROR,
                        "an initial window above 2^31 - 1",
                    ));
                }
                self.initial_window_size = value;
            }
            H2SettingID::MAX_FRAME_SIZE => {
                if !(H2Settings::MINIMUM_FRAME_SIZE..=H2Settings::MAXIMUM_FRAME_SIZE).contains(&value) {
                    return Err(H2Error::protocol("a maximum frame size out of range"));
                }
                self.max_frame_size = value;
            }
            H2SettingID::MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),
            H2SettingID::ENABLE_CONNECT_PROTOCOL => {
                let enabled = flag(value)?;
                if self.enable_connect_protocol && !enabled {
                    return Err(H2Error::protocol("extended CONNECT turned off"));
                }
                self.enable_connect_protocol = enabled;
            }
            H2SettingID::NO_RFC7540_PRIORITIES => self.no_rfc7540_priorities = flag(value)?,
            _ => {}
        }
        Ok(())
    }

    /// The settings that differ from the initial ones, to send.
    pub fn changes(&self) -> Vec<(H2SettingID, u32)> {
        let initial = H2Settings::default();
        let mut changes = Vec::new();
        if self.header_table_size != initial.header_table_size {
            changes.push((H2SettingID::HEADER_TABLE_SIZE, self.header_table_size));
        }
        if self.enable_push != initial.enable_push {
            changes.push((H2SettingID::ENABLE_PUSH, u32::from(self.enable_push)));
        }
        if let Some(maximum) = self.max_concurrent_streams {
            changes.push((H2SettingID::MAX_CONCURRENT_STREAMS, maximum));
        }
        if self.initial_window_size != initial.initial_window_size {
            changes.push((H2SettingID::INITIAL_WINDOW_SIZE, self.initial_window_size));
        }
        if self.max_frame_size != initial.max_frame_size {
            changes.push((H2SettingID::MAX_FRAME_SIZE, self.max_frame_size));
        }
        if let Some(maximum) = self.max_header_list_size {
            changes.push((H2SettingID::MAX_HEADER_LIST_SIZE, maximum));
        }
        if self.enable_connect_protocol {
            changes.push((H2SettingID::ENABLE_CONNECT_PROTOCOL, 1));
        }
        if self.no_rfc7540_priorities {
            changes.push((H2SettingID::NO_RFC7540_PRIORITIES, 1));
        }
        changes
    }
}
