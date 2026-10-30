use crate::bytes::Writer;

use super::{TCPError, TCPSequence};

/// The kind of a TCP option, from the IANA registry "TCP Option Kind
/// Numbers". Kinds without a constant here are kept as they are and ignored
/// (RFC 9293 MUST-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct TCPOptionKind(pub u8);

impl TCPOptionKind {
    /// End of Option List (RFC 9293 §3.2): the rest of the options is padding.
    pub const END: TCPOptionKind = TCPOptionKind(0);
    /// No-Operation (RFC 9293 §3.2).
    pub const NOP: TCPOptionKind = TCPOptionKind(1);
    /// Maximum Segment Size (RFC 9293 §3.2).
    pub const MSS: TCPOptionKind = TCPOptionKind(2);
    /// Window Scale (RFC 7323 §2).
    pub const WINDOW_SCALE: TCPOptionKind = TCPOptionKind(3);
    /// SACK-Permitted (RFC 2018 §2).
    pub const SACK_PERMITTED: TCPOptionKind = TCPOptionKind(4);
    /// SACK (RFC 2018 §3).
    pub const SACK: TCPOptionKind = TCPOptionKind(5);
    /// Timestamps (RFC 7323 §3).
    pub const TIMESTAMPS: TCPOptionKind = TCPOptionKind(8);
    /// TCP Fast Open Cookie (RFC 7413).
    pub const FAST_OPEN: TCPOptionKind = TCPOptionKind(34);
}

/// One option: its kind and the bytes after its kind and length octets
/// (none for End of Option List and No-Operation, which have no length).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TCPOption<'a> {
    pub kind: TCPOptionKind,
    pub data: &'a [u8],
}

impl TCPOption<'_> {
    /// Writes an option of `kind` with `data`; End of Option List and
    /// No-Operation take no data. Fails with [`TCPError::Option`] for data
    /// that does not fit a length octet.
    pub fn encode(kind: TCPOptionKind, data: &[u8], out: &mut impl Writer) -> Result<(), TCPError> {
        if kind == TCPOptionKind::END || kind == TCPOptionKind::NOP {
            if !data.is_empty() {
                return Err(TCPError::Option);
            }
            return Ok(out.write(&[kind.0])?);
        }
        let length = u8::try_from(data.len() + 2).map_err(|_| TCPError::Option)?;
        out.write(&[kind.0, length])?;
        Ok(out.write(data)?)
    }
}

/// The options of a segment, in order, No-Operation included; End of Option
/// List ends them. An option of an illegal length (below 2, or beyond the
/// options) ends them with [`TCPError::Option`] (RFC 9293 MUST-7). Options
/// need not start on a word boundary (MUST-64).
#[derive(Clone, Debug)]
pub struct TCPOptions<'a> {
    pub bytes: &'a [u8],
}

impl<'a> TCPOptions<'a> {
    pub fn new(bytes: &'a [u8]) -> TCPOptions<'a> {
        TCPOptions { bytes }
    }

    /// Checks that every option has a legal length.
    pub fn check(bytes: &[u8]) -> Result<(), TCPError> {
        for option in TCPOptions::new(bytes) {
            option?;
        }
        Ok(())
    }
}

impl<'a> Iterator for TCPOptions<'a> {
    type Item = Result<TCPOption<'a>, TCPError>;

    fn next(&mut self) -> Option<Result<TCPOption<'a>, TCPError>> {
        let (&kind, rest) = self.bytes.split_first()?;
        let kind = TCPOptionKind(kind);
        if kind == TCPOptionKind::END {
            self.bytes = &[];
            return None;
        }
        if kind == TCPOptionKind::NOP {
            self.bytes = rest;
            return Some(Ok(TCPOption { kind, data: &[] }));
        }
        let length = rest.first().map(|&length| length as usize);
        let Some(length) = length.filter(|&length| length >= 2 && length <= self.bytes.len()) else {
            self.bytes = &[];
            return Some(Err(TCPError::Option));
        };
        let option = TCPOption { kind, data: &self.bytes[2..length] };
        self.bytes = &self.bytes[length..];
        Some(Ok(option))
    }
}

/// A block of a SACK option (RFC 2018 §3): the data from `left` up to, not
/// including, `right` was received.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct TCPSACKBlock {
    pub left: TCPSequence,
    pub right: TCPSequence,
}

/// The values of a Timestamps option (RFC 7323 §3.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct TCPTimestamps {
    /// TSval: the sender's timestamp clock.
    pub value: u32,
    /// TSecr: the TSval echoed, when the ACK bit is set.
    pub echo_reply: u32,
}

/// The options this crate understands, read from or written to the options
/// of a segment: Maximum Segment Size, Window Scale, SACK-Permitted, SACK and
/// Timestamps. A known option of a size other than its own is ignored, as an
/// unknown one is (RFC 9293 MUST-6), as Linux does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TCPOptionSet {
    pub mss: Option<u16>,
    /// The shift count, at most [`TCPOptionSet::MAXIMUM_WINDOW_SCALE`].
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: Option<TCPTimestamps>,
    /// The SACK blocks: the first `sack_count` of them.
    pub sack_blocks: [TCPSACKBlock; TCPOptionSet::MAXIMUM_SACK_BLOCKS],
    pub sack_count: u8,
}

impl TCPOptionSet {
    /// The largest window scale (RFC 7323 §2.3).
    pub const MAXIMUM_WINDOW_SCALE: u8 = 14;
    /// The most SACK blocks that the 40 bytes of options hold (RFC 2018 §3).
    pub const MAXIMUM_SACK_BLOCKS: usize = 4;
    /// The most bytes of options a header holds (RFC 9293 §3.1).
    pub const MAXIMUM_LENGTH: usize = 40;

    /// The options of `bytes`. A window scale above 14 is read as 14 (RFC
    /// 7323 §2.3); a SACK option of more than four blocks keeps the first
    /// four. Fails with [`TCPError::Option`] for an illegal length.
    pub fn decode(bytes: &[u8]) -> Result<TCPOptionSet, TCPError> {
        let mut options = TCPOptionSet::default();
        for option in TCPOptions::new(bytes) {
            let option = option?;
            let data = option.data;
            match option.kind {
                TCPOptionKind::MSS if data.len() == 2 => options.mss = Some(u16::from_be_bytes([data[0], data[1]])),
                TCPOptionKind::WINDOW_SCALE if data.len() == 1 => {
                    options.window_scale = Some(data[0].min(TCPOptionSet::MAXIMUM_WINDOW_SCALE));
                }
                TCPOptionKind::SACK_PERMITTED if data.is_empty() => options.sack_permitted = true,
                TCPOptionKind::TIMESTAMPS if data.len() == 8 => {
                    let word = |index: usize| {
                        u32::from_be_bytes([data[index], data[index + 1], data[index + 2], data[index + 3]])
                    };
                    options.timestamps = Some(TCPTimestamps { value: word(0), echo_reply: word(4) });
                }
                TCPOptionKind::SACK if !data.is_empty() && data.len().is_multiple_of(8) => {
                    let blocks = data.as_chunks::<8>().0;
                    options.sack_count = blocks.len().min(TCPOptionSet::MAXIMUM_SACK_BLOCKS) as u8;
                    for (slot, block) in options.sack_blocks.iter_mut().zip(blocks) {
                        let left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
                        let right = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
                        *slot = TCPSACKBlock { left: TCPSequence(left), right: TCPSequence(right) };
                    }
                }
                _ => {}
            }
        }
        Ok(options)
    }

    /// The SACK blocks.
    pub fn sack(&self) -> &[TCPSACKBlock] {
        &self.sack_blocks[..(self.sack_count as usize).min(TCPOptionSet::MAXIMUM_SACK_BLOCKS)]
    }

    /// The options with `blocks` as their SACK blocks, the first four of them.
    pub fn with_sack(mut self, blocks: &[TCPSACKBlock]) -> TCPOptionSet {
        self.sack_count = blocks.len().min(TCPOptionSet::MAXIMUM_SACK_BLOCKS) as u8;
        for (slot, block) in self.sack_blocks.iter_mut().zip(blocks) {
            *slot = *block;
        }
        self
    }

    /// The length of the options [`TCPOptionSet::encode`] writes, a multiple of 4.
    pub fn length(&self) -> usize {
        let mss = if self.mss.is_some() { 4 } else { 0 };
        let timestamps = if self.timestamps.is_some() { 12 } else { 0 };
        let sack_permitted = if self.sack_permitted && self.timestamps.is_none() { 4 } else { 0 };
        let window_scale = if self.window_scale.is_some() { 4 } else { 0 };
        let sack = if self.sack().is_empty() { 0 } else { 4 + 8 * self.sack().len() };
        mss + timestamps + sack_permitted + window_scale + sack
    }

    /// Writes the options as Linux lays them out, each group aligned to 4
    /// bytes with No-Operations: MSS; SACK-Permitted and Timestamps (or
    /// SACK-Permitted alone); Window Scale; SACK. Fails with
    /// [`TCPError::Option`] if they do not fit 40 bytes, or for a window
    /// scale above 14.
    pub fn encode(&self, out: &mut impl Writer) -> Result<(), TCPError> {
        if self.length() > TCPOptionSet::MAXIMUM_LENGTH
            || self.window_scale.is_some_and(|scale| scale > TCPOptionSet::MAXIMUM_WINDOW_SCALE)
        {
            return Err(TCPError::Option);
        }
        if let Some(mss) = self.mss {
            let [high, low] = mss.to_be_bytes();
            out.write(&[TCPOptionKind::MSS.0, 4, high, low])?;
        }
        match (self.timestamps, self.sack_permitted) {
            (Some(timestamps), sack_permitted) => {
                let lead = if sack_permitted { [TCPOptionKind::SACK_PERMITTED.0, 2] } else { [1, 1] };
                out.write(&lead)?;
                out.write(&[TCPOptionKind::TIMESTAMPS.0, 10])?;
                out.write(&timestamps.value.to_be_bytes())?;
                out.write(&timestamps.echo_reply.to_be_bytes())?;
            }
            (None, true) => out.write(&[1, 1, TCPOptionKind::SACK_PERMITTED.0, 2])?,
            (None, false) => {}
        }
        if let Some(scale) = self.window_scale {
            out.write(&[1, TCPOptionKind::WINDOW_SCALE.0, 3, scale])?;
        }
        let sack = self.sack();
        if !sack.is_empty() {
            out.write(&[1, 1, TCPOptionKind::SACK.0, (2 + 8 * sack.len()) as u8])?;
            for block in sack {
                out.write(&block.left.0.to_be_bytes())?;
                out.write(&block.right.0.to_be_bytes())?;
            }
        }
        Ok(())
    }
}
