//! The C ABI of [`crate::protocol::ethernet`].
//!
//! Addresses and tags are structures passed by value; a header is a
//! structure whose tags are the first `tag_count` of its array. An
//! EtherType crosses as its `u16`.

use alloc::string::ToString;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::ethernet::{EtherType, EthernetError, EthernetFrame, EthernetHeader, MACAddress, VLANTag};

/// The statuses of this module, one per variant of [`EthernetError`] that
/// is not another module's.
pub struct EthernetStatus;

impl EthernetStatus {
    pub const LENGTH: Status =
        Status::new(c"protocol.ethernet", c"Length", c"the frame is shorter than its header or length");
    pub const TAG: Status = Status::new(c"protocol.ethernet", c"Tag", c"the VLAN tags are invalid");
    pub const ETHER_TYPE: Status =
        Status::new(c"protocol.ethernet", c"EtherType", c"the type field is neither a length nor an EtherType");
    pub const SYNTAX: Status = Status::new(c"protocol.ethernet", c"Syntax", c"the text is not a MAC address");
}

impl ToStatus for EthernetError {
    fn to_status(&self) -> &'static Status {
        match self {
            EthernetError::Length => &EthernetStatus::LENGTH,
            EthernetError::Tag => &EthernetStatus::TAG,
            EthernetError::EtherType => &EthernetStatus::ETHER_TYPE,
            EthernetError::Syntax => &EthernetStatus::SYNTAX,
            EthernetError::Write(error) => error.to_status(),
        }
    }
}

/// The C form of an [`EthernetHeader`]: the first `tag_count` tags are present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FFIEthernetHeader {
    pub destination: MACAddress,
    pub source: MACAddress,
    pub tags: [VLANTag; EthernetHeader::MAXIMUM_TAGS],
    pub tag_count: u8,
    pub ether_type: u16,
}

impl FFIEthernetHeader {
    /// The tag of nothing, for the absent ones.
    pub const NO_TAG: VLANTag = VLANTag { protocol: EtherType(0), priority: 0, drop_eligible: false, identifier: 0 };

    pub fn from_rust(header: &EthernetHeader) -> FFIEthernetHeader {
        let mut tags = [FFIEthernetHeader::NO_TAG; EthernetHeader::MAXIMUM_TAGS];
        let mut count = 0;
        for (slot, tag) in tags.iter_mut().zip(header.tags.iter().flatten()) {
            *slot = *tag;
            count += 1;
        }
        FFIEthernetHeader {
            destination: header.destination,
            source: header.source,
            tags,
            tag_count: count,
            ether_type: header.ether_type.0,
        }
    }

    pub fn to_rust(&self) -> Result<EthernetHeader, &'static Status> {
        let count = self.tag_count as usize;
        if count > EthernetHeader::MAXIMUM_TAGS {
            return Err(&EthernetStatus::TAG);
        }
        let mut header = EthernetHeader::new(self.destination, self.source, EtherType(self.ether_type));
        for (slot, tag) in header.tags.iter_mut().zip(&self.tags[..count]) {
            *slot = Some(*tag);
        }
        Ok(header)
    }
}

impl Value for MACAddress {
    const TYPE: Type = Type::Named("umilib_protocol_ethernet_MACAddress");
}

impl Value for VLANTag {
    const TYPE: Type = Type::Named("umilib_protocol_ethernet_VLANTag");
}

impl Value for FFIEthernetHeader {
    const TYPE: Type = Type::Named("umilib_protocol_ethernet_EthernetHeader");
}

crate::ffi_functions! {
    /// Reads six hexadecimal pairs separated by colons or hyphens from the UTF-8 text at `text` into
    /// `out`; fails with Syntax.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_parse(text: *const u8, length: usize, out: *mut MACAddress) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            let address = text.parse::<MACAddress>().map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, address) }
        })())
    }

    /// Writes the lowercase text of `address`, separated by colons, into `out`.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_to_string(address: MACAddress, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable buffer.
        Status::from_result(unsafe { Pointer::write_text(out, address.to_string()) })
    }

    /// Whether the Individual/Group bit is set.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_is_multicast(address: MACAddress) -> bool {
        address.is_multicast()
    }

    /// ff:ff:ff:ff:ff:ff.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_is_broadcast(address: MACAddress) -> bool {
        address.is_broadcast()
    }

    /// Whether the Universal/Local bit is set.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_is_local(address: MACAddress) -> bool {
        address.is_local()
    }

    /// Writes the 8 bytes of the modified EUI-64 interface identifier of `address` into `out`.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_modified_eui64(address: MACAddress, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes 8 writable bytes.
            let out = unsafe { Pointer::slice_mut(out, 8) }?;
            out.copy_from_slice(&address.modified_eui64());
            Ok(())
        })())
    }

    /// Writes the address the IPv4 multicast address of the 4 bytes at `address` maps to into `out`.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_from_ipv4_multicast(address: *const u8, out: *mut MACAddress) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes 4 readable bytes and a writable pointer.
            let address = unsafe { Pointer::slice(address, 4) }?;
            let address: [u8; 4] = address.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, MACAddress::from_ipv4_multicast(address)) }
        })())
    }

    /// Writes the address the IPv6 multicast address of the 16 bytes at `address` maps to into `out`.
    pub unsafe extern "C" fn umilib_protocol_ethernet_mac_address_from_ipv6_multicast(address: *const u8, out: *mut MACAddress) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes 16 readable bytes and a writable pointer.
            let address = unsafe { Pointer::slice(address, 16) }?;
            let address: [u8; 16] = address.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write(out, MACAddress::from_ipv6_multicast(address)) }
        })())
    }

    /// Whether the type field `value` is the length of an IEEE 802.3 frame's data.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ether_type_is_length(value: u16) -> bool {
        EtherType(value).is_length()
    }

    /// Whether the type field `value` is an EtherType.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ether_type_is_ether_type(value: u16) -> bool {
        EtherType(value).is_ether_type()
    }

    /// Whether the EtherType `value` is that of a VLAN tag.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ether_type_is_tag(value: u16) -> bool {
        EtherType(value).is_tag()
    }

    /// The tag of the tag protocol identifier `protocol` and the tag control information `control`.
    pub unsafe extern "C" fn umilib_protocol_ethernet_vlan_tag_from_control(protocol: u16, control: u16) -> VLANTag {
        VLANTag::from_control(EtherType(protocol), control)
    }

    /// Writes the tag control information of `tag` into `out`; fails with Tag if a field does not fit.
    pub unsafe extern "C" fn umilib_protocol_ethernet_vlan_tag_control(tag: VLANTag, out: *mut u16) -> *const Status {
        Status::from_result((|| {
            let control = tag.control().ok_or(&EthernetStatus::TAG)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, control) }
        })())
    }

    /// Reads the header at the start of the `length` bytes at `bytes` into `out` and the offset and
    /// length of its data into `out_offset` and `out_length`; fails with Length, Tag or EtherType.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ethernet_header_decode(bytes: *const u8, length: usize, out: *mut FFIEthernetHeader, out_offset: *mut usize, out_length: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(bytes, length)],
                &[Pointer::range(out, 1), Pointer::range(out_offset, 1), Pointer::range(out_length, 1)],
            )?;
            // SAFETY: the caller passes readable bytes and writable pointers.
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            Pointer::check_range(out_offset, 1)?;
            Pointer::check_range(out_length, 1)?;
            let (header, data) = EthernetHeader::decode(bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, FFIEthernetHeader::from_rust(&header)) }?;
            unsafe { Pointer::write(out_offset, header.length()) }?;
            unsafe { Pointer::write(out_length, data.len()) }
        })())
    }

    /// Writes the bytes of the header into `out`; fails with Tag or EtherType.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ethernet_header_encode(header: *const FFIEthernetHeader, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid structure and a writable buffer.
            let header = unsafe { Pointer::reference(header) }?.to_rust()?;
            Pointer::check_range(out, 1)?;
            let mut bytes = crate::bytes::Buffer::new();
            header.encode(&mut bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes.into_vec())) }
        })())
    }

    /// Writes the 4 bytes of the frame check sequence of the `length` bytes at `frame` (the header
    /// and the data) into `out`, in the order they are sent.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ethernet_frame_fcs(frame: *const u8, length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(frame, length)], &[Pointer::range(out, EthernetFrame::FCS_LENGTH)])?;
            // SAFETY: the caller passes readable bytes and 4 writable bytes.
            let frame = unsafe { Pointer::slice(frame, length) }?;
            let out = unsafe { Pointer::slice_mut(out, EthernetFrame::FCS_LENGTH) }?;
            out.copy_from_slice(&EthernetFrame::fcs(frame));
            Ok(())
        })())
    }

    /// Writes whether the `length` bytes at `frame` end with the right frame check sequence into `out`.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ethernet_frame_verify(frame: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(frame, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let frame = unsafe { Pointer::slice(frame, length) }?;
            unsafe { Pointer::write(out, EthernetFrame::verify(frame)) }
        })())
    }

    /// The zero bytes to append to a header and data of `length` bytes to make the smallest frame.
    pub unsafe extern "C" fn umilib_protocol_ethernet_ethernet_frame_padding(length: usize) -> usize {
        EthernetFrame::padding(length)
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "ethernet",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_ethernet_MACAddress",
            documentation: " A 48-bit MAC address, in transmission byte order.",
            fields: &[Parameter { name: "octets", value: <[u8; 6] as Value>::TYPE }],
        },
        Definition::Structure {
            name: "umilib_protocol_ethernet_VLANTag",
            documentation: " A VLAN tag (IEEE 802.1Q): tag protocol identifier, priority, drop eligible, identifier.",
            fields: &[
                Parameter { name: "protocol", value: <u16 as Value>::TYPE },
                Parameter { name: "priority", value: <u8 as Value>::TYPE },
                Parameter { name: "drop_eligible", value: <bool as Value>::TYPE },
                Parameter { name: "identifier", value: <u16 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_ethernet_EthernetHeader",
            documentation: " The header of an Ethernet frame; the first tag_count tags, outermost first, are present.",
            fields: &[
                Parameter { name: "destination", value: <MACAddress as Value>::TYPE },
                Parameter { name: "source", value: <MACAddress as Value>::TYPE },
                Parameter { name: "tags", value: <[VLANTag; 2] as Value>::TYPE },
                Parameter { name: "tag_count", value: <u8 as Value>::TYPE },
                Parameter { name: "ether_type", value: <u16 as Value>::TYPE },
            ],
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
