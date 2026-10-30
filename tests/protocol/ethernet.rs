//! Tests of `umilib::protocol::ethernet`: MAC addresses (IEEE 802, RFC
//! 7042), the header with its VLAN tags (IEEE 802.1Q, 802.1ad), the
//! multicast mappings of RFC 1112 and RFC 2464, and the frame check
//! sequence, against frames of the Linux kernel.

use umilib::bytes::Buffer;
use umilib::hash::crc::{CRC, CRCCatalogue};
use umilib::protocol::ethernet::{EtherType, EthernetError, EthernetFrame, EthernetHeader, MACAddress, VLANTag};

use super::{Capture, Vectors};

fn mac(text: &str) -> MACAddress {
    text.parse().unwrap()
}

fn encode(header: &EthernetHeader) -> Vec<u8> {
    let mut buffer = Buffer::new();
    header.encode(&mut buffer).unwrap();
    buffer.into_vec()
}

#[test]
fn decodes_linux_frames() {
    let frames = Capture::frames("protocol/ethernet/linux.txt");
    assert!(frames.len() >= 50);
    for (description, frame) in &frames {
        let (header, data) = EthernetHeader::decode(frame).unwrap_or_else(|error| panic!("{error}: {description}"));
        // tcpdump: "source > destination, ethertype NAME (0x....), length N: vlan V, p P, ethertype ..."
        let (addresses, rest) = description.split_once(", ethertype ").unwrap();
        let (source, destination) = addresses.split_once(" > ").unwrap();
        assert_eq!(header.source, mac(source), "{description}");
        assert_eq!(header.destination, mac(destination), "{description}");
        assert_eq!(header.length() + data.len(), frame.len());
        let mut types: Vec<u16> = Vec::new();
        for part in rest.split("ethertype ").chain([rest]) {
            if let Some(start) = part.find("(0x") {
                types.push(u16::from_str_radix(&part[start + 3..start + 7], 16).unwrap());
            }
        }
        types.pop();
        let vlans: Vec<u16> =
            rest.split("vlan ").skip(1).map(|part| part.split(',').next().unwrap().parse().unwrap()).collect();
        let tags: Vec<VLANTag> = header.tags.iter().flatten().copied().collect();
        assert_eq!(tags.iter().map(|tag| tag.identifier).collect::<Vec<_>>(), vlans, "{description}");
        assert_eq!(tags.iter().map(|tag| tag.protocol.0).collect::<Vec<_>>(), types[..tags.len()], "{description}");
        assert_eq!(header.ether_type.0, *types.last().unwrap(), "{description}");
        assert_eq!(encode(&header), frame[..header.length()], "{description}");
    }
}

#[test]
fn mac_address_text() {
    assert_eq!(mac("02:00:00:00:00:0a"), MACAddress([2, 0, 0, 0, 0, 0x0A]));
    assert_eq!(mac("02:00:00:00:00:0A").to_string(), "02:00:00:00:00:0a");
    // IEEE writes the octets with hyphens (RFC 7042 §1.1).
    assert_eq!(mac("34-56-78-9A-BC-DE"), MACAddress([0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE]));
    assert_eq!("ff:ff:ff:ff:ff:ff".parse(), Ok(MACAddress::BROADCAST));
    for text in [
        "",
        "02:00:00:00:00",
        "02:00:00:00:00:0a:",
        "02-00:00:00:00:0a",
        "2:00:00:00:00:0a:0",
        "02:00:00:00:00:0g",
        "0200.0000.000a",
        "02:00:00:00:00:+a",
    ] {
        assert_eq!(text.parse::<MACAddress>(), Err(EthernetError::Syntax), "{text:?}");
    }
}

#[test]
fn mac_address_bits() {
    // IEEE 802 (RFC 7042 §2): the Individual/Group bit and the Universal/Local bit of the first octet.
    assert!(MACAddress::BROADCAST.is_broadcast() && MACAddress::BROADCAST.is_multicast());
    assert!(mac("01:00:5e:00:00:01").is_multicast() && !mac("01:00:5e:00:00:01").is_broadcast());
    assert!(mac("33:33:00:00:00:01").is_multicast());
    assert!(mac("00:00:5e:00:53:01").is_unicast() && !mac("00:00:5e:00:53:01").is_local());
    assert!(mac("02:00:00:00:00:0a").is_local() && mac("02:00:00:00:00:0a").is_unicast());
}

#[test]
fn modified_eui64_of_rfc2464() {
    // RFC 2464 §4: 34-56-78-9A-BC-DE gives 36-56-78-FF-FE-9A-BC-DE.
    let text = Vectors::read("protocol/ethernet/rfc2464.txt");
    assert!(text.contains("34-56-78-9A-BC-DE") && text.contains("36-56-78-FF-FE-9A-BC-DE"));
    assert_eq!(mac("34-56-78-9A-BC-DE").modified_eui64(), [0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE]);
    // The link-local addresses of the capture are those of the interfaces' addresses.
    assert_eq!(mac("02:00:00:00:00:0a").modified_eui64(), [0, 0, 0, 0xFF, 0xFE, 0, 0, 0x0A]);
}

#[test]
fn multicast_mappings() {
    // RFC 1112 §6.4: 01-00-5E and the low 23 bits of the group.
    assert_eq!(MACAddress::from_ipv4_multicast([224, 0, 0, 1]), mac("01:00:5e:00:00:01"));
    assert_eq!(MACAddress::from_ipv4_multicast([239, 255, 255, 250]), mac("01:00:5e:7f:ff:fa"));
    assert_eq!(MACAddress::from_ipv4_multicast([224, 128, 1, 2]), MACAddress::from_ipv4_multicast([239, 0, 1, 2]));
    // RFC 2464 §7: 33-33 and the last 32 bits; the capture's frames are so addressed.
    let mut checked = 0;
    for (description, frame) in Capture::frames("protocol/ethernet/linux.txt") {
        let (header, data) = EthernetHeader::decode(&frame).unwrap();
        if header.ether_type == EtherType::IPV6 && data[24] == 0xFF {
            let destination: [u8; 16] = data[24..40].try_into().unwrap();
            assert_eq!(MACAddress::from_ipv6_multicast(destination), header.destination, "{description}");
            checked += 1;
        }
    }
    assert!(checked >= 5);
}

#[test]
fn ether_types() {
    // IEEE 802.3 §3.2.6: up to 1,500 a length, from 0x0600 a type.
    assert!(EtherType(0).is_length() && EtherType(1500).is_length() && !EtherType(1501).is_length());
    assert!(EtherType(0x0600).is_ether_type() && !EtherType(0x05FF).is_ether_type());
    assert_eq!(EtherType::IPV4.0, 0x0800);
    assert_eq!(EtherType::ARP.0, 0x0806);
    assert_eq!(EtherType::IPV6.0, 0x86DD);
    assert_eq!(EtherType::VLAN.0, 0x8100);
    assert_eq!(EtherType::SERVICE_VLAN.0, 0x88A8);
    assert_eq!(EtherType::IPV6.to_string(), "0x86dd");
    let rfc = Vectors::read("protocol/ethernet/rfc7042.txt");
    assert!(rfc.contains("0x88B5  IEEE Std 802      - Local Experimental Ethertype"));
    assert_eq!((EtherType::EXPERIMENTAL_1.0, EtherType::EXPERIMENTAL_2.0), (0x88B5, 0x88B6));
}

#[test]
fn ieee_802_3_lengths() {
    // A type field up to 1,500 is the length of the data; the padding after it is not data.
    let mut frame = vec![0xFF; 6];
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&3u16.to_be_bytes());
    frame.extend_from_slice(&[0x42, 0x42, 0x03]);
    frame.extend_from_slice(&[0; 43]);
    let (header, data) = EthernetHeader::decode(&frame).unwrap();
    assert!(header.ether_type.is_length());
    assert_eq!(data, &[0x42, 0x42, 0x03]);
    frame[12..14].copy_from_slice(&100u16.to_be_bytes());
    assert_eq!(EthernetHeader::decode(&frame), Err(EthernetError::Length));
    for value in [1501u16, 1535] {
        frame[12..14].copy_from_slice(&value.to_be_bytes());
        assert_eq!(EthernetHeader::decode(&frame), Err(EthernetError::EtherType), "{value}");
    }
    let header = EthernetHeader::new(MACAddress::BROADCAST, MACAddress::ZERO, EtherType(1520));
    assert_eq!(header.encode(&mut Buffer::new()), Err(EthernetError::EtherType));
}

#[test]
fn vlan_tags() {
    // IEEE 802.1Q: priority (3 bits), drop eligible (1 bit), identifier (12 bits).
    let tag = VLANTag::from_control(EtherType::VLAN, 0xB064);
    assert_eq!((tag.priority, tag.drop_eligible, tag.identifier), (5, true, 100));
    assert_eq!(tag.control(), Some(0xB064));
    assert_eq!(VLANTag { priority: 8, ..tag }.control(), None);
    assert_eq!(VLANTag { identifier: 4096, ..tag }.control(), None);
    // VLAN identifier 4,095 is reserved and not sent (IEEE 802.1Q), but read.
    assert_eq!(VLANTag { identifier: 4095, ..tag }.control(), None);
    assert_eq!(VLANTag::from_control(EtherType::VLAN, 0x0FFF).identifier, 4095);
    assert_eq!(VLANTag { identifier: 4094, ..tag }.control(), Some(0xBFFE));
    let mut header = EthernetHeader::new(MACAddress::BROADCAST, mac("02:00:00:00:00:01"), EtherType::IPV4);
    header.tags = [Some(VLANTag { protocol: EtherType::SERVICE_VLAN, ..tag }), Some(tag)];
    let bytes = encode(&header);
    assert_eq!(&bytes[12..], &[0x88, 0xA8, 0xB0, 0x64, 0x81, 0x00, 0xB0, 0x64, 0x08, 0x00]);
    assert_eq!(EthernetHeader::decode(&bytes), Ok((header, &[][..])));
    // A tag after an absent one, a tag protocol that is not a tag's, a third tag.
    header.tags = [None, Some(tag)];
    assert_eq!(header.encode(&mut Buffer::new()), Err(EthernetError::Tag));
    header.tags = [Some(VLANTag { protocol: EtherType::IPV4, ..tag }), None];
    assert_eq!(header.encode(&mut Buffer::new()), Err(EthernetError::Tag));
    let mut three = bytes[..12].to_vec();
    for _ in 0..3 {
        three.extend_from_slice(&[0x81, 0x00, 0x00, 0x01]);
    }
    three.extend_from_slice(&[0x08, 0x00]);
    assert_eq!(EthernetHeader::decode(&three), Err(EthernetError::Tag));
    assert_eq!(EthernetHeader::decode(&three[..15]), Err(EthernetError::Length));
    // A tag protocol in the type field would read back as one more tag.
    for ether_type in [EtherType::VLAN, EtherType::SERVICE_VLAN] {
        let header = EthernetHeader::new(MACAddress::BROADCAST, mac("02:00:00:00:00:01"), ether_type);
        assert_eq!(header.encode(&mut Buffer::new()), Err(EthernetError::Tag));
    }
}

#[test]
fn frame_check_sequence() {
    // CRC-32 of IEEE 802.3 §3.2.9 (the check value of "123456789" is CBF43926),
    // sent least significant byte first.
    assert_eq!(EthernetFrame::fcs(b"123456789"), 0xCBF4_3926u32.to_le_bytes());
    let mut frame = Capture::frames("protocol/ethernet/linux.txt")[0].1.clone();
    let fcs = EthernetFrame::fcs(&frame);
    frame.extend_from_slice(&fcs);
    assert!(EthernetFrame::verify(&frame));
    // A frame with its sequence leaves the residue of CRC-32 (0xDEBB20E3 before the final complement).
    assert_eq!(CRC::checksum(CRCCatalogue::CRC32_ISO_HDLC, &frame), !0xDEBB_20E3);
    for index in [0, 13, frame.len() - 1] {
        let mut corrupted = frame.clone();
        corrupted[index] ^= 0x80;
        assert!(!EthernetFrame::verify(&corrupted));
    }
    assert!(!EthernetFrame::verify(&[0; 3]));
}

#[test]
fn padding_to_the_smallest_frame() {
    // IEEE 802.3 §3.2.7: 64 bytes with the frame check sequence.
    assert_eq!(EthernetFrame::padding(14 + 28), 18);
    assert_eq!(EthernetFrame::padding(60), 0);
    assert_eq!(EthernetFrame::padding(1514), 0);
    assert_eq!(EthernetFrame::padding(0), 60);
}
