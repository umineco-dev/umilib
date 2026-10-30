//! Tests of `umilib::protocol::ip`: the addresses and their text forms
//! (RFC 4291, RFC 5952), special addresses (RFC 6890), the Internet
//! checksum (RFC 1071, RFC 1624), the pseudo-headers and the reassembly
//! buffer of fragments.

#[cfg(umilib_feature = "protocol-ip-v4")]
mod v4;
#[cfg(umilib_feature = "protocol-ip-v6")]
mod v6;

use umilib::protocol::ip::{
    IPAddress, IPError, IPFragmentBuffer, IPProtocol, IPPseudoHeader, IPv4Address, IPv6Address, InternetChecksum,
};

use super::{RFC, Vectors};

/// The bytes of the example of RFC 1071 §3, read from the "Byte n/m" lines.
fn rfc1071_example() -> Vec<u8> {
    let section = RFC::section("protocol/ip/rfc1071.txt", "3. Numerical Examples", "4.");
    let mut bytes = Vec::new();
    // The first table, of byte pairs ("Byte 0/1:").
    for line in section.lines().map(str::trim).filter(|line| line.starts_with("Byte ")).take(4) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        bytes.push(u8::from_str_radix(fields[2], 16).unwrap());
        bytes.push(u8::from_str_radix(fields[3], 16).unwrap());
    }
    bytes
}

#[test]
fn checksum_rfc1071_example() {
    let bytes = rfc1071_example();
    assert_eq!(bytes, [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]);
    let mut checksum = InternetChecksum::new();
    checksum.update(&bytes);
    // RFC 1071 §3: every order of summing gives the folded sum ddf2.
    assert_eq!(checksum.sum16(), 0xDDF2);
    assert_eq!(checksum.finish(), !0xDDF2);
    assert_eq!(InternetChecksum::checksum(&bytes), !0xDDF2);
}

#[test]
fn checksum_is_independent_of_the_split() {
    let data: Vec<u8> = (0..1031u32).map(|index| (index.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let whole = InternetChecksum::checksum(&data);
    for first in [0, 1, 2, 3, 5, 8, 511, 1030, 1031] {
        for second in [first, first + 1, first + 7] {
            let second = second.min(data.len());
            let mut checksum = InternetChecksum::new();
            checksum.update(&data[..first]);
            checksum.update(&data[first..second]);
            checksum.update(&data[second..]);
            assert_eq!(checksum.finish(), whole, "split at {first} and {second}");
        }
    }
    let mut bytewise = InternetChecksum::new();
    for byte in &data {
        bytewise.update(core::slice::from_ref(byte));
    }
    assert_eq!(bytewise.finish(), whole);
}

#[test]
fn checksum_pads_an_odd_byte_with_zero() {
    // RFC 1071 §1: the odd byte is the high byte of a word whose low byte is zero.
    assert_eq!(InternetChecksum::checksum(&[0x12, 0x34, 0x56]), !(0x1234u16 + 0x5600));
    assert_eq!(InternetChecksum::checksum(&[0x12, 0x34, 0x56, 0x00]), InternetChecksum::checksum(&[0x12, 0x34, 0x56]));
    // The sum of nothing is +0, whose complement is all ones.
    assert_eq!(InternetChecksum::checksum(&[]), 0xFFFF);
}

#[test]
fn checksum_folds_carries_around() {
    // 0xFFFF + 0x0001 = 0x10000, folded to 0x0001 (end-around carry).
    let mut checksum = InternetChecksum::new();
    checksum.update(&[0xFF, 0xFF, 0x00, 0x01]);
    assert_eq!(checksum.sum16(), 0x0001);
    // A large input of all ones keeps the sum at -0.
    let ones = vec![0xFFu8; 200_000];
    let mut checksum = InternetChecksum::new();
    checksum.update(&ones);
    assert_eq!(checksum.sum16(), 0xFFFF);
}

#[test]
fn checksum_from_any_sum() {
    // A checksum whose sum is set from outside, however large, continues it.
    let mut large = InternetChecksum { sum: u64::MAX - 10, odd: false };
    let start = InternetChecksum::fold(large.sum);
    large.update(&[0xFF; 1000]);
    let mut small = InternetChecksum { sum: start as u64, odd: false };
    small.update(&[0xFF; 1000]);
    assert_eq!(large.sum16(), small.sum16());
}

#[test]
fn checksum_verification() {
    // RFC 1071 §1: data with its checksum sums to all ones.
    let mut data = rfc1071_example();
    data.extend_from_slice(&[0, 0]);
    let checksum = InternetChecksum::checksum(&data);
    data[8..].copy_from_slice(&checksum.to_be_bytes());
    assert!(InternetChecksum::verify(&data));
    for index in 0..data.len() {
        let mut corrupted = data.clone();
        corrupted[index] ^= 0x10;
        assert!(!InternetChecksum::verify(&corrupted), "byte {index}");
    }
}

#[test]
fn checksum_rfc1624_example() {
    let section = RFC::section("protocol/ip/rfc1624.txt", "4.  Examples", "5.  Checksum verification");
    assert!(section.contains("m = 0x5555") && section.contains("m' = 0x3285") && section.contains("0xCD7A"));
    let (sum, old, new) = (0xCD7Au16, 0x5555u16, 0x3285u16);
    let checksum = !InternetChecksum::fold(sum as u64 + old as u64);
    assert_eq!(checksum, 0xDD2F);
    // [Eqn. 3] gives the checksum computed from scratch, 0x0000, where [Eqn. 2] gives 0xFFFF.
    assert_eq!(InternetChecksum::adjust(checksum, old, new), 0x0000);
    assert_eq!(InternetChecksum::adjust(checksum, old, new), !InternetChecksum::fold(sum as u64 + new as u64));
}

#[test]
fn checksum_adjustment_matches_recomputation() {
    let mut data: Vec<u8> = (0..64u32).map(|index| (index * 37 + 11) as u8).collect();
    for step in 0..200u32 {
        let checksum = InternetChecksum::checksum(&data);
        let index = ((step as usize * 6) % 62) & !1;
        let old = [data[index], data[index + 1]];
        let new = [(step * 29) as u8, (step * 53 + 1) as u8];
        data[index..index + 2].copy_from_slice(&new);
        let expected = InternetChecksum::checksum(&data);
        assert_eq!(InternetChecksum::adjust(checksum, u16::from_be_bytes(old), u16::from_be_bytes(new)), expected);
        assert_eq!(InternetChecksum::adjust_bytes(checksum, &old, &new), Some(expected));
    }
    // A longer and an odd-length change at an even offset.
    let checksum = InternetChecksum::checksum(&data);
    let old = data[10..17].to_vec();
    data[10..17].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(InternetChecksum::adjust_bytes(checksum, &old, &data[10..17]), Some(InternetChecksum::checksum(&data)));
    assert_eq!(InternetChecksum::adjust_bytes(checksum, &[1, 2], &[1]), None);
}

#[test]
fn ipv4_text() {
    let address: IPv4Address = "192.0.2.1".parse().unwrap();
    assert_eq!(address, IPv4Address::new(192, 0, 2, 1));
    assert_eq!(address.to_string(), "192.0.2.1");
    assert_eq!("0.0.0.0".parse::<IPv4Address>(), Ok(IPv4Address::UNSPECIFIED));
    assert_eq!("255.255.255.255".parse::<IPv4Address>(), Ok(IPv4Address::BROADCAST));
    // Not dotted decimal of four numbers up to 255; leading zeros, which
    // some readers take as octal, are refused (RFC 6943 §3.1.1).
    for text in [
        "",
        "1.2.3",
        "1.2.3.4.5",
        "256.1.1.1",
        "1.2.3.-4",
        "01.2.3.4",
        "1.2.3.4 ",
        " 1.2.3.4",
        "1..3.4",
        "1.2.3.4.",
        "0x1.2.3.4",
        "1.2.3.1000",
    ] {
        assert_eq!(text.parse::<IPv4Address>(), Err(IPError::Syntax), "{text:?}");
    }
}

/// The address of eight words.
fn words(words: [u16; 8]) -> IPv6Address {
    IPv6Address::from_words(words)
}

#[test]
fn ipv6_text_forms_of_rfc4291() {
    // RFC 4291 §2.2: the preferred form, the compressed form and the mixed form.
    let cases: [(&str, [u16; 8]); 12] = [
        ("ABCD:EF01:2345:6789:ABCD:EF01:2345:6789", [0xABCD, 0xEF01, 0x2345, 0x6789, 0xABCD, 0xEF01, 0x2345, 0x6789]),
        ("2001:DB8:0:0:8:800:200C:417A", [0x2001, 0xDB8, 0, 0, 8, 0x800, 0x200C, 0x417A]),
        ("2001:DB8::8:800:200C:417A", [0x2001, 0xDB8, 0, 0, 8, 0x800, 0x200C, 0x417A]),
        ("FF01:0:0:0:0:0:0:101", [0xFF01, 0, 0, 0, 0, 0, 0, 0x101]),
        ("FF01::101", [0xFF01, 0, 0, 0, 0, 0, 0, 0x101]),
        ("0:0:0:0:0:0:0:1", [0, 0, 0, 0, 0, 0, 0, 1]),
        ("::1", [0, 0, 0, 0, 0, 0, 0, 1]),
        ("0:0:0:0:0:0:0:0", [0; 8]),
        ("::", [0; 8]),
        ("0:0:0:0:0:0:13.1.68.3", [0, 0, 0, 0, 0, 0, 0x0D01, 0x4403]),
        ("::13.1.68.3", [0, 0, 0, 0, 0, 0, 0x0D01, 0x4403]),
        ("::FFFF:129.144.52.38", [0, 0, 0, 0, 0, 0xFFFF, 0x8190, 0x3426]),
    ];
    let text = Vectors::read("protocol/ip/rfc4291.txt");
    for (form, expected) in cases {
        assert!(text.contains(form), "{form} is not in RFC 4291");
        assert_eq!(form.parse::<IPv6Address>(), Ok(words(expected)), "{form}");
    }
}

#[test]
fn ipv6_flexible_forms_of_rfc5952() {
    // RFC 5952 §2: every form of each group is the same address.
    let groups: [&[&str]; 5] = [
        &[
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:0001",
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:001",
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:01",
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:1",
        ],
        &["2001:db8:aaaa:bbbb:cccc:dddd::1", "2001:db8:aaaa:bbbb:cccc:dddd:0:1"],
        &["2001:db8:0:0:0::1", "2001:db8:0:0::1", "2001:db8:0::1", "2001:db8::1"],
        &["2001:db8::aaaa:0:0:1", "2001:db8:0:0:aaaa::1"],
        &[
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:aaaa",
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:AAAA",
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:AaAa",
        ],
    ];
    let text = Vectors::read("protocol/ip/rfc5952.txt");
    for group in groups {
        let first: IPv6Address = group[0].parse().unwrap();
        for form in group {
            assert!(text.contains(form), "{form} is not in RFC 5952");
            assert_eq!(form.parse::<IPv6Address>(), Ok(first), "{form}");
        }
    }
}

#[test]
fn ipv6_canonical_text_of_rfc5952() {
    // RFC 5952 §4 and §5: the one text form of an address.
    let cases = [
        // §4.1: leading zeros suppressed, a zero field as 0.
        ("2001:0db8::0001", "2001:db8::1"),
        ("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),
        // §4.2.1: "::" used to its maximum.
        ("2001:db8:0:0:0:0:2:1", "2001:db8::2:1"),
        ("2001:db8::0:1", "2001:db8::1"),
        // §4.2.2: not for one field.
        ("2001:db8::1:1:1:1:1", "2001:db8:0:1:1:1:1:1"),
        // §4.2.3: the longest run, else the first.
        ("2001:0:0:1:0:0:0:1", "2001:0:0:1::1"),
        ("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"),
        // §4.3: lowercase.
        ("2001:DB8::ABCD", "2001:db8::abcd"),
        // §5: IPv4-mapped addresses in mixed notation.
        ("0:0:0:0:0:ffff:192.0.2.1", "::ffff:192.0.2.1"),
        ("::ffff:c000:0201", "::ffff:192.0.2.1"),
        // The ends of the address.
        ("0:0:0:0:0:0:0:0", "::"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("1:0:0:0:0:0:0:0", "1::"),
        ("0:0:1:0:0:0:0:0", "0:0:1::"),
        ("1:0:0:0:0:0:0:1", "1::1"),
        ("0:1:0:1:0:1:0:1", "0:1:0:1:0:1:0:1"),
        ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        // Embedded IPv4 without the mapped prefix is hexadecimal.
        ("::192.0.2.1", "::c000:201"),
        ("64:ff9b::192.0.2.1", "64:ff9b::c000:201"),
    ];
    let text = Vectors::read("protocol/ip/rfc5952.txt");
    for (input, canonical) in cases {
        let address: IPv6Address = input.parse().unwrap_or_else(|_| panic!("{input}"));
        assert_eq!(address.to_string(), canonical, "{input}");
        assert_eq!(canonical.parse::<IPv6Address>(), Ok(address), "{canonical}");
    }
    for quoted in ["2001:db8::2:1", "2001:db8:0:1:1:1:1:1", "2001:db8::1:0:0:1", "::ffff:192.0.2.1"] {
        assert!(text.contains(quoted), "{quoted} is not in RFC 5952");
    }
}

#[test]
fn ipv6_canonical_text_round_trips() {
    // Every address of fields 0 and 1 has one text form that reads back.
    for bits in 0u32..256 {
        let mut fields = [0u16; 8];
        for (index, field) in fields.iter_mut().enumerate() {
            *field = ((bits >> index) & 1) as u16;
        }
        let address = words(fields);
        let text = address.to_string();
        assert_eq!(text.parse::<IPv6Address>(), Ok(address), "{text}");
        assert!(!text.contains(":::"), "{text}");
        assert!(text.matches("::").count() <= 1, "{text}");
    }
}

#[test]
fn ipv6_invalid_text() {
    let invalid = [
        "",
        ":",
        ":::",
        "1::2::3",
        "::1::",
        "12345::",
        "1:2:3:4:5:6:7:8:9",
        "1:2:3:4:5:6:7",
        // "::" stands for at least one group.
        "1:2:3:4:5:6:7:8::",
        "::1:2:3:4:5:6:7:8",
        "1:2:3:4::5:6:7:8",
        ":1::",
        "1::2:",
        "1:2:3:4:5:6:7:",
        "g::",
        "1.2.3.4",
        "::1.2.3",
        "::1.2.3.4.5",
        "::256.1.1.1",
        "1.2.3.4::",
        "::1.2.3.4:1",
        "1:2:3:4:5:6:7:1.2.3.4",
        "1:2:3:4:5:6:7:8:1.2.3.4",
        "::ffff:1.2.3.4%eth0",
        "[::1]",
        " ::1",
    ];
    for text in invalid {
        assert_eq!(text.parse::<IPv6Address>(), Err(IPError::Syntax), "{text:?}");
    }
    // Seven groups and the IPv4 part make eight.
    assert!("1:2:3:4:5:6:1.2.3.4".parse::<IPv6Address>().is_ok());
    assert!("1:2:3:4:5::1.2.3.4".parse::<IPv6Address>().is_ok());
}

#[test]
fn ipv4_special_addresses() {
    // RFC 6890 §2.2.2 and the references of its table.
    let address = |text: &str| text.parse::<IPv4Address>().unwrap();
    for text in ["127.0.0.1", "127.255.255.255", "127.1.2.3"] {
        assert!(address(text).is_loopback(), "{text}");
    }
    assert!(!address("128.0.0.1").is_loopback());
    for text in ["10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255"] {
        assert!(address(text).is_private(), "{text}");
    }
    for text in ["9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0"] {
        assert!(!address(text).is_private(), "{text}");
    }
    assert!(address("169.254.0.0").is_link_local() && address("169.254.255.255").is_link_local());
    assert!(!address("169.253.255.255").is_link_local() && !address("169.255.0.0").is_link_local());
    assert!(address("224.0.0.0").is_multicast() && address("239.255.255.255").is_multicast());
    assert!(!address("223.255.255.255").is_multicast() && !address("240.0.0.0").is_multicast());
    for text in ["192.0.2.0", "192.0.2.255", "198.51.100.7", "203.0.113.255"] {
        assert!(address(text).is_documentation(), "{text}");
    }
    for text in ["192.0.3.0", "198.51.101.0", "203.0.112.255"] {
        assert!(!address(text).is_documentation(), "{text}");
    }
    assert!(IPv4Address::BROADCAST.is_broadcast() && !address("255.255.255.254").is_broadcast());
    assert!(IPv4Address::UNSPECIFIED.is_unspecified() && !address("0.0.0.1").is_unspecified());
    let table = Vectors::read("protocol/ip/rfc6890.txt");
    for block in ["10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24", "192.168.0.0/16"] {
        assert!(table.contains(block), "{block}");
    }
}

#[test]
fn ipv6_special_addresses() {
    let address = |text: &str| text.parse::<IPv6Address>().unwrap();
    assert!(address("::1").is_loopback() && !address("::2").is_loopback() && !address("::").is_loopback());
    assert!(address("::").is_unspecified() && !address("::1").is_unspecified());
    // RFC 4291 §2.5.6: fe80::/10.
    assert!(address("fe80::1").is_link_local() && address("febf:ffff::").is_link_local());
    assert!(!address("fec0::").is_link_local() && !address("fe7f::").is_link_local());
    // RFC 4193: fc00::/7.
    assert!(address("fc00::").is_unique_local() && address("fdff:ffff::").is_unique_local());
    assert!(!address("fe00::").is_unique_local() && !address("fbff::").is_unique_local());
    // RFC 3849 and RFC 9637.
    assert!(address("2001:db8::").is_documentation() && address("2001:db8:ffff::1").is_documentation());
    assert!(address("3fff::").is_documentation() && address("3fff:fff::1").is_documentation());
    assert!(!address("3ffe:ffff::").is_documentation() && !address("3ff0::").is_documentation());
    assert!(!address("2001:db9::").is_documentation() && !address("3fff:1000::").is_documentation());
    let rfc9637 = Vectors::read("protocol/ip/rfc9637.txt");
    assert!(rfc9637.contains("3fff::/20"));
    // RFC 4291 §2.7: ff00::/8 and its scope field.
    assert!(address("ff02::1").is_multicast() && !address("fe02::1").is_multicast());
    assert_eq!(address("ff02::1").multicast_scope(), Some(2));
    assert_eq!(address("ff0e::1").multicast_scope(), Some(14));
    assert_eq!(address("ff15::1").multicast_scope(), Some(5));
    assert_eq!(address("fe80::1").multicast_scope(), None);
    assert_eq!(IPv6Address::ALL_NODES, address("ff02::1"));
    assert_eq!(IPv6Address::ALL_ROUTERS, address("ff02::2"));
    assert_eq!(IPv6Address::LOOPBACK, address("::1"));
}

#[test]
fn ipv6_solicited_node_address() {
    // RFC 4291 §2.7.1.
    let text = Vectors::read("protocol/ip/rfc4291.txt");
    assert!(text.contains("the IPv6 address 4037::01:800:200E:8C6C is FF02::1:FF0E:8C6C"));
    let address: IPv6Address = "4037::01:800:200E:8C6C".parse().unwrap();
    assert_eq!(address.solicited_node(), "FF02::1:FF0E:8C6C".parse().unwrap());
}

#[test]
fn ipv6_interface_identifiers() {
    // RFC 4291 §2.5.1 and §2.5.6.
    let identifier = [0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE];
    let link_local = IPv6Address::link_local(identifier);
    assert_eq!(link_local.to_string(), "fe80::3656:78ff:fe9a:bcde");
    assert!(link_local.is_link_local());
    assert_eq!(link_local.interface_identifier(), identifier);
    let prefix = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 1];
    assert_eq!(
        IPv6Address::from_interface_identifier(prefix, identifier).to_string(),
        "2001:db8:0:1:3656:78ff:fe9a:bcde"
    );
}

#[test]
fn ipv4_mapped_addresses() {
    // RFC 4291 §2.5.5.2.
    let address = IPv4Address::new(192, 0, 2, 33);
    let mapped = address.to_ipv6_mapped();
    assert_eq!(mapped, "::ffff:192.0.2.33".parse().unwrap());
    assert_eq!(mapped.to_ipv4_mapped(), Some(address));
    assert_eq!("::192.0.2.33".parse::<IPv6Address>().unwrap().to_ipv4_mapped(), None);
    assert_eq!(IPAddress::V6(mapped).to_canonical(), IPAddress::V4(address));
    assert_eq!(IPAddress::V6(IPv6Address::LOOPBACK).to_canonical(), IPAddress::V6(IPv6Address::LOOPBACK));
}

#[test]
fn prefixes() {
    let address = IPv4Address::new(192, 168, 37, 201);
    assert_eq!(address.prefix(24), IPv4Address::new(192, 168, 37, 0));
    assert_eq!(address.prefix(20), IPv4Address::new(192, 168, 32, 0));
    assert_eq!(address.prefix(0), IPv4Address::UNSPECIFIED);
    assert_eq!(address.prefix(32), address);
    assert_eq!(address.prefix(40), address);
    assert!(address.has_prefix(&IPv4Address::new(192, 168, 0, 0), 16));
    assert!(!address.has_prefix(&IPv4Address::new(192, 169, 0, 0), 16));
    assert!(address.has_prefix(&IPv4Address::UNSPECIFIED, 0));
    assert_eq!(IPv4Address::mask(24), 0xFFFF_FF00);
    let address: IPv6Address = "2001:db8:1234:5678:9abc::1".parse().unwrap();
    assert_eq!(address.prefix(48).to_string(), "2001:db8:1234::");
    assert_eq!(address.prefix(127).to_string(), "2001:db8:1234:5678:9abc::");
    assert!(address.has_prefix(&"2001:db8::".parse().unwrap(), 32));
    assert!(!address.has_prefix(&"2001:db9::".parse().unwrap(), 32));
    assert_eq!(address.prefix(128), address);
    assert_eq!(IPv6Address::from_bits(address.to_bits()), address);
    assert_eq!(IPv4Address::from_bits(0xC000_0201), IPv4Address::new(192, 0, 2, 1));
}

#[test]
fn ip_addresses() {
    assert_eq!("192.0.2.1".parse::<IPAddress>(), Ok(IPAddress::V4(IPv4Address::new(192, 0, 2, 1))));
    assert_eq!("2001:db8::1".parse::<IPAddress>().map(|address| address.version()), Ok(6));
    assert_eq!("2001:db8::1".parse::<IPAddress>().unwrap().to_string(), "2001:db8::1");
    assert_eq!(IPAddress::from_octets(&[10, 0, 0, 1]), Ok(IPAddress::V4(IPv4Address::new(10, 0, 0, 1))));
    assert_eq!(IPAddress::from_octets(&[0; 16]), Ok(IPAddress::V6(IPv6Address::UNSPECIFIED)));
    assert_eq!(IPAddress::from_octets(&[0; 5]), Err(IPError::Length));
    assert_eq!(IPAddress::V4(IPv4Address::LOOPBACK).octets(), &[127, 0, 0, 1]);
    assert!("not an address".parse::<IPAddress>().is_err());
}

#[test]
fn protocol_numbers() {
    // The IANA registry "Assigned Internet Protocol Numbers".
    let cases = [
        (IPProtocol::HOP_BY_HOP_OPTIONS, 0, "HOPOPT"),
        (IPProtocol::ICMP, 1, "ICMP"),
        (IPProtocol::TCP, 6, "TCP"),
        (IPProtocol::UDP, 17, "UDP"),
        (IPProtocol::IPV6_ROUTING, 43, "IPv6-Route"),
        (IPProtocol::IPV6_FRAGMENT, 44, "IPv6-Frag"),
        (IPProtocol::ESP, 50, "ESP"),
        (IPProtocol::AH, 51, "AH"),
        (IPProtocol::ICMPV6, 58, "IPv6-ICMP"),
        (IPProtocol::IPV6_NO_NEXT_HEADER, 59, "IPv6-NoNxt"),
        (IPProtocol::IPV6_DESTINATION_OPTIONS, 60, "IPv6-Opts"),
    ];
    for (protocol, number, name) in cases {
        assert_eq!(protocol.0, number);
        assert_eq!(protocol.to_string(), name);
    }
    assert_eq!(IPProtocol(200).name(), None);
    assert_eq!(IPProtocol(200).to_string(), "200");
}

#[test]
fn pseudo_headers() {
    let source = IPv4Address::new(192, 0, 2, 1);
    let destination = IPv4Address::new(198, 51, 100, 2);
    let header = IPPseudoHeader::new(source.into(), destination.into(), IPProtocol::UDP, 0x1234).unwrap();
    let (bytes, length) = header.to_bytes();
    // RFC 768: source, destination, zero, protocol, length.
    assert_eq!(&bytes[..length], &[192, 0, 2, 1, 198, 51, 100, 2, 0, 17, 0x12, 0x34]);
    assert_eq!(header.checksum().sum16(), InternetChecksum::checksum(&bytes[..length]) ^ 0xFFFF);
    let source: IPv6Address = "2001:db8::1".parse().unwrap();
    let destination: IPv6Address = "2001:db8::2".parse().unwrap();
    let header = IPPseudoHeader::new(source.into(), destination.into(), IPProtocol::TCP, 0x0102_0304).unwrap();
    let (bytes, length) = header.to_bytes();
    // RFC 8200 §8.1: source, destination, 32-bit length, three zero bytes, next header.
    assert_eq!(length, 40);
    assert_eq!(&bytes[..16], &source.0);
    assert_eq!(&bytes[16..32], &destination.0);
    assert_eq!(&bytes[32..40], &[1, 2, 3, 4, 0, 0, 0, 6]);
    assert_eq!(
        IPPseudoHeader::new(IPv4Address::LOOPBACK.into(), IPv6Address::LOOPBACK.into(), IPProtocol::UDP, 8),
        Err(IPError::Family)
    );
    assert_eq!(
        IPPseudoHeader::new(IPv4Address::LOOPBACK.into(), IPv4Address::LOOPBACK.into(), IPProtocol::UDP, 65536),
        Err(IPError::Length)
    );
}

#[test]
fn fragment_buffer_reassembles_in_any_order() {
    let data: Vec<u8> = (0..40u8).collect();
    let orders: [[usize; 5]; 4] = [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 0, 4, 1, 3], [1, 3, 0, 4, 2]];
    for order in orders {
        let mut buffer = IPFragmentBuffer::new();
        for (step, &index) in order.iter().enumerate() {
            let complete = buffer.insert(index * 8, &data[index * 8..index * 8 + 8], index == 4, 1000).unwrap();
            assert_eq!(complete, step == 4, "{order:?}");
            assert_eq!(buffer.is_complete(), step == 4);
        }
        assert_eq!(buffer.data, data);
        assert_eq!(buffer.received_length(), 40);
        assert_eq!(buffer.length, Some(40));
    }
}

#[test]
fn fragment_buffer_refuses_overlaps() {
    // RFC 5722, RFC 8200 §4.5: a fragment that overlaps another abandons the packet.
    let data = [7u8; 48];
    let mut buffer = IPFragmentBuffer::new();
    buffer.insert(8, &data[..16], false, 1000).unwrap();
    assert_eq!(buffer.insert(0, &data[..16], false, 1000), Err(IPError::Overlap));
    assert_eq!(buffer.insert(16, &data[..16], false, 1000), Err(IPError::Overlap));
    assert_eq!(buffer.insert(0, &data[..48], true, 1000), Err(IPError::Overlap));
    // Only an exact duplicate (the same fragment again) may be dropped instead.
    assert_eq!(buffer.insert(8, &data[..16], false, 1000), Ok(false));
    // A part of a fragment received, even with the same bytes, overlaps it.
    assert_eq!(buffer.insert(8, &data[..8], false, 1000), Err(IPError::Overlap));
    assert_eq!(buffer.insert(16, &data[..8], false, 1000), Err(IPError::Overlap));
    // The same range with other bytes, or as the last fragment, is not a duplicate.
    assert_eq!(buffer.insert(8, &[1u8; 16], false, 1000), Err(IPError::Overlap));
    assert_eq!(buffer.insert(8, &data[..16], true, 1000), Err(IPError::Overlap));
    // Adjacent fragments do not overlap.
    assert_eq!(buffer.insert(0, &data[..8], false, 1000), Ok(false));
    assert_eq!(buffer.insert(24, &data[..8], true, 1000), Ok(true));
    // A fragment that spans two adjacent fragments with their bytes overlaps them.
    let mut buffer = IPFragmentBuffer::new();
    buffer.insert(0, &data[..16], false, 1000).unwrap();
    buffer.insert(16, &data[..16], false, 1000).unwrap();
    assert_eq!(buffer.insert(8, &data[..16], false, 1000), Err(IPError::Overlap));
    assert_eq!(buffer.insert(0, &data[..32], false, 1000), Err(IPError::Overlap));
}

#[test]
fn fragment_buffer_empty_fragments_add_no_data() {
    // A fragment without data adds no byte: the data never reaches past the
    // last fragment, whatever the order.
    let mut buffer = IPFragmentBuffer::new();
    assert_eq!(buffer.insert(1000, &[], false, 2000), Ok(false));
    assert!(buffer.data.is_empty());
    assert_eq!(buffer.insert(0, &[1; 8], false, 2000), Ok(false));
    assert_eq!(buffer.insert(8, &[2; 8], true, 2000), Ok(true));
    assert_eq!(buffer.data, [[1u8; 8], [2; 8]].concat());
    // An empty last fragment sets the end.
    let mut buffer = IPFragmentBuffer::new();
    assert_eq!(buffer.insert(16, &[], true, 2000), Ok(false));
    assert_eq!(buffer.insert(0, &[3; 16], false, 2000), Ok(true));
    assert_eq!(buffer.data, [3; 16]);
    assert_eq!(buffer.insert(16, &[0; 8], false, 2000), Err(IPError::Length));
}

#[test]
fn fragment_buffer_exact_duplicates_keep_their_last_flag() {
    // The fragment before an empty last fragment is not the last one: a copy
    // of it, with More Fragments set, is an exact duplicate.
    let mut buffer = IPFragmentBuffer::new();
    assert_eq!(buffer.insert(8, &[1; 8], false, 1000), Ok(false));
    assert_eq!(buffer.insert(16, &[], true, 1000), Ok(false));
    assert_eq!(buffer.insert(8, &[1; 8], false, 1000), Ok(false));
    assert_eq!(buffer.insert(8, &[1; 8], true, 1000), Err(IPError::Overlap));
    assert_eq!(buffer.insert(0, &[2; 8], false, 1000), Ok(true));
    // The last fragment's copy is a duplicate only with More Fragments clear.
    let mut buffer = IPFragmentBuffer::new();
    assert_eq!(buffer.insert(8, &[1; 8], true, 1000), Ok(false));
    assert_eq!(buffer.insert(8, &[1; 8], true, 1000), Ok(false));
    assert_eq!(buffer.insert(8, &[1; 8], false, 1000), Err(IPError::Overlap));
}

#[test]
fn fragment_buffer_checks_without_changing() {
    let mut buffer = IPFragmentBuffer::new();
    buffer.insert(0, &[1; 8], false, 1000).unwrap();
    let before = buffer.clone();
    assert_eq!(buffer.check(8, &[2; 8], false, 1000), Ok(8 + IPFragmentBuffer::FRAGMENT_RECORD));
    assert_eq!(buffer.check(0, &[1; 8], false, 1000), Ok(0));
    assert_eq!(buffer.check(4, &[1; 8], false, 1000), Err(IPError::Overlap));
    assert_eq!(buffer.check(996, &[1; 8], false, 1000), Err(IPError::Length));
    assert_eq!(buffer, before);
}

#[test]
fn fragment_buffer_takes_many_fragments_in_reverse() {
    // Every 8-byte fragment of the largest datagram, last first.
    let mut buffer = IPFragmentBuffer::new();
    let count = 65528 / 8;
    for index in (0..count).rev() {
        let complete = buffer.insert(index * 8, &[index as u8; 8], index == count - 1, 65535).unwrap();
        assert_eq!(complete, index == 0);
    }
    assert_eq!(buffer.data.len(), 65528);
    assert_eq!(buffer.data[8 * 300], 300u16 as u8);
}

#[test]
fn fragment_buffer_memory_counts_its_records() {
    let mut buffer = IPFragmentBuffer::new();
    assert_eq!(buffer.memory(), 0);
    buffer.insert(16, &[0; 8], false, 1000).unwrap();
    buffer.insert(0, &[0; 8], false, 1000).unwrap();
    assert!(buffer.memory() >= 24 + 2 * 2 * core::mem::size_of::<usize>());
}

#[test]
fn fragment_buffer_refuses_inconsistent_ends() {
    let mut buffer = IPFragmentBuffer::new();
    buffer.insert(0, &[0; 16], false, 1000).unwrap();
    // A last fragment that ends before received data.
    assert_eq!(buffer.insert(0, &[], true, 1000), Err(IPError::Length));
    buffer.insert(16, &[0; 8], true, 1000).unwrap();
    // Data after the end, or another end.
    assert_eq!(buffer.insert(24, &[0; 8], false, 1000), Err(IPError::Length));
    assert_eq!(buffer.insert(16, &[0; 16], true, 1000), Err(IPError::Length));
    // Data beyond the limit.
    let mut buffer = IPFragmentBuffer::new();
    assert_eq!(buffer.insert(992, &[0; 16], false, 1000), Err(IPError::Length));
    assert_eq!(buffer.insert(usize::MAX - 4, &[0; 8], false, usize::MAX), Err(IPError::Length));
    assert_eq!(buffer.insert(984, &[0; 16], true, 1000), Ok(false));
}
