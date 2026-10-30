//! Tests of `umilib::protocol::dhcp` against the rules of RFC 2131, RFC
//! 2132, RFC 3396, RFC 3442, RFC 4361, RFC 6842, RFC 8925 and RFC 9915.

#[cfg(umilib_feature = "protocol-dhcp-v4")]
mod v4;
#[cfg(umilib_feature = "protocol-dhcp-v6")]
mod v6;

use umilib::crypto::random::HMACDRBG;
use umilib::hash::sha::v2::SHA256;
use umilib::protocol::dhcp::DHCPDUID;
use umilib::runtime::Instant;

pub fn random(seed: u8) -> HMACDRBG<SHA256> {
    HMACDRBG::<SHA256>::new(&[seed; 32], &[seed; 16], b"umilib dhcp tests").unwrap()
}

pub fn at(seconds: u64) -> Instant {
    Instant::from_nanos(seconds * 1_000_000_000)
}

pub fn at_millis(milliseconds: u64) -> Instant {
    Instant::from_nanos(milliseconds * 1_000_000)
}

#[test]
fn duids_of_rfc_9915() {
    // §11.2–§11.5 and RFC 6355 §4: each type's layout; unknown types kept.
    let duids = [
        (DHCPDUID::LLT { hardware: 1, time: 0x0102_0304, address: vec![0xAA; 6] }, "000100010102030"),
        (DHCPDUID::EN { enterprise: 9, identifier: vec![1, 2, 3] }, "0002"),
        (DHCPDUID::LL { hardware: 1, address: vec![0xBB; 6] }, "00030001"),
        (DHCPDUID::UUID([7; 16]), "0004"),
        (DHCPDUID::Other { kind: 9, data: vec![1] }, "0009"),
    ];
    for (duid, prefix) in duids {
        let bytes = duid.encode().unwrap();
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(hex.starts_with(prefix), "{hex}");
        assert_eq!(DHCPDUID::decode(&bytes).unwrap(), duid);
    }
    // §11.1: 2 to 130 bytes in all; known types of their least lengths.
    assert!(DHCPDUID::decode(&[0, 9]).is_err());
    assert!(DHCPDUID::decode(&[0; 131]).is_err());
    assert!(DHCPDUID::decode(&[0, 1, 0, 1, 0]).is_err());
    assert!(DHCPDUID::decode(&[0, 4, 1, 2]).is_err());
    // What decoding refuses, encoding does not make.
    assert!(DHCPDUID::LL { hardware: 1, address: Vec::new() }.encode().is_err());
    assert!(DHCPDUID::EN { enterprise: 9, identifier: Vec::new() }.encode().is_err());
    assert!(DHCPDUID::Other { kind: 3, data: vec![1, 2, 3] }.encode().is_err());
    assert!(DHCPDUID::Other { kind: 9, data: vec![0; 128] }.encode().is_ok());
    assert!(DHCPDUID::Other { kind: 9, data: vec![0; 129] }.encode().is_err());
    // §11.2: the time is of seconds since 2000-01-01 UTC.
    assert_eq!(DHCPDUID::time(946_684_800 + 5), 5);
}
