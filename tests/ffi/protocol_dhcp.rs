//! The C ABI of `umilib::protocol::dhcp`: DUIDs (RFC 9915 §11), the
//! messages and options of DHCPv4 (RFC 2131, RFC 2132, RFC 3396, RFC 3442)
//! and of DHCPv6 (RFC 9915), and clients and servers exchanging through it.

use std::ptr;

#[cfg(umilib_feature = "hash-sha-v2")]
use umilib::ffi::crypto::random::{HMACDRBGState, hmac_drbg};
use umilib::ffi::protocol::dhcp::*;
use umilib::ffi::{Buffer, Definition, Manifest, Type};

use super::super::Check;

/// A generator of the C ABI: an HMAC_DRBG over SHA-256 of a fixed seed,
/// released when dropped.
#[cfg(umilib_feature = "hash-sha-v2")]
struct Generator {
    state: *mut HMACDRBGState,
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl Generator {
    /// The C type name of the handle.
    const TYPE: &'static [u8] = b"umilib_crypto_random_HMACDRBG";

    fn new(label: &[u8]) -> Generator {
        let hash = b"umilib_hash_sha_v2_SHA256";
        let mut state = ptr::null_mut();
        unsafe {
            Check::ok(hmac_drbg::new(
                hash.as_ptr(),
                hash.len(),
                [7u8; 32].as_ptr(),
                32,
                [8u8; 16].as_ptr(),
                16,
                label.as_ptr(),
                label.len(),
                &mut state,
            ))
        };
        Generator { state }
    }

    fn handle(&self) -> *mut core::ffi::c_void {
        self.state.cast()
    }
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl Drop for Generator {
    fn drop(&mut self) {
        unsafe { hmac_drbg::free(self.state) };
    }
}

/// The nanoseconds of `seconds`.
fn at(seconds: u64) -> u64 {
    seconds * 1_000_000_000
}

/// Fails with Malformed of this module.
fn malformed(status: *const umilib::ffi::Status) {
    Check::fails(status, "protocol.dhcp", "Malformed");
}

#[test]
fn duids_through_the_c_abi() {
    unsafe {
        // RFC 9915 §11.2–§11.4 and RFC 6355 §4: the type, then each type's fields.
        let cases: [(FFIDHCPDUID, &[u8], &[u8]); 5] = [
            (
                FFIDHCPDUID { kind: 1, hardware: 1, time: 0x0102_0304, enterprise: 0 },
                &[0xAA; 6],
                &[0, 1, 0, 1, 1, 2, 3, 4, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA],
            ),
            (FFIDHCPDUID { kind: 2, hardware: 0, time: 0, enterprise: 9 }, &[1, 2, 3], &[0, 2, 0, 0, 0, 9, 1, 2, 3]),
            (
                FFIDHCPDUID { kind: 3, hardware: 1, time: 0, enterprise: 0 },
                &[0xBB; 6],
                &[0, 3, 0, 1, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB],
            ),
            (
                FFIDHCPDUID { kind: 4, hardware: 0, time: 0, enterprise: 0 },
                &[7; 16],
                &[0, 4, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
            ),
            (FFIDHCPDUID { kind: 9, hardware: 0, time: 0, enterprise: 0 }, &[1], &[0, 9, 1]),
        ];
        for (duid, data, expected) in cases {
            let mut out = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_dhcp_duid_encode(duid, data.as_ptr(), data.len(), &mut out));
            assert_eq!(out.as_slice(), expected);
            let (mut decoded, mut decoded_data) = (FFIDHCPDUID::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_dhcp_duid_decode(
                expected.as_ptr(),
                expected.len(),
                &mut decoded,
                &mut decoded_data,
            ));
            assert_eq!((decoded, decoded_data.as_slice()), (duid, data));
        }
        // §11.1: a DUID is of 2 bytes of type and 1 to 128 of data; each known type has its least length.
        let (mut decoded, mut data) = (FFIDHCPDUID::default(), Buffer::EMPTY);
        for bytes in [&[0u8, 9][..], &[0; 131], &[0, 1, 0, 1, 0], &[0, 2, 0, 0, 0, 9], &[0, 3, 0, 1], &[0, 4, 1, 2]] {
            malformed(umilib_protocol_dhcp_dhcp_duid_decode(bytes.as_ptr(), bytes.len(), &mut decoded, &mut data));
        }
        let mut out = Buffer::EMPTY;
        let long = [0u8; 129];
        let other = FFIDHCPDUID { kind: 9, hardware: 0, time: 0, enterprise: 0 };
        malformed(umilib_protocol_dhcp_dhcp_duid_encode(other, long.as_ptr(), long.len(), &mut out));
        malformed(umilib_protocol_dhcp_dhcp_duid_encode(other, ptr::null(), 0, &mut out));
        // §11.2–§11.4: DUID-LLT and DUID-LL end in a link-layer address, DUID-EN in an identifier.
        for kind in [1, 2, 3] {
            let empty = FFIDHCPDUID { kind, hardware: 1, time: 0, enterprise: 9 };
            malformed(umilib_protocol_dhcp_dhcp_duid_encode(empty, ptr::null(), 0, &mut out));
        }
        let uuid = FFIDHCPDUID { kind: 4, hardware: 0, time: 0, enterprise: 0 };
        malformed(umilib_protocol_dhcp_dhcp_duid_encode(uuid, long.as_ptr(), 15, &mut out));
        Check::ok(umilib_protocol_dhcp_dhcp_duid_encode(other, long.as_ptr(), 128, &mut out));
        assert_eq!(out.as_slice().len(), 130);
        Check::fails(
            umilib_protocol_dhcp_dhcp_duid_decode(ptr::null(), 3, &mut decoded, &mut data),
            "ffi",
            "NullPointer",
        );
        // §11.2: the time of DUID-LLT counts seconds from 2000-01-01 00:00 UTC, modulo 2^32.
        assert_eq!(umilib_protocol_dhcp_dhcp_duid_time(946_684_800 + 5), 5);
        assert_eq!(umilib_protocol_dhcp_dhcp_duid_time(946_684_800 + (1 << 32) + 7), 7);
    }
}

/// Every structure of the module has the layout of its Rust type, so C and ctypes read what Rust writes.
#[test]
fn structures_have_the_layout_of_their_rust_types() {
    fn layout(
        value: &Type,
        structures: &std::collections::BTreeMap<&str, &[umilib::ffi::Parameter]>,
    ) -> (usize, usize) {
        match value {
            Type::Bool | Type::U8 => (1, 1),
            Type::U16 => (2, 2),
            Type::U32 => (4, 4),
            Type::U64 => (size_of::<u64>(), align_of::<u64>()),
            Type::USize => (size_of::<usize>(), align_of::<usize>()),
            Type::Array { element, length } => {
                let (size, align) = layout(element, structures);
                (size * length, align)
            }
            Type::Named(name) => {
                let (mut size, mut align) = (0usize, 1usize);
                let fields = structures.get(name).unwrap_or_else(|| panic!("{name} is not a structure"));
                for field in fields.iter() {
                    let (field_size, field_align) = layout(&field.value, structures);
                    size = size.next_multiple_of(field_align) + field_size;
                    align = align.max(field_align);
                }
                (size.next_multiple_of(align), align)
            }
            other => panic!("{other:?} in a structure of DHCP"),
        }
    }
    let mut structures = std::collections::BTreeMap::new();
    Manifest::ROOT.visit(|_, module| {
        for definition in module.definitions {
            if let Definition::Structure { name, fields, .. } = definition {
                structures.insert(*name, *fields);
            }
        }
    });
    let mut expected: Vec<(&str, usize, usize)> =
        vec![("umilib_protocol_dhcp_DHCPDUID", size_of::<FFIDHCPDUID>(), align_of::<FFIDHCPDUID>())];
    #[cfg(umilib_feature = "protocol-dhcp-v4")]
    {
        use umilib::ffi::protocol::dhcp::v4::*;
        expected.extend([
            ("umilib_protocol_dhcp_v4_DHCPv4Message", size_of::<FFIDHCPv4Message>(), align_of::<FFIDHCPv4Message>()),
            ("umilib_protocol_dhcp_v4_DHCPv4Route", size_of::<FFIDHCPv4Route>(), align_of::<FFIDHCPv4Route>()),
            (
                "umilib_protocol_dhcp_v4_DHCPv4ClientConfig",
                size_of::<FFIDHCPv4ClientConfig>(),
                align_of::<FFIDHCPv4ClientConfig>(),
            ),
            ("umilib_protocol_dhcp_v4_DHCPv4Lease", size_of::<FFIDHCPv4Lease>(), align_of::<FFIDHCPv4Lease>()),
            (
                "umilib_protocol_dhcp_v4_DHCPv4ClientEvent",
                size_of::<FFIDHCPv4ClientEvent>(),
                align_of::<FFIDHCPv4ClientEvent>(),
            ),
            (
                "umilib_protocol_dhcp_v4_DHCPv4ServerConfig",
                size_of::<FFIDHCPv4ServerConfig>(),
                align_of::<FFIDHCPv4ServerConfig>(),
            ),
            ("umilib_protocol_dhcp_v4_DHCPv4Reply", size_of::<FFIDHCPv4Reply>(), align_of::<FFIDHCPv4Reply>()),
            ("umilib_protocol_dhcp_v4_DHCPv4Binding", size_of::<FFIDHCPv4Binding>(), align_of::<FFIDHCPv4Binding>()),
        ]);
    }
    #[cfg(umilib_feature = "protocol-dhcp-v6")]
    {
        use umilib::ffi::protocol::dhcp::v6::*;
        expected.extend([
            ("umilib_protocol_dhcp_v6_DHCPv6Message", size_of::<FFIDHCPv6Message>(), align_of::<FFIDHCPv6Message>()),
            (
                "umilib_protocol_dhcp_v6_DHCPv6RelayMessage",
                size_of::<FFIDHCPv6RelayMessage>(),
                align_of::<FFIDHCPv6RelayMessage>(),
            ),
            ("umilib_protocol_dhcp_v6_DHCPv6IA", size_of::<FFIDHCPv6IA>(), align_of::<FFIDHCPv6IA>()),
            (
                "umilib_protocol_dhcp_v6_DHCPv6IAAddress",
                size_of::<FFIDHCPv6IAAddress>(),
                align_of::<FFIDHCPv6IAAddress>(),
            ),
            ("umilib_protocol_dhcp_v6_DHCPv6IAPrefix", size_of::<FFIDHCPv6IAPrefix>(), align_of::<FFIDHCPv6IAPrefix>()),
            (
                "umilib_protocol_dhcp_v6_DHCPv6ClientConfig",
                size_of::<FFIDHCPv6ClientConfig>(),
                align_of::<FFIDHCPv6ClientConfig>(),
            ),
            ("umilib_protocol_dhcp_v6_DHCPv6Lease", size_of::<FFIDHCPv6Lease>(), align_of::<FFIDHCPv6Lease>()),
            (
                "umilib_protocol_dhcp_v6_DHCPv6ClientEvent",
                size_of::<FFIDHCPv6ClientEvent>(),
                align_of::<FFIDHCPv6ClientEvent>(),
            ),
            (
                "umilib_protocol_dhcp_v6_DHCPv6ServerConfig",
                size_of::<FFIDHCPv6ServerConfig>(),
                align_of::<FFIDHCPv6ServerConfig>(),
            ),
            ("umilib_protocol_dhcp_v6_DHCPv6Binding", size_of::<FFIDHCPv6Binding>(), align_of::<FFIDHCPv6Binding>()),
        ]);
    }
    let declared = structures.keys().filter(|name| name.starts_with("umilib_protocol_dhcp_")).count();
    assert_eq!(declared, expected.len(), "every structure of DHCP is checked");
    for (name, size, align) in expected {
        assert_eq!(layout(&Type::Named(name), &structures), (size, align), "{name}");
    }
}

#[cfg(umilib_feature = "protocol-dhcp-v4")]
mod v4 {
    use std::ptr;

    use umilib::ffi::Buffer;
    use umilib::ffi::protocol::dhcp::v4::*;
    #[cfg(umilib_feature = "hash-sha-v2")]
    use umilib::protocol::dhcp::v4::DHCPv4Client;
    use umilib::protocol::dhcp::v4::DHCPv4Server;
    use umilib::protocol::ethernet::MACAddress;
    use umilib::protocol::ip::IPv4Address;

    use super::super::super::Check;
    #[cfg(umilib_feature = "hash-sha-v2")]
    use super::Generator;
    use super::{at, malformed};

    const HARDWARE: MACAddress = MACAddress([0x02, 0, 0, 0, 0, 0x01]);
    const SERVER: IPv4Address = IPv4Address([192, 0, 2, 1]);
    #[cfg(umilib_feature = "hash-sha-v2")]
    const BROADCAST: IPv4Address = IPv4Address([255, 255, 255, 255]);
    const UNSPECIFIED: IPv4Address = IPv4Address([0, 0, 0, 0]);

    fn address(last: u8) -> IPv4Address {
        IPv4Address([192, 0, 2, last])
    }

    /// An options area of `options` and END (RFC 2132 §2), each of at most 255 bytes.
    fn area(options: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (code, data) in options {
            out.extend_from_slice(&[*code, data.len() as u8]);
            out.extend_from_slice(data);
        }
        out.push(255);
        out
    }

    /// The data of option `code` of `area`, its parts joined (RFC 3396 §7); PAD and END as RFC 2132 §2.
    fn option(area: &[u8], code: u8) -> Option<Vec<u8>> {
        let (mut found, mut index): (Option<Vec<u8>>, usize) = (None, 0);
        while index < area.len() {
            match area[index] {
                0 => index += 1,
                255 => break,
                found_code => {
                    let length = area[index + 1] as usize;
                    if found_code == code {
                        found.get_or_insert_with(Vec::new).extend_from_slice(&area[index + 2..index + 2 + length]);
                    }
                    index += 2 + length;
                }
            }
        }
        found
    }

    /// The header and options area of the message `bytes`.
    unsafe fn decode(bytes: &[u8]) -> (FFIDHCPv4Message, Vec<u8>) {
        let mut message = unsafe { std::mem::zeroed::<FFIDHCPv4Message>() };
        let mut options = Buffer::EMPTY;
        unsafe {
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_message_decode(
                bytes.as_ptr(),
                bytes.len(),
                &mut message,
                &mut options,
            ))
        };
        (message, options.as_slice().to_vec())
    }

    fn server_config() -> FFIDHCPv4ServerConfig {
        FFIDHCPv4ServerConfig {
            address: SERVER,
            first: address(100),
            last: address(102),
            authoritative: true,
            lease: 3_600_000,
            offer_time: 60_000,
            decline_time: 600_000,
        }
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn server() -> *mut DHCPv4Server {
        let options = area(&[(1, &[255, 255, 255, 0]), (3, &SERVER.0), (6, &[192, 0, 2, 53])]);
        let mut server = ptr::null_mut();
        unsafe {
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_new(
                &server_config(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                options.as_ptr(),
                options.len(),
                &mut server,
            ))
        };
        server
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn new_client() -> *mut DHCPv4Client {
        let config = FFIDHCPv4ClientConfig {
            hardware: HARDWARE,
            broadcast: false,
            ipv6_only: false,
            maximum_message_size: 1500,
            retransmissions: 4,
        };
        let (name, parameters) = (b"host", [1u8, 3, 6]);
        let mut client = ptr::null_mut();
        unsafe {
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_new(
                &config,
                ptr::null(),
                0,
                name.as_ptr(),
                name.len(),
                parameters.as_ptr(),
                parameters.len(),
                0,
                &mut client,
            ))
        };
        client
    }

    /// The client's next message and where it goes.
    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn transmit(client: *mut DHCPv4Client) -> Option<(IPv4Address, Vec<u8>)> {
        let (mut found, mut destination, mut bytes) = (false, UNSPECIFIED, Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_transmit(client, &mut found, &mut destination, &mut bytes))
        };
        found.then(|| (destination, bytes.as_slice().to_vec()))
    }

    /// The server's reply to `bytes` and where it goes.
    unsafe fn answer(server: *mut DHCPv4Server, bytes: &[u8], now: u64) -> Option<(FFIDHCPv4Reply, Vec<u8>)> {
        let (mut found, mut reply, mut out) = (false, FFIDHCPv4Reply::default(), Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_receive(
                server,
                bytes.as_ptr(),
                bytes.len(),
                now,
                &mut found,
                &mut reply,
                &mut out,
            ))
        };
        found.then(|| (reply, out.as_slice().to_vec()))
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn poll_events(client: *mut DHCPv4Client) -> Vec<(FFIDHCPv4ClientEvent, Vec<u8>)> {
        let mut events = Vec::new();
        loop {
            let (mut found, mut event, mut options) = (false, FFIDHCPv4ClientEvent::default(), Buffer::EMPTY);
            unsafe {
                Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_poll_event(
                    client,
                    &mut found,
                    &mut event,
                    &mut options,
                ))
            };
            if !found {
                return events;
            }
            events.push((event, options.as_slice().to_vec()));
        }
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn state(client: *mut DHCPv4Client) -> u8 {
        let mut state = 0xFF;
        unsafe { Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_state(client, &mut state)) };
        state
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn timeout(client: *mut DHCPv4Client) -> Option<u64> {
        let (mut found, mut at) = (false, 0);
        unsafe { Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_poll_timeout(client, &mut found, &mut at)) };
        found.then_some(at)
    }

    /// Moves the client's messages through the server, at `now`, until it has none.
    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn run(client: *mut DHCPv4Client, server: *mut DHCPv4Server, now: u64, random: &Generator) {
        while let Some((_, bytes)) = unsafe { transmit(client) } {
            if let Some((_, reply)) = unsafe { answer(server, &bytes, now) } {
                unsafe {
                    Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_receive(
                        client,
                        reply.as_ptr(),
                        reply.len(),
                        now,
                        random.handle(),
                        Generator::TYPE.as_ptr(),
                        Generator::TYPE.len(),
                    ))
                };
            }
        }
    }

    unsafe fn binding(server: *mut DHCPv4Server, address: IPv4Address) -> Option<(FFIDHCPv4Binding, Vec<u8>)> {
        let (mut found, mut binding, mut client) = (false, FFIDHCPv4Binding::default(), Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_binding(
                server,
                address,
                &mut found,
                &mut binding,
                &mut client,
            ))
        };
        found.then(|| (binding, client.as_slice().to_vec()))
    }

    fn header() -> FFIDHCPv4Message {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&HARDWARE.0);
        FFIDHCPv4Message {
            op: 1,
            hardware_type: 1,
            hardware_length: 6,
            hops: 0,
            xid: 0x1234_5678,
            secs: 3,
            flags: 0x8000,
            ciaddr: UNSPECIFIED,
            yiaddr: UNSPECIFIED,
            siaddr: UNSPECIFIED,
            giaddr: UNSPECIFIED,
            chaddr,
            sname: [0; 64],
            file: [0; 128],
        }
    }

    #[test]
    fn bindings_kept_by_the_caller() {
        // A server's bindings are its caller's to keep: listed, set on another server, removed.
        unsafe {
            let server = server();
            let binding = FFIDHCPv4Binding { state: 1, expires: 5 };
            let client = [1u8, 2, 3];
            let address = IPv4Address([192, 0, 2, 100]);
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_set_binding(server, address, binding, client.as_ptr(), 3));
            let mut count = 0;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_bindings_count(server, &mut count));
            assert_eq!(count, 1);
            let (mut listed, mut out, mut owner) = (IPv4Address([0; 4]), FFIDHCPv4Binding::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_binding_entry(
                server,
                0,
                &mut listed,
                &mut out,
                &mut owner,
            ));
            assert_eq!((listed, out, owner.as_slice()), (address, binding, &client[..]));
            umilib::ffi::umilib_ffi_buffer_free(&mut owner);
            Check::fails(
                umilib_protocol_dhcp_v4_dhcpv4_server_binding_entry(server, 1, &mut listed, &mut out, &mut owner),
                "ffi",
                "InvalidArgument",
            );
            let unknown = FFIDHCPv4Binding { state: 9, expires: 5 };
            Check::fails(
                umilib_protocol_dhcp_v4_dhcpv4_server_set_binding(server, address, unknown, client.as_ptr(), 3),
                "ffi",
                "InvalidArgument",
            );
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_remove_binding(server, address));
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_bindings_count(server, &mut count));
            assert_eq!(count, 0);
            umilib_protocol_dhcp_v4_dhcpv4_server_free(server);
        }
    }

    #[test]
    fn messages_and_options_through_the_c_abi() {
        unsafe {
            // RFC 2131 §2: the fixed fields, the magic cookie (§3), the options; RFC 3396: an option
            // given in two parts is one, written again in parts of at most 255 bytes.
            let long = [7u8; 300];
            let options = area(&[(53, &[1]), (12, &long[..255]), (12, &long[255..])]);
            let mut bytes = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_message_encode(
                &header(),
                options.as_ptr(),
                options.len(),
                &mut bytes,
            ));
            let bytes = bytes.as_slice().to_vec();
            assert_eq!(bytes[..12], [1, 1, 6, 0, 0x12, 0x34, 0x56, 0x78, 0, 3, 0x80, 0]);
            assert_eq!(bytes[28..34], HARDWARE.0);
            assert_eq!(bytes[236..240], [99, 130, 83, 99]);
            assert_eq!(bytes[240..243], [53, 1, 1]);
            assert_eq!(bytes[243..245], [12, 255]);
            assert_eq!(bytes[500..502], [12, 45]);
            assert_eq!(bytes[547], 255);
            let (header_read, options_read) = decode(&bytes);
            assert_eq!(header_read, header());
            assert_eq!(option(&options_read, 12), Some(long.to_vec()));
            assert_eq!(option(&options_read, 53), Some(vec![1]));
            // RFC 1542 §2.1: a message is at least 300 bytes.
            let short = area(&[(53, &[1])]);
            let mut out = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_message_encode(&header(), short.as_ptr(), short.len(), &mut out));
            assert_eq!(out.as_slice().len(), 300);
            // RFC 2131 §4.1: options overloading `file` (overload 1) are read after the options field,
            // and the field is then not a file name; the overload option is not an option of the message.
            let mut overloaded = bytes[..240].to_vec();
            overloaded[108..115].copy_from_slice(&[12, 4, b'h', b'o', b's', b't', 255]);
            overloaded.extend_from_slice(&[53, 1, 1, 52, 1, 1, 255]);
            let (read, options_read) = decode(&overloaded);
            assert_eq!(read.file, [0; 128]);
            assert_eq!(option(&options_read, 12), Some(b"host".to_vec()));
            assert_eq!(option(&options_read, 52), None);
            // Without the magic cookie, cut short, or of another op, it is not a DHCP message.
            let mut message = std::mem::zeroed::<FFIDHCPv4Message>();
            let mut options_out = Buffer::EMPTY;
            for broken in [
                &bytes[..239],
                &[&bytes[..236], &[0, 0, 0, 0][..], &bytes[240..]].concat()[..],
                &[&[3u8][..], &bytes[1..]].concat()[..],
            ] {
                malformed(umilib_protocol_dhcp_v4_dhcpv4_message_decode(
                    broken.as_ptr(),
                    broken.len(),
                    &mut message,
                    &mut options_out,
                ));
            }
            let mut cut_full = bytes[..240].to_vec();
            cut_full.extend_from_slice(&[12, 20, 1, 2]);
            malformed(umilib_protocol_dhcp_v4_dhcpv4_message_decode(
                cut_full.as_ptr(),
                cut_full.len(),
                &mut message,
                &mut options_out,
            ));
            malformed(umilib_protocol_dhcp_v4_dhcpv4_message_encode(&header(), [12u8, 5, 1].as_ptr(), 3, &mut out));
            // RFC 2131 §4.2, RFC 4361 §6.1: a client is known by its client identifier, or by its
            // hardware type and address.
            let mut key = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_message_client_key(
                &header(),
                short.as_ptr(),
                short.len(),
                &mut key,
            ));
            assert_eq!(key.as_slice(), [&[0u8, 1][..], &HARDWARE.0].concat());
            umilib::ffi::umilib_ffi_buffer_free(&mut key);
            let identified = area(&[(53, &[1]), (61, &[255, 0, 0, 0, 1, 0, 3, 0, 1, 2, 0, 0, 0, 0, 1])]);
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_message_client_key(
                &header(),
                identified.as_ptr(),
                identified.len(),
                &mut key,
            ));
            assert_eq!(key.as_slice(), [255, 0, 0, 0, 1, 0, 3, 0, 1, 2, 0, 0, 0, 0, 1]);
            umilib::ffi::umilib_ffi_buffer_free(&mut key);
            // RFC 2132 §2: PAD is dropped; the parts of an option are joined (RFC 3396 §7).
            let padded = [0u8, 0, 3, 4, 192, 0, 2, 1, 0, 3, 4, 192, 0, 2, 2, 255, 9, 9];
            let mut normalized = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_options_decode(padded.as_ptr(), padded.len(), &mut normalized));
            assert_eq!(normalized.as_slice(), [3, 8, 192, 0, 2, 1, 192, 0, 2, 2, 255]);
        }
    }

    #[test]
    fn classless_static_routes_through_the_c_abi() {
        unsafe {
            // RFC 3442 §2: a prefix length, the significant octets of the destination, the router.
            let data = [8u8, 10, 10, 0, 0, 1, 24, 192, 168, 1, 10, 0, 0, 2, 0, 10, 0, 0, 254];
            let options = area(&[(121, &data)]);
            let mut routes = [FFIDHCPv4Route::default(); 4];
            let mut count = 0;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_options_routes(
                options.as_ptr(),
                options.len(),
                routes.as_mut_ptr(),
                routes.len(),
                &mut count,
            ));
            assert_eq!(count, 3);
            assert_eq!(
                routes[..3],
                [
                    FFIDHCPv4Route {
                        destination: IPv4Address([10, 0, 0, 0]),
                        prefix: 8,
                        router: IPv4Address([10, 0, 0, 1])
                    },
                    FFIDHCPv4Route {
                        destination: IPv4Address([192, 168, 1, 0]),
                        prefix: 24,
                        router: IPv4Address([10, 0, 0, 2])
                    },
                    FFIDHCPv4Route { destination: UNSPECIFIED, prefix: 0, router: IPv4Address([10, 0, 0, 254]) },
                ]
            );
            // Too few structures to write them into.
            Check::fails(
                umilib_protocol_dhcp_v4_dhcpv4_options_routes(
                    options.as_ptr(),
                    options.len(),
                    routes.as_mut_ptr(),
                    2,
                    &mut count,
                ),
                "ffi",
                "InvalidArgument",
            );
            // Written back, the bits of a destination beyond its prefix are not sent.
            let mut set = Buffer::EMPTY;
            let wide = [
                FFIDHCPv4Route {
                    destination: IPv4Address([10, 1, 2, 3]),
                    prefix: 8,
                    router: IPv4Address([10, 0, 0, 1]),
                },
                routes[1],
                routes[2],
            ];
            let empty = area(&[]);
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_options_set_routes(
                empty.as_ptr(),
                empty.len(),
                wide.as_ptr(),
                wide.len(),
                &mut set,
            ));
            assert_eq!(option(set.as_slice(), 121), Some(data.to_vec()));
            // A prefix longer than 32 bits, or a route cut short, is malformed.
            for broken in [&[33u8, 1, 2, 3, 4, 5, 10, 0, 0, 1][..], &[24, 192, 168, 1, 10, 0, 0]] {
                let options = area(&[(121, broken)]);
                malformed(umilib_protocol_dhcp_v4_dhcpv4_options_routes(
                    options.as_ptr(),
                    options.len(),
                    routes.as_mut_ptr(),
                    routes.len(),
                    &mut count,
                ));
            }
        }
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    #[test]
    fn a_lease_from_discover_to_release() {
        let random = Generator::new(b"dhcp lease");
        unsafe {
            let server = server();
            let client = new_client();
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_start(
                client,
                ptr::null(),
                at(0),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!(state(client), 1);
            // RFC 2131 §4.4.1: DHCPDISCOVER is broadcast, with the options asked for (RFC 2132 §9.8).
            let (destination, discover) = transmit(client).unwrap();
            assert_eq!(destination, BROADCAST);
            let (header, options) = decode(&discover);
            assert_eq!(
                (header.op, header.hardware_type, header.hardware_length, header.ciaddr),
                (1, 1, 6, UNSPECIFIED)
            );
            assert_eq!(header.chaddr[..6], HARDWARE.0);
            assert_eq!(option(&options, 53), Some(vec![1]));
            assert_eq!(option(&options, 55), Some(vec![1, 3, 6]));
            assert_eq!(option(&options, 57), Some(1500u16.to_be_bytes().to_vec()));
            assert_eq!(option(&options, 12), Some(b"host".to_vec()));
            // §4.3.1: DHCPOFFER of a free address, with the lease time and the server identifier
            // (table 3); unicast to the hardware address of a client that did not ask for broadcast (§4.1).
            let (reply, offer) = answer(server, &discover, at(0)).unwrap();
            assert_eq!(reply, FFIDHCPv4Reply { destination: address(100), port: 68, link: HARDWARE, has_link: true });
            let (offered, offer_options) = decode(&offer);
            assert_eq!((offered.op, offered.xid, offered.yiaddr), (2, header.xid, address(100)));
            assert_eq!(option(&offer_options, 53), Some(vec![2]));
            assert_eq!(option(&offer_options, 54), Some(SERVER.0.to_vec()));
            assert_eq!(option(&offer_options, 51), Some(3600u32.to_be_bytes().to_vec()));
            assert_eq!(binding(server, address(100)).unwrap().0, FFIDHCPv4Binding { state: 0, expires: at(60) });
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_receive(
                client,
                offer.as_ptr(),
                offer.len(),
                at(0),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!(state(client), 2);
            // §4.3.2, table 5: DHCPREQUEST of SELECTING, broadcast, of the offer's xid, with the server
            // identifier and the requested address, ciaddr zero.
            let (destination, request) = transmit(client).unwrap();
            assert_eq!(destination, BROADCAST);
            let (requested, request_options) = decode(&request);
            assert_eq!((requested.xid, requested.ciaddr), (offered.xid, UNSPECIFIED));
            assert_eq!(option(&request_options, 53), Some(vec![3]));
            assert_eq!(option(&request_options, 54), Some(SERVER.0.to_vec()));
            assert_eq!(option(&request_options, 50), Some(address(100).0.to_vec()));
            let (reply, ack) = answer(server, &request, at(1)).unwrap();
            assert_eq!((reply.destination, reply.has_link), (address(100), true));
            let (acked, ack_options) = decode(&ack);
            assert_eq!((acked.yiaddr, option(&ack_options, 53)), (address(100), Some(vec![5])));
            let (bound, client_key) = binding(server, address(100)).unwrap();
            assert_eq!(bound, FFIDHCPv4Binding { state: 1, expires: at(1) + at(3600) });
            assert_eq!(client_key, [&[0u8, 1][..], &HARDWARE.0].concat());
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_receive(
                client,
                ack.as_ptr(),
                ack.len(),
                at(1),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            // §4.4.1: the lease runs from when the request was sent; §4.4.5: T1 and T2 default to half
            // and seven eighths of it.
            let events = poll_events(client);
            assert_eq!(events.len(), 1);
            let (event, options) = &events[0];
            assert_eq!(event.kind, 0);
            assert_eq!(
                event.lease,
                FFIDHCPv4Lease {
                    address: address(100),
                    server: SERVER,
                    lease: 3_600_000,
                    renewal: 1_800_000,
                    rebinding: 3_150_000,
                    acquired: 0
                }
            );
            assert_eq!(option(options, 3), Some(SERVER.0.to_vec()));
            assert_eq!(option(options, 1), Some(vec![255, 255, 255, 0]));
            assert_eq!((state(client), timeout(client)), (4, Some(at(1800))));
            let (mut found, mut lease, mut lease_options) = (false, FFIDHCPv4Lease::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_lease(client, &mut found, &mut lease, &mut lease_options));
            assert!(found);
            assert_eq!((lease, lease_options.as_slice()), (event.lease, options.as_slice()));
            // §4.4.5: RENEWING at T1, unicast to the server, the address in ciaddr, without the server
            // identifier or the requested address (§4.3.2).
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_expire(
                client,
                at(1800),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!(state(client), 5);
            let (destination, renew) = transmit(client).unwrap();
            assert_eq!(destination, SERVER);
            let (renewing, renew_options) = decode(&renew);
            assert_eq!(renewing.ciaddr, address(100));
            assert_eq!((option(&renew_options, 54), option(&renew_options, 50)), (None, None));
            // The ACK goes to ciaddr (§4.1) and extends the lease.
            let (reply, ack) = answer(server, &renew, at(1800)).unwrap();
            assert_eq!(
                reply,
                FFIDHCPv4Reply { destination: address(100), port: 68, link: MACAddress([0; 6]), has_link: false }
            );
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_receive(
                client,
                ack.as_ptr(),
                ack.len(),
                at(1800),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!((state(client), poll_events(client)[0].0.lease.acquired), (4, at(1800)));
            // §4.4.6: DHCPRELEASE to the server, of ciaddr and the server identifier; the client stops.
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_release(client, at(2000)));
            let (destination, release) = transmit(client).unwrap();
            assert_eq!(destination, SERVER);
            let (released, release_options) = decode(&release);
            assert_eq!((released.ciaddr, option(&release_options, 53)), (address(100), Some(vec![7])));
            assert_eq!(option(&release_options, 54), Some(SERVER.0.to_vec()));
            assert_eq!((state(client), timeout(client)), (0, None));
            // §4.3.4: the server answers nothing and the binding ends.
            assert!(answer(server, &release, at(2000)).is_none());
            assert_eq!(binding(server, address(100)).unwrap().0.expires, at(2000));
            Check::fails(umilib_protocol_dhcp_v4_dhcpv4_client_release(client, at(2001)), "protocol.dhcp", "State");
            Check::fails(
                umilib_protocol_dhcp_v4_dhcpv4_client_decline(
                    client,
                    at(2001),
                    random.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                ),
                "protocol.dhcp",
                "State",
            );
            umilib_protocol_dhcp_v4_dhcpv4_client_free(client);
            umilib_protocol_dhcp_v4_dhcpv4_server_free(server);
        }
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    #[test]
    fn declines_refusals_and_information() {
        let random = Generator::new(b"dhcp decline");
        unsafe {
            let server = server();
            let client = new_client();
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_start(
                client,
                ptr::null(),
                at(0),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            run(client, server, at(0), &random);
            assert_eq!(poll_events(client)[0].0.lease.address, address(100));
            // RFC 2131 §4.4.1, table 5: DHCPDECLINE, broadcast, of the requested address and the server
            // identifier, without the options asked for; discovery again after ten seconds (§3.1.5).
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_decline(
                client,
                at(5),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let (destination, decline) = transmit(client).unwrap();
            assert_eq!(destination, BROADCAST);
            let (declined, options) = decode(&decline);
            assert_eq!(declined.ciaddr, UNSPECIFIED);
            assert_eq!((option(&options, 53), option(&options, 50)), (Some(vec![4]), Some(address(100).0.to_vec())));
            assert_eq!(option(&options, 54), Some(SERVER.0.to_vec()));
            assert_eq!((option(&options, 55), option(&options, 57)), (None, None));
            assert_eq!((state(client), timeout(client)), (0, Some(at(15))));
            // §4.3.3: the server marks the address as not available.
            assert!(answer(server, &decline, at(5)).is_none());
            assert_eq!(
                binding(server, address(100)).unwrap(),
                (FFIDHCPv4Binding { state: 2, expires: at(605) }, Vec::new())
            );
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_expire(
                client,
                at(15),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            run(client, server, at(15), &random);
            assert_eq!(poll_events(client)[0].0.lease.address, address(101));
            // §3.2, §4.3.2: INIT-REBOOT asks for the previous address without a server identifier; the
            // authoritative server refuses one not of its network, broadcast (§4.1), and the client
            // discovers again.
            let rebooting = new_client();
            let previous = IPv4Address([198, 51, 100, 7]);
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_start(
                rebooting,
                &previous,
                at(20),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!(state(rebooting), 3);
            let (_, request) = transmit(rebooting).unwrap();
            let (header, options) = decode(&request);
            assert_eq!(
                (header.ciaddr, option(&options, 54), option(&options, 50)),
                (UNSPECIFIED, None, Some(previous.0.to_vec()))
            );
            let (reply, nak) = answer(server, &request, at(20)).unwrap();
            assert_eq!((reply.destination, reply.port, reply.has_link), (BROADCAST, 68, false));
            let (refused, nak_options) = decode(&nak);
            assert_eq!(
                (refused.yiaddr, option(&nak_options, 53), option(&nak_options, 51)),
                (UNSPECIFIED, Some(vec![6]), None)
            );
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_receive(
                rebooting,
                nak.as_ptr(),
                nak.len(),
                at(20),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!(poll_events(rebooting).iter().map(|(event, _)| event.kind).collect::<Vec<_>>(), [1]);
            assert_eq!(state(rebooting), 1);
            // §3.4, §4.3.5: DHCPINFORM of a configured address, in ciaddr, without a requested address;
            // the ACK goes to it, without a lease time or an address.
            let configured = address(50);
            // The rebooting client, discovering again, informs under an xid of its own; its exchange goes on.
            let (mut destination, mut inform) = (UNSPECIFIED, Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_inform(
                rebooting,
                configured,
                at(21),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut destination,
                &mut inform,
            ));
            assert_eq!((destination, state(rebooting)), (BROADCAST, 1));
            let inform = inform.as_slice().to_vec();
            let (header, options) = decode(&inform);
            let (_, discover) = transmit(rebooting).unwrap();
            assert_eq!(option(&decode(&discover).1, 53), Some(vec![1]));
            assert_ne!(decode(&discover).0.xid, header.xid);
            assert_eq!((header.ciaddr, option(&options, 53), option(&options, 50)), (configured, Some(vec![8]), None));
            let (reply, ack) = answer(server, &inform, at(21)).unwrap();
            assert_eq!((reply.destination, reply.port, reply.has_link), (configured, 68, false));
            let (acked, options) = decode(&ack);
            assert_eq!((acked.yiaddr, option(&options, 53), option(&options, 51)), (UNSPECIFIED, Some(vec![5]), None));
            assert_eq!(option(&options, 3), Some(SERVER.0.to_vec()));
            umilib_protocol_dhcp_v4_dhcpv4_client_free(rebooting);
            umilib_protocol_dhcp_v4_dhcpv4_client_free(client);
            umilib_protocol_dhcp_v4_dhcpv4_server_free(server);
        }
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    #[test]
    fn retransmissions_and_errors_as_statuses() {
        let random = Generator::new(b"dhcp retransmit");
        unsafe {
            // RFC 2131 §4.1: the first retransmission after 4 s, randomized by up to a second; §2: secs
            // counts the seconds since the client began.
            let client = new_client();
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_start(
                client,
                ptr::null(),
                at(0),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let (_, first) = transmit(client).unwrap();
            let next = timeout(client).unwrap();
            assert!((at(3)..=at(5)).contains(&next), "{next}");
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_client_expire(
                client,
                next,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let (_, second) = transmit(client).unwrap();
            assert_eq!((decode(&first).0.secs, u64::from(decode(&second).0.secs)), (0, next / at(1)));
            umilib_protocol_dhcp_v4_dhcpv4_client_free(client);
            // A generator of a type umilib does not know, a pool backwards, null pointers.
            let unknown = b"umilib_crypto_random_Unknown";
            let other = new_client();
            Check::fails(
                umilib_protocol_dhcp_v4_dhcpv4_client_start(
                    other,
                    ptr::null(),
                    0,
                    random.handle(),
                    unknown.as_ptr(),
                    unknown.len(),
                ),
                "ffi",
                "InvalidArgument",
            );
            umilib_protocol_dhcp_v4_dhcpv4_client_free(other);
            let backwards = FFIDHCPv4ServerConfig { first: address(102), last: address(100), ..server_config() };
            let mut server = ptr::null_mut();
            let empty = [255u8];
            Check::fails(
                umilib_protocol_dhcp_v4_dhcpv4_server_new(
                    &backwards,
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    empty.as_ptr(),
                    1,
                    &mut server,
                ),
                "protocol.dhcp",
                "Config",
            );
            Check::fails(
                umilib_protocol_dhcp_v4_dhcpv4_client_start(
                    ptr::null_mut(),
                    ptr::null(),
                    0,
                    random.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                ),
                "ffi",
                "NullPointer",
            );
            Check::fails(umilib_protocol_dhcp_v4_dhcpv4_server_expire(ptr::null_mut(), 0), "ffi", "NullPointer");
            umilib_protocol_dhcp_v4_dhcpv4_client_free(ptr::null_mut());
            umilib_protocol_dhcp_v4_dhcpv4_server_free(ptr::null_mut());
        }
    }

    #[test]
    fn reservations_and_relays() {
        unsafe {
            // The configuration of a server of a pool, which offers from it.
            let mut config = std::mem::zeroed::<FFIDHCPv4ServerConfig>();
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_config_new(
                SERVER,
                address(100),
                address(102),
                &mut config,
            ));
            assert_eq!((config.address, config.first, config.last), (SERVER, address(100), address(102)));
            assert!(config.offer_time > 0 && config.decline_time > 0 && config.lease > 0);
            let mut pool = ptr::null_mut();
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_new(
                &config,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                0,
                [255u8].as_ptr(),
                1,
                &mut pool,
            ));
            let discover = area(&[(53, &[1])]);
            let mut bytes = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_message_encode(
                &FFIDHCPv4Message { flags: 0, ..header() },
                discover.as_ptr(),
                discover.len(),
                &mut bytes,
            ));
            let (_, offer) = answer(pool, bytes.as_slice(), 0).unwrap();
            assert_eq!(decode(&offer).0.yiaddr, address(100));
            umilib_protocol_dhcp_v4_dhcpv4_server_free(pool);
            // A reservation by client key; a relayed request answered to the relay's port 67 (§4.1).
            let key = [&[0u8, 1][..], &HARDWARE.0].concat();
            let keys = [key.as_ptr()];
            let lengths = [key.len()];
            let addresses = [address(150)];
            let empty = [255u8];
            let mut server = ptr::null_mut();
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_new(
                &server_config(),
                keys.as_ptr(),
                lengths.as_ptr(),
                addresses.as_ptr(),
                1,
                empty.as_ptr(),
                1,
                &mut server,
            ));
            let relay = IPv4Address([198, 51, 100, 1]);
            let discover = FFIDHCPv4Message { giaddr: relay, flags: 0, ..header() };
            let options = area(&[(53, &[1])]);
            let mut bytes = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_message_encode(
                &discover,
                options.as_ptr(),
                options.len(),
                &mut bytes,
            ));
            let (reply, offer) = answer(server, bytes.as_slice(), at(0)).unwrap();
            assert_eq!((reply.destination, reply.port, reply.has_link), (relay, 67, false));
            let (offered, _) = decode(&offer);
            assert_eq!((offered.yiaddr, offered.giaddr), (address(150), relay));
            // A message of the server's own kind (BOOTREPLY) is not answered.
            assert!(answer(server, &offer, at(0)).is_none());
            Check::ok(umilib_protocol_dhcp_v4_dhcpv4_server_expire(server, at(61)));
            assert!(binding(server, address(150)).is_none());
            umilib_protocol_dhcp_v4_dhcpv4_server_free(server);
        }
    }
}

#[cfg(umilib_feature = "protocol-dhcp-v6")]
mod v6 {
    use std::ptr;

    use umilib::ffi::Buffer;
    use umilib::ffi::protocol::dhcp::v6::*;
    #[cfg(umilib_feature = "hash-sha-v2")]
    use umilib::protocol::dhcp::v6::DHCPv6Client;
    use umilib::protocol::dhcp::v6::DHCPv6Server;
    use umilib::protocol::ip::IPv6Address;

    use super::super::super::Check;
    #[cfg(umilib_feature = "hash-sha-v2")]
    use super::Generator;
    use super::{at, malformed};

    const CLIENT_ID: u16 = 1;
    const SERVER_ID: u16 = 2;
    const IA_NA: u16 = 3;
    const IAADDR: u16 = 5;
    #[cfg(umilib_feature = "hash-sha-v2")]
    const ORO: u16 = 6;
    const ELAPSED_TIME: u16 = 8;
    const RELAY_MSG: u16 = 9;
    const STATUS_CODE: u16 = 13;
    const INTERFACE_ID: u16 = 18;
    const DNS_SERVERS: u16 = 23;
    #[cfg(umilib_feature = "hash-sha-v2")]
    const IA_PD: u16 = 25;
    #[cfg(umilib_feature = "hash-sha-v2")]
    const IAPREFIX: u16 = 26;

    fn address(last: u8) -> IPv6Address {
        let mut bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes[15] = last;
        IPv6Address(bytes)
    }

    fn prefix() -> IPv6Address {
        IPv6Address([0x20, 0x01, 0x0d, 0xb8, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// A DUID-LL of Ethernet (RFC 9915 §11.4).
    fn duid(last: u8) -> Vec<u8> {
        vec![0, 3, 0, 1, 2, 0, 0, 0, 0, last]
    }

    /// The bytes of `options` (RFC 9915 §21.1).
    fn encode(options: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (code, data) in options {
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    /// The options of `bytes`, read independently of umilib.
    fn options(mut bytes: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let code = u16::from_be_bytes([bytes[0], bytes[1]]);
            let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
            out.push((code, bytes[4..4 + length].to_vec()));
            bytes = &bytes[4 + length..];
        }
        out
    }

    fn get(options: &[(u16, Vec<u8>)], code: u16) -> Option<Vec<u8>> {
        options.iter().find(|(found, _)| *found == code).map(|(_, data)| data.clone())
    }

    unsafe fn decode(bytes: &[u8]) -> (FFIDHCPv6Message, Vec<(u16, Vec<u8>)>) {
        let (mut message, mut out) = (FFIDHCPv6Message::default(), Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_message_decode(
                bytes.as_ptr(),
                bytes.len(),
                &mut message,
                &mut out,
            ))
        };
        (message, options(out.as_slice()))
    }

    unsafe fn ia(kind: u16, data: &[u8]) -> (FFIDHCPv6IA, Vec<(u16, Vec<u8>)>) {
        let (mut ia, mut out) = (FFIDHCPv6IA::default(), Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_decode(kind, data.as_ptr(), data.len(), &mut ia, &mut out))
        };
        (ia, options(out.as_slice()))
    }

    unsafe fn server(config: FFIDHCPv6ServerConfig) -> *mut DHCPv6Server {
        let given = encode(&[(DNS_SERVERS, &address(53).0)]);
        let duid = duid(0x53);
        let mut server = ptr::null_mut();
        unsafe {
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_new(
                &config,
                duid.as_ptr(),
                duid.len(),
                given.as_ptr(),
                given.len(),
                &mut server,
            ))
        };
        server
    }

    fn server_config() -> FFIDHCPv6ServerConfig {
        FFIDHCPv6ServerConfig {
            first: address(100),
            last: address(101),
            prefix: prefix(),
            addresses: true,
            prefixes: true,
            prefix_length: 48,
            delegated_length: 56,
            preference: 0,
            rapid_commit: false,
            preferred: 3000,
            valid: 4000,
            t1: 1000,
            t2: 1600,
        }
    }

    unsafe fn answer(server: *mut DHCPv6Server, bytes: &[u8], now: u64) -> Option<Vec<u8>> {
        let (mut found, mut out) = (false, Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_receive(
                server,
                bytes.as_ptr(),
                bytes.len(),
                now,
                &mut found,
                &mut out,
            ))
        };
        found.then(|| out.as_slice().to_vec())
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn new_client(config: FFIDHCPv6ClientConfig, last: u8) -> *mut DHCPv6Client {
        let (duid, requested) = (duid(last), [DNS_SERVERS, 24, 82]);
        let mut client = ptr::null_mut();
        unsafe {
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_new(
                &config,
                duid.as_ptr(),
                duid.len(),
                requested.as_ptr(),
                requested.len(),
                0,
                &mut client,
            ))
        };
        client
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn transmit(client: *mut DHCPv6Client) -> Option<Vec<u8>> {
        let (mut found, mut out) = (false, Buffer::EMPTY);
        unsafe { Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_transmit(client, &mut found, &mut out)) };
        found.then(|| out.as_slice().to_vec())
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn receive(client: *mut DHCPv6Client, bytes: &[u8], now: u64, random: &Generator) {
        unsafe {
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_receive(
                client,
                bytes.as_ptr(),
                bytes.len(),
                now,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ))
        };
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn state(client: *mut DHCPv6Client) -> u8 {
        let mut state = 0xFF;
        unsafe { Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_state(client, &mut state)) };
        state
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn timeout(client: *mut DHCPv6Client) -> Option<u64> {
        let (mut found, mut at) = (false, 0);
        unsafe { Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_poll_timeout(client, &mut found, &mut at)) };
        found.then_some(at)
    }

    /// An event, the options of its IAs and of its Reply, and its server's DUID.
    #[cfg(umilib_feature = "hash-sha-v2")]
    type Event = (FFIDHCPv6ClientEvent, Vec<u8>, Vec<u8>, Vec<u8>);

    #[cfg(umilib_feature = "hash-sha-v2")]
    unsafe fn poll_events(client: *mut DHCPv6Client) -> Vec<Event> {
        let mut events = Vec::new();
        loop {
            let mut found = false;
            let mut event = FFIDHCPv6ClientEvent::default();
            let (mut ias, mut options, mut server) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
            unsafe {
                Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_poll_event(
                    client,
                    &mut found,
                    &mut event,
                    &mut ias,
                    &mut options,
                    &mut server,
                ))
            };
            if !found {
                return events;
            }
            events.push((event, ias.as_slice().to_vec(), options.as_slice().to_vec(), server.as_slice().to_vec()));
        }
    }

    #[test]
    fn bindings_kept_by_the_caller() {
        unsafe {
            let server = server(server_config());
            let binding = FFIDHCPv6Binding {
                address: prefix(),
                iaid: 7,
                kind: 25,
                length: 56,
                has_length: true,
                declined: false,
                expires: u64::MAX,
            };
            let client = [4u8, 5];
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_set_binding(server, binding, client.as_ptr(), 2));
            let mut count = 0;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_bindings_count(server, &mut count));
            assert_eq!(count, 1);
            let (mut out, mut owner) = (FFIDHCPv6Binding::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_binding_entry(server, 0, &mut out, &mut owner));
            assert_eq!((out, owner.as_slice()), (binding, &client[..]));
            umilib::ffi::umilib_ffi_buffer_free(&mut owner);
            // An address of the same bytes is another binding than the prefix.
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_remove_binding(server, prefix(), 0, false));
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_bindings_count(server, &mut count));
            assert_eq!(count, 1);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_remove_binding(server, prefix(), 56, true));
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_bindings_count(server, &mut count));
            assert_eq!(count, 0);
            umilib_protocol_dhcp_v6_dhcpv6_server_free(server);
        }
    }

    #[test]
    fn messages_and_options_through_the_c_abi() {
        unsafe {
            // RFC 9915 §8: the type, 24 bits of transaction ID, then the options (§21.1).
            let given = encode(&[(CLIENT_ID, &duid(1)), (ELAPSED_TIME, &[0, 0])]);
            let message = FFIDHCPv6Message { kind: 1, transaction: 0x12_3456 };
            let mut out = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_message_encode(message, given.as_ptr(), given.len(), &mut out));
            let bytes = out.as_slice().to_vec();
            umilib::ffi::umilib_ffi_buffer_free(&mut out);
            assert_eq!(bytes, [&[1u8, 0x12, 0x34, 0x56][..], &given].concat());
            let (read, read_options) = decode(&bytes);
            assert_eq!((read, read_options), (message, options(&given)));
            let (mut header, mut options_out) = (FFIDHCPv6Message::default(), Buffer::EMPTY);
            for broken in [&bytes[..3], &bytes[..bytes.len() - 1]] {
                malformed(umilib_protocol_dhcp_v6_dhcpv6_message_decode(
                    broken.as_ptr(),
                    broken.len(),
                    &mut header,
                    &mut options_out,
                ));
            }
            // A transaction ID of more than 24 bits, or a relay agent's type, is not a client's message.
            for wrong in
                [FFIDHCPv6Message { kind: 1, transaction: 0x100_0000 }, FFIDHCPv6Message { kind: 12, transaction: 0 }]
            {
                malformed(umilib_protocol_dhcp_v6_dhcpv6_message_encode(wrong, ptr::null(), 0, &mut out));
            }
            malformed(umilib_protocol_dhcp_v6_dhcpv6_message_encode(message, given.as_ptr(), 3, &mut out));
            // §9: a relay agent's message, its hop count and addresses; the relayed message in Relay
            // Message (§21.10).
            let relay = FFIDHCPv6RelayMessage { kind: 12, hops: 1, link: address(1), peer: address(2) };
            let relayed = encode(&[(RELAY_MSG, &bytes)]);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_relay_message_encode(
                &relay,
                relayed.as_ptr(),
                relayed.len(),
                &mut out,
            ));
            let encoded = out.as_slice().to_vec();
            assert_eq!(encoded[..2], [12, 1]);
            assert_eq!(encoded[2..18], address(1).0);
            assert_eq!(encoded[18..34], address(2).0);
            assert_eq!(encoded[34..], relayed);
            let (mut read_relay, mut relay_options) = (FFIDHCPv6RelayMessage::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_relay_message_decode(
                encoded.as_ptr(),
                encoded.len(),
                &mut read_relay,
                &mut relay_options,
            ));
            assert_eq!((read_relay, relay_options.as_slice()), (relay, relayed.as_slice()));
            malformed(umilib_protocol_dhcp_v6_dhcpv6_message_decode(
                encoded.as_ptr(),
                encoded.len(),
                &mut header,
                &mut options_out,
            ));
            malformed(umilib_protocol_dhcp_v6_dhcpv6_relay_message_decode(
                bytes.as_ptr(),
                bytes.len(),
                &mut read_relay,
                &mut relay_options,
            ));
            let client_relay = FFIDHCPv6RelayMessage { kind: 1, ..relay };
            malformed(umilib_protocol_dhcp_v6_dhcpv6_relay_message_encode(&client_relay, ptr::null(), 0, &mut out));
            // §21.4, §21.6: an IA_NA, its T1 and T2, and its address of two lifetimes; §21.13: a status.
            let mut status = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_status_code_encode(0, b"ok".as_ptr(), 2, &mut status));
            assert_eq!(status.as_slice(), [0, 0, b'o', b'k']);
            let (mut code, mut text) = (0xFFFF, Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_status_code_decode([0u8, 2].as_ptr(), 2, &mut code, &mut text));
            assert_eq!((code, text.as_slice()), (2, &[][..]));
            malformed(umilib_protocol_dhcp_v6_dhcpv6_status_code_decode([0u8].as_ptr(), 1, &mut code, &mut text));
            let held = FFIDHCPv6IAAddress { address: address(9), preferred: 300, valid: 400 };
            let mut data = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_address_encode(held, ptr::null(), 0, &mut data));
            assert_eq!(data.as_slice(), [&address(9).0[..], &[0, 0, 1, 44, 0, 0, 1, 144]].concat());
            let inner = encode(&[(IAADDR, data.as_slice()), (STATUS_CODE, status.as_slice())]);
            let mut ia_data = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_encode(
                FFIDHCPv6IA { kind: IA_NA, iaid: 7, t1: 100, t2: 200 },
                inner.as_ptr(),
                inner.len(),
                &mut ia_data,
            ));
            assert_eq!(ia_data.as_slice()[..12], [0, 0, 0, 7, 0, 0, 0, 100, 0, 0, 0, 200]);
            let (read_ia, ia_options) = ia(IA_NA, ia_data.as_slice());
            assert_eq!(
                (read_ia, ia_options),
                (FFIDHCPv6IA { kind: IA_NA, iaid: 7, t1: 100, t2: 200 }, options(&inner))
            );
            let (mut read_address, mut address_options) = (FFIDHCPv6IAAddress::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_address_decode(
                data.as_slice().as_ptr(),
                data.as_slice().len(),
                &mut read_address,
                &mut address_options,
            ));
            assert_eq!(read_address, held);
            umilib::ffi::umilib_ffi_buffer_free(&mut data);
            let mut read_ia = FFIDHCPv6IA::default();
            malformed(umilib_protocol_dhcp_v6_dhcpv6_ia_decode(
                IA_NA,
                [0u8; 11].as_ptr(),
                11,
                &mut read_ia,
                &mut address_options,
            ));
            malformed(umilib_protocol_dhcp_v6_dhcpv6_ia_address_decode(
                [0u8; 23].as_ptr(),
                23,
                &mut read_address,
                &mut address_options,
            ));
            // §21.22: an IA Prefix, its lifetimes, its length and the prefix, at most 128 bits.
            let delegated = FFIDHCPv6IAPrefix { preferred: 1, valid: 2, length: 56, prefix: prefix() };
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_encode(delegated, ptr::null(), 0, &mut data));
            assert_eq!(data.as_slice(), [&[0u8, 0, 0, 1, 0, 0, 0, 2, 56][..], &prefix().0].concat());
            let mut read_prefix = FFIDHCPv6IAPrefix::default();
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_decode(
                data.as_slice().as_ptr(),
                25,
                &mut read_prefix,
                &mut address_options,
            ));
            assert_eq!(read_prefix, delegated);
            let mut long = data.as_slice().to_vec();
            long[8] = 129;
            malformed(umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_decode(
                long.as_ptr(),
                long.len(),
                &mut read_prefix,
                &mut address_options,
            ));
            let too_long = FFIDHCPv6IAPrefix { length: 129, ..delegated };
            malformed(umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_encode(too_long, ptr::null(), 0, &mut data));
        }
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    #[test]
    fn addresses_and_a_prefix_from_solicit_to_release() {
        let random = Generator::new(b"dhcpv6 lease");
        unsafe {
            let server = server(server_config());
            let config = FFIDHCPv6ClientConfig {
                iaid: 1,
                addresses: true,
                prefix: true,
                prefix_hint: true,
                prefix_length: 56,
                rapid_commit: false,
            };
            let client = new_client(config, 1);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_start(
                client,
                at(0),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            // RFC 9915 §18.2.1: the first Solicit after a random delay of up to a second.
            assert!(transmit(client).is_none());
            let delay = timeout(client).unwrap();
            assert!(delay <= at(1), "{delay}");
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_expire(
                client,
                delay,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let solicit = transmit(client).unwrap();
            let (header, solicit_options) = decode(&solicit);
            assert_eq!(header.kind, 1);
            // §16, §18.2.1: the client's DUID, no server's; the elapsed time, 0 at first (§21.9); the
            // options asked for (§21.7); an IA_NA, and an IA_PD with the prefix length as a hint.
            assert_eq!(get(&solicit_options, CLIENT_ID), Some(duid(1)));
            assert_eq!(get(&solicit_options, SERVER_ID), None);
            assert_eq!(get(&solicit_options, ELAPSED_TIME), Some(vec![0, 0]));
            assert!(get(&solicit_options, ORO).unwrap().chunks(2).any(|code| code == DNS_SERVERS.to_be_bytes()));
            let (requested_na, _) = ia(IA_NA, &get(&solicit_options, IA_NA).unwrap());
            assert_eq!(requested_na, FFIDHCPv6IA { kind: IA_NA, iaid: 1, t1: 0, t2: 0 });
            let (_, pd_options) = ia(IA_PD, &get(&solicit_options, IA_PD).unwrap());
            assert_eq!(get(&pd_options, IAPREFIX).unwrap()[8], 56);
            // §18.3.1: an Advertise of the same transaction, with both DUIDs and the addresses offered.
            let advertise = answer(server, &solicit, delay).unwrap();
            let (advertised, advertise_options) = decode(&advertise);
            assert_eq!((advertised.kind, advertised.transaction), (2, header.transaction));
            assert_eq!(
                (get(&advertise_options, SERVER_ID), get(&advertise_options, CLIENT_ID)),
                (Some(duid(0x53)), Some(duid(1)))
            );
            // §18.2.9: below preference 255, the client waits out the first timeout.
            receive(client, &advertise, delay, &random);
            assert_eq!(state(client), 1);
            let first = timeout(client).unwrap();
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_expire(
                client,
                first,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!(state(client), 2);
            // §18.2.2: a Request to the server chosen, of a new transaction, with its DUID and the IAs offered.
            let request = transmit(client).unwrap();
            let (requested, request_options) = decode(&request);
            assert_eq!(requested.kind, 3);
            assert_ne!(requested.transaction, header.transaction);
            assert_eq!(get(&request_options, SERVER_ID), Some(duid(0x53)));
            assert_eq!(get(&request_options, ELAPSED_TIME), Some(vec![0, 0]));
            let reply = answer(server, &request, first).unwrap();
            assert_eq!(decode(&reply).0, FFIDHCPv6Message { kind: 7, transaction: requested.transaction });
            receive(client, &reply, first, &random);
            // §18.2.10.1: bound; T1 and T2 of the IAs, the valid lifetime, from the exchange's start.
            let events = poll_events(client);
            assert_eq!(events.len(), 1);
            let (event, ias, options_read, server_duid) = &events[0];
            assert_eq!(event.kind, 0);
            assert_eq!(
                event.lease,
                FFIDHCPv6Lease { acquired: first, renewal: 1_000_000, rebinding: 1_600_000, valid: 4_000_000 }
            );
            assert_eq!(server_duid, &duid(0x53));
            assert_eq!(get(&options(options_read), DNS_SERVERS), Some(address(53).0.to_vec()));
            let ias = options(ias);
            let (bound_na, na_options) = ia(IA_NA, &get(&ias, IA_NA).unwrap());
            assert_eq!(bound_na, FFIDHCPv6IA { kind: IA_NA, iaid: 1, t1: 1000, t2: 1600 });
            let mut held = FFIDHCPv6IAAddress::default();
            let mut nothing = Buffer::EMPTY;
            let data = get(&na_options, IAADDR).unwrap();
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_address_decode(
                data.as_ptr(),
                data.len(),
                &mut held,
                &mut nothing,
            ));
            assert_eq!(held, FFIDHCPv6IAAddress { address: address(100), preferred: 3000, valid: 4000 });
            let (_, pd_options) = ia(IA_PD, &get(&ias, IA_PD).unwrap());
            let mut delegated = FFIDHCPv6IAPrefix::default();
            let data = get(&pd_options, IAPREFIX).unwrap();
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_ia_prefix_decode(
                data.as_ptr(),
                data.len(),
                &mut delegated,
                &mut nothing,
            ));
            assert_eq!(delegated, FFIDHCPv6IAPrefix { preferred: 3000, valid: 4000, length: 56, prefix: prefix() });
            assert_eq!((state(client), timeout(client)), (3, Some(first + at(1000))));
            let mut found = false;
            let mut lease = FFIDHCPv6Lease::default();
            let (mut lease_ias, mut lease_options, mut lease_server) = (Buffer::EMPTY, Buffer::EMPTY, Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_lease(
                client,
                &mut found,
                &mut lease,
                &mut lease_ias,
                &mut lease_options,
                &mut lease_server,
            ));
            assert!(found);
            assert_eq!(lease, event.lease);
            // §18.2.4: Renew at T1, to the server, with its DUID.
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_expire(
                client,
                first + at(1000),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            assert_eq!(state(client), 4);
            let renew = transmit(client).unwrap();
            let (renewing, renew_options) = decode(&renew);
            assert_eq!((renewing.kind, get(&renew_options, SERVER_ID)), (5, Some(duid(0x53))));
            // §18.2.7: Release to the server, with its DUID and the IAs; its Reply ends the lease.
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_release(
                client,
                first + at(1001),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let release = transmit(client).unwrap();
            let (releasing, release_options) = decode(&release);
            assert_eq!((releasing.kind, get(&release_options, SERVER_ID)), (8, Some(duid(0x53))));
            assert!(get(&release_options, IA_NA).is_some());
            let reply = answer(server, &release, first + at(1001)).unwrap();
            let (_, reply_options) = decode(&reply);
            assert_eq!(get(&reply_options, STATUS_CODE).unwrap()[..2], [0, 0]);
            receive(client, &reply, first + at(1001), &random);
            assert_eq!(poll_events(client).iter().map(|event| event.0.kind).collect::<Vec<_>>(), [3]);
            assert_eq!((state(client), timeout(client)), (0, None));
            for status in [
                umilib_protocol_dhcp_v6_dhcpv6_client_release(
                    client,
                    0,
                    random.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                ),
                umilib_protocol_dhcp_v6_dhcpv6_client_confirm(
                    client,
                    0,
                    random.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                ),
                umilib_protocol_dhcp_v6_dhcpv6_client_decline(
                    client,
                    &address(100),
                    1,
                    0,
                    random.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                ),
            ] {
                Check::fails(status, "protocol.dhcp", "State");
            }
            umilib_protocol_dhcp_v6_dhcpv6_client_free(client);
            umilib_protocol_dhcp_v6_dhcpv6_server_free(server);
        }
    }

    #[cfg(umilib_feature = "hash-sha-v2")]
    #[test]
    fn rapid_commit_and_information() {
        let random = Generator::new(b"dhcpv6 rapid");
        unsafe {
            // §18.2.1, §18.3.1: Rapid Commit on both ends, a Reply to the Solicit, of Rapid Commit.
            let server = server(FFIDHCPv6ServerConfig { rapid_commit: true, ..server_config() });
            let config = FFIDHCPv6ClientConfig {
                iaid: 1,
                addresses: true,
                rapid_commit: true,
                ..FFIDHCPv6ClientConfig::default()
            };
            let client = new_client(config, 2);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_start(
                client,
                at(0),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_expire(
                client,
                at(1),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let solicit = transmit(client).unwrap();
            assert_eq!(get(&decode(&solicit).1, 14), Some(Vec::new()));
            let reply = answer(server, &solicit, at(1)).unwrap();
            let (replied, reply_options) = decode(&reply);
            assert_eq!((replied.kind, get(&reply_options, 14)), (7, Some(Vec::new())));
            receive(client, &reply, at(1), &random);
            assert_eq!((poll_events(client)[0].0.kind, state(client)), (0, 3));
            // §18.2.8: Decline of an address DAD found in use; the server will not lease it again.
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_decline(
                client,
                &address(100),
                1,
                at(2),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let decline = transmit(client).unwrap();
            assert_eq!(decode(&decline).0.kind, 9);
            receive(client, &answer(server, &decline, at(2)).unwrap(), at(2), &random);
            assert_eq!(poll_events(client)[0].0.kind, 3);
            assert_eq!(state(client), 1);
            let solicit = transmit(client).unwrap();
            let reply = answer(server, &solicit, at(3)).unwrap();
            let (_, na) = ia(IA_NA, &get(&decode(&reply).1, IA_NA).unwrap());
            assert_eq!(get(&na, IAADDR).unwrap()[..16], address(101).0);
            umilib_protocol_dhcp_v6_dhcpv6_client_free(client);
            // §18.2.6: asking for neither addresses nor prefixes, an Information-request without IAs;
            // §21.23: without an Information Refresh Time, the configuration is kept IRT_DEFAULT (86400 s).
            let stateless = new_client(FFIDHCPv6ClientConfig::default(), 3);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_start(
                stateless,
                at(0),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_client_expire(
                stateless,
                at(1),
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let request = transmit(stateless).unwrap();
            let (header, request_options) = decode(&request);
            assert_eq!(header.kind, 11);
            assert_eq!(
                (get(&request_options, IA_NA), get(&request_options, IA_PD), get(&request_options, SERVER_ID)),
                (None, None, None)
            );
            let reply = answer(server, &request, at(1)).unwrap();
            receive(stateless, &reply, at(1), &random);
            let events = poll_events(stateless);
            assert_eq!(events[0].0.kind, 2);
            assert_eq!(get(&options(&events[0].2), DNS_SERVERS), Some(address(53).0.to_vec()));
            assert_eq!((state(stateless), timeout(stateless)), (10, Some(at(1) + at(86_400))));
            umilib_protocol_dhcp_v6_dhcpv6_client_free(stateless);
            umilib_protocol_dhcp_v6_dhcpv6_server_free(server);
        }
    }

    #[test]
    fn the_checks_of_section_16_and_relays() {
        unsafe {
            let ia_na = [0u8, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
            let solicit_options = encode(&[(CLIENT_ID, &duid(4)), (ELAPSED_TIME, &[0, 0]), (IA_NA, &ia_na)]);
            // The configuration of a server, given a pool: its addresses' preferred lifetime is not past
            // their valid one (RFC 9915 §21.6).
            let mut config = FFIDHCPv6ServerConfig::default();
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_config_new(&mut config));
            assert!(!config.addresses && !config.prefixes && config.preferred <= config.valid && config.valid > 0);
            let pool =
                server(FFIDHCPv6ServerConfig { addresses: true, first: address(100), last: address(101), ..config });
            let mut first = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_message_encode(
                FFIDHCPv6Message { kind: 1, transaction: 9 },
                solicit_options.as_ptr(),
                solicit_options.len(),
                &mut first,
            ));
            let (advertised, advertise_options) = decode(&answer(pool, first.as_slice(), 0).unwrap());
            assert_eq!(advertised, FFIDHCPv6Message { kind: 2, transaction: 9 });
            let (_, na) = ia(IA_NA, &get(&advertise_options, IA_NA).unwrap());
            assert_eq!(get(&na, IAADDR).unwrap()[..16], address(100).0);
            umilib_protocol_dhcp_v6_dhcpv6_server_free(pool);
            let server = server(server_config());
            let mut solicit = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_message_encode(
                FFIDHCPv6Message { kind: 1, transaction: 7 },
                solicit_options.as_ptr(),
                solicit_options.len(),
                &mut solicit,
            ));
            // §16: a Solicit with a Server Identifier, or without a Client Identifier, is discarded; so is
            // a Request without the server's identifier.
            let with_server = [solicit.as_slice(), &encode(&[(SERVER_ID, &duid(0x53))])].concat();
            assert!(answer(server, &with_server, at(0)).is_none());
            let anonymous = [&[1u8, 0, 0, 7][..], &encode(&[(ELAPSED_TIME, &[0, 0]), (IA_NA, &ia_na)])].concat();
            assert!(answer(server, &anonymous, at(0)).is_none());
            let request = [&[3u8][..], &solicit.as_slice()[1..]].concat();
            assert!(answer(server, &request, at(0)).is_none());
            let elsewhere = [request.as_slice(), &encode(&[(SERVER_ID, &duid(0x54))])].concat();
            assert!(answer(server, &elsewhere, at(0)).is_none());
            // §19.3: a Relay-forward is answered in a Relay-reply of the same addresses and Interface-Id.
            let relay = FFIDHCPv6RelayMessage {
                kind: 12,
                hops: 0,
                link: address(1),
                peer: IPv6Address([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            };
            let relay_options = encode(&[(INTERFACE_ID, b"eth0"), (RELAY_MSG, solicit.as_slice())]);
            let mut forward = Buffer::EMPTY;
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_relay_message_encode(
                &relay,
                relay_options.as_ptr(),
                relay_options.len(),
                &mut forward,
            ));
            let reply = answer(server, forward.as_slice(), at(0)).unwrap();
            let (mut read, mut read_options) = (FFIDHCPv6RelayMessage::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_relay_message_decode(
                reply.as_ptr(),
                reply.len(),
                &mut read,
                &mut read_options,
            ));
            assert_eq!(read, FFIDHCPv6RelayMessage { kind: 13, ..relay });
            let read_options = options(read_options.as_slice());
            assert_eq!(get(&read_options, INTERFACE_ID), Some(b"eth0".to_vec()));
            let (advertised, advertise_options) = decode(&get(&read_options, RELAY_MSG).unwrap());
            assert_eq!((advertised.kind, advertised.transaction), (2, 7));
            assert_eq!(get(&advertise_options, CLIENT_ID), Some(duid(4)));
            // A pool backwards, a delegated prefix shorter than its prefix, a broken DUID.
            let mut out = ptr::null_mut();
            let given = duid(0x53);
            for config in [
                FFIDHCPv6ServerConfig { first: address(101), last: address(100), ..server_config() },
                FFIDHCPv6ServerConfig { prefix_length: 60, ..server_config() },
            ] {
                Check::fails(
                    umilib_protocol_dhcp_v6_dhcpv6_server_new(
                        &config,
                        given.as_ptr(),
                        given.len(),
                        ptr::null(),
                        0,
                        &mut out,
                    ),
                    "protocol.dhcp",
                    "Config",
                );
            }
            malformed(umilib_protocol_dhcp_v6_dhcpv6_server_new(
                &server_config(),
                given.as_ptr(),
                2,
                ptr::null(),
                0,
                &mut out,
            ));
            Check::ok(umilib_protocol_dhcp_v6_dhcpv6_server_expire(server, at(1)));
            umilib_protocol_dhcp_v6_dhcpv6_server_free(server);
        }
    }
}
