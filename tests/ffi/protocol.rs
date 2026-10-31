use std::ptr;

use umilib::ffi::Buffer;
use umilib::ffi::protocol::ip::*;
use umilib::ffi::protocol::tcp::*;
use umilib::protocol::ip::{IPEndpoint, IPEndpointPattern};
use umilib::protocol::tcp::{TCPConnection, TCPFlags, TCPListener, TCPSequence, TCPState};

use super::Check;

/// Moves every segment `from` has at `now` to `to`, and returns how many.
unsafe fn deliver(
    from: *mut TCPConnection,
    to: *mut TCPConnection,
    source: &[u8],
    destination: &[u8],
    now: u64,
) -> usize {
    let mut count = 0;
    loop {
        let (mut found, mut ect, mut bytes) = (false, false, Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_tcp_tcp_connection_transmit(from, now, &mut found, &mut bytes, &mut ect));
            if !found {
                umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
                return count;
            }
            let (segment, options, payload) = decode(bytes.as_slice(), source, destination);
            Check::ok(umilib_protocol_tcp_tcp_connection_receive(
                to,
                &segment,
                options.as_ptr(),
                options.len(),
                payload.as_ptr(),
                payload.len(),
                false,
                now,
            ));
            umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
        }
        count += 1;
    }
}

/// The segment in `bytes` and its options and data.
unsafe fn decode<'a>(bytes: &'a [u8], source: &[u8], destination: &[u8]) -> (FFITCPSegment, &'a [u8], &'a [u8]) {
    let mut segment = FFITCPSegment::default();
    let (mut options_offset, mut options_length, mut payload_offset, mut payload_length) = (0, 0, 0, 0);
    unsafe {
        Check::ok(umilib_protocol_tcp_tcp_segment_decode(
            bytes.as_ptr(),
            bytes.len(),
            source.as_ptr(),
            source.len(),
            destination.as_ptr(),
            destination.len(),
            &mut segment,
            &mut options_offset,
            &mut options_length,
            &mut payload_offset,
            &mut payload_length,
        ));
    }
    (
        segment,
        &bytes[options_offset..options_offset + options_length],
        &bytes[payload_offset..payload_offset + payload_length],
    )
}

fn endpoint(text: &str) -> FFIIPEndpoint {
    let mut endpoint = FFIIPEndpoint::default();
    unsafe { Check::ok(umilib_protocol_ip_ip_endpoint_parse(text.as_ptr(), text.len(), &mut endpoint)) };
    endpoint
}

#[test]
fn tcp_connections_through_the_c_abi() {
    // RFC 9293 §3.5 and §3.6: a handshake, data both ways, and a close.
    let (client_address, server_address) = ([192u8, 0, 2, 1], [192u8, 0, 2, 2]);
    let (client, server) = (endpoint("192.0.2.1:40000"), endpoint("192.0.2.2:80"));
    let mut config = FFITCPConfig::default();
    unsafe {
        Check::ok(umilib_protocol_tcp_tcp_config_default(&mut config));
        let mut isn = ptr::null_mut();
        Check::ok(umilib_protocol_tcp_tcp_isn_generator_new([1u8; 16].as_ptr(), &mut isn));
        let mut iss = TCPSequence(0);
        Check::ok(umilib_protocol_tcp_tcp_isn_generator_generate(isn, &client, &server, 0, &mut iss));
        umilib_protocol_tcp_tcp_isn_generator_free(isn);

        let mut a = ptr::null_mut();
        Check::ok(umilib_protocol_tcp_tcp_connection_connect(&config, &client, &server, iss, 0, &mut a));
        let (mut found, mut ect, mut syn) = (false, false, Buffer::EMPTY);
        Check::ok(umilib_protocol_tcp_tcp_connection_transmit(a, 0, &mut found, &mut syn, &mut ect));
        assert!(found && !ect);
        let (segment, options, payload) = decode(syn.as_slice(), &client_address, &server_address);
        assert_eq!((segment.flags, segment.sequence), (TCPFlags::SYN, iss));
        let mut set = FFITCPOptionSet::default();
        Check::ok(umilib_protocol_tcp_tcp_option_set_decode(options.as_ptr(), options.len(), &mut set));
        let mut b = ptr::null_mut();
        Check::ok(umilib_protocol_tcp_tcp_connection_accept(
            &config,
            &server,
            &client,
            &segment,
            options.as_ptr(),
            options.len(),
            payload.as_ptr(),
            payload.len(),
            TCPSequence(7),
            0,
            &mut b,
        ));
        let syn_options = options.to_vec();
        umilib::ffi::umilib_ffi_buffer_free(&mut syn);
        assert_eq!(deliver(b, a, &server_address, &client_address, 1_000_000), 1);
        assert_eq!(deliver(a, b, &client_address, &server_address, 2_000_000), 1);
        let mut info = FFITCPConnectionInfo::default();
        Check::ok(umilib_protocol_tcp_tcp_connection_info(a, &mut info));
        assert_eq!(info.state, TCPState::Established as u8);
        let (mut kind, mut reason) = (9u8, 9u8);
        Check::ok(umilib_protocol_tcp_tcp_connection_poll_event(b, &mut found, &mut kind, &mut reason));
        assert!(found && kind == 0);
        let (mut local, mut remote) = (FFIIPEndpoint::default(), FFIIPEndpoint::default());
        Check::ok(umilib_protocol_tcp_tcp_connection_endpoints(b, &mut local, &mut remote));
        assert_eq!((local, remote), (server, client));

        // Data both ways; the bytes read are those sent.
        let mut taken = 0usize;
        Check::ok(umilib_protocol_tcp_tcp_connection_send(a, b"hello, tcp".as_ptr(), 10, false, &mut taken));
        assert_eq!(taken, 10);
        Check::ok(umilib_protocol_tcp_tcp_connection_send(b, b"reply".as_ptr(), 5, false, &mut taken));
        deliver(a, b, &client_address, &server_address, 3_000_000);
        deliver(b, a, &server_address, &client_address, 3_000_000);
        let (mut readable, mut writable, mut urgent) = (0usize, 0usize, 0u32);
        Check::ok(umilib_protocol_tcp_tcp_connection_sizes(b, &mut readable, &mut writable, &mut urgent));
        assert_eq!((readable, urgent), (10, 0));
        assert!(writable <= config.send_buffer);
        let mut read = [0u8; 16];
        let mut count = 0usize;
        Check::ok(umilib_protocol_tcp_tcp_connection_read(b, read.as_mut_ptr(), read.len(), &mut count));
        assert_eq!(&read[..count], b"hello, tcp");
        Check::ok(umilib_protocol_tcp_tcp_connection_read(a, read.as_mut_ptr(), read.len(), &mut count));
        assert_eq!(&read[..count], b"reply");
        let mut deadline = 0u64;
        Check::ok(umilib_protocol_tcp_tcp_connection_poll_timeout(b, &mut found, &mut deadline));

        // Packet Too Big about a segment in flight lowers the MTU (RFC 8201 §4); other kinds fail.
        // The segment is sent and lost; the error quotes it.
        Check::ok(umilib_protocol_tcp_tcp_connection_send(a, [0u8; 100].as_ptr(), 100, false, &mut taken));
        let mut lost = Buffer::EMPTY;
        Check::ok(umilib_protocol_tcp_tcp_connection_transmit(a, 3_000_000, &mut found, &mut lost, &mut ect));
        assert!(found);
        let (quoted, _, _) = decode(lost.as_slice(), &client_address, &server_address);
        umilib::ffi::umilib_ffi_buffer_free(&mut lost);
        Check::ok(umilib_protocol_tcp_tcp_connection_receive_error(a, 2, 1280, quoted.sequence, 3_000_000));
        Check::ok(umilib_protocol_tcp_tcp_connection_info(a, &mut info));
        assert_eq!(info.mtu, 1280);
        Check::fails(
            umilib_protocol_tcp_tcp_connection_receive_error(a, 3, 0, info.send_unacknowledged, 3_000_000),
            "ffi",
            "InvalidArgument",
        );
        deliver(a, b, &client_address, &server_address, 3_500_000);
        deliver(b, a, &server_address, &client_address, 3_500_000);
        Check::ok(umilib_protocol_tcp_tcp_connection_read(b, read.as_mut_ptr(), read.len(), &mut count));
        assert_eq!(count, 16);

        // A synchronized connection is not in TIME-WAIT: no SYN reopens it (RFC 6191).
        let mut accepted = true;
        Check::ok(umilib_protocol_tcp_tcp_connection_accepts_syn(
            a,
            &segment,
            syn_options.as_ptr(),
            syn_options.len(),
            ptr::null(),
            0,
            &mut accepted,
        ));
        assert!(!accepted);

        // The configuration crosses both ways (MUST-17: Nagle off).
        let mut current = FFITCPConfig::default();
        Check::ok(umilib_protocol_tcp_tcp_connection_config(a, &mut current));
        current.nagle = false;
        Check::ok(umilib_protocol_tcp_tcp_connection_set_config(a, &current, 4_000_000));
        Check::ok(umilib_protocol_tcp_tcp_connection_config(a, &mut config));
        assert!(!config.nagle);

        // Both close (RFC 9293 Figure 12): TIME-WAIT and CLOSED.
        Check::ok(umilib_protocol_tcp_tcp_connection_close(a));
        deliver(a, b, &client_address, &server_address, 5_000_000);
        deliver(b, a, &server_address, &client_address, 5_000_000);
        Check::ok(umilib_protocol_tcp_tcp_connection_close(b));
        deliver(b, a, &server_address, &client_address, 6_000_000);
        deliver(a, b, &client_address, &server_address, 6_000_000);
        Check::ok(umilib_protocol_tcp_tcp_connection_info(a, &mut info));
        assert_eq!(info.state, TCPState::TimeWait as u8);
        Check::fails(
            umilib_protocol_tcp_tcp_connection_send(a, b"x".as_ptr(), 1, false, &mut taken),
            "protocol.tcp",
            "State",
        );
        Check::fails(umilib_protocol_tcp_tcp_connection_info(a, ptr::null_mut()), "ffi", "NullPointer");
        Check::fails(
            umilib_protocol_tcp_tcp_connection_transmit(a, 0, &mut found, ptr::null_mut(), &mut ect),
            "ffi",
            "NullPointer",
        );
        umilib_protocol_tcp_tcp_connection_free(a);
        umilib_protocol_tcp_tcp_connection_free(b);
        umilib_protocol_tcp_tcp_connection_free(ptr::null_mut());
    }
}

#[test]
fn tcp_listeners_and_rules_through_the_c_abi() {
    // RFC 9293 §3.10.7.2: a SYN to a listener opens a connection that is
    // accepted once established; an ACK for no connection gets a reset.
    let (client_address, server_address) = ([192u8, 0, 2, 1], [192u8, 0, 2, 2]);
    let (client, server) = (endpoint("192.0.2.1:40000"), endpoint("192.0.2.2:80"));
    let pattern = FFIIPEndpointPattern::of(&IPEndpointPattern::port(80));
    let mut config = FFITCPConfig::default();
    unsafe {
        Check::ok(umilib_protocol_tcp_tcp_config_default(&mut config));
        let mut listener: *mut TCPListener = ptr::null_mut();
        Check::ok(umilib_protocol_tcp_tcp_listener_new(&config, &pattern, 2, [0u8; 16].as_ptr(), &mut listener));
        let mut a = ptr::null_mut();
        Check::ok(umilib_protocol_tcp_tcp_connection_connect(&config, &client, &server, TCPSequence(100), 0, &mut a));
        let (mut found, mut ect, mut bytes) = (false, false, Buffer::EMPTY);
        Check::ok(umilib_protocol_tcp_tcp_connection_transmit(a, 0, &mut found, &mut bytes, &mut ect));
        let (segment, options, payload) = decode(bytes.as_slice(), &client_address, &server_address);
        Check::ok(umilib_protocol_tcp_tcp_listener_receive(
            listener,
            &segment,
            options.as_ptr(),
            options.len(),
            payload.as_ptr(),
            payload.len(),
            &server,
            &client,
            false,
            0,
        ));
        umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
        let (mut deadline, mut pending, mut ready) = (0u64, 0usize, 0usize);
        Check::ok(umilib_protocol_tcp_tcp_listener_poll_timeout(
            listener,
            &mut found,
            &mut deadline,
            &mut pending,
            &mut ready,
        ));
        // The SYN-ACK is due now and its retransmission timer not yet set.
        assert_eq!((found, pending, ready), (false, 1, 0));

        let (mut local, mut remote) = (FFIIPEndpoint::default(), FFIIPEndpoint::default());
        Check::ok(umilib_protocol_tcp_tcp_listener_transmit(
            listener,
            1,
            &mut found,
            &mut local,
            &mut remote,
            &mut bytes,
            &mut ect,
        ));
        assert!(found && (local, remote) == (server, client));
        let (synack, options, payload) = decode(bytes.as_slice(), &server_address, &client_address);
        assert_eq!(synack.flags, TCPFlags::SYN.union(TCPFlags::ACK));
        Check::ok(umilib_protocol_tcp_tcp_connection_receive(
            a,
            &synack,
            options.as_ptr(),
            options.len(),
            payload.as_ptr(),
            payload.len(),
            false,
            2,
        ));
        umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
        Check::ok(umilib_protocol_tcp_tcp_connection_transmit(a, 3, &mut found, &mut bytes, &mut ect));
        let (ack, options, payload) = decode(bytes.as_slice(), &client_address, &server_address);
        Check::ok(umilib_protocol_tcp_tcp_listener_receive(
            listener,
            &ack,
            options.as_ptr(),
            options.len(),
            payload.as_ptr(),
            payload.len(),
            &server,
            &client,
            false,
            3,
        ));
        umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
        let mut accepted = ptr::null_mut();
        Check::ok(umilib_protocol_tcp_tcp_listener_accept(listener, &mut found, &mut accepted));
        assert!(found && !accepted.is_null());
        let mut info = FFITCPConnectionInfo::default();
        Check::ok(umilib_protocol_tcp_tcp_connection_info(accepted, &mut info));
        assert_eq!(info.state, TCPState::Established as u8);
        let mut none = ptr::null_mut();
        Check::ok(umilib_protocol_tcp_tcp_listener_accept(listener, &mut found, &mut none));
        assert!(!found && none.is_null());

        // The rule routes the connection by its endpoints.
        let rule = FFITCPRule { local: pattern, remote: FFIIPEndpointPattern::of(&IPEndpointPattern::ANY) };
        let mut matches = false;
        Check::ok(umilib_protocol_tcp_tcp_rule_matches(&rule, &server, &client, &mut matches));
        assert!(matches);
        Check::ok(umilib_protocol_tcp_tcp_rule_matches(&rule, &client, &server, &mut matches));
        assert!(!matches);

        // An ACK from an endpoint with no connection: a reset of its acknowledgment number.
        let stray = FFITCPSegment {
            source_port: 40001,
            destination_port: 80,
            sequence: TCPSequence(5),
            acknowledgment: TCPSequence(77),
            flags: TCPFlags::ACK,
            window: 100,
            urgent_pointer: 0,
        };
        let other = FFIIPEndpoint::of(&"192.0.2.1:40001".parse::<IPEndpoint>().unwrap());
        Check::ok(umilib_protocol_tcp_tcp_listener_receive(
            listener,
            &stray,
            ptr::null(),
            0,
            ptr::null(),
            0,
            &server,
            &other,
            false,
            4,
        ));
        Check::ok(umilib_protocol_tcp_tcp_listener_transmit(
            listener,
            4,
            &mut found,
            &mut local,
            &mut remote,
            &mut bytes,
            &mut ect,
        ));
        let (reset, _, _) = decode(bytes.as_slice(), &server_address, &client_address);
        assert!(found && remote == other);
        assert_eq!((reset.flags, reset.sequence), (TCPFlags::RST, TCPSequence(77)));
        umilib::ffi::umilib_ffi_buffer_free(&mut bytes);

        umilib_protocol_tcp_tcp_connection_free(accepted);
        umilib_protocol_tcp_tcp_connection_free(a);
        umilib_protocol_tcp_tcp_listener_free(listener);
    }
}

/// TLS through the C ABI (RFC 9846): configurations, rules and ECH keys,
/// and a handshake with data both ways.
#[cfg(umilib_feature = "protocol-tls")]
mod tls {
    use std::ptr;

    use umilib::ffi::Buffer;
    use umilib::ffi::auth::cert::key::*;
    use umilib::ffi::auth::cert::path::*;
    use umilib::ffi::auth::cert::x509::*;
    use umilib::ffi::protocol::tls::*;
    use umilib::protocol::tls::{TLSConfig, TLSConnection};

    use super::super::Check;

    const ROOT: &[u8] = include_bytes!("../vectors/protocol/tls/certificates/root.der");
    const CERTIFICATE: &[u8] = include_bytes!("../vectors/protocol/tls/certificates/server-p256.der");
    const KEY: &str = include_str!("../vectors/protocol/tls/certificates/server-p256.key");
    /// 2027-01-01, inside the validity of the certificates.
    const TIME: i64 = 1_798_761_600;

    unsafe fn config() -> *mut TLSConfig {
        let mut config = ptr::null_mut();
        unsafe { Check::ok(umilib_protocol_tls_tls_config_new(&mut config)) };
        config
    }

    #[test]
    fn tls_configurations_rules_and_keys_through_the_c_abi() {
        unsafe {
            let config = config();
            let mut limits = FFITLSLimits::default();
            Check::ok(umilib_protocol_tls_tls_config_limits(config, &mut limits));
            assert_eq!((limits.record_size_limit, limits.require_extended_main_secret), (1 << 14, true));
            limits.record_size_limit = 512;
            Check::ok(umilib_protocol_tls_tls_config_set_limits(config, &limits));
            Check::ok(umilib_protocol_tls_tls_config_limits(config, &mut limits));
            assert_eq!(limits.record_size_limit, 512);
            let versions = [0x0304u16];
            Check::ok(umilib_protocol_tls_tls_config_set_versions(config, versions.as_ptr(), versions.len()));
            let protocols = [b"h2".as_ptr(), b"http/1.1".as_ptr()];
            let lengths = [2usize, 8];
            Check::ok(umilib_protocol_tls_tls_config_set_protocols(config, protocols.as_ptr(), lengths.as_ptr(), 2));
            umilib_protocol_tls_tls_config_free(config);
            // Rules.
            let mut rule = ptr::null_mut();
            Check::ok(umilib_protocol_tls_tls_rule_new(b"*.example".as_ptr(), 9, b"h2".as_ptr(), 2, &mut rule));
            let mut matches = true;
            Check::fails(
                umilib_protocol_tls_tls_rule_matches_client_hello(rule, [1u8].as_ptr(), 1, &mut matches),
                "protocol.tls",
                "Protocol",
            );
            umilib_protocol_tls_tls_rule_free(rule);
            // An ECH key from its parts, its configuration list and private key, and a seed too short.
            let mut key = ptr::null_mut();
            Check::fails(
                umilib_protocol_tls_tls_ech_key_generate(
                    1,
                    0x0020,
                    [1u16, 1].as_ptr(),
                    1,
                    0,
                    b"public.example".as_ptr(),
                    14,
                    true,
                    [0u8; 31].as_ptr(),
                    31,
                    &mut key,
                ),
                "ffi",
                "InvalidArgument",
            );
            // ECH keys need HPKE (`crypto-hpke`).
            #[cfg(not(umilib_feature = "crypto-hpke"))]
            {
                Check::fails(
                    umilib_protocol_tls_tls_ech_key_generate(
                        1,
                        0x0020,
                        [1u16, 1].as_ptr(),
                        1,
                        0,
                        b"public.example".as_ptr(),
                        14,
                        true,
                        [9u8; 48].as_ptr(),
                        48,
                        &mut key,
                    ),
                    "protocol.tls",
                    "Config",
                );
            }
            #[cfg(umilib_feature = "crypto-hpke")]
            {
                Check::ok(umilib_protocol_tls_tls_ech_key_generate(
                    1,
                    0x0020,
                    [1u16, 1].as_ptr(),
                    1,
                    0,
                    b"public.example".as_ptr(),
                    14,
                    true,
                    [9u8; 48].as_ptr(),
                    48,
                    &mut key,
                ));
                let (mut list, mut private) = (Buffer::EMPTY, Buffer::EMPTY);
                Check::ok(umilib_protocol_tls_tls_ech_key_config_list(key, &mut list));
                Check::ok(umilib_protocol_tls_tls_ech_key_private_key(key, &mut private));
                assert_eq!(private.as_slice().len(), 32);
                let mut again = ptr::null_mut();
                Check::ok(umilib_protocol_tls_tls_ech_key_new(
                    list.as_slice().as_ptr(),
                    list.as_slice().len(),
                    private.as_slice().as_ptr(),
                    32,
                    true,
                    &mut again,
                ));
                umilib_protocol_tls_tls_ech_key_free(again);
                umilib_protocol_tls_tls_ech_key_free(key);
                umilib::ffi::umilib_ffi_buffer_free(&mut list);
                umilib::ffi::umilib_ffi_buffer_free(&mut private);
            }
        }
    }

    /// Moves bytes both ways until neither side has more.
    unsafe fn run(client: *mut TLSConnection, server: *mut TLSConnection) {
        loop {
            let mut moved = false;
            for (from, to) in [(client, server), (server, client)] {
                let mut bytes = Buffer::EMPTY;
                unsafe {
                    Check::ok(umilib_protocol_tls_tls_connection_transmit(from, &mut bytes));
                    if !bytes.as_slice().is_empty() {
                        moved = true;
                        Check::ok(umilib_protocol_tls_tls_connection_receive(
                            to,
                            bytes.as_slice().as_ptr(),
                            bytes.as_slice().len(),
                        ));
                    }
                    umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
                }
            }
            if !moved {
                return;
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "whole TLS handshakes take too long under Miri")]
    fn tls_connections_through_the_c_abi() {
        unsafe {
            let mut root = ptr::null_mut();
            Check::ok(umilib_auth_cert_x509_certificate_from_der(ROOT.as_ptr(), ROOT.len(), &mut root));
            let mut anchor = ptr::null_mut();
            Check::ok(umilib_auth_cert_path_trust_anchor_from_certificate(root, 16384, 64, &mut anchor));
            let mut anchors = ptr::null_mut();
            Check::ok(umilib_auth_cert_path_trust_anchors_new(&mut anchors));
            Check::ok(umilib_auth_cert_path_trust_anchors_push(anchors, anchor));
            let mut verifier = ptr::null_mut();
            Check::ok(umilib_protocol_tls_tls_path_verifier_servers(anchors, &mut verifier));
            let mut private = ptr::null_mut();
            Check::ok(umilib_auth_cert_key_private_key_from_pem(KEY.as_ptr(), KEY.len(), &mut private));
            let mut certified = ptr::null_mut();
            Check::ok(umilib_protocol_tls_tls_certified_key_new(
                [CERTIFICATE.as_ptr()].as_ptr(),
                [CERTIFICATE.len()].as_ptr(),
                1,
                private,
                ptr::null(),
                0,
                &mut certified,
            ));
            let config = config();
            let (mut client_config, mut server_config) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_protocol_tls_tls_client_config_new(config, verifier, &mut client_config));
            Check::ok(umilib_protocol_tls_tls_server_config_new(config, &mut server_config));
            Check::ok(umilib_protocol_tls_tls_server_config_add_certificate(server_config, certified));
            let (mut client, mut server) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_protocol_tls_tls_connection_client(
                client_config,
                b"server.example".as_ptr(),
                14,
                [1u8; 48].as_ptr(),
                48,
                TIME,
                &mut client,
            ));
            Check::ok(umilib_protocol_tls_tls_connection_server(
                server_config,
                [2u8; 48].as_ptr(),
                48,
                TIME,
                &mut server,
            ));
            run(client, server);
            let mut session = FFITLSSession::default();
            Check::ok(umilib_protocol_tls_tls_connection_session(client, &mut session));
            assert_eq!((session.version, session.handshaking), (0x0304, false));
            let (mut found, mut kind) = (false, 0u8);
            Check::ok(umilib_protocol_tls_tls_connection_poll_event(client, &mut found, &mut kind));
            assert!(found && kind == 0, "Connected");
            Check::ok(umilib_protocol_tls_tls_connection_send(client, b"hello".as_ptr(), 5));
            run(client, server);
            let (mut read, mut count) = ([0u8; 8], 0usize);
            Check::ok(umilib_protocol_tls_tls_connection_read(server, read.as_mut_ptr(), read.len(), &mut count));
            assert_eq!(&read[..count], b"hello");
            let (mut ours, mut theirs) = ([0u8; 16], [0u8; 16]);
            Check::ok(umilib_protocol_tls_tls_connection_export(
                client,
                b"label".as_ptr(),
                5,
                false,
                ptr::null(),
                0,
                ours.as_mut_ptr(),
                16,
            ));
            Check::ok(umilib_protocol_tls_tls_connection_export(
                server,
                b"label".as_ptr(),
                5,
                false,
                ptr::null(),
                0,
                theirs.as_mut_ptr(),
                16,
            ));
            assert_eq!(ours, theirs);
            // The output may not overlap the label.
            let mut overlapping = *b"label-and-output";
            let label = overlapping.as_ptr();
            Check::fails(
                umilib_protocol_tls_tls_connection_export(
                    client,
                    label,
                    5,
                    false,
                    ptr::null(),
                    0,
                    overlapping.as_mut_ptr(),
                    16,
                ),
                "ffi",
                "InvalidArgument",
            );
            let mut name = Buffer::EMPTY;
            Check::ok(umilib_protocol_tls_tls_connection_server_name(server, &mut found, &mut name));
            assert!(found && name.as_slice() == b"server.example");
            umilib::ffi::umilib_ffi_buffer_free(&mut name);
            // A failure: the alert is in the connection's error.
            Check::fails(
                umilib_protocol_tls_tls_connection_receive(server, [21u8, 3, 3, 0, 2, 2, 40].as_ptr(), 7),
                "protocol.tls",
                "Protocol",
            );
            let (mut failed, mut error, mut alert) = (false, 0u8, 0u8);
            Check::ok(umilib_protocol_tls_tls_connection_error(server, &mut failed, &mut error, &mut alert));
            assert!(failed);
            for handle in [client, server] {
                umilib_protocol_tls_tls_connection_free(handle);
            }
            umilib_protocol_tls_tls_client_config_free(client_config);
            umilib_protocol_tls_tls_server_config_free(server_config);
            umilib_protocol_tls_tls_config_free(config);
            umilib_protocol_tls_tls_certified_key_free(certified);
            umilib_protocol_tls_tls_path_verifier_free(verifier);
            umilib_auth_cert_path_trust_anchors_free(anchors);
            umilib_auth_cert_path_trust_anchor_free(anchor);
            umilib_auth_cert_x509_certificate_free(root);
        }
    }
}

#[cfg(umilib_feature = "protocol-quic")]
mod quic {
    use std::ptr;

    use umilib::ffi::Buffer;
    use umilib::ffi::auth::cert::key::*;
    use umilib::ffi::auth::cert::path::*;
    use umilib::ffi::auth::cert::x509::*;
    use umilib::ffi::protocol::ip::FFIIPEndpoint;
    use umilib::ffi::protocol::quic::*;
    use umilib::ffi::protocol::tls::*;
    use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address};
    use umilib::protocol::quic::{QUICConfig, QUICEndpoint};

    use super::super::Check;

    const ROOT: &[u8] = include_bytes!("../vectors/protocol/tls/certificates/root.der");
    const CERTIFICATE: &[u8] = include_bytes!("../vectors/protocol/tls/certificates/server-p256.der");
    const KEY: &str = include_str!("../vectors/protocol/tls/certificates/server-p256.key");
    const TIME: i64 = 1_798_761_600;

    fn endpoint(last: u8, port: u16) -> FFIIPEndpoint {
        FFIIPEndpoint::of(&IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, last)), port))
    }

    /// Moves datagrams between the two endpoints until both are quiet.
    unsafe fn run(client: *mut QUICEndpoint, server: *mut QUICEndpoint, now: u64) {
        let (client_address, server_address) = (endpoint(2, 50000), endpoint(1, 443));
        for _ in 0..1000 {
            let mut moved = false;
            for (from, to, source) in [(client, server, client_address), (server, client, server_address)] {
                loop {
                    let (mut found, mut destination, mut buffer) = (false, FFIIPEndpoint::default(), Buffer::default());
                    unsafe {
                        Check::ok(umilib_protocol_quic_quic_endpoint_transmit(
                            from,
                            now,
                            &mut found,
                            &mut destination,
                            &mut buffer,
                        ))
                    };
                    if !found {
                        break;
                    }
                    moved = true;
                    let datagram = buffer.as_slice().to_vec();
                    unsafe { umilib::ffi::umilib_ffi_buffer_free(&mut buffer) };
                    let (mut taken, mut handle) = (false, 0u64);
                    unsafe {
                        Check::ok(umilib_protocol_quic_quic_endpoint_receive(
                            to,
                            datagram.as_ptr(),
                            datagram.len(),
                            &source,
                            0,
                            now,
                            TIME,
                            &mut taken,
                            &mut handle,
                        ))
                    };
                }
            }
            if !moved {
                return;
            }
        }
        panic!("never quiet");
    }

    #[test]
    #[cfg_attr(miri, ignore = "whole QUIC handshakes take too long under Miri")]
    fn quic_endpoints_through_the_c_abi() {
        unsafe {
            // The TLS configurations, with a protocol for ALPN (RFC 9001 §8.1).
            let mut root = ptr::null_mut();
            Check::ok(umilib_auth_cert_x509_certificate_from_der(ROOT.as_ptr(), ROOT.len(), &mut root));
            let mut anchor = ptr::null_mut();
            Check::ok(umilib_auth_cert_path_trust_anchor_from_certificate(root, 16384, 64, &mut anchor));
            let mut anchors = ptr::null_mut();
            Check::ok(umilib_auth_cert_path_trust_anchors_new(&mut anchors));
            Check::ok(umilib_auth_cert_path_trust_anchors_push(anchors, anchor));
            let mut verifier = ptr::null_mut();
            Check::ok(umilib_protocol_tls_tls_path_verifier_servers(anchors, &mut verifier));
            let mut private = ptr::null_mut();
            Check::ok(umilib_auth_cert_key_private_key_from_pem(KEY.as_ptr(), KEY.len(), &mut private));
            let mut certified = ptr::null_mut();
            Check::ok(umilib_protocol_tls_tls_certified_key_new(
                [CERTIFICATE.as_ptr()].as_ptr(),
                [CERTIFICATE.len()].as_ptr(),
                1,
                private,
                ptr::null(),
                0,
                &mut certified,
            ));
            let mut tls = ptr::null_mut();
            Check::ok(umilib_protocol_tls_tls_config_new(&mut tls));
            Check::ok(umilib_protocol_tls_tls_config_set_protocols(
                tls,
                [b"test".as_ptr()].as_ptr(),
                [4usize].as_ptr(),
                1,
            ));
            let (mut client_tls, mut server_tls) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_protocol_tls_tls_client_config_new(tls, verifier, &mut client_tls));
            Check::ok(umilib_protocol_tls_tls_server_config_new(tls, &mut server_tls));
            Check::ok(umilib_protocol_tls_tls_server_config_add_certificate(server_tls, certified));
            // The QUIC configuration and its limits.
            let mut config: *mut QUICConfig = ptr::null_mut();
            Check::ok(umilib_protocol_quic_quic_config_new(&mut config));
            let mut limits = FFIQUICLimits::default();
            Check::ok(umilib_protocol_quic_quic_config_limits(config, &mut limits));
            assert_eq!((limits.datagram_size, limits.max_ack_delay), (1200, 25));
            limits.max_datagram_frame_size = 1200;
            Check::ok(umilib_protocol_quic_quic_config_set_limits(config, &limits));
            let mut bad = limits;
            bad.datagram_size = 100;
            Check::fails(umilib_protocol_quic_quic_config_set_limits(config, &bad), "protocol.quic", "Config");
            Check::ok(umilib_protocol_quic_quic_config_set_versions(config, [1u32].as_ptr(), 1));
            Check::ok(umilib_protocol_quic_quic_config_set_reset_key(config, [7u8; 32].as_ptr()));
            // A seed too short.
            let mut server = ptr::null_mut();
            Check::fails(
                umilib_protocol_quic_quic_endpoint_new(
                    config,
                    server_tls,
                    ptr::null(),
                    false,
                    [1u8; 8].as_ptr(),
                    8,
                    &mut server,
                ),
                "ffi",
                "InvalidArgument",
            );
            Check::ok(umilib_protocol_quic_quic_endpoint_new(
                config,
                server_tls,
                ptr::null(),
                false,
                [1u8; 48].as_ptr(),
                48,
                &mut server,
            ));
            let mut client = ptr::null_mut();
            Check::ok(umilib_protocol_quic_quic_endpoint_new(
                config,
                ptr::null(),
                ptr::null(),
                false,
                [2u8; 48].as_ptr(),
                48,
                &mut client,
            ));
            // A connection, the handshake, a stream and a datagram.
            let mut handle = 0u64;
            let server_address = endpoint(1, 443);
            Check::ok(umilib_protocol_quic_quic_endpoint_connect(
                client,
                client_tls,
                b"server.example".as_ptr(),
                14,
                &server_address,
                ptr::null(),
                0,
                [3u8; 48].as_ptr(),
                48,
                1_000_000_000,
                TIME,
                &mut handle,
            ));
            run(client, server, 1_000_000_000);
            let mut session = FFIQUICSession::default();
            Check::ok(umilib_protocol_quic_quic_connection_session(client, handle, &mut session));
            assert_eq!((session.state, session.version, session.handshake_confirmed), (1, 1, true));
            let mut protocol = Buffer::default();
            Check::ok(umilib_protocol_quic_quic_connection_protocol(client, handle, &mut protocol));
            assert_eq!(protocol.as_slice(), b"test");
            umilib::ffi::umilib_ffi_buffer_free(&mut protocol);
            let (mut found, mut accepted) = (false, 0u64);
            Check::ok(umilib_protocol_quic_quic_endpoint_accept(server, &mut found, &mut accepted));
            assert!(found);
            let mut stream = 0u64;
            Check::ok(umilib_protocol_quic_quic_connection_open_stream(client, handle, true, &mut stream));
            let mut written = 0usize;
            Check::ok(umilib_protocol_quic_quic_connection_stream_send(
                client,
                handle,
                stream,
                b"hello".as_ptr(),
                5,
                true,
                &mut written,
            ));
            assert_eq!(written, 5);
            Check::ok(umilib_protocol_quic_quic_connection_send_datagram(client, handle, b"dg".as_ptr(), 2));
            run(client, server, 1_000_000_000);
            let (mut read, mut fin, mut data) = (0usize, false, [0u8; 16]);
            Check::ok(umilib_protocol_quic_quic_connection_stream_read(
                server,
                accepted,
                stream,
                data.as_mut_ptr(),
                16,
                &mut read,
                &mut fin,
            ));
            assert_eq!((&data[..read], fin), (&b"hello"[..], true));
            let mut datagram = Buffer::default();
            Check::ok(umilib_protocol_quic_quic_connection_read_datagram(server, accepted, &mut found, &mut datagram));
            assert!(found && datagram.as_slice() == b"dg");
            umilib::ffi::umilib_ffi_buffer_free(&mut datagram);
            // The events: Connected first, and a StreamOpened of the stream.
            let (mut event, mut bytes) = (FFIQUICEvent::default(), Buffer::default());
            let mut kinds = Vec::new();
            loop {
                Check::ok(umilib_protocol_quic_quic_connection_poll_event(
                    server, accepted, &mut found, &mut event, &mut bytes,
                ));
                umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
                if !found {
                    break;
                }
                kinds.push((event.kind, event.stream));
            }
            assert_eq!(kinds[0].0, 0);
            assert!(kinds.contains(&(2, stream)));
            // Closing: the server is told the application's error.
            Check::ok(umilib_protocol_quic_quic_connection_close(client, handle, 9, b"bye".as_ptr(), 3, 1_000_000_000));
            run(client, server, 1_000_000_000);
            let mut closed = None;
            loop {
                Check::ok(umilib_protocol_quic_quic_connection_poll_event(
                    server, accepted, &mut found, &mut event, &mut bytes,
                ));
                if !found {
                    umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
                    break;
                }
                if event.kind == 11 {
                    closed = Some((event.reason, event.error, bytes.as_slice().to_vec()));
                }
                umilib::ffi::umilib_ffi_buffer_free(&mut bytes);
            }
            assert_eq!(closed, Some((3, 9, b"bye".to_vec())));
            Check::fails(umilib_protocol_quic_quic_connection_ping(client, 99), "protocol.quic", "UnknownConnection");
            let mut timeout = 0u64;
            Check::ok(umilib_protocol_quic_quic_endpoint_poll_timeout(client, &mut found, &mut timeout));
            Check::ok(umilib_protocol_quic_quic_endpoint_expire(client, timeout, TIME));
            umilib_protocol_quic_quic_endpoint_free(client);
            umilib_protocol_quic_quic_endpoint_free(server);
            umilib_protocol_quic_quic_config_free(config);
            umilib_protocol_tls_tls_client_config_free(client_tls);
            umilib_protocol_tls_tls_server_config_free(server_tls);
            umilib_protocol_tls_tls_config_free(tls);
            umilib_protocol_tls_tls_certified_key_free(certified);
            umilib_protocol_tls_tls_path_verifier_free(verifier);
            umilib_auth_cert_path_trust_anchors_free(anchors);
            umilib_auth_cert_path_trust_anchor_free(anchor);
            umilib_auth_cert_x509_certificate_free(root);
        }
    }
}

#[cfg(all(umilib_feature = "protocol-http", umilib_feature = "protocol-websocket"))]
mod http {
    use std::ptr;

    use umilib::codec::hpack::{HPACKDecoderConfig, HPACKEncoderConfig, HPACKField};
    use umilib::codec::qpack::{QPACKDecoderConfig, QPACKEncoderConfig};
    use umilib::ffi::Buffer;
    use umilib::ffi::codec::hpack::*;
    use umilib::ffi::codec::qpack::*;
    use umilib::ffi::protocol::http::v1::*;
    use umilib::ffi::protocol::http::v2::*;
    use umilib::ffi::protocol::http::websocket::*;
    use umilib::ffi::protocol::http::*;
    use umilib::ffi::protocol::websocket::*;
    use umilib::ffi::umilib_ffi_buffer_free;
    use umilib::protocol::http::{HTTPFields, HTTPRequest, HTTPResponse};
    use umilib::protocol::websocket::WebSocketConfig;

    use super::super::Check;

    /// Takes the bytes of `buffer` and frees it.
    unsafe fn take(buffer: &mut Buffer) -> Vec<u8> {
        let bytes = buffer.as_slice().to_vec();
        unsafe { umilib_ffi_buffer_free(buffer) };
        bytes
    }

    #[test]
    fn hpack_and_qpack_through_the_c_abi() {
        unsafe {
            let mut fields = ptr::null_mut();
            Check::ok(umilib_codec_hpack_hpack_fields_new(&mut fields));
            for (name, value, sensitive) in
                [(&b":method"[..], &b"GET"[..], false), (b"x-a", b"1", false), (b"cookie", b"c", true)]
            {
                Check::ok(umilib_codec_hpack_hpack_fields_push(
                    fields,
                    name.as_ptr(),
                    name.len(),
                    value.as_ptr(),
                    value.len(),
                    sensitive,
                ));
            }
            let (mut encoder, mut decoder) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_codec_hpack_hpack_encoder_new(HPACKEncoderConfig::default(), 4096, &mut encoder));
            Check::ok(umilib_codec_hpack_hpack_decoder_new(HPACKDecoderConfig::default(), &mut decoder));
            let mut block = Buffer::EMPTY;
            Check::ok(umilib_codec_hpack_hpack_encoder_encode(encoder, fields, &mut block));
            let mut decoded = ptr::null_mut();
            Check::ok(umilib_codec_hpack_hpack_decoder_decode(
                decoder,
                block.as_slice().as_ptr(),
                block.as_slice().len(),
                &mut decoded,
            ));
            take(&mut block);
            assert_eq!(
                *decoded,
                vec![
                    HPACKField::new(b":method", b"GET"),
                    HPACKField::new(b"x-a", b"1"),
                    HPACKField::sensitive(b"cookie", b"c")
                ]
            );
            let (mut name, mut value, mut sensitive) = (Buffer::EMPTY, Buffer::EMPTY, false);
            Check::ok(umilib_codec_hpack_hpack_fields_get(decoded, 2, &mut name, &mut value, &mut sensitive));
            assert_eq!((take(&mut name), take(&mut value), sensitive), (b"cookie".to_vec(), b"c".to_vec(), true));
            Check::fails(
                umilib_codec_hpack_hpack_fields_get(decoded, 3, &mut name, &mut value, &mut sensitive),
                "codec.hpack",
                "NoSuchField",
            );
            Check::fails(
                umilib_codec_hpack_hpack_decoder_decode(decoder, [0x80u8].as_ptr(), 1, &mut decoded),
                "codec.hpack",
                "InvalidIndex",
            );
            umilib_codec_hpack_hpack_fields_free(decoded);
            // QPACK: a section and its encoder stream.
            let (mut qencoder, mut qdecoder) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_codec_qpack_qpack_encoder_new(QPACKEncoderConfig::default(), &mut qencoder));
            Check::ok(umilib_codec_qpack_qpack_decoder_new(QPACKDecoderConfig::default(), &mut qdecoder));
            Check::ok(umilib_codec_qpack_qpack_encoder_set_peer_settings(qencoder, 4096, 16));
            let mut section = Buffer::EMPTY;
            Check::ok(umilib_codec_qpack_qpack_encoder_encode(qencoder, 0, fields, &mut section));
            let (mut blocked, mut out) = (false, ptr::null_mut());
            Check::ok(umilib_codec_qpack_qpack_decoder_decode(
                qdecoder,
                0,
                section.as_slice().as_ptr(),
                section.as_slice().len(),
                &mut blocked,
                &mut out,
            ));
            assert!(blocked && out.is_null());
            let mut instructions = Buffer::EMPTY;
            Check::ok(umilib_codec_qpack_qpack_encoder_take_instructions(qencoder, &mut instructions));
            Check::ok(umilib_codec_qpack_qpack_decoder_receive_encoder_stream(
                qdecoder,
                instructions.as_slice().as_ptr(),
                instructions.as_slice().len(),
            ));
            take(&mut instructions);
            Check::ok(umilib_codec_qpack_qpack_decoder_decode(
                qdecoder,
                0,
                section.as_slice().as_ptr(),
                section.as_slice().len(),
                &mut blocked,
                &mut out,
            ));
            take(&mut section);
            assert!(!blocked && (*out).len() == 3);
            umilib_codec_hpack_hpack_fields_free(out);
            let mut acknowledgments = Buffer::EMPTY;
            Check::ok(umilib_codec_qpack_qpack_decoder_take_instructions(qdecoder, &mut acknowledgments));
            Check::ok(umilib_codec_qpack_qpack_encoder_receive_decoder_stream(
                qencoder,
                acknowledgments.as_slice().as_ptr(),
                acknowledgments.as_slice().len(),
            ));
            take(&mut acknowledgments);
            Check::ok(umilib_codec_qpack_qpack_decoder_cancel_stream(qdecoder, 4));
            umilib_codec_qpack_qpack_encoder_free(qencoder);
            umilib_codec_qpack_qpack_decoder_free(qdecoder);
            umilib_codec_hpack_hpack_fields_free(fields);
            umilib_codec_hpack_hpack_encoder_free(encoder);
            umilib_codec_hpack_hpack_decoder_free(decoder);
        }
    }

    /// The events of a connection's `poll_event`, their handles freed.
    unsafe fn events(
        poll: impl Fn(
            *mut bool,
            *mut FFIHTTPEvent,
            *mut *mut HTTPRequest,
            *mut *mut HTTPResponse,
            *mut *mut HTTPFields,
        ) -> *const umilib::ffi::Status,
    ) -> Vec<(u8, u64, Option<HTTPRequest>, Option<u16>)> {
        let mut out = Vec::new();
        loop {
            let (mut found, mut event) = (false, FFIHTTPEvent::default());
            let (mut request, mut response, mut fields) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            Check::ok(poll(&mut found, &mut event, &mut request, &mut response, &mut fields));
            if !found {
                assert!(request.is_null() && response.is_null() && fields.is_null());
                return out;
            }
            let request_copy = unsafe { request.as_ref() }.cloned();
            let status = unsafe { response.as_ref() }.map(|response| response.status.0);
            unsafe {
                umilib_protocol_http_http_request_free(request);
                umilib_protocol_http_http_response_free(response);
                umilib_protocol_http_http_fields_free(fields);
            }
            out.push((event.kind, event.stream, request_copy, status));
        }
    }

    #[test]
    fn http_connections_through_the_c_abi() {
        unsafe {
            // Requests, fields and rules.
            let mut request = ptr::null_mut();
            Check::ok(umilib_protocol_http_http_request_new(
                b"POST".as_ptr(),
                4,
                b"http".as_ptr(),
                4,
                b"a".as_ptr(),
                1,
                b"/up".as_ptr(),
                3,
                &mut request,
            ));
            let mut fields = ptr::null_mut();
            Check::ok(umilib_protocol_http_http_fields_new(&mut fields));
            Check::ok(umilib_protocol_http_http_fields_append(
                fields,
                b"content-length".as_ptr(),
                14,
                b"5".as_ptr(),
                1,
            ));
            Check::fails(
                umilib_protocol_http_http_fields_append(fields, b"bad name".as_ptr(), 8, b"x".as_ptr(), 1),
                "protocol.http",
                "Malformed",
            );
            Check::ok(umilib_protocol_http_http_request_set_fields(request, fields));
            umilib_protocol_http_http_fields_free(fields);
            let mut rule = ptr::null_mut();
            Check::ok(umilib_protocol_http_http_rule_new(b"*".as_ptr(), 1, b"/up*".as_ptr(), 4, &mut rule));
            let mut matches = false;
            Check::ok(umilib_protocol_http_http_rule_matches(rule, request, &mut matches));
            assert!(matches);
            Check::fails(
                umilib_protocol_http_http_rule_new(b"a*b".as_ptr(), 3, b"*".as_ptr(), 1, &mut ptr::null_mut()),
                "protocol.http",
                "InvalidPattern",
            );
            umilib_protocol_http_http_rule_free(rule);
            // An HTTP/1.1 exchange.
            let mut limits = FFIH1Limits::default();
            Check::ok(umilib_protocol_http_v1_h1_limits_default(&mut limits));
            let (mut client, mut server) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_protocol_http_v1_h1_connection_client(&limits, b"http".as_ptr(), 4, 1, &mut client));
            Check::ok(umilib_protocol_http_v1_h1_connection_server(&limits, b"http".as_ptr(), 4, 1, &mut server));
            let mut stream = 0u64;
            Check::ok(umilib_protocol_http_v1_h1_connection_send_request(client, request, false, &mut stream));
            let mut taken = 0usize;
            Check::ok(umilib_protocol_http_v1_h1_connection_send_data(
                client,
                stream,
                b"hello".as_ptr(),
                5,
                true,
                &mut taken,
            ));
            let mut wire = Buffer::EMPTY;
            Check::ok(umilib_protocol_http_v1_h1_connection_transmit(client, &mut wire));
            Check::ok(umilib_protocol_http_v1_h1_connection_receive(
                server,
                wire.as_slice().as_ptr(),
                wire.as_slice().len(),
                1,
            ));
            take(&mut wire);
            let received = events(|found, event, request, response, fields| {
                umilib_protocol_http_v1_h1_connection_poll_event(server, found, event, request, response, fields)
            });
            assert_eq!(received[0].0, 0);
            assert_eq!(received[0].2.as_ref().unwrap().path, b"/up");
            let mut body = [0u8; 16];
            let mut count = 0usize;
            Check::ok(umilib_protocol_http_v1_h1_connection_read_data(
                server,
                stream,
                body.as_mut_ptr(),
                body.len(),
                &mut count,
            ));
            assert_eq!(&body[..count], b"hello");
            let mut response = ptr::null_mut();
            Check::ok(umilib_protocol_http_http_response_new(204, &mut response));
            Check::fails(umilib_protocol_http_http_response_new(99, &mut ptr::null_mut()), "ffi", "InvalidArgument");
            Check::ok(umilib_protocol_http_v1_h1_connection_send_response(server, stream, response, true));
            Check::ok(umilib_protocol_http_v1_h1_connection_transmit(server, &mut wire));
            Check::ok(umilib_protocol_http_v1_h1_connection_receive(
                client,
                wire.as_slice().as_ptr(),
                wire.as_slice().len(),
                1,
            ));
            take(&mut wire);
            let answered = events(|found, event, request, response, fields| {
                umilib_protocol_http_v1_h1_connection_poll_event(client, found, event, request, response, fields)
            });
            assert_eq!(answered[0].3, Some(204));
            Check::fails(umilib_protocol_http_v1_h1_connection_reset(client, stream, 9), "ffi", "InvalidArgument");
            let (mut major, mut minor) = (0u8, 0u8);
            Check::ok(umilib_protocol_http_v1_h1_connection_version(client, &mut major, &mut minor));
            assert_eq!((major, minor), (1, 1));
            umilib_protocol_http_v1_h1_connection_free(client);
            umilib_protocol_http_v1_h1_connection_free(server);
            // HTTP/2: prefaces, then the same request.
            let mut config = std::mem::zeroed::<FFIH2Config>();
            Check::ok(umilib_protocol_http_v2_h2_config_default(&mut config));
            let (mut client, mut server) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_protocol_http_v2_h2_connection_client(&config, 1, &mut client));
            Check::ok(umilib_protocol_http_v2_h2_connection_server(&config, 1, &mut server));
            Check::ok(umilib_protocol_http_v2_h2_connection_send_request(client, request, false, &mut stream));
            Check::ok(umilib_protocol_http_v2_h2_connection_send_data(
                client,
                stream,
                b"hello".as_ptr(),
                5,
                true,
                &mut taken,
            ));
            for _ in 0..4 {
                Check::ok(umilib_protocol_http_v2_h2_connection_transmit(client, &mut wire));
                Check::ok(umilib_protocol_http_v2_h2_connection_receive(
                    server,
                    wire.as_slice().as_ptr(),
                    wire.as_slice().len(),
                    1,
                ));
                take(&mut wire);
                Check::ok(umilib_protocol_http_v2_h2_connection_transmit(server, &mut wire));
                Check::ok(umilib_protocol_http_v2_h2_connection_receive(
                    client,
                    wire.as_slice().as_ptr(),
                    wire.as_slice().len(),
                    1,
                ));
                take(&mut wire);
            }
            let received = events(|found, event, request, response, fields| {
                umilib_protocol_http_v2_h2_connection_poll_event(server, found, event, request, response, fields)
            });
            assert!(received.iter().any(|(kind, _, request, _)| *kind == 0 && request.is_some()));
            Check::ok(umilib_protocol_http_v2_h2_connection_ping(client, b"12345678".as_ptr()));
            let mut wants = false;
            Check::ok(umilib_protocol_http_v2_h2_connection_wants_receive(server, &mut wants));
            assert!(wants);
            umilib_protocol_http_v2_h2_connection_free(client);
            umilib_protocol_http_v2_h2_connection_free(server);
            umilib_protocol_http_http_response_free(response);
            umilib_protocol_http_http_request_free(request);
        }
    }

    #[test]
    fn websockets_through_the_c_abi() {
        unsafe {
            let mut accept = Buffer::EMPTY;
            Check::ok(umilib_protocol_http_websocket_websocket_handshake_accept(
                b"dGhlIHNhbXBsZSBub25jZQ==".as_ptr(),
                24,
                &mut accept,
            ));
            assert_eq!(take(&mut accept), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
            let seed = [7u8; 48];
            let deflate = FFIWebSocketDeflateParameters::default();
            let protocol = b"chat";
            let protocols = [protocol.as_ptr()];
            let lengths = [protocol.len()];
            let (mut request, mut key) = (ptr::null_mut(), Buffer::EMPTY);
            Check::ok(umilib_protocol_http_websocket_websocket_handshake_request(
                b"http".as_ptr(),
                4,
                b"a".as_ptr(),
                1,
                b"/chat".as_ptr(),
                5,
                protocols.as_ptr(),
                lengths.as_ptr(),
                1,
                &deflate,
                seed.as_ptr(),
                seed.len(),
                &mut request,
                &mut key,
            ));
            let (mut offer, mut refusal) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_protocol_http_websocket_websocket_handshake_check_request(
                request,
                1,
                1,
                &mut offer,
                &mut refusal,
            ));
            assert!(!offer.is_null() && refusal.is_null());
            let mut agreement = ptr::null_mut();
            Check::ok(umilib_protocol_http_websocket_websocket_handshake_agree(
                offer,
                protocols.as_ptr(),
                lengths.as_ptr(),
                1,
                true,
                &mut agreement,
            ));
            let mut response = ptr::null_mut();
            Check::ok(umilib_protocol_http_websocket_websocket_handshake_response(offer, agreement, &mut response));
            let mut agreed = ptr::null_mut();
            Check::ok(umilib_protocol_http_websocket_websocket_handshake_check_response(
                response,
                key.as_slice().as_ptr(),
                key.as_slice().len(),
                protocols.as_ptr(),
                lengths.as_ptr(),
                1,
                &deflate,
                &mut agreed,
            ));
            Check::fails(
                umilib_protocol_http_websocket_websocket_handshake_check_response(
                    response,
                    b"x".as_ptr(),
                    1,
                    protocols.as_ptr(),
                    lengths.as_ptr(),
                    1,
                    &deflate,
                    &mut ptr::null_mut(),
                ),
                "protocol.http.websocket",
                "Rejected",
            );
            let (mut found, mut chosen) = (false, Buffer::EMPTY);
            Check::ok(umilib_protocol_http_websocket_websocket_agreement_protocol(agreed, &mut found, &mut chosen));
            assert!(found && take(&mut chosen) == b"chat");
            let mut parameters = FFIWebSocketDeflateParameters::default();
            Check::ok(umilib_protocol_http_websocket_websocket_agreement_deflate(agreed, &mut found, &mut parameters));
            assert!(found);
            take(&mut key);
            // Two connections of the agreed parameters.
            let (mut client, mut server) = (ptr::null_mut(), ptr::null_mut());
            Check::ok(umilib_protocol_websocket_websocket_connection_new(
                false,
                WebSocketConfig::default(),
                &parameters,
                seed.as_ptr(),
                48,
                &mut client,
            ));
            Check::ok(umilib_protocol_websocket_websocket_connection_new(
                true,
                WebSocketConfig::default(),
                &parameters,
                seed.as_ptr(),
                48,
                &mut server,
            ));
            Check::fails(
                umilib_protocol_websocket_websocket_connection_new(
                    true,
                    WebSocketConfig::default(),
                    ptr::null(),
                    seed.as_ptr(),
                    47,
                    &mut ptr::null_mut(),
                ),
                "ffi",
                "InvalidArgument",
            );
            Check::ok(umilib_protocol_websocket_websocket_connection_send_text(client, b"hello".as_ptr(), 5));
            Check::fails(
                umilib_protocol_websocket_websocket_connection_send_text(client, [0xFFu8].as_ptr(), 1),
                "ffi",
                "InvalidUTF8",
            );
            let mut wire = Buffer::EMPTY;
            Check::ok(umilib_protocol_websocket_websocket_connection_transmit(client, &mut wire));
            Check::ok(umilib_protocol_websocket_websocket_connection_receive(
                server,
                wire.as_slice().as_ptr(),
                wire.as_slice().len(),
            ));
            take(&mut wire);
            let (mut event, mut bytes) = (FFIWebSocketEvent::default(), Buffer::EMPTY);
            Check::ok(umilib_protocol_websocket_websocket_connection_poll_event(
                server, &mut found, &mut event, &mut bytes,
            ));
            assert!(found && event.kind == 0 && take(&mut bytes) == b"hello");
            Check::fails(
                umilib_protocol_websocket_websocket_connection_close(server, 1005, ptr::null(), 0),
                "protocol.websocket",
                "Refused",
            );
            Check::ok(umilib_protocol_websocket_websocket_connection_close(server, 1000, b"bye".as_ptr(), 3));
            let mut state = 0u8;
            Check::ok(umilib_protocol_websocket_websocket_connection_state(server, &mut state));
            assert_eq!(state, 1);
            umilib_protocol_websocket_websocket_connection_free(client);
            umilib_protocol_websocket_websocket_connection_free(server);
            umilib_protocol_http_websocket_websocket_agreement_free(agreed);
            umilib_protocol_http_websocket_websocket_agreement_free(agreement);
            umilib_protocol_http_websocket_websocket_offer_free(offer);
            umilib_protocol_http_http_response_free(response);
            umilib_protocol_http_http_request_free(request);
        }
    }
}

#[cfg(umilib_feature = "protocol-coap")]
mod coap;

#[cfg(umilib_feature = "protocol-dhcp")]
mod dhcp;

#[cfg(umilib_feature = "protocol-dns")]
mod dns;

#[cfg(umilib_feature = "protocol-smtp")]
mod smtp;

#[cfg(umilib_feature = "protocol-pop-v3")]
mod pop;

#[cfg(umilib_feature = "protocol-imap-v4")]
mod imap;

#[cfg(umilib_feature = "protocol-ftp")]
mod ftp;

mod aliasing;
