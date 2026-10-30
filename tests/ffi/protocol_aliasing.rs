//! The protocol functions reject an output that shares memory with an input
//! range or with another output with InvalidArgument, before they write
//! anything, and still report a null pointer as NullPointer (`docs/ffi.md`,
//! "Aliasing" and "Pointers").

use std::mem::MaybeUninit;
use std::ptr;

use umilib::ffi::{Buffer, Status};

use super::super::Check;

/// Memory aligned for every output type, so that an output can be placed
/// inside the bytes of an input.
#[repr(C, align(16))]
struct Storage([u8; 1024]);

impl Storage {
    /// Storage that starts with `bytes`.
    fn with(bytes: &[u8]) -> Storage {
        let mut storage = Storage([0; 1024]);
        storage.0[..bytes.len()].copy_from_slice(bytes);
        storage
    }
}

/// Asserts that `call` succeeds with its output apart from `input`, and fails
/// with InvalidArgument, leaving `input` as it was, with its output `offset`
/// bytes into `input`. `call` takes the input, its length and the output.
fn rejects_overlap<T>(input: &[u8], offset: usize, call: impl Fn(*const u8, usize, *mut T) -> *const Status) {
    let mut apart = MaybeUninit::<T>::uninit();
    Check::ok(call(input.as_ptr(), input.len(), apart.as_mut_ptr()));
    rejects_only(input, offset, call);
}

/// Asserts that `call` fails with InvalidArgument, leaving `input` as it was,
/// with its output `offset` bytes into `input`, whether or not the input is
/// valid.
fn rejects_only<T>(input: &[u8], offset: usize, call: impl Fn(*const u8, usize, *mut T) -> *const Status) {
    let mut storage = Storage::with(input);
    let base = storage.0.as_mut_ptr();
    // SAFETY: `offset` is within the storage, aligned for `T` by the caller.
    let output = unsafe { base.add(offset) }.cast::<T>();
    Check::fails(call(base, input.len(), output), "ffi", "InvalidArgument");
    assert_eq!(&storage.0[..input.len()], input);
}

#[cfg(umilib_feature = "protocol-ip")]
mod ip {
    use umilib::ffi::protocol::ip::*;
    use umilib::protocol::ip::InternetChecksum;

    use super::*;

    #[test]
    fn internet_checksums_reject_outputs_in_their_input() {
        let data = [0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00];
        for offset in [0, 2, 6] {
            rejects_overlap::<u16>(&data, offset, |input, length, out| unsafe {
                umilib_protocol_ip_internet_checksum_checksum(input, length, out)
            });
        }
        // A checksum updated in place is an output too.
        let mut checksum = InternetChecksum::default();
        unsafe { Check::ok(umilib_protocol_ip_internet_checksum_update(&mut checksum, data.as_ptr(), data.len())) };
        rejects_only::<InternetChecksum>(&data, 0, |input, length, checksum| unsafe {
            umilib_protocol_ip_internet_checksum_update(checksum, input, length)
        });
        // Both ranges of the adjustment are inputs.
        let after = [0x45, 0x00, 0x00, 0x20];
        rejects_overlap::<u16>(&data[..4], 2, |before, length, out| unsafe {
            umilib_protocol_ip_internet_checksum_adjust_bytes(0x1234, before, after.as_ptr(), length, out)
        });
        rejects_only::<u16>(&after, 2, |after, length, out| unsafe {
            umilib_protocol_ip_internet_checksum_adjust_bytes(0x1234, data.as_ptr(), after, length, out)
        });
    }

    #[cfg(umilib_feature = "protocol-ip-v4")]
    #[test]
    fn ipv4_options_reject_an_output_in_their_bytes() {
        use umilib::ffi::protocol::ip::v4::*;
        use umilib::protocol::ip::v4::IPv4Options;

        // Two No Operation options and the End of Options List (RFC 791).
        rejects_overlap::<IPv4Options>(&[1, 1, 0, 0], 0, |input, length, out| unsafe {
            umilib_protocol_ip_v4_ipv4_options_decode(input, length, out)
        });
    }

    #[cfg(umilib_feature = "protocol-ip-v6")]
    #[test]
    fn ipv6_options_headers_reject_an_output_in_their_bytes() {
        use umilib::ffi::protocol::ip::v6::*;

        // No Next Header after a PadN option of four bytes (RFC 8200 §4.2).
        rejects_overlap::<u8>(&[59, 0, 1, 4, 0, 0, 0, 0], 3, |input, length, out| unsafe {
            umilib_protocol_ip_v6_ipv6_options_header_decode(input, length, out)
        });
    }

    #[test]
    fn a_null_output_is_still_null() {
        let data = [1, 2, 3, 4];
        unsafe {
            Check::fails(
                umilib_protocol_ip_internet_checksum_checksum(data.as_ptr(), data.len(), ptr::null_mut()),
                "ffi",
                "NullPointer",
            );
            Check::fails(
                umilib_protocol_ip_internet_checksum_checksum(ptr::null(), 4, ptr::null_mut()),
                "ffi",
                "NullPointer",
            );
        }
    }
}

#[cfg(umilib_feature = "protocol-udp")]
#[test]
fn udp_headers_reject_an_output_in_their_bytes() {
    use umilib::ffi::protocol::udp::*;
    use umilib::protocol::udp::UDPHeader;

    let header = [0xc3, 0x50, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00];
    for offset in [0, 2, 6] {
        rejects_overlap::<UDPHeader>(&header, offset, |input, length, out| unsafe {
            umilib_protocol_udp_udp_header_decode(input, length, out)
        });
    }
}

#[cfg(umilib_feature = "protocol-tcp")]
mod tcp {
    use umilib::ffi::protocol::tcp::*;
    use umilib::protocol::tcp::TCPHeader;

    use super::*;

    #[test]
    fn tcp_headers_reject_an_output_in_their_bytes() {
        let mut header = [0; 20];
        header[12] = 0x50;
        for offset in [0, 8, 16] {
            rejects_overlap::<TCPHeader>(&header, offset, |input, length, out| unsafe {
                umilib_protocol_tcp_tcp_header_decode(input, length, out)
            });
        }
    }

    #[test]
    fn tcp_options_reject_shared_outputs() {
        let options = [1, 1, 0, 0];
        let (mut found, mut kind, mut data) = (false, 0u8, Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_tcp_tcp_options_get(
                options.as_ptr(),
                options.len(),
                0,
                &mut found,
                &mut kind,
                &mut data,
            ));
            assert!(found);
            assert_eq!(kind, 1);
            umilib::ffi::umilib_ffi_buffer_free(&mut data);
            // The found flag and the kind in one byte.
            let mut shared = 0u8;
            let shared = &raw mut shared;
            Check::fails(
                umilib_protocol_tcp_tcp_options_get(
                    options.as_ptr(),
                    options.len(),
                    0,
                    shared.cast(),
                    shared,
                    &mut data,
                ),
                "ffi",
                "InvalidArgument",
            );
            // Two null outputs are null, not shared.
            Check::fails(
                umilib_protocol_tcp_tcp_options_get(
                    options.as_ptr(),
                    options.len(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut data,
                ),
                "ffi",
                "NullPointer",
            );
        }
        rejects_only::<u8>(&options, 1, |input, length, kind| unsafe {
            let mut found = false;
            let mut data = Buffer::EMPTY;
            umilib_protocol_tcp_tcp_options_get(input, length, 0, &mut found, kind, &mut data)
        });
    }
}

#[cfg(umilib_feature = "protocol-icmp")]
mod icmp {
    use umilib::ffi::protocol::icmp::*;

    use super::*;

    #[test]
    fn icmp_extensions_reject_an_output_in_their_bytes() {
        // Version 2 without a checksum and no objects (RFC 4884 §7).
        rejects_only::<u16>(&[0x20, 0, 0, 0], 2, |input, length, out| unsafe {
            umilib_protocol_icmp_icmp_extensions_decode(input, length, out)
        });
    }

    #[cfg(umilib_feature = "protocol-icmp-v4")]
    #[test]
    fn icmpv4_messages_reject_an_output_in_their_bytes() {
        use umilib::ffi::protocol::icmp::v4::*;

        // An Echo with its checksum (RFC 792).
        rejects_overlap::<FFIICMPHeader>(&[8, 0, 0xf7, 0xff, 0, 0, 0, 0], 0, |input, length, out| unsafe {
            umilib_protocol_icmp_v4_icmpv4_message_decode(input, length, out)
        });
    }

    #[cfg(umilib_feature = "protocol-icmp-v6")]
    #[test]
    fn ndp_options_reject_an_output_in_their_bytes() {
        use umilib::ffi::protocol::icmp::v6::*;
        use umilib::protocol::icmp::v6::NDPRouteInformation;

        rejects_only::<NDPRouteInformation>(&[0, 0, 0, 0, 0, 0], 0, |input, length, out| unsafe {
            umilib_protocol_icmp_v6_ndp_route_information_decode(input, length, out)
        });
    }
}

#[cfg(umilib_feature = "protocol-arp")]
#[test]
fn arp_packets_reject_an_output_in_their_bytes() {
    use umilib::ffi::protocol::arp::*;
    use umilib::protocol::arp::ARPPacket;

    // A request for 192.0.2.2 from 192.0.2.1 (RFC 826).
    let mut packet = vec![0, 1, 8, 0, 6, 4, 0, 1];
    packet.extend_from_slice(&[2, 0, 0, 0, 0, 1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2]);
    for offset in [0, 16] {
        rejects_overlap::<ARPPacket>(&packet, offset, |input, length, out| unsafe {
            umilib_protocol_arp_arp_packet_decode(input, length, out)
        });
    }
}

#[cfg(umilib_feature = "protocol-ethernet")]
#[test]
fn frame_check_sequences_reject_an_output_in_the_frame() {
    use umilib::ffi::protocol::ethernet::*;

    let frame = [0x5a; 60];
    // The four bytes of the sequence, at the end of the frame or across it.
    for offset in [56, 58] {
        rejects_overlap::<u8>(&frame, offset, |input, length, out| unsafe {
            umilib_protocol_ethernet_ethernet_frame_fcs(input, length, out)
        });
    }
}

#[cfg(umilib_feature = "protocol-dhcp")]
mod dhcp {
    use umilib::ffi::protocol::dhcp::*;

    use super::*;

    #[test]
    fn duids_reject_an_output_in_their_bytes() {
        // A DUID-LL of an Ethernet address (RFC 9915 §11.4).
        let duid = [0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
        rejects_overlap::<FFIDHCPDUID>(&duid, 0, |input, length, out| unsafe {
            let mut data = Buffer::EMPTY;
            let status = umilib_protocol_dhcp_dhcp_duid_decode(input, length, out, &mut data);
            umilib::ffi::umilib_ffi_buffer_free(&mut data);
            status
        });
    }

    #[cfg(umilib_feature = "protocol-dhcp-v4")]
    #[test]
    fn dhcpv4_messages_reject_an_output_in_their_bytes() {
        use umilib::ffi::protocol::dhcp::v4::*;

        // A BOOTREQUEST with the magic cookie and the End option (RFC 2131 §3).
        let mut message = vec![0; 241];
        (message[0], message[1], message[2]) = (1, 1, 6);
        message[236..241].copy_from_slice(&[99, 130, 83, 99, 255]);
        rejects_overlap::<FFIDHCPv4Message>(&message, 16, |input, length, out| unsafe {
            let mut options = Buffer::EMPTY;
            let status = umilib_protocol_dhcp_v4_dhcpv4_message_decode(input, length, out, &mut options);
            umilib::ffi::umilib_ffi_buffer_free(&mut options);
            status
        });
    }

    #[cfg(umilib_feature = "protocol-dhcp-v6")]
    #[test]
    fn dhcpv6_status_codes_reject_an_output_in_their_bytes() {
        use umilib::ffi::protocol::dhcp::v6::*;

        rejects_overlap::<u16>(b"\0\0ok", 2, |input, length, out| unsafe {
            let mut message = Buffer::EMPTY;
            let status = umilib_protocol_dhcp_v6_dhcpv6_status_code_decode(input, length, out, &mut message);
            umilib::ffi::umilib_ffi_buffer_free(&mut message);
            status
        });
    }
}

#[cfg(umilib_feature = "protocol-dns")]
#[test]
fn zone_files_reject_an_output_in_their_text() {
    use umilib::ffi::protocol::dns::*;

    let zone = b"a.example. 60 IN A 192.0.2.1\n";
    rejects_overlap::<usize>(zone, 8, |input, length, out| unsafe {
        let mut records = Buffer::EMPTY;
        let status =
            umilib_protocol_dns_dns_zone_file_parse(input, length, ptr::null(), 0, false, 0, out, &mut records);
        umilib::ffi::umilib_ffi_buffer_free(&mut records);
        status
    });
}

#[cfg(umilib_feature = "protocol-coap")]
mod coap {
    use umilib::ffi::protocol::coap::*;

    use super::*;

    #[test]
    fn blocks_reject_an_output_in_their_value() {
        // Block 0, more to come, of 64 bytes (RFC 7959 §2.2).
        rejects_overlap::<FFICoAPBlock>(&[0x0a], 0, |input, length, out| unsafe {
            umilib_protocol_coap_coap_block_decode(input, length, out)
        });
    }

    #[test]
    fn option_definitions_reject_shared_outputs() {
        let mut definition = MaybeUninit::<FFICoAPOptionDefinition>::uninit();
        let mut found = false;
        unsafe {
            Check::ok(umilib_protocol_coap_coap_option_number_definition(11, &mut found, definition.as_mut_ptr()));
            assert!(found);
            // The found flag inside the definition.
            let out = definition.as_mut_ptr();
            Check::fails(
                umilib_protocol_coap_coap_option_number_definition(11, out.cast(), out),
                "ffi",
                "InvalidArgument",
            );
        }
    }
}

#[cfg(umilib_feature = "protocol-smtp")]
#[test]
fn smtp_replies_reject_an_output_in_their_text() {
    use umilib::ffi::protocol::smtp::*;

    rejects_overlap::<u16>(b"250 OK\r\n", 2, |input, length, out| unsafe {
        let mut lines = Buffer::EMPTY;
        let status = umilib_protocol_smtp_smtp_reply_decode(input, length, out, &mut lines);
        umilib::ffi::umilib_ffi_buffer_free(&mut lines);
        status
    });
}

#[cfg(umilib_feature = "protocol-pop-v3")]
#[test]
fn pop3_lengths_reject_an_output_in_their_data() {
    use umilib::ffi::protocol::pop::v3::*;

    rejects_overlap::<u64>(b"line one\r\nline two\r\n", 8, |input, length, out| unsafe {
        umilib_protocol_pop_v3_pop3_multi_line_canonical_length(input, length, out)
    });
}

#[cfg(umilib_feature = "protocol-imap-v4")]
#[test]
fn imap_sequence_sets_reject_an_output_in_their_text() {
    use umilib::ffi::protocol::imap::v4::*;

    for offset in [0, 2] {
        rejects_overlap::<bool>(b"1:5,7", offset, |input, length, out| unsafe {
            umilib_protocol_imap_v4_imap_sequence_set_contains(input, length, 3, 10, out)
        });
    }
}

#[cfg(umilib_feature = "protocol-ftp")]
#[test]
fn ftp_data_addresses_reject_an_output_in_their_text() {
    use umilib::ffi::protocol::ftp::*;

    rejects_overlap::<FFIFTPDataAddress>(b"192,0,2,1,4,1", 0, |input, length, out| unsafe {
        umilib_protocol_ftp_ftp_data_address_parse_port(input, length, out)
    });
}

#[cfg(umilib_feature = "protocol-websocket")]
#[test]
fn deflate_parameters_reject_an_output_on_the_offer() {
    use umilib::ffi::protocol::websocket::*;

    let mut parameters = FFIWebSocketDeflateParameters::default();
    let mut accepted = FFIWebSocketDeflateParameters::default();
    unsafe {
        Check::ok(umilib_protocol_websocket_websocket_deflate_parameters_accept(&parameters, &mut accepted));
        let shared = &raw mut parameters;
        Check::fails(
            umilib_protocol_websocket_websocket_deflate_parameters_accept(shared, shared),
            "ffi",
            "InvalidArgument",
        );
    }
}

#[cfg(umilib_feature = "protocol-http")]
mod http {
    use umilib::ffi::protocol::http::v1::*;
    use umilib::ffi::protocol::http::*;

    use super::*;

    #[test]
    fn fields_reject_an_output_in_a_name() {
        let mut fields = ptr::null_mut();
        unsafe { Check::ok(umilib_protocol_http_http_fields_new(&mut fields)) };
        rejects_overlap::<bool>(b"x-name", 3, |input, length, out| unsafe {
            umilib_protocol_http_http_fields_remove(fields, input, length, out)
        });
        unsafe { umilib_protocol_http_http_fields_free(fields) };
    }

    #[test]
    fn connections_reject_shared_outputs() {
        unsafe {
            let mut limits = FFIH1Limits::default();
            Check::ok(umilib_protocol_http_v1_h1_limits_default(&mut limits));
            let mut client = ptr::null_mut();
            Check::ok(umilib_protocol_http_v1_h1_connection_client(&limits, b"http".as_ptr(), 4, 1, &mut client));
            let (mut major, mut minor) = (0u8, 0u8);
            Check::ok(umilib_protocol_http_v1_h1_connection_version(client, &mut major, &mut minor));
            assert_eq!((major, minor), (1, 1));
            let shared = &raw mut major;
            Check::fails(
                umilib_protocol_http_v1_h1_connection_version(client, shared, shared),
                "ffi",
                "InvalidArgument",
            );
            // The count of bytes taken inside the bytes given.
            rejects_only::<usize>(&[0x61; 16], 8, |input, length, out| {
                umilib_protocol_http_v1_h1_connection_send_data(client, 0, input, length, false, out)
            });
            let mut found = false;
            let mut event = MaybeUninit::<FFIHTTPEvent>::uninit();
            let event = event.as_mut_ptr();
            let (mut request, mut response, mut trailers) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            Check::fails(
                umilib_protocol_http_v1_h1_connection_poll_event(
                    client,
                    event.cast(),
                    event,
                    &mut request,
                    &mut response,
                    &mut trailers,
                ),
                "ffi",
                "InvalidArgument",
            );
            Check::ok(umilib_protocol_http_v1_h1_connection_poll_event(
                client,
                &mut found,
                event,
                &mut request,
                &mut response,
                &mut trailers,
            ));
            umilib_protocol_http_v1_h1_connection_free(client);
        }
    }
}

#[cfg(umilib_feature = "protocol-jwt")]
#[test]
fn jwt_claims_reject_an_output_in_a_name() {
    use umilib::ffi::protocol::jwt::*;

    let mut claims = ptr::null_mut();
    unsafe { Check::ok(umilib_protocol_jwt_jwt_claims_new(&mut claims)) };
    rejects_overlap::<bool>(b"sub", 1, |input, length, out| unsafe {
        umilib_protocol_jwt_jwt_claims_remove(claims, input, length, out)
    });
    unsafe { umilib_protocol_jwt_jwt_claims_free(claims) };
}

#[cfg(umilib_feature = "protocol-tls")]
#[test]
fn tls_rules_reject_an_output_in_a_client_hello() {
    use umilib::ffi::protocol::tls::*;

    let mut rule = ptr::null_mut();
    unsafe { Check::ok(umilib_protocol_tls_tls_rule_new(b"*".as_ptr(), 1, ptr::null(), 0, &mut rule)) };
    // A ClientHello body cut short: overlap is rejected before it is read.
    rejects_only::<bool>(&[3, 3, 0, 0], 2, |input, length, out| unsafe {
        umilib_protocol_tls_tls_rule_matches_client_hello(rule, input, length, out)
    });
    unsafe { umilib_protocol_tls_tls_rule_free(rule) };
}
