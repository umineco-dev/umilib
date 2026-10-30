//! The C ABI of `umilib::protocol::dns`: messages, zone files, an
//! authoritative server and a resolver exchanging through it, DNSSEC keys,
//! signing and validation, and the transports' parts.

use std::ptr;

use umilib::ffi::protocol::dns::*;
use umilib::ffi::protocol::ip::FFIIPEndpoint;
use umilib::ffi::{Buffer, umilib_ffi_buffer_free};
use umilib::protocol::dns::{DNSMessage, DNSType};
use umilib::protocol::ip::IPEndpoint;

use crate::Check;

/// Takes the bytes of `buffer` and frees it.
unsafe fn take(buffer: &mut Buffer) -> Vec<u8> {
    let bytes = buffer.as_slice().to_vec();
    unsafe { umilib_ffi_buffer_free(buffer) };
    bytes
}

unsafe fn text(buffer: &mut Buffer) -> String {
    String::from_utf8(unsafe { take(buffer) }).unwrap()
}

fn endpoint(text: &str) -> FFIIPEndpoint {
    FFIIPEndpoint::of(&IPEndpoint::from_ascii(text.as_bytes()).unwrap())
}

/// A generator of the C ABI: an HMAC_DRBG over SHA-256 of a fixed seed,
/// released when dropped.
#[cfg(umilib_feature = "hash-sha-v2")]
struct Generator {
    state: *mut umilib::ffi::crypto::random::HMACDRBGState,
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl Generator {
    /// The C type name of the handle.
    const TYPE: &'static [u8] = b"umilib_crypto_random_HMACDRBG";

    fn new(seed: u8) -> Generator {
        let hash = b"umilib_hash_sha_v2_SHA256";
        let mut state = ptr::null_mut();
        unsafe {
            Check::ok(umilib::ffi::crypto::random::hmac_drbg::new(
                hash.as_ptr(),
                hash.len(),
                [seed; 32].as_ptr(),
                32,
                [seed; 16].as_ptr(),
                16,
                b"dns".as_ptr(),
                3,
                &mut state,
            ));
        }
        Generator { state }
    }

    fn handle(&self) -> *mut core::ffi::c_void {
        self.state.cast()
    }
}

#[cfg(umilib_feature = "hash-sha-v2")]
impl Drop for Generator {
    fn drop(&mut self) {
        unsafe { umilib::ffi::crypto::random::hmac_drbg::free(self.state) };
    }
}

const ZONE: &str = "@ 3600 IN SOA ns admin 1 3600 600 86400 300
@ 3600 IN NS ns
ns 3600 IN A 192.0.2.53
www 300 IN A 192.0.2.80
www 300 IN A 192.0.2.81";

/// A server of the zone example.
unsafe fn authority() -> *mut umilib::protocol::dns::DNSAuthority {
    unsafe {
        let mut config = FFIDNSAuthorityConfig::default();
        Check::ok(umilib_protocol_dns_dns_authority_config_default(&mut config));
        let mut authority = ptr::null_mut();
        Check::ok(umilib_protocol_dns_dns_authority_new(config, &mut authority));
        let origin = "example.";
        Check::ok(umilib_protocol_dns_dns_authority_add_zone(
            authority,
            origin.as_ptr(),
            origin.len(),
            ZONE.as_ptr(),
            ZONE.len(),
        ));
        authority
    }
}

/// The messages of `framed`, each after its length in two bytes.
fn unframe(mut framed: &[u8]) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    while let [high, low, rest @ ..] = framed {
        let length = usize::from(u16::from_be_bytes([*high, *low]));
        messages.push(rest[..length].to_vec());
        framed = &rest[length..];
    }
    messages
}

#[test]
fn messages_through_the_c_abi() {
    unsafe {
        let name = "www.example.";
        let mut message = ptr::null_mut();
        Check::ok(umilib_protocol_dns_dns_message_query(name.as_ptr(), name.len(), 1, 1, 0x1234, &mut message));
        // RFC 1035 §4.1.1: a query, RD set.
        let mut header = FFIDNSHeader::default();
        Check::ok(umilib_protocol_dns_dns_message_header(message, &mut header));
        assert_eq!((header.id, header.response, header.recursion_desired, header.rcode), (0x1234, false, true, 0));
        // EDNS and an option (RFC 6891).
        Check::ok(umilib_protocol_dns_dns_message_set_edns(
            message,
            FFIDNSEDNS { present: true, udp_size: 1232, version: 0, dnssec_ok: true },
        ));
        Check::ok(umilib_protocol_dns_dns_message_set_option(message, 10, [1u8; 8].as_ptr(), 8));
        let mut bytes = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dns_message_encode(message, 512, &mut bytes));
        let encoded = take(&mut bytes);
        umilib_protocol_dns_dns_message_free(message);
        let decoded = DNSMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.edns.as_ref().unwrap().udp_size, 1232);
        let mut message = ptr::null_mut();
        Check::ok(umilib_protocol_dns_dns_message_decode(encoded.as_ptr(), encoded.len(), &mut message));
        let (mut found, mut question, mut kind, mut class) = (false, Buffer::EMPTY, 0, 0);
        Check::ok(umilib_protocol_dns_dns_message_question(message, &mut found, &mut question, &mut kind, &mut class));
        assert_eq!((found, text(&mut question), kind, class), (true, "www.example.".to_string(), 1, 1));
        let (mut has, mut option) = (false, Buffer::EMPTY);
        Check::ok(umilib_protocol_dns_dns_message_option(message, 10, &mut has, &mut option));
        assert_eq!((has, take(&mut option)), (true, vec![1; 8]));
        let mut edns = FFIDNSEDNS::default();
        Check::ok(umilib_protocol_dns_dns_message_edns(message, &mut edns));
        assert!(edns.present && edns.dnssec_ok);
        // Records cross as their presentation format.
        let records = "www.example. 300 IN A 192.0.2.80\nwww.example. 300 IN AAAA 2001:db8::1\n";
        Check::ok(umilib_protocol_dns_dns_message_add_records(message, 0, records.as_ptr(), records.len()));
        let mut lines = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dns_message_records(message, 0, &mut lines));
        assert_eq!(text(&mut lines), records);
        // A response code above 15 is carried by EDNS (RFC 6891 §6.1.3).
        header.rcode = 16;
        header.response = true;
        Check::ok(umilib_protocol_dns_dns_message_set_header(message, header));
        let mut bytes = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dns_message_encode(message, 65535, &mut bytes));
        assert_eq!(DNSMessage::decode(&take(&mut bytes)).unwrap().rcode().0, 16);
        // Errors as statuses.
        let bad = "www..example.";
        let mut other = ptr::null_mut();
        Check::fails(
            umilib_protocol_dns_dns_message_query(bad.as_ptr(), bad.len(), 1, 1, 0, &mut other),
            "protocol.dns",
            "Syntax",
        );
        Check::fails(
            umilib_protocol_dns_dns_message_decode(encoded.as_ptr(), 5, &mut other),
            "protocol.dns",
            "Malformed",
        );
        Check::fails(umilib_protocol_dns_dns_message_records(message, 3, &mut lines), "ffi", "InvalidArgument");
        umilib_protocol_dns_dns_message_free(message);
        umilib_protocol_dns_dns_message_free(ptr::null_mut());
    }
}

#[test]
fn zone_files_through_the_c_abi() {
    unsafe {
        let origin = "example.";
        let (mut line, mut out) = (0usize, Buffer::EMPTY);
        Check::ok(umilib_protocol_dns_dns_zone_file_parse(
            ZONE.as_ptr(),
            ZONE.len(),
            origin.as_ptr(),
            origin.len(),
            false,
            0,
            &mut line,
            &mut out,
        ));
        let records = text(&mut out);
        assert_eq!(records.lines().count(), 5);
        assert!(records.lines().next().unwrap().starts_with("example. 3600 IN SOA ns.example. admin.example. 1"));
        // RFC 1035 §5: the line of an error.
        let bad = "@ 3600 IN SOA ns admin 1 3600 600 86400 300\nwww 300 IN A not-an-address";
        Check::fails(
            umilib_protocol_dns_dns_zone_file_parse(
                bad.as_ptr(),
                bad.len(),
                origin.as_ptr(),
                origin.len(),
                false,
                0,
                &mut line,
                &mut out,
            ),
            "protocol.dns",
            "Syntax",
        );
        assert_eq!(line, 2);
    }
}

#[cfg(umilib_feature = "hash-sha-v2")]
#[test]
fn an_authority_and_a_resolver_through_the_c_abi() {
    unsafe {
        let authority = authority();
        let mut config = FFIDNSResolverConfig::default();
        Check::ok(umilib_protocol_dns_dns_resolver_config_default(&mut config));
        let upstreams = [FFIDNSUpstream { endpoint: endpoint("192.0.2.53:53"), transport: 0 }];
        let random = Generator::new(7);
        let mut resolver = ptr::null_mut();
        Check::ok(umilib_protocol_dns_dns_resolver_new(
            config,
            upstreams.as_ptr(),
            1,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut resolver,
        ));
        let name = "www.example.";
        let mut query = 0;
        Check::ok(umilib_protocol_dns_dns_resolver_resolve(
            resolver,
            name.as_ptr(),
            name.len(),
            1,
            1,
            0,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut query,
        ));
        let (mut found, mut transmission, mut message) = (false, FFIDNSTransmission::default(), Buffer::EMPTY);
        Check::ok(umilib_protocol_dns_dns_resolver_transmit(resolver, &mut found, &mut transmission, &mut message));
        assert!(found && transmission.query == query && transmission.transport == 0);
        let sent = take(&mut message);
        let mut responses = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dns_authority_respond(
            authority,
            sent.as_ptr(),
            sent.len(),
            endpoint("198.51.100.1:40000"),
            0,
            0,
            &mut responses,
        ));
        let responses = unframe(&take(&mut responses));
        assert_eq!(responses.len(), 1);
        Check::ok(umilib_protocol_dns_dns_resolver_receive(
            resolver,
            query,
            0,
            0,
            responses[0].as_ptr(),
            responses[0].len(),
            1,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
        ));
        let (mut resolved, mut error, mut response) = (0u64, ptr::null(), Buffer::EMPTY);
        Check::ok(umilib_protocol_dns_dns_resolver_poll_event(
            resolver,
            &mut found,
            &mut resolved,
            &mut error,
            &mut response,
        ));
        assert!(found && resolved == query && error.is_null());
        let answer = DNSMessage::decode(&take(&mut response)).unwrap();
        assert_eq!(answer.answers.len(), 2);
        assert!(answer.header.authoritative);
        // A question unanswered: after its rounds, Timeout.
        Check::ok(umilib_protocol_dns_dns_resolver_resolve(
            resolver,
            name.as_ptr(),
            name.len(),
            28,
            1,
            0,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut query,
        ));
        for _ in 0..4 {
            let mut deadline = 0;
            Check::ok(umilib_protocol_dns_dns_resolver_poll_timeout(resolver, &mut found, &mut deadline));
            if !found {
                break;
            }
            Check::ok(umilib_protocol_dns_dns_resolver_expire(
                resolver,
                deadline,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
        }
        Check::ok(umilib_protocol_dns_dns_resolver_poll_event(
            resolver,
            &mut found,
            &mut resolved,
            &mut error,
            &mut response,
        ));
        take(&mut response);
        assert!(found && !error.is_null());
        assert_eq!((*error).name().to_str().unwrap(), "Timeout");
        // RFC 5936: no transfers by default; allowed, the SOA first and last.
        let axfr = DNSMessage::query(
            1,
            umilib::protocol::dns::DNSQuestion::new(
                umilib::protocol::dns::DNSName::parse("example.", None).unwrap(),
                DNSType::AXFR,
            ),
        );
        let bytes = axfr.encode(512).unwrap();
        let mut out = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dns_authority_respond(
            authority,
            bytes.as_ptr(),
            bytes.len(),
            endpoint("198.51.100.1:40000"),
            1,
            0,
            &mut out,
        ));
        assert_eq!(DNSMessage::decode(&unframe(&take(&mut out))[0]).unwrap().rcode().0, 5);
        let pattern =
            umilib::ffi::protocol::ip::FFIIPEndpointPattern::of(&umilib::protocol::ip::IPEndpointPattern::ANY);
        Check::ok(umilib_protocol_dns_dns_authority_set_transfers(authority, &pattern, 1));
        Check::ok(umilib_protocol_dns_dns_authority_respond(
            authority,
            bytes.as_ptr(),
            bytes.len(),
            endpoint("198.51.100.1:40000"),
            1,
            0,
            &mut out,
        ));
        let records: Vec<_> =
            unframe(&take(&mut out)).iter().flat_map(|bytes| DNSMessage::decode(bytes).unwrap().answers).collect();
        assert_eq!(
            (records.first().unwrap().kind, records.last().unwrap().kind, records.len()),
            (DNSType::SOA, DNSType::SOA, 6)
        );
        // A zone without its SOA is not one.
        let bad = "www 300 IN A 192.0.2.1";
        let origin = "other.";
        Check::fails(
            umilib_protocol_dns_dns_authority_add_zone(
                authority,
                origin.as_ptr(),
                origin.len(),
                bad.as_ptr(),
                bad.len(),
            ),
            "protocol.dns",
            "Config",
        );
        // A resolver without servers, or of a generator of no known type.
        let mut other = ptr::null_mut();
        Check::fails(
            umilib_protocol_dns_dns_resolver_new(
                config,
                upstreams.as_ptr(),
                0,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut other,
            ),
            "protocol.dns",
            "Config",
        );
        let unknown = b"umilib_crypto_random_Other";
        Check::fails(
            umilib_protocol_dns_dns_resolver_new(
                config,
                upstreams.as_ptr(),
                1,
                random.handle(),
                unknown.as_ptr(),
                unknown.len(),
                &mut other,
            ),
            "ffi",
            "InvalidArgument",
        );
        // RFC 9018 §5: secrets of 16 bytes each.
        let secrets = [1u8; 32];
        Check::ok(umilib_protocol_dns_dns_authority_set_cookie_secrets(authority, secrets.as_ptr(), 32));
        Check::fails(
            umilib_protocol_dns_dns_authority_set_cookie_secrets(authority, secrets.as_ptr(), 31),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(umilib_protocol_dns_dns_authority_set_cookie_secrets(authority, ptr::null(), 0));
        umilib_protocol_dns_dns_resolver_free(resolver);
        umilib_protocol_dns_dns_authority_free(authority);
    }
}

#[cfg(umilib_feature = "protocol-dns-dnssec")]
#[test]
fn dnssec_through_the_c_abi() {
    use umilib::ffi::protocol::dns::dnssec::*;

    unsafe {
        let random = Generator::new(9);
        let mut key = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dnssec_dnssec_private_key_generate(
            15,
            0,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut key,
        ));
        let key = text(&mut key);
        assert!(key.starts_with("Private-key-format: v1.2\nAlgorithm: 15 (ED25519)\n"));
        let origin = "example.";
        let mut dnskey = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dnssec_dnssec_private_key_dnskey(
            key.as_ptr(),
            key.len(),
            origin.as_ptr(),
            origin.len(),
            257,
            3600,
            &mut dnskey,
        ));
        let dnskey = text(&mut dnskey);
        assert!(dnskey.starts_with("example. 3600 IN DNSKEY 257 3 15 "));
        let mut ds = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dnssec_dnssec_private_key_delegation(
            key.as_ptr(),
            key.len(),
            origin.as_ptr(),
            origin.len(),
            257,
            2,
            3600,
            &mut ds,
        ));
        let ds = text(&mut ds);
        // RFC 4035 §2: the zone signed by the key.
        let keys = [std::ffi::CString::new(key.clone()).unwrap()];
        let pointers: Vec<*const umilib::ffi::Char> =
            keys.iter().map(|key| key.as_ptr() as *const umilib::ffi::Char).collect();
        let flags = [257u16];
        let mut signed = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dnssec_dns_zone_sign(
            origin.as_ptr(),
            origin.len(),
            ZONE.as_ptr(),
            ZONE.len(),
            pointers.as_ptr(),
            flags.as_ptr(),
            1,
            1000,
            2_000_000_000,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
            &mut signed,
        ));
        let signed = text(&mut signed);
        let lines = |kind: &str| -> String {
            signed
                .lines()
                .filter(|line| line.split_whitespace().nth(3) == Some(kind))
                .map(|line| format!("{line}\n"))
                .collect()
        };
        let signatures = lines("RRSIG");
        assert!(!signatures.is_empty() && !lines("NSEC").is_empty());
        let mut validator = ptr::null_mut();
        Check::ok(umilib_protocol_dns_dnssec_dnssec_validator_new(&mut validator));
        let www: String =
            lines("A").lines().filter(|line| line.starts_with("www.")).map(|line| format!("{line}\n")).collect();
        let (mut verified, mut encloser, mut code) = (FFIDNSSECVerified::default(), Buffer::EMPTY, 0u16);
        Check::ok(umilib_protocol_dns_dnssec_dnssec_validator_verify(
            validator,
            www.as_ptr(),
            www.len(),
            signatures.as_ptr(),
            signatures.len(),
            dnskey.as_ptr(),
            dnskey.len(),
            5000,
            &mut verified,
            &mut encloser,
            &mut code,
        ));
        take(&mut encloser);
        assert_eq!((verified.ttl, verified.expanded), (300, false));
        // A changed record: Bogus, DNSSEC Bogus (RFC 8914 §4.7).
        let changed = www.replace("192.0.2.80", "192.0.2.99");
        Check::fails(
            umilib_protocol_dns_dnssec_dnssec_validator_verify(
                validator,
                changed.as_ptr(),
                changed.len(),
                signatures.as_ptr(),
                signatures.len(),
                dnskey.as_ptr(),
                dnskey.len(),
                5000,
                &mut verified,
                &mut encloser,
                &mut code,
            ),
            "protocol.dns",
            "Bogus",
        );
        assert_eq!(code, 6);
        // RFC 4035 §5.2: the keys by their DS.
        let all_keys = lines("DNSKEY");
        let (mut secure, mut code) = (false, 0u16);
        Check::ok(umilib_protocol_dns_dnssec_dnssec_validator_verify_keys(
            validator,
            all_keys.as_ptr(),
            all_keys.len(),
            signatures.as_ptr(),
            signatures.len(),
            ds.as_ptr(),
            ds.len(),
            5000,
            &mut secure,
            &mut code,
        ));
        assert!(secure);
        // RFC 4035 §5.4: the NSEC chain denies a name.
        let nsec: String = [lines("NSEC"), signatures.clone()].concat();
        let (none, zone) = ("none.example.", "example.");
        Check::ok(umilib_protocol_dns_dnssec_dnssec_validator_prove(
            validator,
            0,
            none.as_ptr(),
            none.len(),
            0,
            ptr::null(),
            0,
            zone.as_ptr(),
            zone.len(),
            nsec.as_ptr(),
            nsec.len(),
            &mut secure,
            &mut code,
        ));
        assert!(secure);
        let www_name = "www.example.";
        Check::fails(
            umilib_protocol_dns_dnssec_dnssec_validator_prove(
                validator,
                0,
                www_name.as_ptr(),
                www_name.len(),
                0,
                ptr::null(),
                0,
                zone.as_ptr(),
                zone.len(),
                nsec.as_ptr(),
                nsec.len(),
                &mut secure,
                &mut code,
            ),
            "protocol.dns",
            "Bogus",
        );
        umilib_protocol_dns_dnssec_dnssec_validator_free(validator);
        // RFC 9718: the root's anchors, and the anchors of an XML document.
        let mut root = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_dnssec_dnssec_trust_anchor_root(1_793_222_185, &mut root));
        let root = text(&mut root);
        assert!(root.contains("20326 8 2") && root.contains("38696 8 2"));
        let xml = "<TrustAnchor id=\"a\" source=\"b\"><Zone>example.</Zone><KeyDigest id=\"k\" validFrom=\"2020-01-01T00:00:00Z\"><KeyTag>1</KeyTag><Algorithm>15</Algorithm><DigestType>2</DigestType><Digest>00</Digest></KeyDigest></TrustAnchor>";
        let (mut zone_out, mut anchors) = (Buffer::EMPTY, Buffer::EMPTY);
        Check::ok(umilib_protocol_dns_dnssec_dnssec_trust_anchor_parse(
            xml.as_ptr(),
            xml.len(),
            1_700_000_000,
            &mut zone_out,
            &mut anchors,
        ));
        assert_eq!(
            (text(&mut zone_out), text(&mut anchors)),
            ("example.".to_string(), "example. 0 IN DS 1 15 2 00\n".to_string())
        );
        Check::fails(
            umilib_protocol_dns_dnssec_dnssec_trust_anchor_parse(xml.as_ptr(), 10, 0, &mut zone_out, &mut anchors),
            "protocol.dns",
            "Syntax",
        );
    }
}

#[cfg(all(
    umilib_feature = "protocol-dns-tcp",
    umilib_feature = "protocol-dns-udp",
    umilib_feature = "protocol-dns-https"
))]
#[test]
fn transports_through_the_c_abi() {
    use umilib::ffi::protocol::dns::https::*;
    use umilib::ffi::protocol::dns::tcp::*;
    use umilib::ffi::protocol::dns::udp::*;

    unsafe {
        // RFC 1035 §4.2.2: framing, a server's connection over TCP.
        let query = DNSMessage::query(
            5,
            umilib::protocol::dns::DNSQuestion::new(
                umilib::protocol::dns::DNSName::parse("www.example.", None).unwrap(),
                DNSType::A,
            ),
        )
        .encode(512)
        .unwrap();
        let mut framed = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_framer_frame(query.as_ptr(), query.len(), &mut framed));
        let framed = take(&mut framed);
        assert_eq!(framed[..2], (query.len() as u16).to_be_bytes());
        let authority = authority();
        let mut server = ptr::null_mut();
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_server_new(
            endpoint("198.51.100.1:40000"),
            10_000,
            10_000,
            0,
            &mut server,
        ));
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_server_receive(
            server,
            framed.as_ptr(),
            framed.len(),
            authority,
            0,
            0,
        ));
        let mut output = Buffer::EMPTY;
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_server_transmit(server, &mut output));
        let output = take(&mut output);
        let mut framer = ptr::null_mut();
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_framer_new(&mut framer));
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_framer_receive(framer, output.as_ptr(), output.len()));
        let (mut found, mut message) = (false, Buffer::EMPTY);
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_framer_next_message(framer, &mut found, &mut message));
        assert!(found);
        assert_eq!(DNSMessage::decode(&take(&mut message)).unwrap().answers.len(), 2);
        let mut idle = false;
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_server_is_idle(server, 10_000_000_001, &mut idle));
        assert!(idle);
        Check::ok(umilib_protocol_dns_tcp_dns_tcp_framer_receive(framer, [0u8, 0].as_ptr(), 2));
        Check::fails(
            umilib_protocol_dns_tcp_dns_tcp_framer_next_message(framer, &mut found, &mut message),
            "protocol.dns",
            "Malformed",
        );
        umilib_protocol_dns_tcp_dns_tcp_framer_free(framer);
        umilib_protocol_dns_tcp_dns_tcp_server_free(server);
        umilib_protocol_dns_dns_authority_free(authority);
        // RFC 5452 §9.1.
        let mut accepts = false;
        Check::ok(umilib_protocol_dns_udp_dns_udp_accepts(
            endpoint("192.0.2.53:53"),
            endpoint("192.0.2.53:53"),
            &mut accepts,
        ));
        assert!(accepts);
        Check::ok(umilib_protocol_dns_udp_dns_udp_accepts(
            endpoint("192.0.2.53:5353"),
            endpoint("192.0.2.53:53"),
            &mut accepts,
        ));
        assert!(!accepts);
        // RFC 8484 §4.1.1: the GET of www.example.com A.
        let example = DNSMessage::query(
            0,
            umilib::protocol::dns::DNSQuestion::new(
                umilib::protocol::dns::DNSName::parse("www.example.com.", None).unwrap(),
                DNSType::A,
            ),
        )
        .encode(512)
        .unwrap();
        let mut path = Buffer::EMPTY;
        let base = "/dns-query";
        Check::ok(umilib_protocol_dns_https_dns_https_get_path(
            example.as_ptr(),
            example.len(),
            base.as_ptr(),
            base.len(),
            &mut path,
        ));
        let path = text(&mut path);
        assert_eq!(path, "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB");
        let (mut status, mut decoded) = (0u16, Buffer::EMPTY);
        Check::ok(umilib_protocol_dns_https_dns_https_query(
            b"GET".as_ptr(),
            3,
            path.as_ptr(),
            path.len(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            &mut status,
            &mut decoded,
        ));
        assert_eq!((status, take(&mut decoded)), (0, example.clone()));
        let media = "text/plain";
        Check::ok(umilib_protocol_dns_https_dns_https_query(
            b"POST".as_ptr(),
            4,
            base.as_ptr(),
            base.len(),
            media.as_ptr(),
            media.len(),
            example.as_ptr(),
            example.len(),
            &mut status,
            &mut decoded,
        ));
        take(&mut decoded);
        assert_eq!(status, 415);
        let media = "application/dns-message";
        Check::ok(umilib_protocol_dns_https_dns_https_check_response(
            200,
            media.as_ptr(),
            media.len(),
            example.as_ptr(),
            example.len(),
        ));
        Check::fails(
            umilib_protocol_dns_https_dns_https_check_response(
                404,
                media.as_ptr(),
                media.len(),
                example.as_ptr(),
                example.len(),
            ),
            "protocol.dns",
            "Malformed",
        );
    }
}
