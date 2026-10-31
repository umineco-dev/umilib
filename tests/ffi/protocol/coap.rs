//! The C ABI of `umilib::protocol::coap` against the rules and examples of
//! RFC 7252, RFC 8974, RFC 7641, RFC 7959 and RFC 6690, through the
//! functions C calls.

#![cfg(umilib_feature = "hash-sha-v2")]

use std::ffi::CString;
use std::ptr;

use umilib::ffi::crypto::random::{HMACDRBGState, hmac_drbg};
use umilib::ffi::protocol::coap::*;
use umilib::ffi::protocol::ip::FFIIPEndpoint;
use umilib::ffi::{Buffer, Definition, Manifest, Parameter, Type};
use umilib::protocol::coap::{
    CoAPBlockwise, CoAPEndpoint, CoAPLink, CoAPMessage, CoAPObservers, CoAPOptions, CoAPRule,
};
use umilib::protocol::ip::{IPAddress, IPEndpoint, IPv4Address};

use super::super::Check;

/// The type bits of RFC 7252 §3.
const CON: u8 = 0;
const NON: u8 = 1;
const ACK: u8 = 2;
const RST: u8 = 3;
/// The codes of RFC 7252 §12.1, as c.dd: (c << 5) | dd.
const EMPTY: u8 = 0x00;
const GET: u8 = 0x01;
const POST: u8 = 0x02;
const CONTENT: u8 = 0x45;
const BAD_OPTION: u8 = 0x82;
const NOT_FOUND: u8 = 0x84;
/// The option numbers of RFC 7252 table 4, RFC 7641 §2 and RFC 7959 §2.1.
const IF_MATCH: u16 = 1;
const URI_HOST: u16 = 3;
const ETAG: u16 = 4;
const OBSERVE: u16 = 6;
const URI_PATH: u16 = 11;
const CONTENT_FORMAT: u16 = 12;
const MAX_AGE: u16 = 14;
const URI_QUERY: u16 = 15;
const ACCEPT: u16 = 17;
const BLOCK2: u16 = 23;
const SIZE2: u16 = 28;
const SIZE1: u16 = 60;
/// A millisecond in the nanoseconds of `now`.
const MILLISECOND: u64 = 1_000_000;

/// A generator of the C ABI: an HMAC_DRBG over SHA-256 of a fixed seed,
/// released when dropped.
struct Generator {
    state: *mut HMACDRBGState,
}

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

impl Drop for Generator {
    fn drop(&mut self) {
        unsafe { hmac_drbg::free(self.state) };
    }
}

/// Messages, options and buffers of the C ABI.
struct Message;

impl Message {
    /// The bytes of a buffer, which is released.
    fn take(buffer: &mut Buffer) -> Vec<u8> {
        let bytes = buffer.as_slice().to_vec();
        unsafe { umilib::ffi::umilib_ffi_buffer_free(buffer) };
        bytes
    }

    fn make(kind: u8, code: u8, id: u16) -> *mut CoAPMessage {
        let mut message = ptr::null_mut();
        unsafe { Check::ok(umilib_protocol_coap_coap_message_new(kind, code, id, &mut message)) };
        message
    }

    /// A GET request of `kind` for `path`.
    fn get(path: &str, kind: u8) -> *mut CoAPMessage {
        let message = Message::make(kind, GET, 0);
        Message::change_options(message, |options| unsafe {
            Check::ok(umilib_protocol_coap_coap_options_set_uri(options, path.as_ptr(), path.len(), ptr::null(), 0));
        });
        message
    }

    /// Changes the options of `message` with `change`.
    fn change_options(message: *mut CoAPMessage, change: impl FnOnce(*mut CoAPOptions)) {
        let mut options = ptr::null_mut();
        unsafe {
            Check::ok(umilib_protocol_coap_coap_message_options(message, &mut options));
            change(options);
            Check::ok(umilib_protocol_coap_coap_message_set_options(message, options));
            umilib_protocol_coap_coap_options_free(options);
        }
    }

    /// A copy of the options of `message`, released by the caller.
    fn options(message: *const CoAPMessage) -> *mut CoAPOptions {
        let mut options = ptr::null_mut();
        unsafe { Check::ok(umilib_protocol_coap_coap_message_options(message, &mut options)) };
        options
    }

    /// The entries of `options`, in their order.
    fn entries(options: *const CoAPOptions) -> Vec<(u16, Vec<u8>)> {
        let mut count = 0;
        unsafe { Check::ok(umilib_protocol_coap_coap_options_count(options, &mut count)) };
        (0..count)
            .map(|index| {
                let (mut number, mut value) = (0u16, Buffer::EMPTY);
                unsafe { Check::ok(umilib_protocol_coap_coap_options_entry(options, index, &mut number, &mut value)) };
                (number, Message::take(&mut value))
            })
            .collect()
    }

    /// The uint of the option `number` of `message`, if any.
    fn uint(message: *const CoAPMessage, number: u16) -> Option<u32> {
        let options = Message::options(message);
        let (mut found, mut value) = (false, 0u32);
        unsafe {
            Check::ok(umilib_protocol_coap_coap_options_uint(options, number, &mut found, &mut value));
            umilib_protocol_coap_coap_options_free(options);
        }
        found.then_some(value)
    }

    fn set_uint(message: *mut CoAPMessage, number: u16, value: u32) {
        Message::change_options(message, |options| unsafe {
            Check::ok(umilib_protocol_coap_coap_options_set_uint(options, number, value));
        });
    }

    fn encode(message: *const CoAPMessage) -> Vec<u8> {
        let mut buffer = Buffer::EMPTY;
        unsafe { Check::ok(umilib_protocol_coap_coap_message_encode(message, &mut buffer)) };
        Message::take(&mut buffer)
    }

    fn decode(bytes: &[u8]) -> *mut CoAPMessage {
        let mut message = ptr::null_mut();
        unsafe { Check::ok(umilib_protocol_coap_coap_message_decode(bytes.as_ptr(), bytes.len(), &mut message)) };
        message
    }

    /// The type, code and Message ID of `message`.
    fn header(message: *const CoAPMessage) -> (u8, u8, u16) {
        let (mut kind, mut code, mut id) = (0u8, 0u8, 0u16);
        unsafe {
            Check::ok(umilib_protocol_coap_coap_message_kind(message, &mut kind));
            Check::ok(umilib_protocol_coap_coap_message_code(message, &mut code));
            Check::ok(umilib_protocol_coap_coap_message_id(message, &mut id));
        }
        (kind, code, id)
    }

    /// The type, code and Message ID of the message of `bytes`.
    fn header_of(bytes: &[u8]) -> (u8, u8, u16) {
        let message = Message::decode(bytes);
        let header = Message::header(message);
        unsafe { umilib_protocol_coap_coap_message_free(message) };
        header
    }

    fn token(message: *const CoAPMessage) -> Vec<u8> {
        let mut buffer = Buffer::EMPTY;
        unsafe { Check::ok(umilib_protocol_coap_coap_message_token(message, &mut buffer)) };
        Message::take(&mut buffer)
    }

    fn set_token(message: *mut CoAPMessage, token: &[u8]) {
        unsafe { Check::ok(umilib_protocol_coap_coap_message_set_token(message, token.as_ptr(), token.len())) };
    }

    fn payload(message: *const CoAPMessage) -> Vec<u8> {
        let mut buffer = Buffer::EMPTY;
        unsafe { Check::ok(umilib_protocol_coap_coap_message_payload(message, &mut buffer)) };
        Message::take(&mut buffer)
    }

    fn set_payload(message: *mut CoAPMessage, payload: &[u8]) {
        unsafe { Check::ok(umilib_protocol_coap_coap_message_set_payload(message, payload.as_ptr(), payload.len())) };
    }

    /// The Uri-Path of `message`, its segments as text.
    fn path(message: *const CoAPMessage) -> Vec<String> {
        let options = Message::options(message);
        let entries = Message::entries(options);
        unsafe { umilib_protocol_coap_coap_options_free(options) };
        entries
            .into_iter()
            .filter(|(number, _)| *number == URI_PATH)
            .map(|(_, value)| String::from_utf8(value).unwrap())
            .collect()
    }

    fn free(message: *mut CoAPMessage) {
        unsafe { umilib_protocol_coap_coap_message_free(message) };
    }
}

/// The endpoints of the tests.
struct Peer;

impl Peer {
    fn client() -> FFIIPEndpoint {
        FFIIPEndpoint::of(&IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, 2)), 40000))
    }

    fn server() -> FFIIPEndpoint {
        FFIIPEndpoint::of(&IPEndpoint::new(IPAddress::V4(IPv4Address::new(192, 0, 2, 1)), 5683))
    }
}

/// An endpoint of the C ABI and what it says.
struct Endpoint {
    endpoint: *mut CoAPEndpoint,
}

impl Endpoint {
    fn new(config: &FFICoAPConfig, random: &Generator) -> Endpoint {
        let mut endpoint = ptr::null_mut();
        unsafe {
            Check::ok(umilib_protocol_coap_coap_endpoint_new(
                config,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut endpoint,
            ))
        };
        Endpoint { endpoint }
    }

    fn default(random: &Generator) -> Endpoint {
        let mut config = FFICoAPConfig::default();
        unsafe { Check::ok(umilib_protocol_coap_coap_config_default(&mut config)) };
        Endpoint::new(&config, random)
    }

    fn request(&self, peer: &FFIIPEndpoint, message: *const CoAPMessage, now: u64, random: &Generator) -> u64 {
        let mut handle = 0;
        unsafe {
            Check::ok(umilib_protocol_coap_coap_endpoint_request(
                self.endpoint,
                peer,
                message,
                now,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut handle,
            ))
        };
        handle
    }

    fn receive(&self, peer: &FFIIPEndpoint, bytes: &[u8], now: u64, random: &Generator) {
        unsafe {
            Check::ok(umilib_protocol_coap_coap_endpoint_receive(
                self.endpoint,
                peer,
                bytes.as_ptr(),
                bytes.len(),
                now,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ))
        };
    }

    fn respond(
        &self,
        exchange: u64,
        response: *const CoAPMessage,
        now: u64,
        random: &Generator,
    ) -> *const umilib::ffi::Status {
        unsafe {
            umilib_protocol_coap_coap_endpoint_respond(
                self.endpoint,
                exchange,
                response,
                now,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            )
        }
    }

    /// The next datagram to send and its peer.
    fn transmit(&self) -> Option<(FFIIPEndpoint, Vec<u8>)> {
        let (mut found, mut peer, mut buffer) = (false, FFIIPEndpoint::default(), Buffer::EMPTY);
        unsafe {
            Check::ok(umilib_protocol_coap_coap_endpoint_transmit(self.endpoint, &mut found, &mut peer, &mut buffer))
        };
        let bytes = Message::take(&mut buffer);
        found.then_some((peer, bytes))
    }

    /// The next event, and its message (null if none).
    fn poll_event(&self) -> Option<(FFICoAPEvent, *mut CoAPMessage)> {
        let (mut found, mut event, mut message) = (false, FFICoAPEvent::default(), ptr::null_mut());
        unsafe {
            Check::ok(umilib_protocol_coap_coap_endpoint_poll_event(
                self.endpoint,
                &mut found,
                &mut event,
                &mut message,
            ))
        };
        found.then_some((event, message))
    }

    /// Every event pending, their messages released.
    fn events(&self) -> Vec<FFICoAPEvent> {
        std::iter::from_fn(|| self.poll_event())
            .map(|(event, message)| {
                Message::free(message);
                event
            })
            .collect()
    }

    fn poll_timeout(&self) -> Option<u64> {
        let (mut found, mut timeout) = (false, 0u64);
        unsafe { Check::ok(umilib_protocol_coap_coap_endpoint_poll_timeout(self.endpoint, &mut found, &mut timeout)) };
        found.then_some(timeout)
    }

    fn expire(&self, now: u64) {
        unsafe { Check::ok(umilib_protocol_coap_coap_endpoint_expire(self.endpoint, now)) };
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        unsafe { umilib_protocol_coap_coap_endpoint_free(self.endpoint) };
    }
}

/// A client and a server and the datagrams between them.
struct Pair {
    client: Endpoint,
    server: Endpoint,
    random: Generator,
}

impl Pair {
    fn new() -> Pair {
        let random = Generator::new(b"pair");
        Pair { client: Endpoint::default(&random), server: Endpoint::default(&random), random }
    }

    /// Delivers what each has to send at `now` until neither has any; the datagrams, client's first.
    fn run(&self, now: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let (mut from_client, mut from_server) = (Vec::new(), Vec::new());
        loop {
            let mut moved = false;
            while let Some((peer, bytes)) = self.client.transmit() {
                assert_eq!(peer, Peer::server());
                self.server.receive(&Peer::client(), &bytes, now, &self.random);
                from_client.push(bytes);
                moved = true;
            }
            while let Some((peer, bytes)) = self.server.transmit() {
                assert_eq!(peer, Peer::client());
                self.client.receive(&Peer::server(), &bytes, now, &self.random);
                from_server.push(bytes);
                moved = true;
            }
            if !moved {
                return (from_client, from_server);
            }
        }
    }

    /// The one request the server has to answer: its exchange and message.
    fn request(&self) -> (FFICoAPEvent, *mut CoAPMessage) {
        let (event, message) = self.server.poll_event().expect("a request");
        assert_eq!((event.kind, event.peer), (0, Peer::client()));
        assert!(!message.is_null());
        assert!(self.server.poll_event().is_none());
        (event, message)
    }
}

/// The C layout of the structures of the manifest.
struct Layout;

impl Layout {
    fn of(value: &Type, structures: &std::collections::BTreeMap<&str, &'static [Parameter]>) -> (usize, usize) {
        match value {
            Type::Bool | Type::U8 => (1, 1),
            Type::U16 => (2, 2),
            Type::U32 => (4, 4),
            Type::U64 => (size_of::<u64>(), align_of::<u64>()),
            Type::USize => (size_of::<usize>(), align_of::<usize>()),
            Type::Array { element, length } => {
                let (size, align) = Layout::of(element, structures);
                (size * length, align)
            }
            Type::Named(name) => {
                let (mut size, mut align) = (0usize, 1usize);
                for field in structures[name].iter() {
                    let (field_size, field_align) = Layout::of(&field.value, structures);
                    size = size.next_multiple_of(field_align) + field_size;
                    align = align.max(field_align);
                }
                (size.next_multiple_of(align), align)
            }
            other => panic!("{other:?} is not used by the structures of CoAP"),
        }
    }
}

#[test]
fn coap_structures_have_the_layout_of_their_rust_types() {
    let mut structures = std::collections::BTreeMap::new();
    Manifest::ROOT.visit(|_, module| {
        for definition in module.definitions {
            if let Definition::Structure { name, fields, .. } = definition {
                structures.insert(*name, *fields);
            }
        }
    });
    for (name, size, align) in [
        ("umilib_protocol_coap_CoAPBlock", size_of::<FFICoAPBlock>(), align_of::<FFICoAPBlock>()),
        (
            "umilib_protocol_coap_CoAPOptionDefinition",
            size_of::<FFICoAPOptionDefinition>(),
            align_of::<FFICoAPOptionDefinition>(),
        ),
        ("umilib_protocol_coap_CoAPConfig", size_of::<FFICoAPConfig>(), align_of::<FFICoAPConfig>()),
        ("umilib_protocol_coap_CoAPEvent", size_of::<FFICoAPEvent>(), align_of::<FFICoAPEvent>()),
    ] {
        assert_eq!(Layout::of(&Type::Named(name), &structures), (size, align), "{name}");
    }
    // `kind`, padding to the alignment of `u64` (4 on i386 System V, 8 elsewhere), then three `u64`s.
    assert_eq!(std::mem::offset_of!(FFICoAPEvent, peer), std::mem::align_of::<u64>() + 24);
}

#[test]
fn coap_messages_through_the_c_abi() {
    unsafe {
        // RFC 7252 §3 and its example of appendix A: a CON GET of /temperature, token 0x20.
        let request = Message::get("/temperature", CON);
        Check::ok(umilib_protocol_coap_coap_message_set_id(request, 0x7d34));
        Message::set_token(request, &[0x20]);
        let bytes = Message::encode(request);
        let mut expected = vec![0x41, 0x01, 0x7d, 0x34, 0x20, 0xbb];
        expected.extend_from_slice(b"temperature");
        assert_eq!(bytes, expected);
        let decoded = Message::decode(&bytes);
        assert_eq!(Message::header(decoded), (CON, GET, 0x7d34));
        assert_eq!((Message::token(decoded), Message::path(decoded)), (vec![0x20], vec!["temperature".to_string()]));
        Message::free(decoded);
        // A copy is a message of its own.
        let mut copy = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_message_clone(request, &mut copy));
        Check::ok(umilib_protocol_coap_coap_message_set_kind(copy, NON));
        assert_eq!((Message::header(request).0, Message::header(copy).0), (CON, NON));
        Message::free(copy);
        Message::free(request);
        // A payload follows the marker 0xFF.
        let response = Message::make(ACK, CONTENT, 0x7d34);
        Message::set_token(response, &[0x20]);
        Message::set_payload(response, b"22.3 C");
        let bytes = Message::encode(response);
        assert_eq!(bytes[..6], [0x61, 0x45, 0x7d, 0x34, 0x20, 0xff]);
        assert_eq!(&bytes[6..], b"22.3 C");
        let decoded = Message::decode(&bytes);
        assert_eq!(Message::payload(decoded), b"22.3 C");
        Message::free(decoded);
        Message::free(response);
        // §3.1: deltas and lengths of 13 to 268 take one more byte (minus 13), from 269 two (minus 269).
        for (number, length, header) in [
            (12u16, 12usize, vec![0xcc]),
            (13, 13, vec![0xdd, 0x00, 0x00]),
            (268, 268, vec![0xdd, 0xff, 0xff]),
            (269, 269, vec![0xee, 0x00, 0x00, 0x00, 0x00]),
            (1000, 300, vec![0xee, 0x02, 0xdb, 0x00, 0x1f]),
            (65535, 1034, vec![0xee, 0xfe, 0xf2, 0x02, 0xfd]),
        ] {
            let message = Message::make(NON, POST, 1);
            let value = vec![b'x'; length];
            Message::change_options(message, |options| {
                Check::ok(umilib_protocol_coap_coap_options_push(options, number, value.as_ptr(), value.len()));
            });
            let bytes = Message::encode(message);
            assert_eq!(bytes[4..4 + header.len()], header[..], "{number} {length}");
            let decoded = Message::decode(&bytes);
            let options = Message::options(decoded);
            assert_eq!(Message::entries(options), [(number, value)]);
            umilib_protocol_coap_coap_options_free(options);
            Message::free(decoded);
            Message::free(message);
        }
        // Options go in the order of their numbers, repeated ones in the order given (§3.1, §5.4.5).
        let message = Message::make(CON, GET, 2);
        Message::change_options(message, |options| {
            for (number, value) in [(URI_QUERY, &b"q"[..]), (URI_PATH, b"a"), (URI_PATH, b"b"), (URI_HOST, b"h")] {
                Check::ok(umilib_protocol_coap_coap_options_push(options, number, value.as_ptr(), value.len()));
            }
        });
        let decoded = Message::decode(&Message::encode(message));
        let options = Message::options(decoded);
        let numbers: Vec<u16> = Message::entries(options).into_iter().map(|(number, _)| number).collect();
        assert_eq!(numbers, [URI_HOST, URI_PATH, URI_PATH, URI_QUERY]);
        assert_eq!(Message::path(decoded), ["a", "b"]);
        umilib_protocol_coap_coap_options_free(options);
        Message::free(decoded);
        Message::free(message);
        // RFC 8974 §2.1: token lengths up to 12 in the nibble, 13 to 268 in one more byte, then two.
        for (length, nibble, extension) in [
            (0usize, 0u8, vec![]),
            (8, 8, vec![]),
            (12, 12, vec![]),
            (13, 13, vec![0]),
            (268, 13, vec![255]),
            (269, 14, vec![0, 0]),
            (1000, 14, vec![2, 219]),
        ] {
            let message = Message::make(NON, GET, 3);
            Message::set_token(message, &vec![7; length]);
            let bytes = Message::encode(message);
            assert_eq!((bytes[0] & 15, &bytes[4..4 + extension.len()]), (nibble, &extension[..]), "{length}");
            let decoded = Message::decode(&bytes);
            assert_eq!(Message::token(decoded).len(), length);
            Message::free(decoded);
            Message::free(message);
        }
        // The largest token is of 65804 bytes (RFC 8974 §2.1); a longer one cannot be encoded.
        let message = Message::make(NON, GET, 4);
        Message::set_token(message, &vec![1; 65804]);
        assert_eq!(Message::encode(message)[..6], [0x5e, 0x01, 0, 4, 0xff, 0xff]);
        Message::set_token(message, &vec![1; 65805]);
        let mut buffer = Buffer::EMPTY;
        Check::fails(umilib_protocol_coap_coap_message_encode(message, &mut buffer), "protocol.coap", "TooLarge");
        Message::free(message);
        // Message format errors (§3, §3.1, §4.1, RFC 8974 §2.1).
        for bytes in [
            &[0x40, 0x01, 0][..],
            &[0x80, 0x01, 0, 1],
            &[0x4f, 0x01, 0, 1],
            &[0x4d, 0x01, 0, 1],
            &[0x41, 0x01, 0, 1],
            &[0x40, 0x01, 0, 1, 0xf0],
            &[0x40, 0x01, 0, 1, 0x1f],
            &[0x40, 0x01, 0, 1, 0xff],
            &[0x40, 0x01, 0, 1, 0xd0],
            &[0x40, 0x01, 0, 1, 0x02, 0x61],
            &[0x61, 0x00, 0, 1, 9],
            &[0x60, 0x00, 0, 1, 0xff, 1],
            &[0x60, 0x00, 0, 1, 0x10],
        ] {
            let mut message = ptr::null_mut();
            Check::fails(
                umilib_protocol_coap_coap_message_decode(bytes.as_ptr(), bytes.len(), &mut message),
                "protocol.coap",
                "Malformed",
            );
            assert!(message.is_null(), "{bytes:?}");
        }
        // An empty message is the header alone (§4.1).
        let empty = Message::decode(&[0x60, 0x00, 0x12, 0x34]);
        assert_eq!(Message::header(empty), (ACK, EMPTY, 0x1234));
        let mut made = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_message_empty(RST, 0x1234, &mut made));
        assert_eq!(Message::encode(made), [0x70, 0x00, 0x12, 0x34]);
        Message::free(made);
        Message::free(empty);
        // The header of a message that cannot be read, to reject it (§4.2): of version 1 only.
        let (mut found, mut kind, mut id) = (false, 9u8, 0u16);
        let bytes = [0x40, 0x01, 0, 10, 0xf0];
        Check::ok(umilib_protocol_coap_coap_message_header(
            bytes.as_ptr(),
            bytes.len(),
            &mut found,
            &mut kind,
            &mut id,
        ));
        assert_eq!((found, kind, id), (true, CON, 10));
        let bytes = [0x80, 0x01, 0, 10];
        Check::ok(umilib_protocol_coap_coap_message_header(
            bytes.as_ptr(),
            bytes.len(),
            &mut found,
            &mut kind,
            &mut id,
        ));
        assert!(!found);
        // A type is of two bits; null outputs are refused.
        let mut message = ptr::null_mut();
        Check::fails(umilib_protocol_coap_coap_message_new(4, GET, 0, &mut message), "ffi", "InvalidArgument");
        Check::fails(umilib_protocol_coap_coap_message_new(CON, GET, 0, ptr::null_mut()), "ffi", "NullPointer");
        let bytes = [0x40, 0x01, 0, 1];
        Check::fails(
            umilib_protocol_coap_coap_message_decode(bytes.as_ptr(), 4, ptr::null_mut()),
            "ffi",
            "NullPointer",
        );
        umilib_protocol_coap_coap_message_free(ptr::null_mut());
    }
}

#[test]
fn coap_options_through_the_c_abi() {
    unsafe {
        // RFC 7252 §5.4.6: the properties are of the number's bits; table 4 marks them so.
        let property = |function: unsafe extern "C" fn(u16, *mut bool) -> *const umilib::ffi::Status, number| {
            let mut out = false;
            Check::ok(function(number, &mut out));
            out
        };
        for (number, critical, unsafe_, no_cache_key) in [
            (IF_MATCH, true, false, false),
            (URI_HOST, true, true, false),
            (ETAG, false, false, false),
            (OBSERVE, false, true, false),
            (URI_PATH, true, true, false),
            (CONTENT_FORMAT, false, false, false),
            (MAX_AGE, false, true, false),
            (ACCEPT, true, false, false),
            (SIZE1, false, false, true),
        ] {
            assert_eq!(property(umilib_protocol_coap_coap_option_number_is_critical, number), critical, "{number}");
            assert_eq!(property(umilib_protocol_coap_coap_option_number_is_unsafe, number), unsafe_, "{number}");
            assert_eq!(
                property(umilib_protocol_coap_coap_option_number_is_no_cache_key, number),
                no_cache_key,
                "{number}"
            );
        }
        // Table 4: format (0 empty, 1 opaque, 2 uint, 3 string), lengths and repeatability.
        for (number, expected) in [
            (IF_MATCH, Some((1u8, 0usize, 8usize, true))),
            (URI_HOST, Some((3, 1, 255, false))),
            (ETAG, Some((1, 1, 8, true))),
            (5, Some((0, 0, 0, false))),
            (URI_PATH, Some((3, 0, 255, true))),
            (MAX_AGE, Some((2, 0, 4, false))),
            (35, Some((3, 1, 1034, false))),
            (OBSERVE, Some((2, 0, 3, false))),
            (BLOCK2, Some((2, 0, 3, false))),
            (9, None),
        ] {
            let (mut found, mut definition) = (false, FFICoAPOptionDefinition::default());
            Check::ok(umilib_protocol_coap_coap_option_number_definition(number, &mut found, &mut definition));
            let got =
                found.then_some((definition.format, definition.least, definition.greatest, definition.repeatable));
            assert_eq!(got, expected, "{number}");
        }
        // §3.2: uints of as few bytes as they need.
        for (value, bytes) in [(0u32, &[][..]), (1, &[1]), (0x1234, &[0x12, 0x34]), (0x0100_0000, &[1, 0, 0, 0])] {
            let mut buffer = Buffer::EMPTY;
            Check::ok(umilib_protocol_coap_coap_options_uint_bytes(value, &mut buffer));
            assert_eq!(Message::take(&mut buffer), bytes);
            let (mut found, mut read) = (false, 0u32);
            Check::ok(umilib_protocol_coap_coap_options_uint_of(bytes.as_ptr(), bytes.len(), &mut found, &mut read));
            assert_eq!((found, read), (true, value));
        }
        let (mut found, mut read) = (false, 0u32);
        Check::ok(umilib_protocol_coap_coap_options_uint_of([0, 0, 1].as_ptr(), 3, &mut found, &mut read));
        assert_eq!((found, read), (true, 1));
        Check::ok(umilib_protocol_coap_coap_options_uint_of([1, 2, 3, 4, 5].as_ptr(), 5, &mut found, &mut read));
        assert!(!found);
        // §6.4: a URI's path and query in Uri-Path and Uri-Query options.
        let mut options = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_options_new(&mut options));
        let (path, query) = ("/a/b", "x=1&y");
        Check::ok(umilib_protocol_coap_coap_options_set_uri(
            options,
            path.as_ptr(),
            path.len(),
            query.as_ptr(),
            query.len(),
        ));
        assert_eq!(
            Message::entries(options),
            [
                (URI_PATH, b"a".to_vec()),
                (URI_PATH, b"b".to_vec()),
                (URI_QUERY, b"x=1".to_vec()),
                (URI_QUERY, b"y".to_vec())
            ]
        );
        let (mut found, mut value) = (false, Buffer::EMPTY);
        Check::ok(umilib_protocol_coap_coap_options_get(options, URI_PATH, &mut found, &mut value));
        assert_eq!((found, Message::take(&mut value)), (true, b"a".to_vec()));
        Check::ok(umilib_protocol_coap_coap_options_get(options, ETAG, &mut found, &mut value));
        assert_eq!((found, Message::take(&mut value)), (false, vec![]));
        let mut contains = false;
        Check::ok(umilib_protocol_coap_coap_options_contains(options, URI_QUERY, &mut contains));
        assert!(contains);
        let mut count = 0usize;
        let (mut number, mut value) = (0u16, Buffer::EMPTY);
        Check::fails(
            umilib_protocol_coap_coap_options_entry(options, 4, &mut number, &mut value),
            "ffi",
            "InvalidArgument",
        );
        // §5.4.1, §5.4.3, §5.4.5: an unknown critical option, a value out of its lengths, or a
        // non-repeatable one repeated rejects the message; elective ones are ignored.
        let (mut rejected, mut number) = (false, 0u16);
        Check::ok(umilib_protocol_coap_coap_options_check(options, &mut rejected, &mut number));
        assert!(!rejected);
        for (added, value, rejects) in [
            (9u16, &[1u8][..], true),
            (10, &[1], false),
            (URI_HOST, &[], true),
            (ETAG, &[], false),
            (ACCEPT, &[1, 2, 3], true),
        ] {
            let mut changed = ptr::null_mut();
            Check::ok(umilib_protocol_coap_coap_options_clone(options, &mut changed));
            Check::ok(umilib_protocol_coap_coap_options_push(changed, added, value.as_ptr(), value.len()));
            Check::ok(umilib_protocol_coap_coap_options_check(changed, &mut rejected, &mut number));
            assert_eq!(rejected, rejects, "{added}");
            if rejects {
                assert_eq!(number, added);
            } else {
                let mut usable = ptr::null_mut();
                Check::ok(umilib_protocol_coap_coap_options_usable(changed, &mut usable));
                assert_eq!(Message::entries(usable), Message::entries(options), "{added}");
                umilib_protocol_coap_coap_options_free(usable);
            }
            umilib_protocol_coap_coap_options_free(changed);
        }
        let mut repeated = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_options_new(&mut repeated));
        Check::ok(umilib_protocol_coap_coap_options_push(repeated, URI_HOST, b"a".as_ptr(), 1));
        Check::ok(umilib_protocol_coap_coap_options_push(repeated, URI_HOST, b"b".as_ptr(), 1));
        Check::ok(umilib_protocol_coap_coap_options_check(repeated, &mut rejected, &mut number));
        assert_eq!((rejected, number), (true, URI_HOST));
        // Set replaces every option of the number; remove drops them.
        Check::ok(umilib_protocol_coap_coap_options_set(repeated, URI_HOST, b"c".as_ptr(), 1));
        assert_eq!(Message::entries(repeated), [(URI_HOST, b"c".to_vec())]);
        Check::ok(umilib_protocol_coap_coap_options_remove(repeated, URI_HOST));
        Check::ok(umilib_protocol_coap_coap_options_count(repeated, &mut count));
        assert_eq!(count, 0);
        // §5.10.5: Max-Age is 60 seconds without the option; a repeated elective one counts once.
        let mut age = 0u32;
        Check::ok(umilib_protocol_coap_coap_options_max_age(repeated, &mut age));
        assert_eq!(age, 60);
        Check::ok(umilib_protocol_coap_coap_options_push(repeated, MAX_AGE, [1u8].as_ptr(), 1));
        Check::ok(umilib_protocol_coap_coap_options_push(repeated, MAX_AGE, [2u8].as_ptr(), 1));
        let mut usable = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_options_usable(repeated, &mut usable));
        Check::ok(umilib_protocol_coap_coap_options_max_age(usable, &mut age));
        assert_eq!(age, 1);
        umilib_protocol_coap_coap_options_free(usable);
        // §5.10.3 and RFC 7641 §2: Content-Format and Observe, as uints.
        let (mut found, mut format) = (false, 0u16);
        Check::ok(umilib_protocol_coap_coap_options_content_format(options, &mut found, &mut format));
        assert!(!found);
        Check::ok(umilib_protocol_coap_coap_options_set_uint(options, CONTENT_FORMAT, 50));
        Check::ok(umilib_protocol_coap_coap_options_content_format(options, &mut found, &mut format));
        assert_eq!((found, format), (true, 50));
        let (mut found, mut observe) = (false, 0u32);
        Check::ok(umilib_protocol_coap_coap_options_set_uint(options, OBSERVE, 0x12_3456));
        Check::ok(umilib_protocol_coap_coap_options_observe(options, &mut found, &mut observe));
        assert_eq!((found, observe), (true, 0x12_3456));
        let (mut found, mut value) = (false, Buffer::EMPTY);
        Check::ok(umilib_protocol_coap_coap_options_get(options, OBSERVE, &mut found, &mut value));
        assert_eq!(Message::take(&mut value), [0x12, 0x34, 0x56]);
        // RFC 7959 §2.2: a Block2 option, read; SZX 7 is reserved.
        let (mut found, mut block) = (false, FFICoAPBlock::default());
        Check::ok(umilib_protocol_coap_coap_options_set(options, BLOCK2, [0x3b].as_ptr(), 1));
        Check::ok(umilib_protocol_coap_coap_options_block(options, BLOCK2, &mut found, &mut block));
        assert_eq!((found, block), (true, FFICoAPBlock { number: 3, more: true, exponent: 3 }));
        Check::ok(umilib_protocol_coap_coap_options_set(options, BLOCK2, [0x0f].as_ptr(), 1));
        Check::fails(
            umilib_protocol_coap_coap_options_block(options, BLOCK2, &mut found, &mut block),
            "protocol.coap",
            "Option",
        );
        Check::ok(umilib_protocol_coap_coap_options_block(options, 27, &mut found, &mut block));
        assert!(!found);
        umilib_protocol_coap_coap_options_free(repeated);
        umilib_protocol_coap_coap_options_free(options);
        umilib_protocol_coap_coap_options_free(ptr::null_mut());
    }
}

#[test]
fn coap_blocks_through_the_c_abi() {
    unsafe {
        // RFC 7959 §2.2: NUM, M and SZX; a size of 2^(SZX + 4); the offset NUM × size.
        let mut block = FFICoAPBlock::default();
        Check::ok(umilib_protocol_coap_coap_block_new(3, true, 128, &mut block));
        assert_eq!(block, FFICoAPBlock { number: 3, more: true, exponent: 3 });
        let mut buffer = Buffer::EMPTY;
        Check::ok(umilib_protocol_coap_coap_block_encode(block, &mut buffer));
        assert_eq!(Message::take(&mut buffer), [0x3b]);
        let (mut size, mut offset) = (0usize, 0usize);
        Check::ok(umilib_protocol_coap_coap_block_size(block, &mut size));
        Check::ok(umilib_protocol_coap_coap_block_offset(block, &mut offset));
        assert_eq!((size, offset), (128, 384));
        let mut decoded = FFICoAPBlock::default();
        Check::ok(umilib_protocol_coap_coap_block_decode([0x3b].as_ptr(), 1, &mut decoded));
        assert_eq!(decoded, block);
        // A value of zero bytes is block 0 of 16 bytes; of three, a number of 20 bits.
        Check::ok(umilib_protocol_coap_coap_block_decode(ptr::null(), 0, &mut decoded));
        assert_eq!(decoded, FFICoAPBlock { number: 0, more: false, exponent: 0 });
        Check::ok(umilib_protocol_coap_coap_block_decode([0xff, 0xff, 0xf6].as_ptr(), 3, &mut decoded));
        assert_eq!(decoded, FFICoAPBlock { number: (1 << 20) - 1, more: false, exponent: 6 });
        for value in [&[0x07u8][..], &[1, 2, 3, 4]] {
            Check::fails(
                umilib_protocol_coap_coap_block_decode(value.as_ptr(), value.len(), &mut decoded),
                "protocol.coap",
                "Option",
            );
        }
        for (number, size) in [(0u32, 2048usize), (0, 8), (0, 100), (1 << 20, 16)] {
            Check::fails(
                umilib_protocol_coap_coap_block_new(number, false, size, &mut block),
                "protocol.coap",
                "Option",
            );
        }
        let reserved = FFICoAPBlock { number: 0, more: false, exponent: 7 };
        Check::fails(umilib_protocol_coap_coap_block_encode(reserved, &mut buffer), "protocol.coap", "Option");
        // §2.4: the block of a body, and whether more follow.
        let body: Vec<u8> = (0..300u16).map(|value| value as u8).collect();
        let (mut found, mut length, mut more) = (false, 0usize, false);
        for (number, expected) in [(0u32, Some((128usize, true))), (2, Some((44, false))), (3, None)] {
            Check::ok(umilib_protocol_coap_coap_block_new(number, false, 128, &mut block));
            Check::ok(umilib_protocol_coap_coap_block_slice(
                block,
                body.as_ptr(),
                body.len(),
                &mut found,
                &mut length,
                &mut more,
            ));
            assert_eq!(found.then_some((length, more)), expected, "{number}");
        }
        // A server's blocks of a body, Size2 if asked (§4); a smaller size keeps the offset (§2.4).
        let request = Message::get("/large", CON);
        Message::set_uint(request, SIZE2, 0);
        let response = Message::make(ACK, CONTENT, 0);
        Check::ok(umilib_protocol_coap_coap_blockwise_respond(request, body.as_ptr(), body.len(), 128, response));
        let options = Message::options(response);
        Check::ok(umilib_protocol_coap_coap_options_block(options, BLOCK2, &mut found, &mut block));
        assert_eq!((found, block), (true, FFICoAPBlock { number: 0, more: true, exponent: 3 }));
        umilib_protocol_coap_coap_options_free(options);
        assert_eq!((Message::payload(response), Message::uint(response, SIZE2)), (body[..128].to_vec(), Some(300)));
        Message::change_options(request, |options| {
            Check::ok(umilib_protocol_coap_coap_options_set(options, BLOCK2, [0x14].as_ptr(), 1));
        });
        Check::ok(umilib_protocol_coap_coap_blockwise_respond(request, body.as_ptr(), body.len(), 64, response));
        let options = Message::options(response);
        Check::ok(umilib_protocol_coap_coap_options_block(options, BLOCK2, &mut found, &mut block));
        assert_eq!(block, FFICoAPBlock { number: 4, more: false, exponent: 2 });
        umilib_protocol_coap_coap_options_free(options);
        assert_eq!(Message::payload(response), body[256..]);
        // A block past the end is an error, and the response is left as it was.
        Message::change_options(request, |options| {
            Check::ok(umilib_protocol_coap_coap_options_set(options, BLOCK2, [0x92].as_ptr(), 1));
        });
        Check::fails(
            umilib_protocol_coap_coap_blockwise_respond(request, body.as_ptr(), body.len(), 64, response),
            "protocol.coap",
            "Option",
        );
        assert_eq!(Message::payload(response), body[256..]);
        Message::free(response);
        // A body that fits in a block, without Block2, is sent whole.
        let small = Message::get("/small", CON);
        let whole = Message::make(ACK, CONTENT, 0);
        Check::ok(umilib_protocol_coap_coap_blockwise_respond(small, body.as_ptr(), 100, 128, whole));
        assert_eq!(Message::payload(whole), body[..100]);
        // One handle as both the request and the response: sound, the request read first.
        let both = Message::get("/both", CON);
        Check::ok(umilib_protocol_coap_coap_blockwise_respond(both, body.as_ptr(), 100, 128, both));
        assert_eq!(Message::payload(both), body[..100]);
        Message::free(both);
        let options = Message::options(whole);
        let mut contains = true;
        Check::ok(umilib_protocol_coap_coap_options_contains(options, BLOCK2, &mut contains));
        assert!(!contains);
        umilib_protocol_coap_coap_options_free(options);
        Message::free(whole);
        Message::free(small);
        // §2.4, §2.5: a receiver takes blocks in order, each but the last full, of one ETag.
        let mut receiver: *mut CoAPBlockwise = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_blockwise_new(1000, &mut receiver));
        let etag = [1u8];
        let receive = |number: u32, more: bool, payload: &[u8], etag: &[u8]| {
            let mut block = FFICoAPBlock::default();
            Check::ok(umilib_protocol_coap_coap_block_new(number, more, 128, &mut block));
            let mut whole = false;
            let status = umilib_protocol_coap_coap_blockwise_receive(
                receiver,
                block,
                payload.as_ptr(),
                payload.len(),
                etag.as_ptr(),
                etag.len(),
                &mut whole,
            );
            (status, whole)
        };
        let (status, whole) = receive(0, true, &body[..128], &etag);
        Check::ok(status);
        assert!(!whole);
        Check::fails(receive(2, true, &body[256..], &etag).0, "protocol.coap", "State");
        Check::fails(receive(1, true, &body[128..256], &[2]).0, "protocol.coap", "State");
        Check::fails(receive(1, true, &body[128..200], &etag).0, "protocol.coap", "Malformed");
        Check::ok(receive(1, true, &body[128..256], &etag).0);
        // The next request asks for the next block at the end of the body so far, without Observe.
        Message::set_uint(request, OBSERVE, 0);
        let options = Message::options(request);
        let mut asked = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_blockwise_next_request(receiver, options, 128, &mut asked));
        Check::ok(umilib_protocol_coap_coap_options_block(asked, BLOCK2, &mut found, &mut block));
        assert_eq!(block, FFICoAPBlock { number: 2, more: false, exponent: 3 });
        Check::ok(umilib_protocol_coap_coap_options_contains(asked, OBSERVE, &mut contains));
        assert!(!contains);
        umilib_protocol_coap_coap_options_free(asked);
        // RFC 7959 §2.4: smaller blocks are numbered at their size; 100 bytes is not a size.
        Check::ok(umilib_protocol_coap_coap_blockwise_next_request(receiver, options, 64, &mut asked));
        Check::ok(umilib_protocol_coap_coap_options_block(asked, BLOCK2, &mut found, &mut block));
        assert_eq!(block, FFICoAPBlock { number: 4, more: false, exponent: 2 });
        umilib_protocol_coap_coap_options_free(asked);
        Check::fails(
            umilib_protocol_coap_coap_blockwise_next_request(receiver, options, 100, &mut asked),
            "protocol.coap",
            "Option",
        );
        umilib_protocol_coap_coap_options_free(options);
        let (status, whole) = receive(2, false, &body[256..], &etag);
        Check::ok(status);
        assert!(whole);
        let mut buffer = Buffer::EMPTY;
        Check::ok(umilib_protocol_coap_coap_blockwise_body(receiver, &mut buffer));
        assert_eq!(Message::take(&mut buffer), body);
        umilib_protocol_coap_coap_blockwise_free(receiver);
        // More than the receiver takes.
        Check::ok(umilib_protocol_coap_coap_blockwise_new(100, &mut receiver));
        Check::ok(umilib_protocol_coap_coap_block_new(0, true, 128, &mut block));
        let mut whole = false;
        Check::fails(
            umilib_protocol_coap_coap_blockwise_receive(
                receiver,
                block,
                body.as_ptr(),
                128,
                ptr::null(),
                0,
                &mut whole,
            ),
            "protocol.coap",
            "TooLarge",
        );
        umilib_protocol_coap_coap_blockwise_free(receiver);
        Message::free(request);
    }
}

#[test]
fn coap_endpoints_through_the_c_abi() {
    unsafe {
        let pair = Pair::new();
        let random = Generator::new(b"endpoints");
        // RFC 7252 §5.2.1: the response in the ACK of a Confirmable request, of its Message ID and token.
        let request = Message::get("/a", CON);
        let handle = pair.client.request(&Peer::server(), request, 0, &random);
        Message::free(request);
        let (sent, _) = pair.run(0);
        let sent = Message::decode(&sent[0]);
        let (event, message) = pair.request();
        assert_eq!(Message::path(message), ["a"]);
        // §5.3.1: a token of at least 32 bits of randomness, of at most 8 bytes.
        let token = Message::token(message);
        assert!((4..=8).contains(&token.len()));
        assert_eq!(token, Message::token(sent));
        Message::free(message);
        let response = Message::make(ACK, CONTENT, 0);
        Message::set_payload(response, b"one");
        Check::ok(pair.server.respond(event.exchange, response, 10 * MILLISECOND, &random));
        let (_, replies) = pair.run(10 * MILLISECOND);
        assert_eq!(replies.len(), 1);
        assert_eq!(Message::header_of(&replies[0]), (ACK, CONTENT, Message::header(sent).2));
        let (event, message) = pair.client.poll_event().expect("a response");
        assert_eq!((event.kind, event.request), (1, handle));
        assert_eq!(
            (Message::header(message).0, Message::payload(message), Message::token(message)),
            (ACK, b"one".to_vec(), token)
        );
        Message::free(message);
        Message::free(sent);
        // A request is answered once.
        Check::fails(
            pair.server.respond(event.exchange, response, 10 * MILLISECOND, &random),
            "protocol.coap",
            "State",
        );
        // §5.2.2: unanswered, an empty ACK, then the response Confirmable, acknowledged by the client.
        let request = Message::get("/b", CON);
        let handle = pair.client.request(&Peer::server(), request, 100 * MILLISECOND, &random);
        Message::free(request);
        let (sent, _) = pair.run(100 * MILLISECOND);
        let id = Message::header_of(&sent[0]).2;
        let (event, message) = pair.request();
        Message::free(message);
        let deadline = pair.server.poll_timeout().expect("the deadline of the ACK");
        pair.server.expire(deadline);
        let (_, replies) = pair.run(deadline);
        assert_eq!(replies.iter().map(|bytes| Message::header_of(bytes)).collect::<Vec<_>>(), [(ACK, EMPTY, id)]);
        assert!(pair.client.poll_event().is_none());
        Check::ok(pair.server.respond(event.exchange, response, 5000 * MILLISECOND, &random));
        let (acknowledgements, replies) = pair.run(5000 * MILLISECOND);
        let (kind, code, separate) = Message::header_of(&replies[0]);
        assert_eq!((kind, code), (CON, CONTENT));
        assert_eq!(
            acknowledgements.iter().map(|bytes| Message::header_of(bytes)).collect::<Vec<_>>(),
            [(ACK, EMPTY, separate)]
        );
        let (event, message) = pair.client.poll_event().expect("a response");
        assert_eq!((event.kind, event.request, Message::header(message).0), (1, handle, CON));
        Message::free(message);
        // §5.2.3: a Non-confirmable request gets a Non-confirmable response.
        let request = Message::get("/c", NON);
        let handle = pair.client.request(&Peer::server(), request, 6000 * MILLISECOND, &random);
        Message::free(request);
        pair.run(6000 * MILLISECOND);
        let (event, message) = pair.request();
        assert_eq!(Message::header(message).0, NON);
        Message::free(message);
        Check::ok(pair.server.respond(event.exchange, response, 6000 * MILLISECOND, &random));
        pair.run(6000 * MILLISECOND);
        let (event, message) = pair.client.poll_event().expect("a response");
        assert_eq!((event.kind, event.request, Message::header(message).0), (1, handle, NON));
        Message::free(message);
        // A request must be a CON or NON message of a method code.
        for (kind, code) in [(ACK, GET), (CON, CONTENT), (CON, EMPTY)] {
            let wrong = Message::make(kind, code, 0);
            let mut handle = 0u64;
            Check::fails(
                umilib_protocol_coap_coap_endpoint_request(
                    pair.client.endpoint,
                    &Peer::server(),
                    wrong,
                    0,
                    random.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                    &mut handle,
                ),
                "protocol.coap",
                "State",
            );
            Message::free(wrong);
        }
        Message::free(response);
    }
}

#[test]
fn coap_retransmissions_through_the_c_abi() {
    unsafe {
        let random = Generator::new(b"retransmissions");
        let client = Endpoint::default(&random);
        let request = Message::get("/a", CON);
        let handle = client.request(&Peer::server(), request, 0, &random);
        Message::free(request);
        let (_, first) = client.transmit().expect("the request");
        // RFC 7252 §4.2, §4.8: a first timeout from ACK_TIMEOUT to ACK_TIMEOUT × ACK_RANDOM_FACTOR
        // (2 to 3 s), doubled at each of MAX_RETRANSMIT (4) retransmissions, then a timeout.
        let mut deadline = client.poll_timeout().expect("a timeout");
        assert!((2000 * MILLISECOND..=3000 * MILLISECOND).contains(&deadline), "{deadline}");
        let initial = deadline;
        for retransmission in 1..=4u32 {
            client.expire(deadline - 1);
            assert!(client.transmit().is_none());
            client.expire(deadline);
            let (peer, again) = client.transmit().expect("a retransmission");
            assert_eq!((peer, again.clone()), (Peer::server(), first.clone()));
            let next = client.poll_timeout().unwrap();
            assert_eq!(next - deadline, initial << retransmission);
            deadline = next;
        }
        assert!(client.events().is_empty());
        client.expire(deadline);
        assert!(client.transmit().is_none());
        assert_eq!(client.events().iter().map(|event| (event.kind, event.message)).collect::<Vec<_>>(), [(2, handle)]);
        // §4.5: a duplicate of a Confirmable request gets the same reply, and is not told again.
        let server = Endpoint::default(&random);
        server.receive(&Peer::client(), &first, 0, &random);
        let (event, message) = server.poll_event().expect("a request");
        Message::free(message);
        let response = Message::make(ACK, CONTENT, 0);
        Check::ok(server.respond(event.exchange, response, 0, &random));
        let (_, reply) = server.transmit().unwrap();
        server.receive(&Peer::client(), &first, 3000 * MILLISECOND, &random);
        assert_eq!(server.transmit().unwrap().1, reply);
        assert!(server.poll_event().is_none());
        // Remembered for EXCHANGE_LIFETIME (247 s), then a message of its own again.
        server.expire(248_000 * MILLISECOND);
        server.receive(&Peer::client(), &first, 248_000 * MILLISECOND, &random);
        assert_eq!(server.events().iter().map(|event| event.kind).collect::<Vec<_>>(), [0]);
        Message::free(response);
        // §4.2: a RST of the request ends it.
        let request = Message::get("/b", CON);
        let handle = client.request(&Peer::server(), request, 0, &random);
        Message::free(request);
        let id = Message::header_of(&client.transmit().unwrap().1).2;
        let mut reset = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_message_empty(RST, id, &mut reset));
        client.receive(&Peer::server(), &Message::encode(reset), 1, &random);
        Message::free(reset);
        assert_eq!(client.events().iter().map(|event| (event.kind, event.message)).collect::<Vec<_>>(), [(3, handle)]);
    }
}

#[test]
fn coap_rejections_through_the_c_abi() {
    unsafe {
        let random = Generator::new(b"rejections");
        let server = Endpoint::default(&random);
        let reply = || Message::header_of(&server.transmit().expect("a reply").1);
        // RFC 7252 §4.3: a ping, an empty Confirmable message, is answered with a RST.
        let mut ping = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_message_empty(CON, 9, &mut ping));
        server.receive(&Peer::client(), &Message::encode(ping), 0, &random);
        Message::free(ping);
        assert_eq!(reply(), (RST, EMPTY, 9));
        // §4.2: a Confirmable message that cannot be read, RST; a Non-confirmable one, nothing (§4.3).
        server.receive(&Peer::client(), &[0x40, 0x01, 0, 10, 0xf0], 0, &random);
        assert_eq!(reply(), (RST, EMPTY, 10));
        server.receive(&Peer::client(), &[0x50, 0x01, 0, 11, 0xf0], 0, &random);
        assert!(server.transmit().is_none());
        // RFC 8974 §2.2.1: a token longer than the endpoint takes is a message format error.
        let long = Message::get("/a", CON);
        Check::ok(umilib_protocol_coap_coap_message_set_id(long, 12));
        Message::set_token(long, &[1; 9]);
        server.receive(&Peer::client(), &Message::encode(long), 0, &random);
        Message::free(long);
        assert_eq!(reply(), (RST, EMPTY, 12));
        // §5.4.1: an unrecognized critical option in a Confirmable request: 4.02 Bad Option, piggybacked.
        let unknown = Message::get("/a", CON);
        Check::ok(umilib_protocol_coap_coap_message_set_id(unknown, 13));
        Message::change_options(unknown, |options| {
            Check::ok(umilib_protocol_coap_coap_options_push(options, 9, [1u8].as_ptr(), 1));
        });
        server.receive(&Peer::client(), &Message::encode(unknown), 0, &random);
        Message::free(unknown);
        assert_eq!(reply(), (ACK, BAD_OPTION, 13));
        assert!(server.poll_event().is_none());
        // An endpoint that takes longer tokens (RFC 8974 §2.2.1) is told of the request.
        let mut config = FFICoAPConfig::default();
        Check::ok(umilib_protocol_coap_coap_config_default(&mut config));
        assert_eq!(
            (config.ack_timeout, config.ack_random_factor, config.max_retransmit, config.nstart),
            (2000, 1500, 4, 1)
        );
        assert_eq!((config.exchange_lifetime, config.non_lifetime), (247_000, 145_000));
        config.maximum_token = 16;
        let extended = Endpoint::new(&config, &random);
        let long = Message::get("/a", CON);
        Message::set_token(long, &[1; 9]);
        extended.receive(&Peer::client(), &Message::encode(long), 0, &random);
        Message::free(long);
        let events = extended.events();
        assert_eq!(events.iter().map(|event| event.kind).collect::<Vec<_>>(), [0]);
        // RFC 7967 §2: a request not answered; a Confirmable one is acknowledged by an empty ACK (§4.2).
        Check::ok(umilib_protocol_coap_coap_endpoint_ignore(extended.endpoint, events[0].exchange));
        let (kind, code, _) = Message::header_of(&extended.transmit().unwrap().1);
        assert_eq!((kind, code), (ACK, EMPTY));
        assert!(extended.transmit().is_none());
        Check::fails(
            umilib_protocol_coap_coap_endpoint_ignore(extended.endpoint, events[0].exchange),
            "protocol.coap",
            "State",
        );
        // §5.3.2: a Confirmable response that matches no request is rejected.
        let client = Endpoint::default(&random);
        let stray = Message::make(CON, CONTENT, 14);
        Message::set_token(stray, &[5]);
        client.receive(&Peer::server(), &Message::encode(stray), 0, &random);
        Message::free(stray);
        assert_eq!(Message::header_of(&client.transmit().unwrap().1), (RST, EMPTY, 14));
        // A configuration that cannot work, and a generator of no known type.
        let changes: [fn(&mut FFICoAPConfig); 3] = [
            |config: &mut FFICoAPConfig| config.ack_timeout = 0,
            |config: &mut FFICoAPConfig| config.ack_random_factor = 999,
            |config: &mut FFICoAPConfig| config.nstart = 0,
        ];
        for change in changes {
            let mut bad = config;
            change(&mut bad);
            let mut endpoint = ptr::null_mut();
            Check::fails(
                umilib_protocol_coap_coap_endpoint_new(
                    &bad,
                    random.handle(),
                    Generator::TYPE.as_ptr(),
                    Generator::TYPE.len(),
                    &mut endpoint,
                ),
                "protocol.coap",
                "Config",
            );
            assert!(endpoint.is_null());
        }
        let mut endpoint = ptr::null_mut();
        Check::fails(
            umilib_protocol_coap_coap_endpoint_new(&config, random.handle(), b"other".as_ptr(), 5, &mut endpoint),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            umilib_protocol_coap_coap_endpoint_new(
                &config,
                ptr::null_mut(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut endpoint,
            ),
            "ffi",
            "NullPointer",
        );
        let response = Message::make(ACK, CONTENT, 0);
        Check::fails(server.respond(77, response, 0, &random), "protocol.coap", "State");
        Message::free(response);
        umilib_protocol_coap_coap_endpoint_free(ptr::null_mut());
    }
}

#[test]
fn coap_nstart_through_the_c_abi() {
    // RFC 7252 §4.7: one outstanding interaction with a peer (NSTART 1); the next waits.
    let pair = Pair::new();
    let random = Generator::new(b"nstart");
    for path in ["/a", "/b"] {
        let request = Message::get(path, CON);
        pair.client.request(&Peer::server(), request, 0, &random);
        Message::free(request);
    }
    let (sent, _) = pair.run(0);
    assert_eq!(sent.len(), 1);
    let (event, message) = pair.request();
    assert_eq!(Message::path(message), ["a"]);
    Message::free(message);
    let response = Message::make(ACK, CONTENT, 0);
    Check::ok(pair.server.respond(event.exchange, response, MILLISECOND, &random));
    Message::free(response);
    pair.run(MILLISECOND);
    let (_, message) = pair.request();
    assert_eq!(Message::path(message), ["b"]);
    Message::free(message);
}

#[test]
fn coap_observations_through_the_c_abi() {
    unsafe {
        let pair = Pair::new();
        let random = Generator::new(b"observations");
        let mut observers: *mut CoAPObservers = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_observers_new(&mut observers));
        // RFC 7641 §4.5: a Confirmable notification at least every 24 hours.
        let (mut interval, mut maximum) = (0u64, 0usize);
        Check::ok(umilib_protocol_coap_coap_observers_confirm_interval(observers, &mut interval));
        Check::ok(umilib_protocol_coap_coap_observers_maximum(observers, &mut maximum));
        assert!(interval <= 86_400_000 && maximum > 0);
        // §3.1, §4.1: a GET with Observe 0 registers; the response carries Observe.
        let request = Message::get("/temp", CON);
        Message::set_uint(request, OBSERVE, 0);
        let handle = pair.client.request(&Peer::server(), request, 0, &random);
        Message::free(request);
        pair.run(0);
        let (event, message) = pair.request();
        let mut observing = false;
        Check::ok(umilib_protocol_coap_coap_observers_register(observers, &event.peer, message, 0, &mut observing));
        assert!(observing);
        let token = Message::token(message);
        Message::free(message);
        let (mut count, mut peer, mut buffer) = (0usize, FFIIPEndpoint::default(), Buffer::EMPTY);
        Check::ok(umilib_protocol_coap_coap_observers_count(observers, &mut count));
        Check::ok(umilib_protocol_coap_coap_observers_observer(observers, 0, &mut peer, &mut buffer));
        assert_eq!((count, peer, Message::take(&mut buffer)), (1, Peer::client(), token.clone()));
        let mut value = 0u32;
        Check::ok(umilib_protocol_coap_coap_observers_next_value(observers, &mut value));
        let response = Message::make(ACK, CONTENT, 0);
        Message::set_uint(response, OBSERVE, value);
        Message::set_payload(response, b"20");
        Check::ok(pair.server.respond(event.exchange, response, 0, &random));
        pair.run(0);
        let (event, message) = pair.client.poll_event().expect("the response");
        assert_eq!((event.kind, event.request, Message::uint(message, OBSERVE)), (1, handle, Some(value)));
        Message::free(message);
        // §4.2, §4.4: notifications of the observer's token and of Observe values strictly increasing.
        let path = [CString::new("temp").unwrap()];
        let segments = [path[0].as_ptr()];
        let mut previous = value;
        for payload in [&b"21"[..], b"22"] {
            Message::set_payload(response, payload);
            Check::ok(umilib_protocol_coap_coap_observers_notify(
                observers,
                pair.server.endpoint,
                segments.as_ptr().cast(),
                1,
                response,
                false,
                1000 * MILLISECOND,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let (_, notifications) = pair.run(1000 * MILLISECOND);
            let notification = Message::decode(&notifications[0]);
            assert_eq!(Message::token(notification), token);
            let observe = Message::uint(notification, OBSERVE).expect("Observe");
            assert!(observe > previous && observe < 1 << 24);
            previous = observe;
            Message::free(notification);
            let (event, message) = pair.client.poll_event().expect("a notification");
            assert_eq!((event.kind, event.request, Message::payload(message)), (1, handle, payload.to_vec()));
            Message::free(message);
        }
        // §3.4: the order of notifications, of 24-bit serial numbers or 128 seconds apart.
        for (freshest, at, value, now, fresher) in [
            (1u32, 0u64, 2u32, 0u64, true),
            (2, 0, 1, 0, false),
            (0xff_ffff, 0, 1, 0, true),
            (1, 0, 1 + (1 << 23), 0, false),
            (2, 0, 1, 128_001 * MILLISECOND, true),
            (2, 0, 1, 128_000 * MILLISECOND, false),
        ] {
            let mut out = false;
            Check::ok(umilib_protocol_coap_coap_endpoint_is_fresher(freshest, at, value, now, &mut out));
            assert_eq!(out, fresher, "{freshest} {value} {now}");
        }
        // §3.6: a client that forgets the observation rejects the next notification, which ends it.
        Check::ok(umilib_protocol_coap_coap_endpoint_cancel(pair.client.endpoint, handle, 3000 * MILLISECOND));
        Check::ok(umilib_protocol_coap_coap_observers_notify(
            observers,
            pair.server.endpoint,
            segments.as_ptr().cast(),
            1,
            response,
            false,
            3000 * MILLISECOND,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
        ));
        let (resets, _) = pair.run(3000 * MILLISECOND);
        assert_eq!(Message::header_of(&resets[0]).0, RST);
        assert!(pair.client.poll_event().is_none());
        let mut ended = false;
        for event in pair.server.events() {
            let mut handled = false;
            Check::ok(umilib_protocol_coap_coap_observers_handle(observers, &event, &mut handled));
            ended |= handled && event.kind == 3;
        }
        Check::ok(umilib_protocol_coap_coap_observers_count(observers, &mut count));
        assert!(ended && count == 0);
        let wrong = FFICoAPEvent { kind: 4, ..FFICoAPEvent::default() };
        Check::fails(
            umilib_protocol_coap_coap_observers_handle(observers, &wrong, &mut ended),
            "ffi",
            "InvalidArgument",
        );
        // §3.6: a GET with Observe 1 deregisters; a POST does not observe.
        let request = Message::get("/temp", CON);
        Message::set_token(request, &[1]);
        Message::set_uint(request, OBSERVE, 0);
        Check::ok(umilib_protocol_coap_coap_observers_register(observers, &Peer::client(), request, 0, &mut observing));
        assert!(observing);
        Message::set_uint(request, OBSERVE, 1);
        Check::ok(umilib_protocol_coap_coap_observers_register(observers, &Peer::client(), request, 0, &mut observing));
        Check::ok(umilib_protocol_coap_coap_observers_count(observers, &mut count));
        assert_eq!((observing, count), (false, 0));
        Message::set_uint(request, OBSERVE, 0);
        Check::ok(umilib_protocol_coap_coap_message_set_code(request, POST));
        Check::ok(umilib_protocol_coap_coap_observers_register(observers, &Peer::client(), request, 0, &mut observing));
        assert!(!observing);
        // §4.2: a notification of an error has no Observe and ends the observations.
        Check::ok(umilib_protocol_coap_coap_message_set_code(request, GET));
        Check::ok(umilib_protocol_coap_coap_observers_register(observers, &Peer::client(), request, 0, &mut observing));
        let error = Message::make(NON, NOT_FOUND, 0);
        Check::ok(umilib_protocol_coap_coap_observers_notify(
            observers,
            pair.server.endpoint,
            segments.as_ptr().cast(),
            1,
            error,
            false,
            4000 * MILLISECOND,
            random.handle(),
            Generator::TYPE.as_ptr(),
            Generator::TYPE.len(),
        ));
        let (_, sent) = pair.server.transmit().expect("the notification");
        let notification = Message::decode(&sent);
        assert_eq!((Message::header(notification).1, Message::uint(notification, OBSERVE)), (NOT_FOUND, None));
        Message::free(notification);
        Check::ok(umilib_protocol_coap_coap_observers_count(observers, &mut count));
        assert_eq!(count, 0);
        // §4.5: a notification is Confirmable once the interval passed since the last Confirmable one.
        Check::ok(umilib_protocol_coap_coap_observers_set_confirm_interval(observers, 60_000));
        Check::ok(umilib_protocol_coap_coap_observers_register(observers, &Peer::client(), request, 0, &mut observing));
        Message::set_uint(response, OBSERVE, 0);
        for (now, kind) in [(1000u64, NON), (60_000, CON)] {
            Check::ok(umilib_protocol_coap_coap_observers_notify(
                observers,
                pair.server.endpoint,
                segments.as_ptr().cast(),
                1,
                response,
                false,
                now * MILLISECOND,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
            ));
            let (_, sent) = pair.server.transmit().expect("the notification");
            assert_eq!(Message::header_of(&sent).0, kind, "{now}");
        }
        // A notification needs Observe and a response code.
        let mut notification = 0u64;
        Check::fails(
            umilib_protocol_coap_coap_endpoint_notify(
                pair.server.endpoint,
                &Peer::client(),
                error,
                0,
                random.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                &mut notification,
            ),
            "protocol.coap",
            "State",
        );
        Check::ok(umilib_protocol_coap_coap_observers_set_maximum(observers, 0));
        Check::ok(umilib_protocol_coap_coap_observers_register(observers, &Peer::server(), request, 0, &mut observing));
        assert!(!observing);
        Message::free(error);
        Message::free(request);
        Message::free(response);
        umilib_protocol_coap_coap_observers_free(observers);
    }
}

#[test]
fn coap_links_through_the_c_abi() {
    unsafe {
        // RFC 6690 §5: the links of a resource directory, with an anchor and a title.
        let text = "</sensors>;ct=40;title=\"Sensor Index\",</sensors/temp>;rt=\"temperature-c\";if=\"sensor\",\
                    </sensors/light>;rt=\"light-lux\";if=\"sensor\",\
                    <http://www.example.com/sensors/t123>;anchor=\"/sensors/temp\";rel=\"describedby\",\
                    </t>;anchor=\"/sensors/temp\";rel=\"alternate\"";
        let mut links: *mut Vec<CoAPLink> = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_link_parse(text.as_ptr(), text.len(), &mut links));
        let mut count = 0usize;
        Check::ok(umilib_protocol_coap_coap_links_count(links, &mut count));
        assert_eq!(count, 5);
        let link = |index: usize| {
            let mut link = ptr::null_mut();
            Check::ok(umilib_protocol_coap_coap_links_get(links, index, &mut link));
            link
        };
        let target = |link: *const CoAPLink| {
            let mut buffer = Buffer::EMPTY;
            Check::ok(umilib_protocol_coap_coap_link_target(link, &mut buffer));
            String::from_utf8(Message::take(&mut buffer)).unwrap()
        };
        let attribute = |link: *const CoAPLink, name: &str| {
            let (mut found, mut has_value, mut buffer) = (false, false, Buffer::EMPTY);
            Check::ok(umilib_protocol_coap_coap_link_attribute(
                link,
                name.as_ptr(),
                name.len(),
                &mut found,
                &mut has_value,
                &mut buffer,
            ));
            let value = String::from_utf8(Message::take(&mut buffer)).unwrap();
            found.then_some(has_value.then_some(value))
        };
        let first = link(0);
        assert_eq!(target(first), "/sensors");
        assert_eq!(attribute(first, "ct"), Some(Some("40".to_string())));
        assert_eq!(attribute(first, "TITLE"), Some(Some("Sensor Index".to_string())));
        assert_eq!(attribute(first, "rt"), None);
        let fourth = link(3);
        assert_eq!(target(fourth), "http://www.example.com/sensors/t123");
        assert_eq!(attribute(fourth, "anchor"), Some(Some("/sensors/temp".to_string())));
        assert_eq!(attribute(fourth, "rel"), Some(Some("describedby".to_string())));
        // The text of the links reads back as the same links.
        let mut buffer = Buffer::EMPTY;
        Check::ok(umilib_protocol_coap_coap_link_format(links, &mut buffer));
        let formatted = String::from_utf8(Message::take(&mut buffer)).unwrap();
        assert!(formatted.starts_with("</sensors>;ct=40;title=\"Sensor Index\","), "{formatted}");
        let mut again: *mut Vec<CoAPLink> = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_link_parse(formatted.as_ptr(), formatted.len(), &mut again));
        assert_eq!(*again, *links);
        umilib_protocol_coap_coap_links_free(again);
        // Links made by hand: attributes without values, quoted values with escapes (RFC 6690 §2).
        let mut made: *mut CoAPLink = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_link_new("/a".as_ptr(), 2, &mut made));
        Check::ok(umilib_protocol_coap_coap_link_with(made, "obs".as_ptr(), 3, ptr::null(), 0));
        Check::ok(umilib_protocol_coap_coap_link_with(made, "title".as_ptr(), 5, "x\"y".as_ptr(), 3));
        let mut list: *mut Vec<CoAPLink> = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_links_new(&mut list));
        Check::ok(umilib_protocol_coap_coap_links_push(list, made));
        let mut other = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_link_new("/b".as_ptr(), 2, &mut other));
        Check::ok(umilib_protocol_coap_coap_links_push(list, other));
        Check::ok(umilib_protocol_coap_coap_link_format(list, &mut buffer));
        assert_eq!(Message::take(&mut buffer), b"</a>;obs;title=\"x\\\"y\",</b>");
        assert_eq!(attribute(made, "obs"), Some(None));
        let mut attributes = 0usize;
        Check::ok(umilib_protocol_coap_coap_link_attribute_count(made, &mut attributes));
        let (mut name, mut has_value, mut value) = (Buffer::EMPTY, false, Buffer::EMPTY);
        Check::ok(umilib_protocol_coap_coap_link_attribute_entry(made, 1, &mut name, &mut has_value, &mut value));
        assert_eq!(
            (attributes, Message::take(&mut name), has_value, Message::take(&mut value)),
            (2, b"title".to_vec(), true, b"x\"y".to_vec())
        );
        Check::fails(
            umilib_protocol_coap_coap_link_attribute_entry(made, 2, &mut name, &mut has_value, &mut value),
            "ffi",
            "InvalidArgument",
        );
        let mut copy = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_link_clone(made, &mut copy));
        assert_eq!(*copy, *made);
        umilib_protocol_coap_coap_link_free(copy);
        // Text that is not of the link format.
        for malformed in ["/a", "</a", "</a>;", "</a>;=1", "</a>x", "</a>;t=\"open"] {
            let mut out = ptr::null_mut();
            Check::fails(
                umilib_protocol_coap_coap_link_parse(malformed.as_ptr(), malformed.len(), &mut out),
                "protocol.coap",
                "Malformed",
            );
        }
        let invalid = [b'<', 0xff, b'>'];
        Check::fails(umilib_protocol_coap_coap_link_parse(invalid.as_ptr(), 3, &mut again), "ffi", "InvalidUTF8");
        for link in [first, fourth, made, other] {
            umilib_protocol_coap_coap_link_free(link);
        }
        umilib_protocol_coap_coap_links_free(list);
        umilib_protocol_coap_coap_links_free(links);
    }
}

#[test]
fn coap_rules_through_the_c_abi() {
    unsafe {
        let mut rule: *mut CoAPRule = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_rule_new("/sensors".as_ptr(), 8, &mut rule));
        Check::ok(umilib_protocol_coap_coap_rule_with_method(rule, GET));
        let matches = |rule: *const CoAPRule, message: *mut CoAPMessage| {
            let mut out = false;
            Check::ok(umilib_protocol_coap_coap_rule_matches(rule, message, &mut out));
            Message::free(message);
            out
        };
        assert!(matches(rule, Message::get("/sensors/temp", CON)));
        assert!(matches(rule, Message::get("/sensors", NON)));
        assert!(!matches(rule, Message::get("/sensorsx", CON)));
        assert!(!matches(rule, Message::get("/other", CON)));
        let post = Message::get("/sensors", CON);
        Check::ok(umilib_protocol_coap_coap_message_set_code(post, POST));
        assert!(!matches(rule, post));
        // Responses are not routed.
        let mut root = ptr::null_mut();
        Check::ok(umilib_protocol_coap_coap_rule_new("/".as_ptr(), 1, &mut root));
        assert!(!matches(root, Message::make(CON, CONTENT, 0)));
        assert!(matches(root, Message::get("/anything", CON)));
        umilib_protocol_coap_coap_rule_free(root);
        umilib_protocol_coap_coap_rule_free(rule);
    }
}
