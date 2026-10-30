//! Fuzz targets of the operating system layers of `umilib::platform`.

use umilib::platform::fuzz::FuzzTarget;

/// Socket addresses of the system's form converted to std ones convert back to the same.
#[cfg(all(
    umilib_feature = "platform-native",
    any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
))]
pub const ADDRESSES: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("platform-addresses", |data| {
        use umilib::platform::native::RawSocketAddress;
        let mut raw = RawSocketAddress::empty();
        let length = data.len().min(raw.bytes.len());
        raw.bytes[..length].copy_from_slice(&data[..length]);
        if let Some(address) = raw.to_std() {
            assert_eq!(RawSocketAddress::from_std(&address).to_std(), Some(address));
            // Its text (which has no flow label) parses back to its IP and port.
            let parsed: std::net::SocketAddr = address.to_string().parse().expect("the text of an address parses");
            assert_eq!((parsed.ip(), parsed.port()), (address.ip(), address.port()));
        }
    });

/// Handshakes of a supervisor decode without panicking, and one that decodes
/// encodes back to the bytes it was read from.
#[cfg(all(
    umilib_feature = "platform-runtime",
    any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
))]
pub const HANDSHAKES: umilib::platform::fuzz::FuzzFunction<fn(&[u8])> =
    umilib::platform::fuzz::FuzzFunction::new("platform-runtime-handshakes", |data| {
        use umilib::platform::runtime::WorkerHandshake;
        let mut reader = data;
        if let Ok(handshake) = WorkerHandshake::decode(&mut reader) {
            let consumed = data.len() - reader.len();
            assert_eq!(handshake.encode(), &data[..consumed]);
            assert!(handshake.listeners.len() <= WorkerHandshake::MAXIMUM_LISTENERS);
        }
    });

pub const TARGETS: &[&dyn FuzzTarget] = &[
    #[cfg(all(
        umilib_feature = "platform-native",
        any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
    ))]
    &ADDRESSES,
    #[cfg(all(
        umilib_feature = "platform-runtime",
        any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)
    ))]
    &HANDSHAKES,
];
