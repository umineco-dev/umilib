//! A TLS client and server over TCP, to try umilib's TLS against other
//! implementations (`examples/tls.sh` runs it against OpenSSL and curl).
//!
//! ```text
//! tls client HOST PORT [--name NAME] [--version 1.2|1.3] [--groups x25519,p256,...] [--alpn h2,http/1.1]
//!                      [--ca FILE | --insecure] [--cert FILE --key FILE] [--ech BASE64] [--ocsp]
//!                      [--connections N] [--early TEXT] [--send TEXT] [--key-update] [--post-handshake-auth]
//! tls server PORT --cert FILE --key FILE [--version 1.2|1.3] [--groups ...] [--alpn ...] [--client-ca FILE]
//!                      [--require-certificate] [--tickets] [--early-data BYTES] [--ech PUBLIC_NAME]
//!                      [--connections N] [--http] [--request-certificate] [--ocsp-response FILE]
//! ```
//!
//! Each connection prints what was negotiated, one `key: value` per line.
//! It needs the operating system's random source: Linux, Android, the Apple
//! platforms and Windows.
#![cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)),
    allow(unused_imports, dead_code)
)]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use umilib::auth::cert::key::{KeyLimits, PrivateKey};
use umilib::auth::cert::path::{ServiceIdentity, TrustAnchor};
use umilib::auth::cert::x509::Certificate;
use umilib::codec::base::Encoding;
use umilib::codec::base::base64::Base64;
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
use umilib::platform::native::Random;
use umilib::protocol::tls::{
    TLSAlertDescription, TLSCertificateVerifier, TLSCertifiedKey, TLSClientAuthentication, TLSClientConfig, TLSConfig,
    TLSConnection, TLSECHCipher, TLSECHCipherSuite, TLSECHConfig, TLSError, TLSEvent, TLSNamedGroup, TLSPathVerifier,
    TLSReplayCache, TLSServerConfig, TLSSessionCache, TLSTicketKey, TLSTicketKeys, TLSVersion,
};

/// The command line: positional arguments and `--name value` options.
pub struct Arguments {
    pub positional: Vec<String>,
    pub options: Vec<(String, Option<String>)>,
}

impl Arguments {
    /// The options that take no value.
    pub const FLAGS: [&'static str; 10] = [
        "--insecure",
        "--ocsp",
        "--key-update",
        "--post-handshake-auth",
        "--require-certificate",
        "--tickets",
        "--http",
        "--request-certificate",
        "--ech-grease",
        "--quiet",
    ];

    pub fn parse() -> Arguments {
        let mut positional = Vec::new();
        let mut options = Vec::new();
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            if !argument.starts_with("--") {
                positional.push(argument);
            } else if Arguments::FLAGS.contains(&argument.as_str()) {
                options.push((argument, None));
            } else {
                let value = arguments.next().unwrap_or_else(|| Tool::fail(&format!("{argument} needs a value")));
                options.push((argument, Some(value)));
            }
        }
        Arguments { positional, options }
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|(option, _)| option == name).and_then(|(_, value)| value.as_deref())
    }

    pub fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(option, _)| option == name)
    }

    pub fn number(&self, name: &str, default: usize) -> usize {
        self.get(name)
            .map_or(default, |value| value.parse().unwrap_or_else(|_| Tool::fail(&format!("{name}: a number"))))
    }
}

/// A verifier that accepts any chain, for `--insecure`.
pub struct AnyCertificate;

impl TLSCertificateVerifier for AnyCertificate {
    fn verify(
        &self,
        _chain: &[Vec<u8>],
        _identity: Option<&ServiceIdentity>,
        _ocsp: Option<&[u8]>,
        _time: i64,
    ) -> Result<(), TLSAlertDescription> {
        Ok(())
    }
}

pub struct Tool;

impl Tool {
    pub fn fail(message: &str) -> ! {
        eprintln!("error: {message}");
        std::process::exit(2)
    }

    pub fn now() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs() as i64)
    }

    pub fn read(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|error| Tool::fail(&format!("{path}: {error}")))
    }

    /// The configuration both ends share, from the options.
    pub fn config(arguments: &Arguments) -> TLSConfig {
        let mut config = TLSConfig::default();
        if let Some(version) = arguments.get("--version") {
            config.versions = vec![match version {
                "1.2" => TLSVersion::TLS1_2,
                "1.3" => TLSVersion::TLS1_3,
                _ => Tool::fail("--version: 1.2 or 1.3"),
            }];
        }
        if let Some(groups) = arguments.get("--groups") {
            config.groups = groups.split(',').map(Tool::group).collect();
        }
        if let Some(protocols) = arguments.get("--alpn") {
            config.protocols = protocols.split(',').map(|protocol| protocol.as_bytes().to_vec()).collect();
        }
        config
    }

    pub fn group(name: &str) -> TLSNamedGroup {
        match name {
            "x25519" => TLSNamedGroup::X25519,
            "x448" => TLSNamedGroup::X448,
            "p256" => TLSNamedGroup::SECP256R1,
            "p384" => TLSNamedGroup::SECP384R1,
            "p521" => TLSNamedGroup::SECP521R1,
            "ffdhe2048" => TLSNamedGroup::FFDHE2048,
            "x25519mlkem768" => TLSNamedGroup::X25519_MLKEM768,
            "p256mlkem768" => TLSNamedGroup::SECP256R1_MLKEM768,
            "p384mlkem1024" => TLSNamedGroup::SECP384R1_MLKEM1024,
            _ => Tool::fail(&format!("unknown group {name}")),
        }
    }

    pub fn anchors(path: &str) -> Vec<TrustAnchor> {
        Certificate::from_pem_all(&Tool::read(path))
            .unwrap_or_else(|error| Tool::fail(&format!("{path}: {error:?}")))
            .into_iter()
            .map(|certificate| TrustAnchor::from_certificate(certificate, &KeyLimits::default()).expect("an anchor"))
            .collect()
    }

    pub fn certified(arguments: &Arguments) -> Option<TLSCertifiedKey> {
        let (certificate, key) = (arguments.get("--cert")?, arguments.get("--key")?);
        let chain = Certificate::from_pem_all(&Tool::read(certificate))
            .unwrap_or_else(|error| Tool::fail(&format!("{certificate}: {error:?}")))
            .iter()
            .map(|certificate| certificate.to_der().expect("a certificate writes"))
            .collect();
        let key =
            PrivateKey::from_pem(&Tool::read(key)).unwrap_or_else(|error| Tool::fail(&format!("{key}: {error:?}")));
        let ocsp = arguments.get("--ocsp-response").map(|path| std::fs::read(path).expect("the OCSP response"));
        Some(TLSCertifiedKey { chain, key, ocsp })
    }

    /// Moves bytes between `connection` and `stream` until `done` holds,
    /// the peer closes, or nothing moves for `idle`.
    pub fn pump(
        connection: &mut TLSConnection,
        stream: &mut TcpStream,
        idle: Duration,
        mut done: impl FnMut(&mut TLSConnection) -> bool,
    ) -> Result<(), TLSError> {
        stream.set_read_timeout(Some(Duration::from_millis(50))).expect("a timeout");
        let mut last = Instant::now();
        let mut buffer = vec![0u8; 1 << 16];
        loop {
            let mut out = Vec::new();
            connection.transmit(&mut out)?;
            if !out.is_empty() {
                stream.write_all(&out).map_err(|_| TLSError::State)?;
            }
            if done(connection) {
                return Ok(());
            }
            match stream.read(&mut buffer) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    last = Instant::now();
                    let result = connection.receive(&buffer[..count]);
                    let mut out = Vec::new();
                    connection.transmit(&mut out)?;
                    let _ = stream.write_all(&out);
                    result?;
                }
                Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if last.elapsed() > idle {
                        return Ok(());
                    }
                }
                Err(_) => return Ok(()),
            }
        }
    }

    pub fn report(connection: &TLSConnection, quiet: bool) {
        if quiet {
            return;
        }
        let session = &connection.session;
        println!("version: {:?}", session.version.map(|version| version.0));
        println!("cipher_suite: {:04x}", session.cipher_suite.map_or(0, |suite| suite.0));
        println!("group: {:04x}", session.group.map_or(0, |group| group.0));
        println!("signature_scheme: {:04x}", session.peer_signature_scheme.map_or(0, |scheme| scheme.0));
        println!(
            "protocol: {}",
            session
                .protocol
                .as_deref()
                .map_or(String::from("-"), |protocol| String::from_utf8_lossy(protocol).into_owned())
        );
        println!("server_name: {}", session.server_name.as_deref().unwrap_or("-"));
        println!("peer_certificates: {}", session.peer_certificates.len());
        println!("certificate_status: {}", session.certificate_status.as_ref().map_or(0, Vec::len));
        println!("resumed: {}", session.resumed);
        println!("early_data: {:?}", session.early_data);
        println!("ech: {:?}", session.ech);
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
    pub fn client(arguments: &Arguments) {
        let host = arguments.positional.get(1).unwrap_or_else(|| Tool::fail("client HOST PORT"));
        let port = arguments.positional.get(2).unwrap_or_else(|| Tool::fail("client HOST PORT"));
        let name = arguments.get("--name").unwrap_or(host).to_string();
        let verifier: Arc<dyn TLSCertificateVerifier> = match arguments.get("--ca") {
            Some(path) => Arc::new(TLSPathVerifier::servers(Tool::anchors(path))),
            None if arguments.flag("--insecure") => Arc::new(AnyCertificate),
            None => Tool::fail("--ca FILE or --insecure"),
        };
        let mut config = TLSClientConfig::new(verifier);
        config.config = Tool::config(arguments);
        config.key_share_groups = TLSClientConfig::default_key_shares(&config.config.groups);
        config.certificate = Tool::certified(arguments).map(Arc::new);
        config.request_certificate_status = arguments.flag("--ocsp");
        config.post_handshake_authentication = arguments.flag("--post-handshake-auth");
        config.ech_grease = arguments.flag("--ech-grease");
        config.sessions = Some(Arc::new(TLSSessionCache::new(8)));
        config.early_data = arguments.get("--early").is_some();
        if let Some(list) = arguments.get("--ech") {
            let list = Base64::STANDARD.decode(list.as_bytes()).unwrap_or_else(|_| Tool::fail("--ech: base64"));
            config.ech_configs =
                TLSECHConfig::decode_list(&list).unwrap_or_else(|_| Tool::fail("--ech: an ECHConfigList"));
        }
        let config = Arc::new(config);
        let mut failed = false;
        for index in 0..arguments.number("--connections", 1) {
            let mut stream = TcpStream::connect(format!("{host}:{port}"))
                .unwrap_or_else(|error| Tool::fail(&format!("connect: {error}")));
            let mut connection = TLSConnection::client(config.clone(), Some(&name), Box::new(Random), Tool::now())
                .unwrap_or_else(|error| Tool::fail(&format!("{error:?}")));
            if index > 0
                && let Some(early) = arguments.get("--early")
                && connection.send(early.as_bytes()).is_ok()
            {
                println!("early_data_sent: {}", early.len());
            }
            let result = Tool::pump(&mut connection, &mut stream, Duration::from_secs(5), |connection| {
                !connection.is_handshaking()
            });
            println!("connection: {index}");
            Tool::report(&connection, arguments.flag("--quiet"));
            if let Err(error) =
                result.and_then(|_| if connection.is_handshaking() { Err(TLSError::State) } else { Ok(()) })
            {
                println!("error: {error:?}");
                failed = true;
                continue;
            }
            if arguments.flag("--key-update") {
                connection.update_keys(true).expect("a key update");
            }
            let request = arguments.get("--send").map_or_else(
                || format!("GET / HTTP/1.0\r\nHost: {name}\r\n\r\n"),
                |text| text.replace("\\n", "\n").replace("\\r", "\r"),
            );
            connection.send(request.as_bytes()).expect("data goes out");
            let mut received = Vec::new();
            let result = Tool::pump(&mut connection, &mut stream, Duration::from_secs(2), |connection| {
                let mut chunk = [0u8; 4096];
                loop {
                    let count = connection.read(&mut chunk);
                    if count == 0 {
                        break;
                    }
                    received.extend_from_slice(&chunk[..count]);
                }
                std::iter::from_fn(|| connection.poll_event()).any(|event| event == TLSEvent::PeerClosed)
            });
            println!("received: {}", received.len());
            println!("response: {}", String::from_utf8_lossy(&received).lines().next().unwrap_or(""));
            if let Err(error) = result {
                println!("error: {error:?}");
                failed = true;
            }
            let _ = connection.close();
            let mut out = Vec::new();
            let _ = connection.transmit(&mut out);
            let _ = stream.write_all(&out);
        }
        std::process::exit(i32::from(failed));
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
    pub fn server(arguments: &Arguments) {
        let port = arguments.positional.get(1).unwrap_or_else(|| Tool::fail("server PORT"));
        let key = Tool::certified(arguments).unwrap_or_else(|| Tool::fail("--cert FILE --key FILE"));
        let mut config = TLSServerConfig::new(vec![Arc::new(key)]);
        config.config = Tool::config(arguments);
        if let Some(path) = arguments.get("--client-ca") {
            config.client_verifier = Some(Arc::new(TLSPathVerifier::clients(Tool::anchors(path))));
            config.client_authentication = if arguments.flag("--require-certificate") {
                TLSClientAuthentication::Required
            } else {
                TLSClientAuthentication::Optional
            };
        }
        if arguments.flag("--tickets") {
            let key = TLSTicketKey::generate(&mut Random).expect("a ticket key");
            config.tickets = Some(Arc::new(TLSTicketKeys::new(vec![key])));
        }
        if let Some(bytes) = arguments.get("--early-data") {
            config.maximum_early_data = bytes.parse().unwrap_or_else(|_| Tool::fail("--early-data BYTES"));
            config.anti_replay = Some(Arc::new(TLSReplayCache::new(10, 1024)));
        }
        if let Some(public_name) = arguments.get("--ech") {
            let template = TLSECHConfig {
                config_id: 1,
                kem_id: TLSECHConfig::DHKEM_X25519,
                public_key: Vec::new(),
                cipher_suites: vec![TLSECHCipherSuite::MANDATORY],
                maximum_name_length: 64,
                public_name: public_name.as_bytes().to_vec(),
                extensions: Vec::new(),
            };
            let key = TLSECHCipher::generate(template, true, &mut Random).expect("an ECH key");
            let mut list = Vec::new();
            TLSECHConfig::encode_list(std::slice::from_ref(&key.config), &mut list).expect("a list");
            println!("ech_config_list: {}", Base64::STANDARD.encode(&list));
            config.ech_keys = vec![key];
        }
        let config = Arc::new(config);
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .unwrap_or_else(|error| Tool::fail(&format!("bind: {error}")));
        println!("listening: {port}");
        let _ = std::io::stdout().flush();
        for index in 0..arguments.number("--connections", 1) {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut connection =
                TLSConnection::server(config.clone(), Box::new(Random), Tool::now()).expect("a server");
            let mut early = Vec::new();
            let result = Tool::pump(&mut connection, &mut stream, Duration::from_secs(5), |connection| {
                let mut chunk = [0u8; 4096];
                let count = connection.read(&mut chunk);
                early.extend_from_slice(&chunk[..count]);
                !connection.is_handshaking()
            });
            println!("connection: {index}");
            Tool::report(&connection, arguments.flag("--quiet"));
            if let Err(error) =
                result.and_then(|_| if connection.is_handshaking() { Err(TLSError::State) } else { Ok(()) })
            {
                println!("error: {error:?}");
                let _ = std::io::stdout().flush();
                continue;
            }
            if !early.is_empty() {
                println!("early_data_received: {}", String::from_utf8_lossy(&early));
            }
            if arguments.flag("--request-certificate") {
                connection.request_certificate().expect("a certificate request");
                let _ = Tool::pump(&mut connection, &mut stream, Duration::from_secs(5), |connection| {
                    std::iter::from_fn(|| connection.poll_event()).any(|event| event == TLSEvent::Authenticated)
                });
                println!("authenticated: {}", connection.session.peer_certificates.len());
            }
            let mut received = early;
            let http = arguments.flag("--http");
            let _ = Tool::pump(&mut connection, &mut stream, Duration::from_secs(2), |connection| {
                let mut chunk = [0u8; 4096];
                loop {
                    let count = connection.read(&mut chunk);
                    if count == 0 {
                        break;
                    }
                    received.extend_from_slice(&chunk[..count]);
                    if !http {
                        let _ = connection.send(&chunk[..count]);
                    }
                }
                let closed = std::iter::from_fn(|| connection.poll_event()).any(|event| event == TLSEvent::PeerClosed);
                let request = received.windows(4).any(|window| window == b"\r\n\r\n");
                if http && request {
                    let body = format!("hello from umilib over {:?}\n", connection.session.version);
                    let response =
                        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = connection.send(response.as_bytes());
                    let _ = connection.close();
                    return true;
                }
                closed
            });
            println!("received: {}", received.len());
            let _ = connection.close();
            let mut out = Vec::new();
            let _ = connection.transmit(&mut out);
            let _ = stream.write_all(&out);
            let _ = std::io::stdout().flush();
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows))]
fn main() {
    let arguments = Arguments::parse();
    match arguments.positional.first().map(String::as_str) {
        Some("client") => Tool::client(&arguments),
        Some("server") => Tool::server(&arguments),
        _ => Tool::fail("tls client HOST PORT ... | tls server PORT ..."),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", windows)))]
fn main() {
    Tool::fail("this platform has no random source in umilib::platform::native");
}
