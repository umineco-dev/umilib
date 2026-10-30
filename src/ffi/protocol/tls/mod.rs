//! The C ABI of [`crate::protocol::tls`].
//!
//! A connection, the configurations, a certificate verifier, a certified
//! key, an ECH key and a rule are handles; the limits, the options and what
//! a session negotiated are structures. Versions, cipher suites, groups,
//! signature schemes and alerts cross as their numbers; lists of them as
//! arrays and a count; lists of byte strings (application protocols,
//! certificate chains) as arrays of pointers and lengths and a count.
//!
//! A connection draws its randomness from an HMAC-DRBG (SP 800-90A)
//! seeded by the caller with at least 48 bytes from the operating system.
//! A failed operation of a connection gives the status `Protocol` or
//! `Alert`; [`umilib_protocol_tls_tls_connection_error`] tells the alert.

#[cfg(umilib_feature = "protocol-tls-v1_2")]
pub mod v1_2;
#[cfg(umilib_feature = "protocol-tls-v1_3")]
pub mod v1_3;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::auth::cert::key::PrivateKey;
use crate::auth::cert::path::TrustAnchor;
use crate::crypto::random::HMACDRBG;
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::hash::sha::v2::SHA256;
use crate::protocol::tls::{
    TLSAlertDescription, TLSCertifiedKey, TLSCipherSuite, TLSClientAuthentication, TLSClientConfig, TLSClientHello,
    TLSConfig, TLSConnection, TLSECHConfig, TLSECHKey, TLSECHStatus, TLSEarlyData, TLSError, TLSEvent,
    TLSMiddleboxCompatibility, TLSNamePattern, TLSNamedGroup, TLSPathVerifier, TLSReplayCache, TLSRule,
    TLSServerConfig, TLSSessionCache, TLSSignatureScheme, TLSTicketKey, TLSTicketKeys, TLSVersion,
};
use crate::secret::Secret;
use crate::service::Rule;

/// The statuses of this module, one per variant of [`TLSError`] that is not
/// another module's.
pub struct TLSStatus;

impl TLSStatus {
    pub const PROTOCOL: Status = Status::new(
        c"protocol.tls",
        c"Protocol",
        c"what the TLS peer sent breaks the protocol; the connection's error tells the alert",
    );
    pub const ALERT: Status =
        Status::new(c"protocol.tls", c"Alert", c"the TLS peer sent a fatal alert; the connection's error tells which");
    pub const STATE: Status = Status::new(c"protocol.tls", c"State", c"the TLS connection's state does not allow it");
    pub const CONFIG: Status = Status::new(c"protocol.tls", c"Config", c"the TLS configuration cannot work");
    pub const TRANSPORT: Status =
        Status::new(c"protocol.tls", c"Transport", c"the TLS handshake breaks a rule of the transport that carries it");
    /// The fewest bytes of seed a connection's randomness takes.
    pub const SEED_LENGTH: usize = 48;

    /// The random source of a connection: an HMAC-DRBG (SP 800-90A) of the
    /// `length` bytes at `seed`, at least 48 (InvalidArgument otherwise):
    /// the entropy input is the first 32, the nonce the rest.
    ///
    /// # Safety
    /// As [`Pointer::slice`].
    pub unsafe fn random(seed: *const u8, length: usize) -> Result<Box<HMACDRBG<SHA256>>, &'static Status> {
        // SAFETY: the caller's promise.
        let seed = unsafe { Pointer::slice(seed, length) }?;
        if seed.len() < TLSStatus::SEED_LENGTH {
            return Err(&Status::INVALID_ARGUMENT);
        }
        let (entropy, nonce) = seed.split_at(32);
        let random = HMACDRBG::new(entropy, nonce, b"umilib protocol tls").map_err(|_| &Status::INVALID_ARGUMENT)?;
        Ok(Box::new(random))
    }

    /// The values of `count` numbers at `values`.
    ///
    /// # Safety
    /// As [`Pointer::slice_of`].
    pub unsafe fn numbers<T: Copy, U>(
        values: *const T,
        count: usize,
        to: impl Fn(T) -> U,
    ) -> Result<Vec<U>, &'static Status> {
        // SAFETY: the caller's promise.
        Ok(unsafe { Pointer::slice_of(values, count) }?.iter().copied().map(to).collect())
    }

    /// The `count` byte strings at `values` and `lengths`, copied.
    ///
    /// # Safety
    /// As [`Pointer::slices`].
    pub unsafe fn byte_strings(
        values: *const *const u8,
        lengths: *const usize,
        count: usize,
    ) -> Result<Vec<Vec<u8>>, &'static Status> {
        // SAFETY: the caller's promise.
        Ok(unsafe { Pointer::slices(values, lengths, count) }?.into_iter().map(<[u8]>::to_vec).collect())
    }
}

impl ToStatus for TLSError {
    fn to_status(&self) -> &'static Status {
        match self {
            TLSError::Protocol(_) => &TLSStatus::PROTOCOL,
            TLSError::Alert(_) => &TLSStatus::ALERT,
            TLSError::State => &TLSStatus::STATE,
            TLSError::Config => &TLSStatus::CONFIG,
            TLSError::Write(error) => error.to_status(),
            TLSError::Transport => &TLSStatus::TRANSPORT,
        }
    }
}

/// The limits of a [`TLSConfig`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITLSLimits {
    pub maximum_handshake_message: usize,
    pub record_size_limit: u16,
    pub maximum_buffered_data: usize,
    pub maximum_key_updates: u32,
    pub require_extended_main_secret: bool,
    pub maximum_ignored_records: u32,
}

impl FFITLSLimits {
    pub fn of(config: &TLSConfig) -> FFITLSLimits {
        FFITLSLimits {
            maximum_handshake_message: config.maximum_handshake_message,
            record_size_limit: config.record_size_limit,
            maximum_buffered_data: config.maximum_buffered_data,
            maximum_key_updates: config.maximum_key_updates,
            require_extended_main_secret: config.require_extended_main_secret,
            maximum_ignored_records: config.maximum_ignored_records,
        }
    }

    pub fn apply(&self, config: &mut TLSConfig) {
        config.maximum_handshake_message = self.maximum_handshake_message;
        config.record_size_limit = self.record_size_limit;
        config.maximum_buffered_data = self.maximum_buffered_data;
        config.maximum_key_updates = self.maximum_key_updates;
        config.require_extended_main_secret = self.require_extended_main_secret;
        config.maximum_ignored_records = self.maximum_ignored_records;
    }
}

/// The options of a [`TLSClientConfig`] that are flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITLSClientOptions {
    pub middlebox_compatibility: bool,
    pub send_server_name: bool,
    pub request_certificate_status: bool,
    pub post_handshake_authentication: bool,
    pub early_data: bool,
    pub ech_grease: bool,
}

/// The options of a [`TLSServerConfig`] that are numbers or flags; the
/// client authentication as 0 off, 1 optional, 2 required.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITLSServerOptions {
    pub prefer_own_cipher_suites: bool,
    pub client_authentication: u8,
    pub ticket_count: usize,
    pub ticket_lifetime: u32,
    pub maximum_early_data: u32,
    pub freshness_window: i64,
}

/// What a session negotiated ([`crate::protocol::tls::TLSSession`]): 0 for
/// what is not negotiated yet; the early data and the ECH status as the
/// numbers of their variants.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFITLSSession {
    pub version: u16,
    pub cipher_suite: u16,
    pub group: u16,
    pub peer_signature_scheme: u16,
    pub resumed: bool,
    pub early_data: u8,
    pub ech: u8,
    pub handshaking: bool,
}

impl FFITLSSession {
    pub fn of(connection: &TLSConnection) -> FFITLSSession {
        let session = &connection.session;
        FFITLSSession {
            version: session.version.map_or(0, |version| version.0),
            cipher_suite: session.cipher_suite.map_or(0, |suite| suite.0),
            group: session.group.map_or(0, |group| group.0),
            peer_signature_scheme: session.peer_signature_scheme.map_or(0, |scheme| scheme.0),
            resumed: session.resumed,
            early_data: match session.early_data {
                TLSEarlyData::NotOffered => 0,
                TLSEarlyData::Offered => 1,
                TLSEarlyData::Accepted => 2,
                TLSEarlyData::Rejected => 3,
            },
            ech: match session.ech {
                TLSECHStatus::NotOffered => 0,
                TLSECHStatus::Grease => 1,
                TLSECHStatus::Offered => 2,
                TLSECHStatus::Accepted => 3,
                TLSECHStatus::Rejected { .. } => 4,
            },
            handshaking: connection.is_handshaking(),
        }
    }
}

/// The numbers of [`TLSEvent`].
pub struct FFITLSEvent;

impl FFITLSEvent {
    pub fn of(event: &TLSEvent) -> u8 {
        match event {
            TLSEvent::Connected => 0,
            TLSEvent::Readable => 1,
            TLSEvent::PeerClosed => 2,
            TLSEvent::Authenticated => 3,
        }
    }
}

/// A [`TLSPathVerifier`] behind the trait object the configurations hold.
pub struct FFITLSVerifier(pub Arc<TLSPathVerifier>);

impl Value for FFITLSLimits {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSLimits");
}

impl Value for FFITLSClientOptions {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSClientOptions");
}

impl Value for FFITLSServerOptions {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSServerOptions");
}

impl Value for FFITLSSession {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSSession");
}

impl Value for TLSConfig {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSConfig");
}

impl Value for TLSClientConfig {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSClientConfig");
}

impl Value for TLSServerConfig {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSServerConfig");
}

impl Value for FFITLSVerifier {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSPathVerifier");
}

impl Value for TLSCertifiedKey {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSCertifiedKey");
}

impl Value for TLSECHKey {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSECHKey");
}

impl Value for TLSConnection {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSConnection");
}

impl Value for TLSRule {
    const TYPE: Type = Type::Named("umilib_protocol_tls_TLSRule");
}

crate::ffi_functions! {
    /// Writes the default configuration (every version, suite, group and scheme compiled in) into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_new(out: *mut *mut TLSConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, TLSConfig::default()) })
    }

    /// Releases a configuration. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_free(config: *mut TLSConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Sets the versions, most preferred first, to the `count` numbers at `versions`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_set_versions(config: *mut TLSConfig, versions: *const u16, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable numbers.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.versions = unsafe { TLSStatus::numbers(versions, count, TLSVersion) }?;
            Ok(())
        })())
    }

    /// Sets the cipher suites, most preferred first, to the `count` numbers at `suites`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_set_cipher_suites(config: *mut TLSConfig, suites: *const u16, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable numbers.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.cipher_suites = unsafe { TLSStatus::numbers(suites, count, TLSCipherSuite) }?;
            Ok(())
        })())
    }

    /// Sets the groups of key exchange, most preferred first, to the `count` numbers at `groups`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_set_groups(config: *mut TLSConfig, groups: *const u16, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable numbers.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.groups = unsafe { TLSStatus::numbers(groups, count, TLSNamedGroup) }?;
            Ok(())
        })())
    }

    /// Sets the signature schemes, most preferred first, to the `count` numbers at `schemes`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_set_signature_schemes(config: *mut TLSConfig, schemes: *const u16, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable numbers.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.signature_schemes = unsafe { TLSStatus::numbers(schemes, count, TLSSignatureScheme) }?;
            Ok(())
        })())
    }

    /// Sets the application protocols (ALPN), most preferred first, to the `count` byte strings at `protocols` and `lengths`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_set_protocols(config: *mut TLSConfig, protocols: *const *const u8, lengths: *const usize, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable byte strings.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.protocols = unsafe { TLSStatus::byte_strings(protocols, lengths, count) }?;
            Ok(())
        })())
    }

    /// Writes the limits of the configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_limits(config: *const TLSConfig, out: *mut FFITLSLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            unsafe { Pointer::write(out, FFITLSLimits::of(config)) }
        })())
    }

    /// Sets the limits of the configuration.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_config_set_limits(config: *mut TLSConfig, limits: *const FFITLSLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structure.
            let config = unsafe { Pointer::reference_mut(config) }?;
            unsafe { Pointer::reference(limits) }?.apply(config);
            Ok(())
        })())
    }

    /// Writes the verifier of servers' certificates to the anchors of the list `anchors` (copied) into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_path_verifier_servers(anchors: *const Vec<TrustAnchor>, out: *mut *mut FFITLSVerifier) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let anchors = unsafe { Pointer::reference(anchors) }?;
            unsafe { Pointer::write_handle(out, FFITLSVerifier(Arc::new(TLSPathVerifier::servers(anchors.clone())))) }
        })())
    }

    /// Writes the verifier of clients' certificates to the anchors of the list `anchors` (copied) into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_path_verifier_clients(anchors: *const Vec<TrustAnchor>, out: *mut *mut FFITLSVerifier) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let anchors = unsafe { Pointer::reference(anchors) }?;
            unsafe { Pointer::write_handle(out, FFITLSVerifier(Arc::new(TLSPathVerifier::clients(anchors.clone())))) }
        })())
    }

    /// Releases a verifier. Does nothing if `verifier` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_path_verifier_free(verifier: *mut FFITLSVerifier) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(verifier) }
    }

    /// Writes the key `key` (consumed: the handle is released) with the chain of the `count` DER
    /// certificates at `chain` and `lengths` (the end-entity certificate first), and the OCSP response
    /// of `ocsp_length` bytes at `ocsp` to staple (none for 0 bytes), into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_certified_key_new(chain: *const *const u8, lengths: *const usize, count: usize, key: *mut PrivateKey, ocsp: *const u8, ocsp_length: usize, out: *mut *mut TLSCertifiedKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable byte strings, a handle it gives up and a writable pointer.
            let chain = unsafe { TLSStatus::byte_strings(chain, lengths, count) }?;
            let ocsp = unsafe { Pointer::slice(ocsp, ocsp_length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(key, 1)?;
            let key = *unsafe { Box::from_raw(key) };
            let ocsp = (!ocsp.is_empty()).then(|| ocsp.to_vec());
            unsafe { Pointer::write_handle(out, TLSCertifiedKey { chain, key, ocsp }) }
        })())
    }

    /// Releases a certified key. Does nothing if `key` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_certified_key_free(key: *mut TLSCertifiedKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes the configuration of clients of `config` (copied), checking servers with `verifier`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_client_config_new(config: *const TLSConfig, verifier: *const FFITLSVerifier, out: *mut *mut TLSClientConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let verifier = unsafe { Pointer::reference(verifier) }?;
            let mut client = TLSClientConfig::new(verifier.0.clone());
            client.key_share_groups = TLSClientConfig::default_key_shares(&config.groups);
            client.config = config.clone();
            unsafe { Pointer::write_handle(out, client) }
        })())
    }

    /// Releases a configuration of clients. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_client_config_free(config: *mut TLSClientConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Sets the flags of the configuration of clients.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_client_config_set_options(config: *mut TLSClientConfig, options: *const FFITLSClientOptions) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structure.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let options = unsafe { Pointer::reference(options) }?;
            config.middlebox_compatibility = if options.middlebox_compatibility { TLSMiddleboxCompatibility::On } else { TLSMiddleboxCompatibility::Off };
            config.send_server_name = options.send_server_name;
            config.request_certificate_status = options.request_certificate_status;
            config.post_handshake_authentication = options.post_handshake_authentication;
            config.early_data = options.early_data;
            config.ech_grease = options.ech_grease;
            Ok(())
        })())
    }

    /// Sets the groups of the first ClientHello's key shares to the `count` numbers at `groups`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_client_config_set_key_share_groups(config: *mut TLSClientConfig, groups: *const u16, count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable numbers.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.key_share_groups = unsafe { TLSStatus::numbers(groups, count, TLSNamedGroup) }?;
            Ok(())
        })())
    }

    /// Sets the certificate sent when a server asks for one to a copy of `key`, or none if `key` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_client_config_set_certificate(config: *mut TLSClientConfig, key: *const TLSCertifiedKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a valid handle or null.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.certificate = unsafe { Pointer::optional_reference(key) }?.map(FFITLSCertifiedKey::copy).transpose()?.map(Arc::new);
            Ok(())
        })())
    }

    /// Keeps the tickets of servers in a cache of `capacity` tickets, or none for 0.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_client_config_set_session_cache(config: *mut TLSClientConfig, capacity: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.sessions = (capacity > 0).then(|| Arc::new(TLSSessionCache::new(capacity)) as Arc<dyn crate::protocol::tls::TLSSessionStore>);
            Ok(())
        })())
    }

    /// Sets the server's ECH configurations to those of the `ECHConfigList` of `length` bytes at `list`; fails with Protocol for a malformed list.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_client_config_set_ech_configs(config: *mut TLSClientConfig, list: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let list = unsafe { Pointer::slice(list, length) }?;
            config.ech_configs = if list.is_empty() { Vec::new() } else { TLSECHConfig::decode_list(list).map_err(|error| error.to_status())? };
            Ok(())
        })())
    }

    /// Writes the configuration of servers of `config` (copied), without certificates yet, into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_new(config: *const TLSConfig, out: *mut *mut TLSServerConfig) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let mut server = TLSServerConfig::new(Vec::new());
            server.config = config.clone();
            unsafe { Pointer::write_handle(out, server) }
        })())
    }

    /// Releases a configuration of servers. Does nothing if `config` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_free(config: *mut TLSServerConfig) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(config) }
    }

    /// Adds a copy of `key` to the certificates the server presents, in order of preference.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_add_certificate(config: *mut TLSServerConfig, key: *const TLSCertifiedKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let key = unsafe { Pointer::reference(key) }?;
            config.certificates.push(Arc::new(FFITLSCertifiedKey::copy(key)?));
            Ok(())
        })())
    }

    /// Sets the numbers and flags of the configuration of servers; fails with InvalidArgument for an
    /// unknown client authentication.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_set_options(config: *mut TLSServerConfig, options: *const FFITLSServerOptions) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and structure.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let options = unsafe { Pointer::reference(options) }?;
            config.client_authentication = match options.client_authentication {
                0 => TLSClientAuthentication::Off,
                1 => TLSClientAuthentication::Optional,
                2 => TLSClientAuthentication::Required,
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            config.prefer_own_cipher_suites = options.prefer_own_cipher_suites;
            config.ticket_count = options.ticket_count;
            config.ticket_lifetime = options.ticket_lifetime;
            config.maximum_early_data = options.maximum_early_data;
            config.freshness_window = options.freshness_window;
            Ok(())
        })())
    }

    /// Sets the verifier of clients' certificates, or none if `verifier` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_set_client_verifier(config: *mut TLSServerConfig, verifier: *const FFITLSVerifier) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a valid handle or null.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.client_verifier = unsafe { Pointer::optional_reference(verifier) }?.map(|verifier| verifier.0.clone() as Arc<dyn crate::protocol::tls::TLSCertificateVerifier>);
            Ok(())
        })())
    }

    /// Makes tickets with the AES-256-GCM key of 32 bytes at `key` named by the 16 bytes at `name`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_set_ticket_key(config: *mut TLSServerConfig, name: *const u8, key: *const u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, 16 and 32 readable bytes.
            let config = unsafe { Pointer::reference_mut(config) }?;
            let name: [u8; 16] = unsafe { Pointer::slice(name, 16) }?.try_into().map_err(|_| &Status::INVALID_ARGUMENT)?;
            let key = Secret::new(<[u8; 32]>::try_from(unsafe { Pointer::slice(key, 32) }?).map_err(|_| &Status::INVALID_ARGUMENT)?);
            let key = TLSTicketKey::new(name, key.expose()).map_err(|error| error.to_status())?;
            config.tickets = Some(Arc::new(TLSTicketKeys::new(alloc::vec![key])));
            Ok(())
        })())
    }

    /// Refuses replayed early data with a record of `capacity` ClientHellos over `window` seconds.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_set_replay_cache(config: *mut TLSServerConfig, window: i64, capacity: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.anti_replay = Some(Arc::new(TLSReplayCache::new(window, capacity)));
            Ok(())
        })())
    }

    /// Adds a copy of the ECH key `key` to those the server decrypts with.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_server_config_add_ech_key(config: *mut TLSServerConfig, key: *const TLSECHKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let config = unsafe { Pointer::reference_mut(config) }?;
            config.ech_keys.push(unsafe { Pointer::reference(key) }?.clone());
            Ok(())
        })())
    }

    /// Writes the ECH key of the configuration of the `ECHConfigList` of `length` bytes at `list` (its
    /// first configuration of version 0xfe0d) and the KEM's serialized private key of `private_length`
    /// bytes at `private_key`, sent to rejected clients if `retry`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_ech_key_new(list: *const u8, length: usize, private_key: *const u8, private_length: usize, retry: bool, out: *mut *mut TLSECHKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let list = unsafe { Pointer::slice(list, length) }?;
            let private_key = unsafe { Pointer::slice(private_key, private_length) }?;
            let config = TLSECHConfig::decode_list(list).map_err(|error| error.to_status())?.into_iter().next().ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, TLSECHKey { config, private_key: Secret::new(private_key.to_vec()), retry }) }
        })())
    }

    /// Writes a new ECH key of the KEM `kem_id`, for the configuration `config_id` with the `count`
    /// HPKE suites at `suites` (pairs of kdf_id and aead_id), the longest name `maximum_name_length`
    /// and the public name (UTF-8) of `length` bytes at `public_name`, sent to rejected clients if
    /// `retry`, with randomness seeded by the `seed_length` bytes at `seed` (at least 48), into `out`;
    /// fails with Config for a KEM not compiled in (ECH needs `crypto-hpke`).
    pub unsafe extern "C" fn umilib_protocol_tls_tls_ech_key_generate(config_id: u8, kem_id: u16, suites: *const u16, count: usize, maximum_name_length: u8, public_name: *const u8, length: usize, retry: bool, seed: *const u8, seed_length: usize, out: *mut *mut TLSECHKey) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable numbers and bytes and a writable pointer.
            let pairs = unsafe { Pointer::slice_of(suites, count.checked_mul(2).ok_or(&Status::INVALID_ARGUMENT)?) }?;
            let public_name = unsafe { Pointer::slice(public_name, length) }?;
            let mut random = unsafe { TLSStatus::random(seed, seed_length) }?;
            Pointer::check_range(out, 1)?;
            let cipher_suites = pairs.as_chunks::<2>().0.iter().map(|&[kdf_id, aead_id]| crate::protocol::tls::TLSECHCipherSuite { kdf_id, aead_id }).collect();
            let config = TLSECHConfig { config_id, kem_id, public_key: Vec::new(), cipher_suites, maximum_name_length, public_name: public_name.to_vec(), extensions: Vec::new() };
            #[cfg(umilib_feature = "crypto-hpke")]
            let key = crate::protocol::tls::TLSECHCipher::generate(config, retry, &mut *random).map_err(|error| error.to_status());
            #[cfg(not(umilib_feature = "crypto-hpke"))]
            let key: Result<TLSECHKey, &'static Status> = {
                let _ = (config, retry, &mut random);
                Err(&TLSStatus::CONFIG)
            };
            unsafe { Pointer::write_handle(out, key?) }
        })())
    }

    /// Writes the `ECHConfigList` of the key's configuration into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_ech_key_config_list(key: *const TLSECHKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            let mut list = Vec::new();
            TLSECHConfig::encode_list(core::slice::from_ref(&key.config), &mut list).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(list)) }
        })())
    }

    /// Writes the KEM's serialized private key of the key into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_ech_key_private_key(key: *const TLSECHKey, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let key = unsafe { Pointer::reference(key) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(key.private_key.expose().clone())) }
        })())
    }

    /// Releases an ECH key. Does nothing if `key` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_ech_key_free(key: *mut TLSECHKey) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(key) }
    }

    /// Writes a client connecting to the name (UTF-8) of `length` bytes at `server_name` (none for 0
    /// bytes) at `time` (seconds since 1970), its ClientHello written, with randomness seeded by the
    /// `seed_length` bytes at `seed` (at least 48), into `out`; fails with Config for a configuration
    /// that cannot work.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_client(config: *const TLSClientConfig, server_name: *const u8, length: usize, seed: *const u8, seed_length: usize, time: i64, out: *mut *mut TLSConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let server_name = unsafe { Pointer::optional_text(server_name, length) }?.filter(|name| !name.is_empty());
            let random = unsafe { TLSStatus::random(seed, seed_length) }?;
            Pointer::check_range(out, 1)?;
            let connection = TLSConnection::client(Arc::new(config.clone()), server_name, random, time).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, connection) }
        })())
    }

    /// Writes a server at `time` (seconds since 1970), with randomness seeded by the `seed_length`
    /// bytes at `seed` (at least 48), into `out`; fails with Config for a configuration that cannot work.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_server(config: *const TLSServerConfig, seed: *const u8, seed_length: usize, time: i64, out: *mut *mut TLSConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let config = unsafe { Pointer::reference(config) }?;
            let random = unsafe { TLSStatus::random(seed, seed_length) }?;
            Pointer::check_range(out, 1)?;
            let connection = TLSConnection::server(Arc::new(config.clone()), random, time).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, connection) }
        })())
    }

    /// Releases a connection. Does nothing if `connection` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_free(connection: *mut TLSConnection) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(connection) }
    }

    /// Takes the `length` bytes at `bytes` received from the transport; fails with Protocol, Alert or State.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_receive(connection: *mut TLSConnection, bytes: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            connection.receive(bytes).map_err(|error| error.to_status())
        })())
    }

    /// Writes the bytes to send to the transport into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_transmit(connection: *mut TLSConnection, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out, 1)?;
            let mut bytes = Vec::new();
            connection.transmit(&mut bytes).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }

    /// Sends the `length` bytes at `data` as application data (or early data the handshake allows);
    /// fails with State before the handshake allows it or after closing.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_send(connection: *mut TLSConnection, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            connection.send(data).map(|_| ()).map_err(|error| error.to_status())
        })())
    }

    /// Reads up to `length` bytes of application data into `out` and writes how many into `out_count`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_read(connection: *mut TLSConnection, out: *mut u8, length: usize, out_count: *mut usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out, length), Pointer::range(out_count, 1)])?;
            // SAFETY: the caller passes a valid handle and writable memory.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            Pointer::check_range(out_count, 1)?;
            let count = connection.read(out);
            unsafe { Pointer::write(out_count, count) }
        })())
    }

    /// Writes whether an event is pending into `out_found` and its number into `out_kind`: 0 Connected,
    /// 1 Readable, 2 PeerClosed, 3 Authenticated.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_poll_event(connection: *mut TLSConnection, out_found: *mut bool, out_kind: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out_kind, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out_kind, 1)?;
            let event = connection.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            unsafe { Pointer::write(out_kind, event.as_ref().map_or(0, FFITLSEvent::of)) }
        })())
    }

    /// Sends close_notify; fails with State if it was sent or the connection failed.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_close(connection: *mut TLSConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            connection.close().map_err(|error| error.to_status())
        })())
    }

    /// Updates the keys of sending, asking the peer to update its own if `request` (TLS 1.3); fails with State.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_update_keys(connection: *mut TLSConnection, request: bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            connection.update_keys(request).map_err(|error| error.to_status())
        })())
    }

    /// Asks the client for a certificate after the handshake (TLS 1.3); fails with State.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_request_certificate(connection: *mut TLSConnection) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let connection = unsafe { Pointer::reference_mut(connection) }?;
            connection.request_certificate().map_err(|error| error.to_status())
        })())
    }

    /// Writes `length` bytes of keying material for the label of `label_length` bytes at `label` and,
    /// if `has_context`, the context of `context_length` bytes at `context`, into `out`; fails with State.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_export(connection: *const TLSConnection, label: *const u8, label_length: usize, has_context: bool, context: *const u8, context_length: usize, out: *mut u8, length: usize) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(label, label_length), Pointer::range(context, context_length)],
                &[Pointer::range(out, length)],
            )?;
            // SAFETY: the caller passes a valid handle, readable bytes and writable memory.
            let connection = unsafe { Pointer::reference(connection) }?;
            let label = unsafe { Pointer::slice(label, label_length) }?;
            let context = unsafe { Pointer::slice(context, context_length) }?;
            let out = unsafe { Pointer::slice_mut(out, length) }?;
            connection.export(label, has_context.then_some(context), out).map_err(|error| error.to_status())
        })())
    }

    /// Writes what the session negotiated into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_session(connection: *const TLSConnection, out: *mut FFITLSSession) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, FFITLSSession::of(connection)) }
        })())
    }

    /// Writes whether an application protocol was negotiated into `out_found` and it into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_protocol(connection: *const TLSConnection, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write_optional(connection.session.protocol.clone().map(Buffer::from_vec), out_found, out) }
        })())
    }

    /// Writes whether the client asked for a name into `out_found` and the name (UTF-8) into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_server_name(connection: *const TLSConnection, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            let name = connection.session.server_name.clone().map(String::into_bytes);
            unsafe { Pointer::write_optional(name.map(Buffer::from_vec), out_found, out) }
        })())
    }

    /// Writes whether the peer's chain has a certificate at `index` (0 is the end-entity certificate)
    /// into `out_found` and its DER into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_peer_certificate(connection: *const TLSConnection, index: usize, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            let certificate = connection.session.peer_certificates.get(index).cloned();
            unsafe { Pointer::write_optional(certificate.map(Buffer::from_vec), out_found, out) }
        })())
    }

    /// Writes whether the server stapled an OCSP response into `out_found` and it into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_certificate_status(connection: *const TLSConnection, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write_optional(connection.session.certificate_status.clone().map(Buffer::from_vec), out_found, out) }
        })())
    }

    /// Writes whether a server that rejected ECH sent retry configurations into `out_found` and its
    /// `ECHConfigList` into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_ech_retry_configs(connection: *const TLSConnection, out_found: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            let list = match &connection.session.ech {
                TLSECHStatus::Rejected { retry_configs } => retry_configs.clone(),
                _ => None,
            };
            unsafe { Pointer::write_optional(list.map(Buffer::from_vec), out_found, out) }
        })())
    }

    /// Writes whether the connection failed into `out_failed`, and its error: `out_kind` 0 Protocol
    /// (the alert sent), 1 Alert (the alert received), 2 State, 3 Config, 4 Write, 5 Transport, and
    /// the alert's description into `out_alert`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_connection_error(connection: *const TLSConnection, out_failed: *mut bool, out_kind: *mut u8, out_alert: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[Pointer::range(out_failed, 1), Pointer::range(out_kind, 1), Pointer::range(out_alert, 1)],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let connection = unsafe { Pointer::reference(connection) }?;
            Pointer::check_range(out_failed, 1)?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_alert, 1)?;
            let (kind, alert) = match connection.error {
                Some(TLSError::Protocol(alert)) => (0, alert),
                Some(TLSError::Alert(alert)) => (1, alert),
                Some(TLSError::State) => (2, TLSAlertDescription(0)),
                Some(TLSError::Config) => (3, TLSAlertDescription(0)),
                Some(TLSError::Write(_)) | None => (4, TLSAlertDescription(0)),
                Some(TLSError::Transport) => (5, TLSAlertDescription(0)),
            };
            unsafe { Pointer::write(out_failed, connection.error.is_some()) }?;
            unsafe { Pointer::write(out_kind, kind) }?;
            unsafe { Pointer::write(out_alert, alert.0) }
        })())
    }

    /// Writes the rule of the server names of the pattern (UTF-8) of `length` bytes at `pattern`
    /// (`*` any, `*.domain` one label of `domain`, otherwise that name; none for 0 bytes: no name), and
    /// of the application protocol of `protocol_length` bytes at `protocol` (any for 0 bytes), into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_rule_new(pattern: *const u8, length: usize, protocol: *const u8, protocol_length: usize, out: *mut *mut TLSRule) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let pattern = unsafe { Pointer::text(pattern, length) }?;
            let protocol = unsafe { Pointer::slice(protocol, protocol_length) }?;
            let names = if pattern.is_empty() { TLSNamePattern::None } else { TLSNamePattern::parse(pattern) };
            let rule = TLSRule { server_name: names, protocol: (!protocol.is_empty()).then(|| protocol.to_vec()) };
            unsafe { Pointer::write_handle(out, rule) }
        })())
    }

    /// Releases a rule. Does nothing if `rule` is null.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_rule_free(rule: *mut TLSRule) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(rule) }
    }

    /// Writes whether the rule matches the session of `connection` into `out`.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_rule_matches_session(rule: *const TLSRule, connection: *const TLSConnection, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let rule = unsafe { Pointer::reference(rule) }?;
            let connection = unsafe { Pointer::reference(connection) }?;
            unsafe { Pointer::write(out, rule.matches(&connection.session)) }
        })())
    }

    /// Writes whether the rule matches the body of a ClientHello of `length` bytes at `hello` into
    /// `out`; fails with Protocol for a malformed ClientHello.
    pub unsafe extern "C" fn umilib_protocol_tls_tls_rule_matches_client_hello(rule: *const TLSRule, hello: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(hello, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let rule = unsafe { Pointer::reference(rule) }?;
            let hello = TLSClientHello::decode(unsafe { Pointer::slice(hello, length) }?).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, rule.matches(&hello)) }
        })())
    }
}

/// Copies of certified keys, whose private key cannot be cloned.
pub struct FFITLSCertifiedKey;

impl FFITLSCertifiedKey {
    /// A copy of `key`, its private key through its PKCS #8 encoding.
    pub fn copy(key: &TLSCertifiedKey) -> Result<TLSCertifiedKey, &'static Status> {
        let der = key.key.to_pkcs8_der().map_err(|_| &Status::INVALID_ARGUMENT)?;
        let private = PrivateKey::from_pkcs8_der(der.expose()).map_err(|_| &Status::INVALID_ARGUMENT)?;
        Ok(TLSCertifiedKey { chain: key.chain.clone(), key: private, ocsp: key.ocsp.clone() })
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "tls",
    definitions: &[
        Definition::Structure {
            name: "umilib_protocol_tls_TLSLimits",
            documentation: " The limits of a TLS configuration.",
            fields: &[
                Parameter { name: "maximum_handshake_message", value: <usize as Value>::TYPE },
                Parameter { name: "record_size_limit", value: <u16 as Value>::TYPE },
                Parameter { name: "maximum_buffered_data", value: <usize as Value>::TYPE },
                Parameter { name: "maximum_key_updates", value: <u32 as Value>::TYPE },
                Parameter { name: "require_extended_main_secret", value: <bool as Value>::TYPE },
                Parameter { name: "maximum_ignored_records", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tls_TLSClientOptions",
            documentation: " The flags of a configuration of TLS clients.",
            fields: &[
                Parameter { name: "middlebox_compatibility", value: <bool as Value>::TYPE },
                Parameter { name: "send_server_name", value: <bool as Value>::TYPE },
                Parameter { name: "request_certificate_status", value: <bool as Value>::TYPE },
                Parameter { name: "post_handshake_authentication", value: <bool as Value>::TYPE },
                Parameter { name: "early_data", value: <bool as Value>::TYPE },
                Parameter { name: "ech_grease", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tls_TLSServerOptions",
            documentation: " The numbers and flags of a configuration of TLS servers.",
            fields: &[
                Parameter { name: "prefer_own_cipher_suites", value: <bool as Value>::TYPE },
                Parameter { name: "client_authentication", value: <u8 as Value>::TYPE },
                Parameter { name: "ticket_count", value: <usize as Value>::TYPE },
                Parameter { name: "ticket_lifetime", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_early_data", value: <u32 as Value>::TYPE },
                Parameter { name: "freshness_window", value: <i64 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_tls_TLSSession",
            documentation: " What a TLS session negotiated; 0 for what is not negotiated yet.",
            fields: &[
                Parameter { name: "version", value: <u16 as Value>::TYPE },
                Parameter { name: "cipher_suite", value: <u16 as Value>::TYPE },
                Parameter { name: "group", value: <u16 as Value>::TYPE },
                Parameter { name: "peer_signature_scheme", value: <u16 as Value>::TYPE },
                Parameter { name: "resumed", value: <bool as Value>::TYPE },
                Parameter { name: "early_data", value: <u8 as Value>::TYPE },
                Parameter { name: "ech", value: <u8 as Value>::TYPE },
                Parameter { name: "handshaking", value: <bool as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSConfig",
            documentation: " What both ends of TLS configure: versions, algorithms and limits.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSClientConfig",
            documentation: " The configuration of TLS clients.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSServerConfig",
            documentation: " The configuration of TLS servers.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSPathVerifier",
            documentation: " The verification of certificate chains to trust anchors.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSCertifiedKey",
            documentation: " A certificate chain and the private key of its first certificate.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSECHKey",
            documentation: " An ECH configuration and its private key.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSConnection",
            documentation: " A TLS connection without I/O.",
        },
        Definition::Opaque {
            name: "umilib_protocol_tls_TLSRule",
            documentation: " A rule that routes TLS connections by server name and application protocol.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[
        #[cfg(umilib_feature = "protocol-tls-v1_2")]
        v1_2::MODULE,
        #[cfg(umilib_feature = "protocol-tls-v1_3")]
        v1_3::MODULE,
    ],
};
