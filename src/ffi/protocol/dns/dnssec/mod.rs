//! The C ABI of [`crate::protocol::dns::dnssec`].
//!
//! Records cross as zone-file text, one a line, absolute names; private
//! keys as the text of the private key format v1.2; trust anchors as the
//! XML of RFC 9718. A configuration, a validator's and a validating
//! resolver are handles. A bogus result fails with the dns module's Bogus
//! and writes its extended error (RFC 8914) into `out_code`. Times are
//! seconds since 1970 (`time`) and, for the resolver, nanoseconds of the
//! caller's monotonic clock (`now`). A function that needs randomness takes
//! a generator of `crypto::random` (a handle and the C name of its type).

use alloc::vec::Vec;
use core::ffi::c_void;

use crate::ffi::crypto::random::RandomSource;
use crate::ffi::protocol::dns::{DNSStatus, FFIDNSResolverConfig, FFIDNSTransmission, FFIDNSUpstream};
use crate::ffi::{Buffer, Char, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};
use crate::protocol::dns::dnssec::{
    DNSSECAlgorithm, DNSSECConfig, DNSSECDigest, DNSSECPrivateKey, DNSSECProof, DNSSECResolver, DNSSECResolverEvent,
    DNSSECSigner, DNSSECStatus, DNSSECTrust, DNSSECTrustAnchor, DNSSECValidator,
};
use crate::protocol::dns::{DNSClass, DNSError, DNSMessage, DNSQuestion, DNSRecord, DNSType, DNSZone, DNSZoneFile};
use crate::runtime::Instant;

/// The helpers of this module.
pub struct DNSSECFFI;

impl DNSSECFFI {
    /// The extended error of a bogus error, else 0.
    pub fn code(error: &DNSError) -> u16 {
        match error {
            DNSError::Bogus { code, .. } => *code,
            _ => 0,
        }
    }

    /// The records of the zone-file text of the `length` bytes at `text`.
    ///
    /// # Safety
    /// As [`Pointer::text`].
    pub unsafe fn records(text: *const u8, length: usize) -> Result<Vec<DNSRecord>, &'static Status> {
        // SAFETY: the caller's promise.
        DNSStatus::records(unsafe { Pointer::text(text, length) }?)
    }

    /// Writes `code` into `out_code`, and fails with the status of `error`.
    ///
    /// # Safety
    /// As [`Pointer::write`].
    pub unsafe fn fail(error: DNSError, out_code: *mut u16) -> Result<(), &'static Status> {
        // SAFETY: the caller's promise.
        unsafe { Pointer::write(out_code, DNSSECFFI::code(&error)) }?;
        Err(error.to_status())
    }

    /// A signer of the private key of the text `key`, for `origin`, with the DNSKEY flags `flags`.
    pub fn signer(key: &str, origin: &str, flags: u16) -> Result<DNSSECSigner, &'static Status> {
        let key = DNSSECPrivateKey::parse(key).map_err(|error| error.to_status())?;
        let origin = crate::protocol::dns::DNSName::parse(origin, None).map_err(|error| error.to_status())?;
        Ok(DNSSECSigner::new(origin, flags, key))
    }
}

/// The limits of a [`DNSSECConfig`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSSECLimits {
    pub minimum_rsa_bits: u32,
    pub insecure_nsec3_iterations: u16,
    pub bogus_nsec3_iterations: u16,
    pub maximum_verifications: u32,
    pub clock_skew: u32,
    pub maximum_rsa_exponent_bits: u32,
}

/// What a verification tells: the TTL kept, the key's tag, and whether
/// the records were expanded from a wildcard.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct FFIDNSSECVerified {
    pub ttl: u32,
    pub key_tag: u16,
    pub expanded: bool,
}

impl Value for FFIDNSSECLimits {
    const TYPE: Type = Type::Named("umilib_protocol_dns_dnssec_DNSSECLimits");
}

impl Value for FFIDNSSECVerified {
    const TYPE: Type = Type::Named("umilib_protocol_dns_dnssec_DNSSECVerified");
}

impl Value for DNSSECValidator {
    const TYPE: Type = Type::Named("umilib_protocol_dns_dnssec_DNSSECValidator");
}

impl Value for DNSSECResolver {
    const TYPE: Type = Type::Named("umilib_protocol_dns_dnssec_DNSSECResolver");
}

crate::ffi_functions! {
    /// Writes a validator of the defaults (every algorithm and digest RFC 9904 says to implement) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_new(out: *mut *mut DNSSECValidator) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, DNSSECValidator::default()) })
    }

    /// Releases a validator. Does nothing if `validator` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_free(validator: *mut DNSSECValidator) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(validator) }
    }

    /// Sets the algorithms in use to the `count` numbers at `algorithms`, and the digests to the
    /// `digest_count` numbers at `digests`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_set_algorithms(validator: *mut DNSSECValidator, algorithms: *const u8, count: usize, digests: *const u8, digest_count: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable numbers.
            let validator = unsafe { Pointer::reference_mut(validator) }?;
            let algorithms = unsafe { Pointer::slice(algorithms, count) }?;
            let digests = unsafe { Pointer::slice(digests, digest_count) }?;
            validator.config.algorithms = algorithms.iter().map(|number| DNSSECAlgorithm(*number)).collect();
            validator.config.digests = digests.iter().map(|number| DNSSECDigest(*number)).collect();
            Ok(())
        })())
    }

    /// Writes the limits into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_limits(validator: *const DNSSECValidator, out: *mut FFIDNSSECLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let config = &unsafe { Pointer::reference(validator) }?.config;
            let limits = FFIDNSSECLimits {
                minimum_rsa_bits: config.minimum_rsa_bits,
                insecure_nsec3_iterations: config.insecure_nsec3_iterations,
                bogus_nsec3_iterations: config.bogus_nsec3_iterations,
                maximum_verifications: config.maximum_verifications as u32,
                clock_skew: config.clock_skew,
                maximum_rsa_exponent_bits: config.maximum_rsa_exponent_bits,
            };
            unsafe { Pointer::write(out, limits) }
        })())
    }

    /// Sets the limits to `limits`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_set_limits(validator: *mut DNSSECValidator, limits: FFIDNSSECLimits) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let config = &mut unsafe { Pointer::reference_mut(validator) }?.config;
            config.minimum_rsa_bits = limits.minimum_rsa_bits;
            config.insecure_nsec3_iterations = limits.insecure_nsec3_iterations;
            config.bogus_nsec3_iterations = limits.bogus_nsec3_iterations;
            config.maximum_verifications = limits.maximum_verifications as usize;
            config.clock_skew = limits.clock_skew;
            config.maximum_rsa_exponent_bits = limits.maximum_rsa_exponent_bits;
            Ok(())
        })())
    }

    /// Verifies the RRset of the records of the `length` bytes of text at `records` with the RRSIG
    /// records of `signatures` and the DNSKEY records of `keys`, at `time` (RFC 4035 §5.3); writes
    /// what it tells into `out` and, for records expanded from a wildcard, the closest encloser into
    /// `out_encloser`. Fails with Bogus and its extended error in `out_code`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_verify(validator: *const DNSSECValidator, records: *const u8, length: usize, signatures: *const u8, signatures_length: usize, keys: *const u8, keys_length: usize, time: u32, out: *mut FFIDNSSECVerified, out_encloser: *mut Buffer, out_code: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(records, length),
                    Pointer::range(signatures, signatures_length),
                    Pointer::range(keys, keys_length),
                ],
                &[Pointer::range(out, 1), Pointer::range(out_code, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let validator = unsafe { Pointer::reference(validator) }?;
            let (records, signatures, keys) = unsafe {
                (DNSSECFFI::records(records, length)?, DNSSECFFI::records(signatures, signatures_length)?, DNSSECFFI::records(keys, keys_length)?)
            };
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_encloser, 1)?;
            Pointer::check_range(out_code, 1)?;
            match validator.verify(&records, &signatures, &keys, time) {
                Ok(verified) => {
                    let structure = FFIDNSSECVerified { ttl: verified.ttl, key_tag: verified.key_tag, expanded: verified.closest_encloser.is_some() };
                    unsafe { Pointer::write(out, structure) }?;
                    unsafe { Pointer::write_text(out_encloser, verified.closest_encloser.map(|name| alloc::format!("{name}")).unwrap_or_default()) }?;
                    unsafe { Pointer::write(out_code, 0) }
                }
                Err(error) => unsafe { DNSSECFFI::fail(error, out_code) },
            }
        })())
    }

    /// Checks the DNSKEY records of `keys`, signed by the RRSIG records of `signatures`, against the DS
    /// or DNSKEY records of `anchors`, at `time` (RFC 4035 §5.2): writes whether they are secure into
    /// `out_secure` and, if insecure, the extended error that tells why into `out_code`. Fails with Bogus.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_verify_keys(validator: *const DNSSECValidator, keys: *const u8, keys_length: usize, signatures: *const u8, signatures_length: usize, anchors: *const u8, anchors_length: usize, time: u32, out_secure: *mut bool, out_code: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(keys, keys_length),
                    Pointer::range(signatures, signatures_length),
                    Pointer::range(anchors, anchors_length),
                ],
                &[Pointer::range(out_secure, 1), Pointer::range(out_code, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let validator = unsafe { Pointer::reference(validator) }?;
            let (keys, signatures, anchors) = unsafe {
                (DNSSECFFI::records(keys, keys_length)?, DNSSECFFI::records(signatures, signatures_length)?, DNSSECFFI::records(anchors, anchors_length)?)
            };
            Pointer::check_range(out_secure, 1)?;
            Pointer::check_range(out_code, 1)?;
            match validator.verify_keys(&keys, &signatures, &anchors, time) {
                Ok(DNSSECTrust::Secure(_)) => {
                    unsafe { Pointer::write(out_secure, true) }?;
                    unsafe { Pointer::write(out_code, 0) }
                }
                Ok(DNSSECTrust::Insecure(code)) => {
                    unsafe { Pointer::write(out_secure, false) }?;
                    unsafe { Pointer::write(out_code, code) }
                }
                Err(error) => unsafe { DNSSECFFI::fail(error, out_code) },
            }
        })())
    }

    /// Proves, with the NSEC and NSEC3 records of `records` (verified), the denial `kind` of the name
    /// of `name` in the zone of `zone`: 0 that it does not exist, 1 that it has no records of the type
    /// `record_type`, 2 that it was answered by the wildcard below the closest encloser of `encloser`,
    /// 3 that its delegation has no DS. Writes whether the proof is secure into `out_secure` (if not,
    /// an extended error, or 0, into `out_code`); fails with Bogus.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_validator_prove(validator: *const DNSSECValidator, kind: u8, name: *const u8, name_length: usize, record_type: u16, encloser: *const u8, encloser_length: usize, zone: *const u8, zone_length: usize, records: *const u8, length: usize, out_secure: *mut bool, out_code: *mut u16) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[
                    Pointer::range(name, name_length),
                    Pointer::range(encloser, encloser_length),
                    Pointer::range(zone, zone_length),
                    Pointer::range(records, length),
                ],
                &[Pointer::range(out_secure, 1), Pointer::range(out_code, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable text and writable pointers.
            let validator = unsafe { Pointer::reference(validator) }?;
            let name = unsafe { DNSStatus::name(name, name_length) }?;
            let zone = unsafe { DNSStatus::name(zone, zone_length) }?;
            let records = unsafe { DNSSECFFI::records(records, length) }?;
            Pointer::check_range(out_secure, 1)?;
            Pointer::check_range(out_code, 1)?;
            let proof = match kind {
                0 => validator.prove_nonexistence(&name, &zone, &records),
                1 => validator.prove_nodata(&name, DNSType(record_type), &zone, &records),
                2 => {
                    let encloser = unsafe { DNSStatus::name(encloser, encloser_length) }?;
                    validator.prove_expansion(&name, &encloser, &zone, &records)
                }
                3 => validator.prove_unsigned_delegation(&name, &zone, &records),
                _ => return Err(&Status::INVALID_ARGUMENT),
            };
            match proof {
                Ok(DNSSECProof::Secure) => {
                    unsafe { Pointer::write(out_secure, true) }?;
                    unsafe { Pointer::write(out_code, 0) }
                }
                Ok(DNSSECProof::Insecure(code)) => {
                    unsafe { Pointer::write(out_secure, false) }?;
                    unsafe { Pointer::write(out_code, code.unwrap_or(0)) }
                }
                Err(error) => unsafe { DNSSECFFI::fail(error, out_code) },
            }
        })())
    }

    /// Writes a new private key of `algorithm` (an RSA modulus of `bits`), drawn from `random`, in the
    /// private key format into `out`; fails with Config for an algorithm not implemented.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_private_key_generate(algorithm: u8, bits: u32, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a live generator and a writable pointer.
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let key = DNSSECPrivateKey::generate(DNSSECAlgorithm(algorithm), bits, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, key.format()) }
        })())
    }

    /// Writes the DNSKEY record of the private key of the text at `key`, owned by the zone of
    /// `origin`, of `flags` and `ttl`, into `out`; fails with Syntax.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_private_key_dnskey(key: *const u8, key_length: usize, origin: *const u8, origin_length: usize, flags: u16, ttl: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let signer = DNSSECFFI::signer(unsafe { Pointer::text(key, key_length) }?, unsafe { Pointer::text(origin, origin_length) }?, flags)?;
            unsafe { Pointer::write_text(out, alloc::format!("{}\n", signer.dnskey(ttl))) }
        })())
    }

    /// Writes the DS record of `digest` of that DNSKEY into `out` (RFC 4034 §5); fails with Config
    /// for a digest not implemented.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_private_key_delegation(key: *const u8, key_length: usize, origin: *const u8, origin_length: usize, flags: u16, digest: u8, ttl: u32, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let signer = DNSSECFFI::signer(unsafe { Pointer::text(key, key_length) }?, unsafe { Pointer::text(origin, origin_length) }?, flags)?;
            let ds = signer.delegation(DNSSECDigest(digest), ttl).ok_or(&DNSStatus::CONFIG)?;
            unsafe { Pointer::write_text(out, alloc::format!("{ds}\n")) }
        })())
    }

    /// Writes the zone of the origin of `origin` and the zone-file text of `zone`, signed by the
    /// `count` private keys of the NUL-terminated texts at `keys` with the DNSKEY flags at `flags`,
    /// valid from `inception` to `expiration` (RFC 4035 §2), the signatures' randomness drawn from
    /// `random`, its records one a line, into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dns_zone_sign(origin: *const u8, origin_length: usize, zone: *const u8, zone_length: usize, keys: *const *const Char, flags: *const u16, count: usize, inception: u32, expiration: u32, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, keys and flags and a writable pointer.
            let origin_text = unsafe { Pointer::text(origin, origin_length) }?;
            let origin = unsafe { DNSStatus::name(origin, origin_length) }?;
            let text = unsafe { Pointer::text(zone, zone_length) }?;
            let keys = unsafe { Pointer::strings(keys, count) }?;
            let flags = unsafe { Pointer::slice_of(flags, count) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let records = DNSZoneFile::new(Some(origin.clone())).parse(text).map_err(|error| error.error.to_status())?;
            let unsigned = DNSZone::new(origin, records).map_err(|error| error.to_status())?;
            let signers = keys.iter().zip(flags).map(|(key, flags)| DNSSECFFI::signer(key, origin_text, *flags)).collect::<Result<Vec<_>, _>>()?;
            let signed = unsigned.sign(&signers, inception, expiration, &mut random).map_err(|error| error.to_status())?;
            let records: Vec<DNSRecord> = signed.records().cloned().collect();
            unsafe { Pointer::write_text(out, DNSStatus::lines(&records)) }
        })())
    }

    /// Writes the DS records of the root's trust anchors valid at `time` (RFC 9718) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_trust_anchor_root(time: i64, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_text(out, DNSStatus::lines(&DNSSECTrustAnchor::root().delegations(time))) })
    }

    /// Writes the DS records of the trust anchors of the XML of the `length` bytes at `xml` valid at
    /// `time` (RFC 9718 §2) into `out`, and the zone they are of into `out_zone`; fails with Syntax.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_trust_anchor_parse(xml: *const u8, length: usize, time: i64, out_zone: *mut Buffer, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and writable pointers.
            let anchor = DNSSECTrustAnchor::parse(unsafe { Pointer::text(xml, length) }?).map_err(|error| error.to_status())?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write_text(out_zone, alloc::format!("{}", anchor.zone)) }?;
            unsafe { Pointer::write_text(out, DNSStatus::lines(&anchor.delegations(time))) }
        })())
    }

    /// Writes a validating resolver of `config`, the `count` servers at `upstreams`, the configuration
    /// of `validator`, and the trust anchors of the XML of `anchors` (the root's if `anchors_length`
    /// is 0), its cookie secret drawn from `random`, into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_new(config: FFIDNSResolverConfig, upstreams: *const FFIDNSUpstream, count: usize, validator: *const DNSSECValidator, anchors: *const u8, anchors_length: usize, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut *mut DNSSECResolver) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable servers, handle and text, a live generator and a writable pointer.
            let upstreams = unsafe { FFIDNSUpstream::list(upstreams, count) }?;
            let validator: DNSSECConfig = unsafe { Pointer::reference(validator) }?.config.clone();
            let anchor = match anchors_length {
                0 => DNSSECTrustAnchor::root(),
                _ => DNSSECTrustAnchor::parse(unsafe { Pointer::text(anchors, anchors_length) }?).map_err(|error| error.to_status())?,
            };
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let resolver = DNSSECResolver::new(config.config(upstreams), validator, anchor, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, resolver) }
        })())
    }

    /// Releases a validating resolver. Does nothing if `resolver` is null.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_free(resolver: *mut DNSSECResolver) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(resolver) }
    }

    /// Starts resolving and validating the name of `name`, of `kind` and `record_class`, at `now` and
    /// `time`, its IDs drawn from `random`, and writes the query's handle into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_resolve(resolver: *mut DNSSECResolver, name: *const u8, length: usize, kind: u16, record_class: u16, now: u64, time: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[Pointer::range(name, length), Pointer::range(random_type, random_type_length)],
                &[Pointer::range(out, 1)],
            )?;
            // SAFETY: the caller passes a valid handle, readable text and a writable pointer.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            let name = unsafe { DNSStatus::name(name, length) }?;
            let question = DNSQuestion { name, kind: DNSType(kind), class: DNSClass(record_class) };
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            let query = resolver.resolve(question, Instant::from_nanos(now), time, &mut random).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, query) }
        })())
    }

    /// Writes whether a query is to be sent into `out_found`, where into `out`, and its bytes into `out_message`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_transmit(resolver: *mut DNSSECResolver, out_found: *mut bool, out: *mut FFIDNSTransmission, out_message: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_message, 1)?;
            let transmission = resolver.transmit();
            unsafe { Pointer::write(out_found, transmission.is_some()) }?;
            let (structure, bytes) = transmission.map_or((FFIDNSTransmission::default(), Vec::new()), |transmission| {
                let structure = FFIDNSTransmission {
                    query: transmission.query,
                    upstream: transmission.upstream as u32,
                    transport: DNSStatus::transport_number(transmission.transport),
                };
                (structure, transmission.message)
            });
            unsafe { Pointer::write(out, structure) }?;
            unsafe { Pointer::write(out_message, Buffer::from_vec(bytes)) }
        })())
    }

    /// Takes the response of the `length` bytes at `bytes` from `upstream` over `transport` to `query`, at `now` and `time`,
    /// the queries it needs drawing their IDs from `random`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_receive(resolver: *mut DNSSECResolver, query: u64, upstream: u32, transport: u8, bytes: *const u8, length: usize, now: u64, time: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            let bytes = unsafe { Pointer::slice(bytes, length) }?;
            let transport = DNSStatus::transport(transport)?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            resolver.receive(query, upstream as usize, transport, bytes, Instant::from_nanos(now), time, &mut random);
            Ok(())
        })())
    }

    /// Writes whether a timer is set into `out_found` and when it fires (nanoseconds) into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_poll_timeout(resolver: *const DNSSECResolver, out_found: *mut bool, out: *mut u64) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let resolver = unsafe { Pointer::reference(resolver) }?;
            Pointer::check_range(out_found, 1)?;
            Pointer::check_range(out, 1)?;
            let timeout = resolver.poll_timeout();
            unsafe { Pointer::write(out_found, timeout.is_some()) }?;
            unsafe { Pointer::write(out, timeout.map_or(0, Instant::as_nanos)) }
        })())
    }

    /// Sends again the queries unanswered at `now`, and goes on with the validations, at `time`,
    /// their IDs drawn from `random`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_expire(resolver: *mut DNSSECResolver, now: u64, time: u64, random: *mut c_void, random_type: *const u8, random_type_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            resolver.expire(Instant::from_nanos(now), time, &mut random);
            Ok(())
        })())
    }

    /// Writes whether a question is answered into `out_found`, its query into `out_query`, the status
    /// of its failure (null for an answer; Bogus for a failed validation, its extended error in
    /// `out_code`) into `out_error`, whether the answer is secure into `out_secure`, and the response,
    /// AD set if secure, into `out`.
    pub unsafe extern "C" fn umilib_protocol_dns_dnssec_dnssec_resolver_poll_event(resolver: *mut DNSSECResolver, out_found: *mut bool, out_query: *mut u64, out_error: *mut *const Status, out_secure: *mut bool, out_code: *mut u16, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(
                &[],
                &[
                    Pointer::range(out_found, 1),
                    Pointer::range(out_query, 1),
                    Pointer::range(out_error, 1),
                    Pointer::range(out_secure, 1),
                    Pointer::range(out_code, 1),
                ],
            )?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let resolver = unsafe { Pointer::reference_mut(resolver) }?;
            for pointer in [out_found as *const u8, out_query as *const u8, out_error as *const u8, out_secure as *const u8, out_code as *const u8, out as *const u8] {
                Pointer::check_range(pointer, 1)?;
            }
            let event = resolver.poll_event();
            unsafe { Pointer::write(out_found, event.is_some()) }?;
            let (query, error, secure, code, bytes): (u64, *const Status, bool, u16, Vec<u8>) = match event {
                Some(DNSSECResolverEvent::Resolved { query, result: Ok((response, status)), .. }) => {
                    let (secure, code) = match status {
                        DNSSECStatus::Secure => (true, 0),
                        DNSSECStatus::Insecure(code) => (false, code.unwrap_or(0)),
                    };
                    (query, core::ptr::null(), secure, code, response.encode(DNSMessage::MAXIMUM_SIZE).unwrap_or_default())
                }
                Some(DNSSECResolverEvent::Resolved { query, result: Err(error), .. }) => {
                    (query, error.to_status() as *const Status, false, DNSSECFFI::code(&error), Vec::new())
                }
                None => (0, core::ptr::null(), false, 0, Vec::new()),
            };
            unsafe { Pointer::write(out_query, query) }?;
            unsafe { Pointer::write(out_error, error) }?;
            unsafe { Pointer::write(out_secure, secure) }?;
            unsafe { Pointer::write(out_code, code) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(bytes)) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "dnssec",
    definitions: &[
        Definition::Opaque {
            name: "umilib_protocol_dns_dnssec_DNSSECValidator",
            documentation: " A DNSSEC validator and its configuration.",
        },
        Definition::Opaque {
            name: "umilib_protocol_dns_dnssec_DNSSECResolver",
            documentation: " A validating stub resolver.",
        },
        Definition::Structure {
            name: "umilib_protocol_dns_dnssec_DNSSECLimits",
            documentation: " The limits of a validator.",
            fields: &[
                Parameter { name: "minimum_rsa_bits", value: <u32 as Value>::TYPE },
                Parameter { name: "insecure_nsec3_iterations", value: <u16 as Value>::TYPE },
                Parameter { name: "bogus_nsec3_iterations", value: <u16 as Value>::TYPE },
                Parameter { name: "maximum_verifications", value: <u32 as Value>::TYPE },
                Parameter { name: "clock_skew", value: <u32 as Value>::TYPE },
                Parameter { name: "maximum_rsa_exponent_bits", value: <u32 as Value>::TYPE },
            ],
        },
        Definition::Structure {
            name: "umilib_protocol_dns_dnssec_DNSSECVerified",
            documentation: " What a verification tells: the TTL kept, the key's tag, whether the records were expanded from a wildcard.",
            fields: &[
                Parameter { name: "ttl", value: <u32 as Value>::TYPE },
                Parameter { name: "key_tag", value: <u16 as Value>::TYPE },
                Parameter { name: "expanded", value: <bool as Value>::TYPE },
            ],
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
