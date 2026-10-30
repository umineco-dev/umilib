//! The C ABI of [`crate::codec::uri`].
//!
//! A [`URIReference`] is a handle whose components are read and changed one
//! at a time; an optional component is passed as a null pointer when absent.
//! [`URIAuthority`] crosses as its three components. [`URIHostKind`] is
//! passed as `0` (IPv6), `1` (IPvFuture), `2` (IPv4) or `3` (RegName). The
//! octets that `URIPercent::encode` keeps are passed as a list of bytes, as a
//! closure cannot cross the boundary. The name and value pairs of the form
//! encoding are a list handle.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::uri::{URIAuthority, URIError, URIForm, URIHostKind, URIPercent, URIReference};
use crate::ffi::{Buffer, Definition, Function, Module, Pointer, Status, ToStatus, Type, Value};

impl Value for URIReference {
    const TYPE: Type = Type::Named("umilib_codec_uri_URIReference");
}

impl Value for Vec<(String, String)> {
    const TYPE: Type = Type::Named("umilib_codec_uri_URIFormPairs");
}

/// The [`URIHostKind`] values of the C ABI.
pub struct URIHostKindValue;

impl URIHostKindValue {
    pub const IPV6: u8 = 0;
    pub const IPVFUTURE: u8 = 1;
    pub const IPV4: u8 = 2;
    pub const REG_NAME: u8 = 3;

    pub fn encode(kind: URIHostKind) -> u8 {
        match kind {
            URIHostKind::IPv6 => URIHostKindValue::IPV6,
            URIHostKind::IPvFuture => URIHostKindValue::IPVFUTURE,
            URIHostKind::IPv4 => URIHostKindValue::IPV4,
            URIHostKind::RegName => URIHostKindValue::REG_NAME,
        }
    }
}

/// The statuses of [`URIError`], one per variant.
pub struct URIStatus;

impl URIStatus {
    pub const SYNTAX: Status = Status::new(c"codec.uri", c"Syntax", c"text not of the grammar of RFC 3986");
    pub const PERCENT: Status = Status::new(c"codec.uri", c"Percent", c"a % not of two hexadecimal digits");
    pub const UTF8: Status = Status::new(c"codec.uri", c"UTF8", c"decoded octets that are not UTF-8");
    pub const NOT_ABSOLUTE: Status = Status::new(c"codec.uri", c"NotAbsolute", c"a base that is not an absolute URI");
    pub const NO_SUCH_PAIR: Status = Status::new(c"codec.uri", c"NoSuchPair", c"the list has no pair of that index");
}

impl ToStatus for URIError {
    fn to_status(&self) -> &'static Status {
        match self {
            URIError::Syntax { .. } => &URIStatus::SYNTAX,
            URIError::Percent { .. } => &URIStatus::PERCENT,
            URIError::UTF8 => &URIStatus::UTF8,
            URIError::NotAbsolute => &URIStatus::NOT_ABSOLUTE,
        }
    }
}

crate::ffi_functions! {
    /// Writes an empty relative reference (no scheme, authority, query or fragment, an empty
    /// path) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_new(out: *mut *mut URIReference) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, URIReference::default()) })
    }

    /// Releases a reference. Does nothing if `reference` is null.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_free(reference: *mut URIReference) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(reference) }
    }

    /// Writes the reference of the text at `text`, checked against RFC 3986, into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_parse(text: *const u8, length: usize, out: *mut *mut URIReference) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            Pointer::check_range(out, 1)?;
            let reference = URIReference::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, reference) }
        })())
    }

    /// Writes the text of `reference`, its components written back (RFC 3986 §5.3), into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_format(reference: *const URIReference, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write_text(out, reference.to_string()) }
        })())
    }

    /// Succeeds if the components of `reference`, written back, read as the same reference.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_check(reference: *const URIReference) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            let reference = unsafe { Pointer::reference(reference) }?;
            reference.check().map_err(|error| error.to_status())
        })())
    }

    /// Writes whether `reference` has a scheme into `out_has` and the scheme into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_scheme(reference: *const URIReference, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write_optional_text(out_has, out, reference.scheme.as_deref()) }
        })())
    }

    /// Sets the scheme of `reference` to the text at `text`, or removes it if `text` is null.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_set_scheme(reference: *mut URIReference, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text or null.
            let text = unsafe { Pointer::optional_text(text, length) }?;
            let reference = unsafe { Pointer::reference_mut(reference) }?;
            reference.scheme = text.map(str::to_string);
            Ok(())
        })())
    }

    /// Writes whether `reference` has an authority into `out_has`, and its userinfo (whether it
    /// has one into `out_has_userinfo`), its host and its port (whether it has one into
    /// `out_has_port`) into the other outputs; every output is empty without an authority.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_authority(reference: *const URIReference, out_has: *mut bool, out_has_userinfo: *mut bool, out_userinfo: *mut Buffer, out_host: *mut Buffer, out_has_port: *mut bool, out_port: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_range(out_has, 1)?;
            Pointer::check_ranges(&[], &[Pointer::range(out_has, 1), Pointer::range(out_has_userinfo, 1), Pointer::range(out_userinfo, 1), Pointer::range(out_host, 1), Pointer::range(out_has_port, 1), Pointer::range(out_port, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reference = unsafe { Pointer::reference(reference) }?;
            let authority = reference.authority.clone().unwrap_or_default();
            unsafe { URIStatus::write_authority(&authority, out_has_userinfo, out_userinfo, out_host, out_has_port, out_port) }?;
            unsafe { Pointer::write(out_has, reference.authority.is_some()) }
        })())
    }

    /// Sets the authority of `reference` to the userinfo at `userinfo` (null for none), the host
    /// at `host` and the port at `port` (null for none) if `has` is true, or removes it.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_set_authority(reference: *mut URIReference, has: bool, userinfo: *const u8, userinfo_length: usize, host: *const u8, host_length: usize, port: *const u8, port_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text or null.
            let authority = if has {
                let userinfo = unsafe { Pointer::optional_text(userinfo, userinfo_length) }?;
                let host = unsafe { Pointer::text(host, host_length) }?;
                let port = unsafe { Pointer::optional_text(port, port_length) }?;
                Some(URIAuthority { userinfo: userinfo.map(str::to_string), host: host.to_string(), port: port.map(str::to_string) })
            } else {
                None
            };
            let reference = unsafe { Pointer::reference_mut(reference) }?;
            reference.authority = authority;
            Ok(())
        })())
    }

    /// Writes the path of `reference` into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_path(reference: *const URIReference, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write_text(out, reference.path.clone()) }
        })())
    }

    /// Sets the path of `reference` to the text at `text`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_set_path(reference: *mut URIReference, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let text = unsafe { Pointer::text(text, length) }?;
            let reference = unsafe { Pointer::reference_mut(reference) }?;
            reference.path = text.to_string();
            Ok(())
        })())
    }

    /// Writes whether `reference` has a query into `out_has` and the query into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_query(reference: *const URIReference, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write_optional_text(out_has, out, reference.query.as_deref()) }
        })())
    }

    /// Sets the query of `reference` to the text at `text`, or removes it if `text` is null.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_set_query(reference: *mut URIReference, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text or null.
            let text = unsafe { Pointer::optional_text(text, length) }?;
            let reference = unsafe { Pointer::reference_mut(reference) }?;
            reference.query = text.map(str::to_string);
            Ok(())
        })())
    }

    /// Writes whether `reference` has a fragment into `out_has` and the fragment into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_fragment(reference: *const URIReference, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle and writable pointers.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write_optional_text(out_has, out, reference.fragment.as_deref()) }
        })())
    }

    /// Sets the fragment of `reference` to the text at `text`, or removes it if `text` is null.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_set_fragment(reference: *mut URIReference, text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text or null.
            let text = unsafe { Pointer::optional_text(text, length) }?;
            let reference = unsafe { Pointer::reference_mut(reference) }?;
            reference.fragment = text.map(str::to_string);
            Ok(())
        })())
    }

    /// Writes whether `reference` is a relative reference (RFC 3986 §4.2, no scheme) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_is_relative(reference: *const URIReference, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write(out, reference.is_relative()) }
        })())
    }

    /// Writes whether `reference` is an absolute URI (RFC 3986 §4.3, a scheme and no fragment)
    /// into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_is_absolute(reference: *const URIReference, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write(out, reference.is_absolute()) }
        })())
    }

    /// Writes the target of `reference` resolved against `base` (RFC 3986 §5.2.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_resolve(reference: *const URIReference, base: *const URIReference, out: *mut *mut URIReference) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles and a writable pointer.
            let reference = unsafe { Pointer::reference(reference) }?;
            let base = unsafe { Pointer::reference(base) }?;
            Pointer::check_range(out, 1)?;
            let target = reference.resolve(base).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, target) }
        })())
    }

    /// Writes `reference` normalized by its syntax (RFC 3986 §6.2.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_normalize(reference: *const URIReference, out: *mut *mut URIReference) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let reference = unsafe { Pointer::reference(reference) }?;
            unsafe { Pointer::write_handle(out, reference.normalize()) }
        })())
    }

    /// Writes the path of `base` merged with the relative path at `path` (RFC 3986 §5.2.3) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_merge(base: *const URIReference, path: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(path, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes a valid handle, readable text and a writable buffer.
            let base = unsafe { Pointer::reference(base) }?;
            let path = unsafe { Pointer::text(path, length) }?;
            unsafe { Pointer::write_text(out, URIReference::merge(base, path)) }
        })())
    }

    /// Writes the path at `path` with its `.` and `..` segments removed (RFC 3986 §5.2.4) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_remove_dot_segments(path: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(path, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let path = unsafe { Pointer::text(path, length) }?;
            unsafe { Pointer::write_text(out, URIReference::remove_dot_segments(path)) }
        })())
    }

    /// Succeeds if the text at `scheme` is a scheme (RFC 3986 §3.1).
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_check_scheme(scheme: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text.
            let scheme = unsafe { Pointer::text(scheme, length) }?;
            URIReference::check_scheme(scheme).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether `byte` may stand in a path as it is into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_is_path_byte(byte: u8, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, URIReference::is_path_byte(byte)) })
    }

    /// Writes whether `byte` may stand in a query or a fragment as it is into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_reference_is_query_byte(byte: u8, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, URIReference::is_query_byte(byte)) })
    }

    /// Writes the authority of the text at `text` (RFC 3986 §3.2) as
    /// `umilib_codec_uri_uri_reference_authority` does, without `out_has`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_authority_parse(text: *const u8, length: usize, out_has_userinfo: *mut bool, out_userinfo: *mut Buffer, out_host: *mut Buffer, out_has_port: *mut bool, out_port: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let outputs = [Pointer::range(out_has_userinfo, 1), Pointer::range(out_userinfo, 1), Pointer::range(out_host, 1), Pointer::range(out_has_port, 1), Pointer::range(out_port, 1)];
            Pointer::check_ranges(&[Pointer::range(text, length)], &outputs)?;
            // SAFETY: the caller passes readable text and writable pointers.
            let text = unsafe { Pointer::text(text, length) }?;
            let authority = URIAuthority::parse(text).map_err(|error| error.to_status())?;
            unsafe { URIStatus::write_authority(&authority, out_has_userinfo, out_userinfo, out_host, out_has_port, out_port) }
        })())
    }

    /// Writes the form of the host at `host` (RFC 3986 §3.2.2: 0 IPv6, 1 IPvFuture, 2 IPv4,
    /// 3 RegName) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_authority_host_kind(host: *const u8, length: usize, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(host, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable pointer.
            let host = unsafe { Pointer::text(host, length) }?;
            let authority = URIAuthority { userinfo: None, host: host.to_string(), port: None };
            unsafe { Pointer::write(out, URIHostKindValue::encode(authority.host_kind())) }
        })())
    }

    /// Writes whether the bytes at `text` are an IPv4address (RFC 3986 §3.2.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_authority_is_ipv4(text: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            unsafe { Pointer::write(out, URIAuthority::is_ipv4(text)) }
        })())
    }

    /// Writes whether the bytes at `text` are an IPv6address (RFC 3986 §3.2.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_authority_is_ipv6(text: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            unsafe { Pointer::write(out, URIAuthority::is_ipv6(text)) }
        })())
    }

    /// Writes whether the bytes at `text` are an IPvFuture (RFC 3986 §3.2.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_authority_is_ipvfuture(text: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            unsafe { Pointer::write(out, URIAuthority::is_ipvfuture(text)) }
        })())
    }

    /// Writes the `length` bytes at `data` with every octet not among the `keep_length` bytes
    /// at `keep` percent-encoded (RFC 3986 §2.1) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_encode(data: *const u8, length: usize, keep: *const u8, keep_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length), Pointer::range(keep, keep_length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            let keep = unsafe { Pointer::slice(keep, keep_length) }?;
            unsafe { Pointer::write_text(out, URIPercent::encode(data, |byte| keep.contains(&byte))) }
        })())
    }

    /// Writes the `length` bytes at `data` with every octet but the unreserved percent-encoded into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_encode_component(data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(data, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write_text(out, URIPercent::encode_component(data)) }
        })())
    }

    /// Writes the octets of the `length` bytes at `text`, percent-encodings decoded, into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_decode(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let data = URIPercent::decode(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes the UTF-8 text of the `length` bytes at `text`, percent-encodings decoded, into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_decode_text(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let decoded = URIPercent::decode_text(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, decoded) }
        })())
    }

    /// Succeeds if every `%` of the `length` bytes at `text` begins a percent-encoding.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_check(text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes.
            let text = unsafe { Pointer::slice(text, length) }?;
            URIPercent::check(text).map_err(|error| error.to_status())
        })())
    }

    /// Writes whether `byte` is unreserved (RFC 3986 §2.3) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_is_unreserved(byte: u8, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, URIPercent::is_unreserved(byte)) })
    }

    /// Writes whether `byte` is a sub-delimiter (RFC 3986 §2.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_is_sub_delim(byte: u8, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, URIPercent::is_sub_delim(byte)) })
    }

    /// Writes whether `byte` is a general delimiter (RFC 3986 §2.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_is_gen_delim(byte: u8, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, URIPercent::is_gen_delim(byte)) })
    }

    /// Writes whether `byte` is a pchar other than a percent-encoding (RFC 3986 §3.3) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_is_pchar(byte: u8, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, URIPercent::is_pchar(byte)) })
    }

    /// Writes whether `byte` is a hexadecimal digit into `out_found` and its value into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_percent_digit(byte: u8, out_found: *mut bool, out: *mut u8) -> *const Status {
        // SAFETY: the caller passes writable pointers.
        Status::from_result(unsafe { Pointer::write_optional(URIPercent::digit(byte), out_found, out) })
    }

    /// Writes an empty list of name and value pairs into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_pairs_new(out: *mut *mut Vec<(String, String)>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::<(String, String)>::new()) })
    }

    /// Releases a list of pairs. Does nothing if `pairs` is null.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_pairs_free(pairs: *mut Vec<(String, String)>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(pairs) }
    }

    /// Appends the pair of the UTF-8 `name` and `value`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_pairs_push(pairs: *mut Vec<(String, String)>, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable text.
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::text(value, value_length) }?;
            let pairs = unsafe { Pointer::reference_mut(pairs) }?;
            pairs.push((name.to_string(), value.to_string()));
            Ok(())
        })())
    }

    /// Writes the number of pairs of the list into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_pairs_count(pairs: *const Vec<(String, String)>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let pairs = unsafe { Pointer::reference(pairs) }?;
            unsafe { Pointer::write(out, pairs.len()) }
        })())
    }

    /// Writes the name of the pair `index` into `out_name` and its value into `out_value`;
    /// fails with NoSuchPair past the end.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_pairs_get(pairs: *const Vec<(String, String)>, index: usize, out_name: *mut Buffer, out_value: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[], &[Pointer::range(out_name, 1), Pointer::range(out_value, 1)])?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_value, 1)?;
            // SAFETY: the caller passes a valid handle and writable buffers.
            let pairs = unsafe { Pointer::reference(pairs) }?;
            let (name, value) = pairs.get(index).ok_or(&URIStatus::NO_SUCH_PAIR)?;
            unsafe { Pointer::write_text(out_name, name.clone()) }?;
            unsafe { Pointer::write_text(out_value, value.clone()) }
        })())
    }

    /// Writes the pairs of the `length` bytes at `input` (WHATWG URL Standard §5.1; octets that
    /// are not UTF-8 fail) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_parse(input: *const u8, length: usize, out: *mut *mut Vec<(String, String)>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let input = unsafe { Pointer::slice(input, length) }?;
            Pointer::check_range(out, 1)?;
            let pairs = URIForm::parse(input).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, pairs) }
        })())
    }

    /// Writes the text of one name or value at `text` (`+` a space, percent-encodings decoded) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_decode(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable bytes and a writable buffer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let decoded = URIForm::decode(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, decoded) }
        })())
    }

    /// Writes the UTF-8 `text` as one name or value of the form encoding (WHATWG URL Standard §5.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_encode_text(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            Pointer::check_ranges(&[Pointer::range(text, length)], &[Pointer::range(out, 1)])?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let text = unsafe { Pointer::text(text, length) }?;
            unsafe { Pointer::write_text(out, URIForm::encode_text(text)) }
        })())
    }

    /// Writes `pairs` in the form encoding (`name=value` joined by `&`) into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_encode(pairs: *const Vec<(String, String)>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable buffer.
            let pairs = unsafe { Pointer::reference(pairs) }?;
            unsafe { Pointer::write_text(out, URIForm::encode(pairs)) }
        })())
    }

    /// Writes whether the form serializer keeps `byte` as it is into `out`.
    pub unsafe extern "C" fn umilib_codec_uri_uri_form_is_kept(byte: u8, out: *mut bool) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, URIForm::is_kept(byte)) })
    }
}

impl URIStatus {
    /// Writes the components of `authority` into the outputs of
    /// `umilib_codec_uri_uri_authority_parse`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write_authority(
        authority: &URIAuthority,
        out_has_userinfo: *mut bool,
        out_userinfo: *mut Buffer,
        out_host: *mut Buffer,
        out_has_port: *mut bool,
        out_port: *mut Buffer,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out_has_userinfo, 1)?;
        Pointer::check_range(out_userinfo, 1)?;
        Pointer::check_range(out_host, 1)?;
        Pointer::check_range(out_has_port, 1)?;
        Pointer::check_range(out_port, 1)?;
        // SAFETY: guaranteed by the caller; every pointer is non-null.
        unsafe { Pointer::write_optional_text(out_has_userinfo, out_userinfo, authority.userinfo.as_deref()) }?;
        unsafe { Pointer::write_text(out_host, authority.host.clone()) }?;
        unsafe { Pointer::write_optional_text(out_has_port, out_port, authority.port.as_deref()) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "uri",
    definitions: &[
        Definition::Opaque { name: "umilib_codec_uri_URIReference", documentation: " A URI reference of RFC 3986." },
        Definition::Opaque {
            name: "umilib_codec_uri_URIFormPairs",
            documentation: " The name and value pairs of the form encoding.",
        },
    ],
    functions: &Function::concat::<{ FUNCTIONS.len() }>(&[FUNCTIONS]),
    modules: &[],
};
