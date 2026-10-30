use std::collections::BTreeSet;
use std::fs;
use std::mem::{align_of, size_of};
use std::path::PathBuf;

use umilib::ffi::{Buffer, CHeader, Definition, Manifest, Module, Type};

use super::Check;

fn prefix(path: &[&str]) -> String {
    if path.is_empty() { String::from("umilib_") } else { format!("umilib_{}_", path.join("_")) }
}

#[test]
fn names_follow_the_module_path_and_are_unique() {
    let mut names = BTreeSet::new();
    Manifest::ROOT.visit(|path, module: &Module| {
        let prefix = prefix(path);
        for function in module.functions {
            assert!(function.name.starts_with(&prefix), "{} must start with {prefix}", function.name);
            assert!(
                !function.name.chars().any(|character| character.is_ascii_uppercase()),
                "{} must be snake_case",
                function.name
            );
            assert!(names.insert(function.name), "{} is exported twice", function.name);
            assert!(!function.documentation.trim().is_empty(), "{} is undocumented", function.name);
        }
        for definition in module.definitions {
            let rest = definition.name().strip_prefix(prefix.as_str());
            assert!(
                rest.is_some_and(|rest| rest.starts_with(|character: char| character.is_ascii_uppercase())),
                "{} must be {prefix}<RustType>",
                definition.name()
            );
            assert!(names.insert(definition.name()), "{} is declared twice", definition.name());
        }
    });
}

#[test]
fn names_are_not_reserved_in_c_or_cpp() {
    const RESERVED: &[&str] = &[
        "alignas",
        "alignof",
        "and",
        "asm",
        "auto",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "class",
        "const",
        "constexpr",
        "continue",
        "default",
        "delete",
        "do",
        "double",
        "else",
        "enum",
        "explicit",
        "export",
        "extern",
        "false",
        "float",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "mutable",
        "namespace",
        "new",
        "noexcept",
        "not",
        "nullptr",
        "operator",
        "or",
        "private",
        "protected",
        "public",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "template",
        "this",
        "throw",
        "true",
        "try",
        "typedef",
        "typeid",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "while",
        "xor",
    ];
    Manifest::ROOT.visit(|_, module| {
        let mut names: Vec<(&str, &str)> = Vec::new();
        for function in module.functions {
            names.extend(function.parameters.iter().map(|parameter| (function.name, parameter.name)));
        }
        for definition in module.definitions {
            match definition {
                Definition::Structure { name, fields, .. } => {
                    names.extend(fields.iter().map(|field| (*name, field.name)))
                }
                Definition::Callback { name, parameters, .. } => {
                    names.extend(parameters.iter().map(|parameter| (*name, parameter.name)))
                }
                Definition::Opaque { .. } => {}
            }
        }
        for (owner, name) in names {
            assert!(!RESERVED.contains(&name), "{owner} uses the reserved name {name}");
        }
    });
}

#[test]
fn every_named_type_is_declared() {
    let mut declared = BTreeSet::new();
    let mut used = BTreeSet::new();
    fn collect(value: &Type, used: &mut BTreeSet<&'static str>) {
        match value {
            Type::Named(name) => {
                used.insert(*name);
            }
            Type::Pointer { target, .. } => collect(target, used),
            Type::Array { element, .. } => collect(element, used),
            _ => {}
        }
    }
    Manifest::ROOT.visit(|_, module| {
        for definition in module.definitions {
            declared.insert(definition.name());
            match definition {
                Definition::Structure { fields, .. } => {
                    fields.iter().for_each(|field| collect(&field.value, &mut used))
                }
                Definition::Callback { parameters, returns, .. } => {
                    parameters.iter().for_each(|parameter| collect(&parameter.value, &mut used));
                    collect(returns, &mut used);
                }
                Definition::Opaque { .. } => {}
            }
        }
        for function in module.functions {
            function.parameters.iter().for_each(|parameter| collect(&parameter.value, &mut used));
            collect(&function.returns, &mut used);
        }
    });
    let undeclared: Vec<_> = used.difference(&declared).collect();
    assert!(undeclared.is_empty(), "undeclared types: {undeclared:?}");
}

#[test]
fn void_is_only_a_return_type_or_a_pointer_target() {
    Manifest::ROOT.visit(|_, module| {
        for function in module.functions {
            for parameter in function.parameters {
                assert_ne!(parameter.value, Type::Void, "{}({}) is void", function.name, parameter.name);
            }
        }
    });
}

#[test]
#[cfg_attr(
    miri,
    ignore = "builds the manifest of the whole library: too slow under Miri (safe Rust, apart from the buffer other tests reach)"
)]
fn manifest_json_is_exported_and_matches_the_rust_manifest() {
    let mut buffer = Buffer::EMPTY;
    Check::ok(unsafe { umilib::ffi::umilib_ffi_manifest(&mut buffer) });
    assert_eq!(buffer.as_slice(), Manifest::json(&Manifest::ROOT).as_bytes());
    let text = std::str::from_utf8(buffer.as_slice()).unwrap();
    assert!(text.starts_with("{\"name\":\"umilib\""));
    assert_eq!(text.matches('{').count(), text.matches('}').count());
    unsafe { umilib::ffi::umilib_ffi_buffer_free(&mut buffer) };
    assert!(buffer.as_slice().is_empty());
    // Releasing an empty or null buffer does nothing.
    unsafe { umilib::ffi::umilib_ffi_buffer_free(&mut buffer) };
    unsafe { umilib::ffi::umilib_ffi_buffer_free(std::ptr::null_mut()) };
    Check::fails(unsafe { umilib::ffi::umilib_ffi_manifest(std::ptr::null_mut()) }, "ffi", "NullPointer");
}

#[test]
fn version_matches_the_crate() {
    let version = unsafe { std::ffi::CStr::from_ptr(umilib::ffi::umilib_version().cast()) };
    assert_eq!(version.to_str().unwrap(), umilib::VERSION);
}

#[test]
fn json_strings_are_escaped() {
    let mut output = String::new();
    Manifest::write_json_string(&mut output, "a\"b\\c\nd\u{1}é");
    assert_eq!(output, "\"a\\\"b\\\\c\\nd\\u0001é\"");
}

#[test]
fn integers_split_into_halves() {
    use umilib::ffi::{I128, U128};
    let value = 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10u128;
    assert_eq!(U128::from(value), U128 { high: 0x0102_0304_0506_0708, low: 0x090A_0B0C_0D0E_0F10 });
    assert_eq!(u128::from(U128::from(value)), value);
    assert_eq!(I128::from(-1i128), I128 { high: -1, low: u64::MAX });
    assert_eq!(i128::from(I128::from(i128::MIN)), i128::MIN);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "builds the manifest of the whole library: too slow under Miri (safe Rust, apart from the buffer other tests reach)"
)]
fn headers_match_the_manifest() {
    let include = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("include");
    let bless = std::env::var_os("UMILIB_BLESS").is_some();
    let headers = CHeader::generate(&Manifest::ROOT);
    // `include/` describes the build with every feature: the headers of a
    // module and its parents list only the enabled children, so other builds
    // can neither be compared with it nor bless it.
    if !cfg!(umilib_all_features) {
        assert!(!bless, "UMILIB_BLESS needs --all-features");
        return;
    }
    for header in &headers {
        let path = include.join(&header.path);
        if bless {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &header.text).unwrap();
        } else {
            let existing = fs::read_to_string(&path).unwrap_or_default();
            assert!(existing == header.text, "{} is out of date; run with UMILIB_BLESS=1", path.display());
        }
    }
    // With every feature enabled, every header file must come from the manifest.
    #[cfg(umilib_all_features)]
    {
        let expected: BTreeSet<PathBuf> = headers.iter().map(|header| include.join(&header.path)).collect();
        let mut stack = vec![include.clone()];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path()));
            } else if !expected.contains(&path) {
                if bless {
                    fs::remove_file(&path).unwrap();
                } else {
                    panic!("{} does not come from the manifest; run with UMILIB_BLESS=1", path.display());
                }
            }
        }
    }
}

#[test]
fn header_types_are_spelled_in_c() {
    assert_eq!(CHeader::type_name(&Type::Pointer { target: &Type::U8, mutable: false }), "const uint8_t*");
    assert_eq!(CHeader::type_name(&Type::Pointer { target: &Type::Named("x"), mutable: true }), "x*");
    static POINTER: Type = Type::Pointer { target: &Type::Named("x"), mutable: true };
    assert_eq!(CHeader::type_name(&Type::Pointer { target: &POINTER, mutable: true }), "x**");
    assert_eq!(CHeader::type_name(&Type::Pointer { target: &POINTER, mutable: false }), "x* const*");
    assert_eq!(CHeader::declaration(&Type::Array { element: &Type::U8, length: 16 }, "salt"), "uint8_t salt[16]");
    assert_eq!(CHeader::declaration(&Type::U32, "depth"), "uint32_t depth");
    assert_eq!(CHeader::path_of(&[]), "umilib.h");
    assert_eq!(CHeader::path_of(&["platform", "bench"]), "umilib/platform/bench.h");
    assert_eq!(CHeader::guard_of("umilib/platform/bench.h"), "UMILIB_PLATFORM_BENCH_H");
}

#[test]
fn arrays_are_only_structure_fields() {
    fn contains_array(value: &Type) -> bool {
        match value {
            Type::Array { .. } => true,
            Type::Pointer { target, .. } => contains_array(target),
            _ => false,
        }
    }
    Manifest::ROOT.visit(|_, module| {
        for function in module.functions {
            for parameter in function.parameters {
                assert!(!contains_array(&parameter.value), "{} takes an array", function.name);
            }
            assert!(!contains_array(&function.returns), "{} returns an array", function.name);
        }
        for definition in module.definitions {
            if let Definition::Callback { name, parameters, returns, .. } = definition {
                assert!(parameters.iter().all(|parameter| !contains_array(&parameter.value)), "{name}");
                assert!(!contains_array(returns), "{name}");
            }
        }
    });
}

/// The C layout (size and alignment) of `value`, from the definitions of the manifest.
fn layout(
    value: &Type,
    structures: &std::collections::BTreeMap<&str, &'static [umilib::ffi::Parameter]>,
) -> (usize, usize) {
    match value {
        Type::Bool | Type::Char | Type::U8 | Type::I8 => (1, 1),
        Type::U16 | Type::I16 => (2, 2),
        Type::U32 | Type::I32 | Type::F32 => (4, 4),
        Type::U64 | Type::I64 | Type::F64 => (size_of::<u64>(), align_of::<u64>()),
        Type::USize | Type::ISize | Type::Pointer { .. } => (size_of::<usize>(), align_of::<usize>()),
        Type::Array { element, length } => {
            let (size, align) = layout(element, structures);
            (size * length, align)
        }
        Type::Named(name) => {
            let fields = structures.get(name).unwrap_or_else(|| panic!("{name} is not a structure"));
            let (mut size, mut align) = (0usize, 1usize);
            for field in fields.iter() {
                let (field_size, field_align) = layout(&field.value, structures);
                size = size.next_multiple_of(field_align) + field_size;
                align = align.max(field_align);
            }
            (size.next_multiple_of(align), align)
        }
        Type::Void => (0, 1),
    }
}

/// The structures of the manifest have the layout of their Rust types, so
/// the headers and ctypes read the fields Rust writes.
#[test]
fn structures_have_the_layout_of_their_rust_types() {
    let mut structures = std::collections::BTreeMap::new();
    Manifest::ROOT.visit(|_, module| {
        for definition in module.definitions {
            if let Definition::Structure { name, fields, .. } = definition {
                structures.insert(*name, *fields);
            }
        }
    });
    let expected: &[(&str, usize, usize)] = &[
        ("umilib_ffi_Buffer", size_of::<Buffer>(), align_of::<Buffer>()),
        ("umilib_ffi_U128", size_of::<umilib::ffi::U128>(), align_of::<umilib::ffi::U128>()),
        #[cfg(umilib_feature = "hash-blake-v2")]
        (
            "umilib_hash_blake_v2_BLAKE2bParameters",
            size_of::<umilib::hash::blake::v2::BLAKE2bParameters>(),
            align_of::<umilib::hash::blake::v2::BLAKE2bParameters>(),
        ),
        #[cfg(umilib_feature = "hash-blake-v2")]
        (
            "umilib_hash_blake_v2_BLAKE2sParameters",
            size_of::<umilib::hash::blake::v2::BLAKE2sParameters>(),
            align_of::<umilib::hash::blake::v2::BLAKE2sParameters>(),
        ),
        #[cfg(umilib_feature = "hash-crc")]
        (
            "umilib_hash_crc_CRCParameters",
            size_of::<umilib::ffi::hash::crc::CRCParameters>(),
            align_of::<umilib::ffi::hash::crc::CRCParameters>(),
        ),
        #[cfg(umilib_feature = "codec")]
        ("umilib_codec_Progress", size_of::<umilib::codec::Progress>(), align_of::<umilib::codec::Progress>()),
        #[cfg(umilib_feature = "crypto-random")]
        (
            "umilib_crypto_random_DRBGConfig",
            size_of::<umilib::crypto::random::DRBGConfig>(),
            align_of::<umilib::crypto::random::DRBGConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-ip")]
        (
            "umilib_protocol_ip_IPv4Address",
            size_of::<umilib::protocol::ip::IPv4Address>(),
            align_of::<umilib::protocol::ip::IPv4Address>(),
        ),
        #[cfg(umilib_feature = "protocol-ip")]
        (
            "umilib_protocol_ip_IPv6Address",
            size_of::<umilib::protocol::ip::IPv6Address>(),
            align_of::<umilib::protocol::ip::IPv6Address>(),
        ),
        #[cfg(umilib_feature = "protocol-ip")]
        (
            "umilib_protocol_ip_InternetChecksum",
            size_of::<umilib::protocol::ip::InternetChecksum>(),
            align_of::<umilib::protocol::ip::InternetChecksum>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v4")]
        (
            "umilib_protocol_ip_v4_IPv4Options",
            size_of::<umilib::protocol::ip::v4::IPv4Options>(),
            align_of::<umilib::protocol::ip::v4::IPv4Options>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v4")]
        (
            "umilib_protocol_ip_v4_IPv4Header",
            size_of::<umilib::protocol::ip::v4::IPv4Header>(),
            align_of::<umilib::protocol::ip::v4::IPv4Header>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v4")]
        (
            "umilib_protocol_ip_v4_IPv4ReassemblyConfig",
            size_of::<umilib::ffi::protocol::ip::v4::FFIIPv4ReassemblyConfig>(),
            align_of::<umilib::ffi::protocol::ip::v4::FFIIPv4ReassemblyConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v4")]
        (
            "umilib_protocol_ip_v4_IPv4ReassemblyKey",
            size_of::<umilib::protocol::ip::v4::IPv4ReassemblyKey>(),
            align_of::<umilib::protocol::ip::v4::IPv4ReassemblyKey>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v6")]
        (
            "umilib_protocol_ip_v6_IPv6Header",
            size_of::<umilib::protocol::ip::v6::IPv6Header>(),
            align_of::<umilib::protocol::ip::v6::IPv6Header>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v6")]
        (
            "umilib_protocol_ip_v6_IPv6FragmentHeader",
            size_of::<umilib::protocol::ip::v6::IPv6FragmentHeader>(),
            align_of::<umilib::protocol::ip::v6::IPv6FragmentHeader>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v6")]
        (
            "umilib_protocol_ip_v6_IPv6ReassemblyConfig",
            size_of::<umilib::ffi::protocol::ip::v6::FFIIPv6ReassemblyConfig>(),
            align_of::<umilib::ffi::protocol::ip::v6::FFIIPv6ReassemblyConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-ip-v6")]
        (
            "umilib_protocol_ip_v6_IPv6ReassemblyKey",
            size_of::<umilib::protocol::ip::v6::IPv6ReassemblyKey>(),
            align_of::<umilib::protocol::ip::v6::IPv6ReassemblyKey>(),
        ),
        #[cfg(umilib_feature = "protocol-ethernet")]
        (
            "umilib_protocol_ethernet_MACAddress",
            size_of::<umilib::protocol::ethernet::MACAddress>(),
            align_of::<umilib::protocol::ethernet::MACAddress>(),
        ),
        #[cfg(umilib_feature = "protocol-ethernet")]
        (
            "umilib_protocol_ethernet_VLANTag",
            size_of::<umilib::protocol::ethernet::VLANTag>(),
            align_of::<umilib::protocol::ethernet::VLANTag>(),
        ),
        #[cfg(umilib_feature = "protocol-ethernet")]
        (
            "umilib_protocol_ethernet_EthernetHeader",
            size_of::<umilib::ffi::protocol::ethernet::FFIEthernetHeader>(),
            align_of::<umilib::ffi::protocol::ethernet::FFIEthernetHeader>(),
        ),
        #[cfg(umilib_feature = "protocol-arp")]
        (
            "umilib_protocol_arp_ARPPacket",
            size_of::<umilib::protocol::arp::ARPPacket>(),
            align_of::<umilib::protocol::arp::ARPPacket>(),
        ),
        #[cfg(umilib_feature = "auth-oauth")]
        (
            "umilib_auth_oauth_OAuthServerLimits",
            size_of::<umilib::ffi::auth::oauth::FFIOAuthServerLimits>(),
            align_of::<umilib::ffi::auth::oauth::FFIOAuthServerLimits>(),
        ),
        #[cfg(umilib_feature = "protocol-arp")]
        (
            "umilib_protocol_arp_ARPConfig",
            size_of::<umilib::ffi::protocol::arp::FFIARPConfig>(),
            align_of::<umilib::ffi::protocol::arp::FFIARPConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-icmp")]
        (
            "umilib_protocol_icmp_ICMPHeader",
            size_of::<umilib::ffi::protocol::icmp::FFIICMPHeader>(),
            align_of::<umilib::ffi::protocol::icmp::FFIICMPHeader>(),
        ),
        #[cfg(umilib_feature = "protocol-ip")]
        (
            "umilib_protocol_ip_IPEndpoint",
            size_of::<umilib::ffi::protocol::ip::FFIIPEndpoint>(),
            align_of::<umilib::ffi::protocol::ip::FFIIPEndpoint>(),
        ),
        #[cfg(umilib_feature = "protocol-ip")]
        (
            "umilib_protocol_ip_IPEndpointPattern",
            size_of::<umilib::ffi::protocol::ip::FFIIPEndpointPattern>(),
            align_of::<umilib::ffi::protocol::ip::FFIIPEndpointPattern>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPHeader",
            size_of::<umilib::protocol::tcp::TCPHeader>(),
            align_of::<umilib::protocol::tcp::TCPHeader>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPSegment",
            size_of::<umilib::ffi::protocol::tcp::FFITCPSegment>(),
            align_of::<umilib::ffi::protocol::tcp::FFITCPSegment>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPSACKBlock",
            size_of::<umilib::protocol::tcp::TCPSACKBlock>(),
            align_of::<umilib::protocol::tcp::TCPSACKBlock>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPTimestamps",
            size_of::<umilib::protocol::tcp::TCPTimestamps>(),
            align_of::<umilib::protocol::tcp::TCPTimestamps>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPOptionSet",
            size_of::<umilib::ffi::protocol::tcp::FFITCPOptionSet>(),
            align_of::<umilib::ffi::protocol::tcp::FFITCPOptionSet>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPRetransmissionTimer",
            size_of::<umilib::ffi::protocol::tcp::FFITCPRetransmissionTimer>(),
            align_of::<umilib::ffi::protocol::tcp::FFITCPRetransmissionTimer>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPConfig",
            size_of::<umilib::ffi::protocol::tcp::FFITCPConfig>(),
            align_of::<umilib::ffi::protocol::tcp::FFITCPConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPConnectionInfo",
            size_of::<umilib::ffi::protocol::tcp::FFITCPConnectionInfo>(),
            align_of::<umilib::ffi::protocol::tcp::FFITCPConnectionInfo>(),
        ),
        #[cfg(umilib_feature = "protocol-tcp")]
        (
            "umilib_protocol_tcp_TCPRule",
            size_of::<umilib::ffi::protocol::tcp::FFITCPRule>(),
            align_of::<umilib::ffi::protocol::tcp::FFITCPRule>(),
        ),
        #[cfg(umilib_feature = "codec-hpack")]
        (
            "umilib_codec_hpack_HPACKEncoderConfig",
            size_of::<umilib::codec::hpack::HPACKEncoderConfig>(),
            align_of::<umilib::codec::hpack::HPACKEncoderConfig>(),
        ),
        #[cfg(umilib_feature = "codec-hpack")]
        (
            "umilib_codec_hpack_HPACKDecoderConfig",
            size_of::<umilib::codec::hpack::HPACKDecoderConfig>(),
            align_of::<umilib::codec::hpack::HPACKDecoderConfig>(),
        ),
        #[cfg(umilib_feature = "codec-mail")]
        (
            "umilib_codec_mail_MailConfig",
            size_of::<umilib::codec::mail::MailConfig>(),
            align_of::<umilib::codec::mail::MailConfig>(),
        ),
        #[cfg(umilib_feature = "codec-mail")]
        (
            "umilib_codec_mail_MailDate",
            size_of::<umilib::codec::mail::MailDate>(),
            align_of::<umilib::codec::mail::MailDate>(),
        ),
        #[cfg(umilib_feature = "codec-qpack")]
        (
            "umilib_codec_qpack_QPACKEncoderConfig",
            size_of::<umilib::codec::qpack::QPACKEncoderConfig>(),
            align_of::<umilib::codec::qpack::QPACKEncoderConfig>(),
        ),
        #[cfg(umilib_feature = "codec-qpack")]
        (
            "umilib_codec_qpack_QPACKDecoderConfig",
            size_of::<umilib::codec::qpack::QPACKDecoderConfig>(),
            align_of::<umilib::codec::qpack::QPACKDecoderConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-http")]
        (
            "umilib_protocol_http_HTTPConfig",
            size_of::<umilib::protocol::http::HTTPConfig>(),
            align_of::<umilib::protocol::http::HTTPConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-http")]
        (
            "umilib_protocol_http_HTTPEvent",
            size_of::<umilib::ffi::protocol::http::FFIHTTPEvent>(),
            align_of::<umilib::ffi::protocol::http::FFIHTTPEvent>(),
        ),
        #[cfg(umilib_feature = "protocol-http-v1")]
        (
            "umilib_protocol_http_v1_H1Limits",
            size_of::<umilib::ffi::protocol::http::v1::FFIH1Limits>(),
            align_of::<umilib::ffi::protocol::http::v1::FFIH1Limits>(),
        ),
        #[cfg(umilib_feature = "protocol-http-v2")]
        (
            "umilib_protocol_http_v2_H2Config",
            size_of::<umilib::ffi::protocol::http::v2::FFIH2Config>(),
            align_of::<umilib::ffi::protocol::http::v2::FFIH2Config>(),
        ),
        #[cfg(umilib_feature = "protocol-http-v3")]
        (
            "umilib_protocol_http_v3_H3Config",
            size_of::<umilib::protocol::http::v3::H3Config>(),
            align_of::<umilib::protocol::http::v3::H3Config>(),
        ),
        #[cfg(umilib_feature = "protocol-websocket")]
        (
            "umilib_protocol_websocket_WebSocketConfig",
            size_of::<umilib::protocol::websocket::WebSocketConfig>(),
            align_of::<umilib::protocol::websocket::WebSocketConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-websocket")]
        (
            "umilib_protocol_websocket_WebSocketDeflateParameters",
            size_of::<umilib::ffi::protocol::websocket::FFIWebSocketDeflateParameters>(),
            align_of::<umilib::ffi::protocol::websocket::FFIWebSocketDeflateParameters>(),
        ),
        #[cfg(umilib_feature = "protocol-websocket")]
        (
            "umilib_protocol_websocket_WebSocketEvent",
            size_of::<umilib::ffi::protocol::websocket::FFIWebSocketEvent>(),
            align_of::<umilib::ffi::protocol::websocket::FFIWebSocketEvent>(),
        ),
        #[cfg(umilib_feature = "protocol-quic")]
        (
            "umilib_protocol_quic_QUICLimits",
            size_of::<umilib::ffi::protocol::quic::FFIQUICLimits>(),
            align_of::<umilib::ffi::protocol::quic::FFIQUICLimits>(),
        ),
        #[cfg(umilib_feature = "protocol-quic")]
        (
            "umilib_protocol_quic_QUICSession",
            size_of::<umilib::ffi::protocol::quic::FFIQUICSession>(),
            align_of::<umilib::ffi::protocol::quic::FFIQUICSession>(),
        ),
        #[cfg(umilib_feature = "protocol-quic")]
        (
            "umilib_protocol_quic_QUICEvent",
            size_of::<umilib::ffi::protocol::quic::FFIQUICEvent>(),
            align_of::<umilib::ffi::protocol::quic::FFIQUICEvent>(),
        ),
        #[cfg(umilib_feature = "protocol-tls")]
        (
            "umilib_protocol_tls_TLSLimits",
            size_of::<umilib::ffi::protocol::tls::FFITLSLimits>(),
            align_of::<umilib::ffi::protocol::tls::FFITLSLimits>(),
        ),
        #[cfg(umilib_feature = "protocol-tls")]
        (
            "umilib_protocol_tls_TLSClientOptions",
            size_of::<umilib::ffi::protocol::tls::FFITLSClientOptions>(),
            align_of::<umilib::ffi::protocol::tls::FFITLSClientOptions>(),
        ),
        #[cfg(umilib_feature = "protocol-tls")]
        (
            "umilib_protocol_tls_TLSServerOptions",
            size_of::<umilib::ffi::protocol::tls::FFITLSServerOptions>(),
            align_of::<umilib::ffi::protocol::tls::FFITLSServerOptions>(),
        ),
        #[cfg(umilib_feature = "protocol-tls")]
        (
            "umilib_protocol_tls_TLSSession",
            size_of::<umilib::ffi::protocol::tls::FFITLSSession>(),
            align_of::<umilib::ffi::protocol::tls::FFITLSSession>(),
        ),
        #[cfg(umilib_feature = "protocol-udp")]
        (
            "umilib_protocol_udp_UDPHeader",
            size_of::<umilib::protocol::udp::UDPHeader>(),
            align_of::<umilib::protocol::udp::UDPHeader>(),
        ),
        #[cfg(umilib_feature = "protocol-udp")]
        (
            "umilib_protocol_udp_UDPDatagram",
            size_of::<umilib::ffi::protocol::udp::FFIUDPDatagram>(),
            align_of::<umilib::ffi::protocol::udp::FFIUDPDatagram>(),
        ),
        #[cfg(umilib_feature = "protocol-udp")]
        (
            "umilib_protocol_udp_UDPRule",
            size_of::<umilib::ffi::protocol::udp::FFIUDPRule>(),
            align_of::<umilib::ffi::protocol::udp::FFIUDPRule>(),
        ),
        #[cfg(umilib_feature = "protocol-icmp-v6")]
        (
            "umilib_protocol_icmp_v6_NDPRouterAdvertisement",
            size_of::<umilib::ffi::protocol::icmp::v6::FFINDPRouterAdvertisement>(),
            align_of::<umilib::ffi::protocol::icmp::v6::FFINDPRouterAdvertisement>(),
        ),
        #[cfg(umilib_feature = "protocol-icmp-v6")]
        (
            "umilib_protocol_icmp_v6_NDPNeighborAdvertisement",
            size_of::<umilib::ffi::protocol::icmp::v6::FFINDPNeighborAdvertisement>(),
            align_of::<umilib::ffi::protocol::icmp::v6::FFINDPNeighborAdvertisement>(),
        ),
        #[cfg(umilib_feature = "protocol-icmp-v6")]
        (
            "umilib_protocol_icmp_v6_NDPPrefixInformation",
            size_of::<umilib::protocol::icmp::v6::NDPPrefixInformation>(),
            align_of::<umilib::protocol::icmp::v6::NDPPrefixInformation>(),
        ),
        #[cfg(umilib_feature = "protocol-icmp-v6")]
        (
            "umilib_protocol_icmp_v6_NDPRouteInformation",
            size_of::<umilib::protocol::icmp::v6::NDPRouteInformation>(),
            align_of::<umilib::protocol::icmp::v6::NDPRouteInformation>(),
        ),
        #[cfg(umilib_feature = "protocol-icmp-v6")]
        (
            "umilib_protocol_icmp_v6_NeighborConfig",
            size_of::<umilib::ffi::protocol::icmp::v6::FFINeighborConfig>(),
            align_of::<umilib::ffi::protocol::icmp::v6::FFINeighborConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-smtp")]
        (
            "umilib_protocol_smtp_SMTPConfig",
            size_of::<umilib::ffi::protocol::smtp::FFISMTPConfig>(),
            align_of::<umilib::ffi::protocol::smtp::FFISMTPConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-smtp")]
        (
            "umilib_protocol_smtp_SMTPServerConfig",
            size_of::<umilib::ffi::protocol::smtp::FFISMTPServerConfig>(),
            align_of::<umilib::ffi::protocol::smtp::FFISMTPServerConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-pop-v3")]
        (
            "umilib_protocol_pop_v3_POP3Config",
            size_of::<umilib::ffi::protocol::pop::v3::FFIPOP3Config>(),
            align_of::<umilib::ffi::protocol::pop::v3::FFIPOP3Config>(),
        ),
        #[cfg(umilib_feature = "protocol-pop-v3")]
        (
            "umilib_protocol_pop_v3_POP3ServerConfig",
            size_of::<umilib::ffi::protocol::pop::v3::FFIPOP3ServerConfig>(),
            align_of::<umilib::ffi::protocol::pop::v3::FFIPOP3ServerConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-imap-v4")]
        (
            "umilib_protocol_imap_v4_IMAPConfig",
            size_of::<umilib::ffi::protocol::imap::v4::FFIIMAPConfig>(),
            align_of::<umilib::ffi::protocol::imap::v4::FFIIMAPConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-imap-v4")]
        (
            "umilib_protocol_imap_v4_IMAPServerConfig",
            size_of::<umilib::ffi::protocol::imap::v4::FFIIMAPServerConfig>(),
            align_of::<umilib::ffi::protocol::imap::v4::FFIIMAPServerConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-ftp")]
        (
            "umilib_protocol_ftp_FTPDataAddress",
            size_of::<umilib::ffi::protocol::ftp::FFIFTPDataAddress>(),
            align_of::<umilib::ffi::protocol::ftp::FFIFTPDataAddress>(),
        ),
        #[cfg(umilib_feature = "protocol-ftp")]
        (
            "umilib_protocol_ftp_FTPConfig",
            size_of::<umilib::ffi::protocol::ftp::FFIFTPConfig>(),
            align_of::<umilib::ffi::protocol::ftp::FFIFTPConfig>(),
        ),
        #[cfg(umilib_feature = "protocol-ftp")]
        (
            "umilib_protocol_ftp_FTPServerConfig",
            size_of::<umilib::ffi::protocol::ftp::FFIFTPServerConfig>(),
            align_of::<umilib::ffi::protocol::ftp::FFIFTPServerConfig>(),
        ),
    ];
    #[cfg(umilib_feature = "protocol-ip-v4")]
    assert_eq!(std::mem::offset_of!(umilib::protocol::ip::v4::IPv4Header, options), 20);
    #[cfg(umilib_feature = "protocol-ip-v6")]
    assert_eq!(std::mem::offset_of!(umilib::protocol::ip::v6::IPv6Header, destination), 28);
    #[cfg(umilib_feature = "protocol-ethernet")]
    assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::ethernet::FFIEthernetHeader, ether_type), 26);
    #[cfg(umilib_feature = "protocol-arp")]
    assert_eq!(std::mem::offset_of!(umilib::protocol::arp::ARPPacket, target_protocol), 22);
    #[cfg(umilib_feature = "protocol-ip")]
    {
        assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::ip::FFIIPEndpoint, port), 18);
        assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::ip::FFIIPEndpointPattern, last_port), 20);
    }
    #[cfg(umilib_feature = "protocol-udp")]
    assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::udp::FFIUDPRule, remote), 22);
    #[cfg(umilib_feature = "protocol-tcp")]
    {
        assert_eq!(std::mem::offset_of!(umilib::protocol::tcp::TCPHeader, data_offset), 12);
        assert_eq!(std::mem::offset_of!(umilib::protocol::tcp::TCPHeader, urgent_pointer), 20);
        assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::tcp::FFITCPOptionSet, sack_blocks), 16);
        // The fields before `timer` end at 57; the timer starts at the next multiple of the
        // alignment of its `u64` fields, which is 4 on i386 System V and 8 elsewhere.
        assert_eq!(
            std::mem::offset_of!(umilib::ffi::protocol::tcp::FFITCPConnectionInfo, timer),
            57usize.next_multiple_of(std::mem::align_of::<u64>())
        );
    }
    #[cfg(umilib_feature = "protocol-icmp-v6")]
    {
        assert_eq!(std::mem::offset_of!(umilib::protocol::icmp::v6::NDPPrefixInformation, flags), 3);
        assert_eq!(std::mem::offset_of!(umilib::protocol::icmp::v6::NDPPrefixInformation, prefix), 12);
        assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::icmp::v6::FFINDPRouterAdvertisement, flags), 4);
        assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::icmp::v6::FFINDPRouterAdvertisement, reachable_time), 8);
    }
    #[cfg(umilib_feature = "hash-blake-v2")]
    {
        assert_eq!(std::mem::offset_of!(umilib::hash::blake::v2::BLAKE2bParameters, salt), 18);
        assert_eq!(std::mem::offset_of!(umilib::hash::blake::v2::BLAKE2sParameters, personal), 24);
    }
    // `width`, then two `U128`s (two `u64`s each) and two `bool`s, each `U128` at a multiple of
    // the alignment of `u64` (4 on i386 System V, 8 elsewhere).
    #[cfg(umilib_feature = "hash-crc")]
    assert_eq!(
        std::mem::offset_of!(umilib::ffi::hash::crc::CRCParameters, xor_output),
        (4usize.next_multiple_of(std::mem::align_of::<u64>()) + 32 + 2).next_multiple_of(std::mem::align_of::<u64>())
    );
    #[cfg(all(umilib_feature = "protocol-http-v2", target_pointer_width = "64"))]
    {
        assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::http::v2::FFIH2Config, max_concurrent_streams), 80);
        assert_eq!(std::mem::offset_of!(umilib::ffi::protocol::http::v2::FFIH2Config, settings_timeout), 104);
    }
    for &(name, size, align) in expected {
        if structures.contains_key(name) {
            assert_eq!(layout(&Type::Named(name), &structures), (size, align), "{name}");
        }
    }
    // Arrays of arrays have no C spelling in a declaration of this form.
    for fields in structures.values() {
        for field in fields.iter() {
            if let Type::Array { element, .. } = field.value {
                assert!(!matches!(element, Type::Array { .. }), "{} is an array of arrays", field.name);
            }
        }
    }
}
