//! Certification path validation against NIST PKITS (RFC 5280 §6, with RFC
//! 9618) and the rules of RFC 5280 and RFC 9525 it relies on.

use umilib::auth::cert::key::KeyLimits;
use umilib::auth::cert::path::{
    PathConfig, PathErrorReason, PathProfile, PathValidator, RevocationConfig, TrustAnchor,
};
use umilib::auth::cert::x509::{Certificate, CertificateList};
use umilib::codec::asn1::{ASN1Time, ObjectIdentifier};

/// One test or sub-test of `tests/vectors/auth/cert/path/pkits/cases.txt`.
struct PKITSCase {
    number: String,
    title: String,
    valid: bool,
    settings: String,
    objects: Vec<String>,
}

impl PKITSCase {
    const DIRECTORY: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/auth/cert/path/pkits");
    /// PKITS tests DSA, which this library does not implement (FIPS 186-5 no longer allows DSA signatures).
    const UNSUPPORTED: [&'static str; 2] = ["4.1.4", "4.1.5"];

    fn all() -> Vec<PKITSCase> {
        let text = std::fs::read_to_string(format!("{}/cases.txt", PKITSCase::DIRECTORY)).unwrap();
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| {
                let fields: Vec<&str> = line.split(" | ").collect();
                PKITSCase {
                    number: fields[0].to_string(),
                    title: fields[1].to_string(),
                    valid: fields[2] == "OK",
                    settings: fields[3].to_string(),
                    objects: fields[4].split(' ').map(String::from).collect(),
                }
            })
            .collect()
    }

    fn config(&self) -> PathConfig {
        let mut config = PathConfig::new(ASN1Time::new(2020, 1, 1, 0, 0, 0, 0).unwrap());
        config.profile = PathProfile::Algorithm;
        config.revocation = RevocationConfig::REQUIRED;
        for setting in self.settings.split(' ') {
            match setting {
                "default" => {}
                "explicit-policy" => config.initial_explicit_policy = true,
                "mapping-inhibit" => config.initial_policy_mapping_inhibit = true,
                "any-inhibit" => config.initial_any_policy_inhibit = true,
                policies => {
                    let numbers = policies.strip_prefix("policy-set=").unwrap();
                    let set = numbers
                        .split(',')
                        .map(|number| ObjectIdentifier::parse(&format!("2.16.840.1.101.3.2.1.48.{number}")).unwrap());
                    config.initial_policy_set = Some(set.collect());
                }
            }
        }
        config
    }

    fn run(&self) -> Result<(), PathErrorReason> {
        self.run_with(PathProfile::Algorithm)
    }

    fn run_with(&self, profile: PathProfile) -> Result<(), PathErrorReason> {
        self.run_adjusted(profile, |config| config)
    }

    /// The validation under `profile` and the configuration of the case changed by `adjust`.
    fn run_adjusted(
        &self,
        profile: PathProfile,
        adjust: impl Fn(PathConfig) -> PathConfig,
    ) -> Result<(), PathErrorReason> {
        let read = |kind: &str, name: &str| std::fs::read(format!("{}/{kind}/{name}", PKITSCase::DIRECTORY)).unwrap();
        let certificates: Vec<Certificate<'static>> = self
            .objects
            .iter()
            .filter(|name| name.ends_with(".crt"))
            .map(|name| Certificate::from_der(&read("certs", name)).map(Certificate::into_owned))
            .collect::<Result<_, _>>()
            .map_err(PathErrorReason::Certificate)?;
        let crls: Vec<CertificateList<'static>> = self
            .objects
            .iter()
            .filter(|name| name.ends_with(".crl"))
            .map(|name| CertificateList::from_der(&read("crls", name)).map(CertificateList::into_owned))
            .collect::<Result<_, _>>()
            .map_err(PathErrorReason::Certificate)?;
        let (target, rest) = certificates.split_last().unwrap();
        let (root, intermediates) = rest.split_first().unwrap();
        let anchor =
            TrustAnchor::from_certificate(root.clone(), &KeyLimits::default()).map_err(|error| error.reason)?;
        let config = PathConfig { profile, ..adjust(self.config()) };
        let anchors = [anchor];
        let validator = PathValidator::new(&config, &anchors, intermediates, &crls);
        validator.validate(target).map(drop).map_err(|error| error.reason)
    }
}

#[test]
fn pkits() {
    let cases = PKITSCase::all();
    assert_eq!(cases.len(), 247);
    let mut failures = Vec::new();
    for case in &cases {
        if PKITSCase::UNSUPPORTED.contains(&case.number.as_str()) {
            continue;
        }
        let result = case.run();
        if result.is_ok() != case.valid {
            failures.push(format!(
                "{} {} [{}]: expected {}, got {result:?}",
                case.number,
                case.title,
                case.settings,
                if case.valid { "valid" } else { "invalid" }
            ));
        }
    }
    assert!(failures.is_empty(), "{} of {} PKITS cases differ:\n{}", failures.len(), cases.len(), failures.join("\n"));
}

#[test]
fn crl_issuer_paths_nest_as_deep_as_the_configuration_allows() {
    // PKITS 4.14.28: the CRL is signed by a CRL issuer whose own path (RFC 5280 §6.3.3 (f)) must
    // be validated, one level of nesting. Without it, the CRL has no valid signer.
    let cases = PKITSCase::all();
    let case = cases.iter().find(|case| case.number == "4.14.28").unwrap();
    assert!(case.valid);
    assert_eq!(PathConfig::new(ASN1Time::new(2020, 1, 1, 0, 0, 0, 0).unwrap()).maximum_nested_signers, 4);
    let nested = |depth: usize| {
        case.run_adjusted(PathProfile::Algorithm, |config| PathConfig { maximum_nested_signers: depth, ..config })
    };
    assert_eq!(nested(1), Ok(()));
    assert_eq!(nested(0), Err(PathErrorReason::InvalidCRL));
}

#[test]
fn the_profile_of_rfc_5280_refuses_cas_that_break_it() {
    // PKITS tests the algorithm of §6, which accepts these paths; their CAs break MUSTs of §4.2.
    let cases = PKITSCase::all();
    let case = |number: &str, settings: &str| {
        cases.iter().find(|case| case.number == number && case.settings == settings).unwrap()
    };
    // §4.2.1.9: basic constraints critical in CA certificates.
    let not_critical = case("4.6.4", "default");
    assert_eq!(not_critical.run_with(PathProfile::Algorithm), Ok(()));
    assert_eq!(not_critical.run_with(PathProfile::RFC5280), Err(PathErrorReason::Profile));
    // §4.2.1.11: policy constraints critical.
    let policies = case("4.8.10", "default");
    assert_eq!(policies.run_with(PathProfile::Algorithm), Ok(()));
    assert_eq!(policies.run_with(PathProfile::RFC5280), Err(PathErrorReason::Profile));
    // A path whose CAs meet the profile is valid under it.
    assert_eq!(case("4.1.1", "default").run_with(PathProfile::RFC5280), Ok(()));
}

/// One test case of x509-limbo (`tests/vectors/auth/cert/path/limbo/limbo.json`,
/// or the full file `UMILIB_LIMBO` names).
struct LimboCase<'j> {
    case: &'j umilib::codec::json::JSONValue,
}

impl<'j> LimboCase<'j> {
    /// The cases whose expectation this library does not meet, with why.
    const DIVERGENCES: [(&'static str, &'static str); 13] = [
        (
            "webpki::nc::permitted-dns-match-noncritical",
            "the Web PKI profile keeps the MUST of RFC 5280 §4.2.1.10 that name constraints are critical",
        ),
        (
            "rfc5280::aki::cross-signed-root-missing-aki",
            "a trust anchor ends the path the authority key identifier helps to build (RFC 5280 §6.2)",
        ),
        ("webpki::cn::ipv4-hex-mismatch", "the common name is not used for identity (RFC 9525 §6.3) and not checked"),
        (
            "webpki::cn::ipv4-leading-zeros-mismatch",
            "the common name is not used for identity (RFC 9525 §6.3) and not checked",
        ),
        (
            "webpki::cn::ipv6-uppercase-mismatch",
            "the common name is not used for identity (RFC 9525 §6.3) and not checked",
        ),
        (
            "webpki::cn::ipv6-uncompressed-mismatch",
            "the common name is not used for identity (RFC 9525 §6.3) and not checked",
        ),
        (
            "webpki::cn::ipv6-non-rfc5952-mismatch",
            "the common name is not used for identity (RFC 9525 §6.3) and not checked",
        ),
        ("webpki::cn::punycode-not-in-san", "the common name is not used for identity (RFC 9525 §6.3) and not checked"),
        (
            "webpki::cn::utf8-vs-punycode-mismatch",
            "the common name is not used for identity (RFC 9525 §6.3) and not checked",
        ),
        ("webpki::cn::not-in-san", "the common name is not used for identity (RFC 9525 §6.3) and not checked"),
        ("webpki::cn::case-mismatch", "the common name is not used for identity (RFC 9525 §6.3) and not checked"),
        (
            "webpki::san::public-suffix-multi-label-wildcard-san",
            "wildcards on public suffixes need the Public Suffix List, which this library does not have",
        ),
        (
            "webpki::san::public-suffix-private-namespace-wildcard-san",
            "wildcards on public suffixes need the Public Suffix List, which this library does not have",
        ),
    ];

    fn text(&self, key: &str) -> &'j str {
        self.case.get(key).and_then(|value| value.as_str()).unwrap_or("")
    }

    fn list(&self, key: &str) -> Vec<&'j str> {
        let values = self.case.get(key).and_then(|value| value.as_array());
        values.map(|values| values.iter().filter_map(|value| value.as_str()).collect()).unwrap_or_default()
    }

    /// An RFC 3339 time with an offset of zero, such as `2024-01-01T00:00:00.5+00:00`.
    fn time(text: &str) -> ASN1Time {
        let number = |range: std::ops::Range<usize>| text[range].parse::<u32>().unwrap();
        let fraction = text[19..].split(['+', 'Z', '-']).next().unwrap_or("");
        let nanosecond = match fraction.strip_prefix('.') {
            Some(digits) => format!("{digits:0<9}")[..9].parse().unwrap(),
            None => 0,
        };
        assert!(text.ends_with("+00:00") || text.ends_with('Z'), "{text}");
        ASN1Time::new(
            number(0..4) as u16,
            number(5..7) as u8,
            number(8..10) as u8,
            number(11..13) as u8,
            number(14..16) as u8,
            number(17..19) as u8,
            nanosecond,
        )
        .unwrap()
    }

    fn config(&self) -> PathConfig {
        use umilib::auth::cert::path::ServiceIdentity;
        use umilib::auth::cert::x509::{ExtendedKeyUsage, KeyUsage};
        let time = match self.text("validation_time") {
            "" => {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
                ASN1Time::from_unix_seconds(now).unwrap()
            }
            text => LimboCase::time(text),
        };
        let mut config = PathConfig::new(time);
        let identifier = self.text("id");
        config.profile = if identifier.starts_with("webpki::") || identifier.starts_with("bettertls::") {
            PathProfile::WebPKI
        } else {
            PathProfile::RFC5280
        };
        if let Some(peer) = self.case.get("expected_peer_name").filter(|peer| !peer.is_null()) {
            let value = peer.get("value").and_then(|value| value.as_str()).unwrap().to_string();
            config.identity = Some(match peer.get("kind").and_then(|kind| kind.as_str()).unwrap() {
                "DNS" => ServiceIdentity::DNS(value),
                "IP" => ServiceIdentity::IPAddress(
                    value
                        .parse::<std::net::IpAddr>()
                        .map(|address| match address {
                            std::net::IpAddr::V4(address) => address.octets().to_vec(),
                            std::net::IpAddr::V6(address) => address.octets().to_vec(),
                        })
                        .unwrap(),
                ),
                "RFC822" => ServiceIdentity::Email(value),
                kind => panic!("peer name of kind {kind}"),
            });
        }
        if self.text("validation_kind") == "SERVER" && self.list("extended_key_usage").is_empty() {
            config.extended_key_usage = Some(ExtendedKeyUsage::SERVER_AUTH);
        }
        for usage in self.list("extended_key_usage") {
            config.extended_key_usage = Some(match usage {
                "serverAuth" => ExtendedKeyUsage::SERVER_AUTH,
                "clientAuth" => ExtendedKeyUsage::CLIENT_AUTH,
                "codeSigning" => ExtendedKeyUsage::CODE_SIGNING,
                "emailProtection" => ExtendedKeyUsage::EMAIL_PROTECTION,
                "anyExtendedKeyUsage" => ExtendedKeyUsage::ANY,
                usage => panic!("extended key usage {usage}"),
            });
        }
        for usage in self.list("key_usage") {
            let bits = match usage {
                "digitalSignature" => KeyUsage::DIGITAL_SIGNATURE,
                "keyEncipherment" => KeyUsage::KEY_ENCIPHERMENT,
                "keyAgreement" => KeyUsage::KEY_AGREEMENT,
                usage => panic!("key usage {usage}"),
            };
            config.key_usage = Some(config.key_usage.map_or(bits, |wanted| wanted | bits));
        }
        if let Some(depth) =
            self.case.get("max_chain_depth").and_then(|depth| depth.as_number()).and_then(|depth| depth.as_f64())
        {
            config.maximum_intermediates = depth as usize;
        }
        if !self.list("crls").is_empty() {
            config.revocation = RevocationConfig { check: true, require: false, ..RevocationConfig::REQUIRED };
        }
        config
    }

    fn certificates(pems: &[&str]) -> Result<Vec<Certificate<'static>>, PathErrorReason> {
        pems.iter().map(|pem| Certificate::from_pem(pem).map_err(PathErrorReason::Certificate)).collect()
    }

    fn run(&self) -> Result<(), PathErrorReason> {
        let anchors: Vec<TrustAnchor> = LimboCase::certificates(&self.list("trusted_certs"))?
            .into_iter()
            .map(|certificate| {
                TrustAnchor::from_certificate(certificate, &KeyLimits::default()).map_err(|error| error.reason)
            })
            .collect::<Result<_, _>>()?;
        let intermediates = LimboCase::certificates(&self.list("untrusted_intermediates"))?;
        let target = Certificate::from_pem(self.text("peer_certificate")).map_err(PathErrorReason::Certificate)?;
        let crls: Vec<CertificateList<'static>> = self
            .list("crls")
            .iter()
            .map(|pem| CertificateList::from_pem(pem).map_err(PathErrorReason::Certificate))
            .collect::<Result<_, _>>()?;
        let config = self.config();
        let validator = PathValidator::new(&config, &anchors, &intermediates, &crls);
        validator.validate(&target).map(drop).map_err(|error| error.reason)
    }
}

#[test]
fn x509_limbo() {
    let path = std::env::var("UMILIB_LIMBO")
        .unwrap_or_else(|_| format!("{}/tests/vectors/auth/cert/path/limbo/limbo.json", env!("CARGO_MANIFEST_DIR")));
    let text = std::fs::read_to_string(&path).unwrap();
    let document = umilib::codec::json::JSONValue::parse(&text).unwrap();
    let cases = document.get("testcases").and_then(|cases| cases.as_array()).unwrap();
    assert!(cases.len() >= 900, "{path}");
    let mut failures = Vec::new();
    for case in cases.iter().map(|case| LimboCase { case }) {
        let identifier = case.text("id");
        if let Ok(only) = std::env::var("UMILIB_LIMBO_ONLY")
            && only != identifier
        {
            continue;
        }
        if LimboCase::DIVERGENCES.iter().any(|(divergent, _)| *divergent == identifier) {
            continue;
        }
        let valid = case.text("expected_result") == "SUCCESS";
        let result = case.run();
        if result.is_ok() != valid {
            failures
                .push(format!("{identifier}: expected {}, got {result:?}", if valid { "success" } else { "failure" }));
        }
    }
    assert!(failures.is_empty(), "{} of {} limbo cases differ:\n{}", failures.len(), cases.len(), failures.join("\n"));
}

#[test]
fn name_constraints_compare_as_rfc_5280_defines() {
    use umilib::auth::cert::path::NameMatching;
    // §4.2.1.10: a DNS constraint has the names made by adding labels on the left.
    assert!(NameMatching::dns_within("host.example.com", "host.example.com"));
    assert!(NameMatching::dns_within("www.host.example.com", "host.example.com"));
    assert!(!NameMatching::dns_within("host1.example.com", "host.example.com"));
    assert!(!NameMatching::dns_within("myhost.example.com", "host.example.com"), "label by label, not by suffix");
    assert!(NameMatching::dns_within("WWW.Host.Example.COM", "host.example.com"), "§7.2: without case");
    assert!(NameMatching::dns_within("anything.example", ""));
    // A DNS constraint is a DNS name: no leading period, no wildcard.
    assert!(!NameMatching::is_dns_constraint(".example.com"));
    assert!(!NameMatching::is_dns_constraint("*.example.com"));
    // A wildcard name is within when every name it stands for is, and meets a constraint one of them is within.
    assert!(NameMatching::dns_within("*.example.com", "example.com"));
    assert!(!NameMatching::dns_within("*.example.com", "bar.example.com"));
    assert!(NameMatching::dns_meets("*.example.com", "bar.example.com"));
    assert!(!NameMatching::dns_meets("*.example.com", "a.bar.example.com"));
    // §4.2.1.10: a mailbox, a host, or a domain beginning with a period.
    assert_eq!(NameMatching::email_within("root@example.com", "root@example.com"), Some(true));
    assert_eq!(
        NameMatching::email_within("Root@example.com", "root@example.com"),
        Some(false),
        "§7.5: the local part is exact"
    );
    assert_eq!(
        NameMatching::email_within("root@EXAMPLE.com", "root@example.com"),
        Some(true),
        "§7.5: the host is without case"
    );
    assert_eq!(NameMatching::email_within("user@example.com", "example.com"), Some(true));
    assert_eq!(NameMatching::email_within("user@mail.example.com", "example.com"), Some(false));
    assert_eq!(NameMatching::email_within("user@mail.example.com", ".example.com"), Some(true));
    assert_eq!(NameMatching::email_within("user@example.com", ".example.com"), Some(false));
    assert_eq!(NameMatching::email_within("not a mailbox", "example.com"), None);
    assert!(!NameMatching::is_email_constraint("invalid@invalid@example.com"));
    // §4.2.1.10: URIs by their host; a constraint beginning with a period has the subdomains only.
    assert_eq!(NameMatching::uri_within("https://host.example.com/path", "host.example.com"), Some(true));
    assert_eq!(NameMatching::uri_within("https://user@host.example.com:8443/", ".example.com"), Some(true));
    assert_eq!(NameMatching::uri_within("https://my.host.example.com/", ".example.com"), Some(true));
    assert_eq!(NameMatching::uri_within("https://example.com/", ".example.com"), Some(false));
    assert_eq!(
        NameMatching::uri_within("https://192.0.2.1/", ".example.com"),
        None,
        "an address is not a fully qualified domain name"
    );
    assert_eq!(NameMatching::uri_within("urn:isbn:0451450523", ".example.com"), None, "no authority");
    // §4.2.1.6: a URI name follows the syntax of RFC 3986; the host of anything else is not guessed.
    // `\` is not in the userinfo of RFC 3986 §3.2.1, and WHATWG parsers read `a.example` as the host.
    assert_eq!(NameMatching::uri_within("http://a.example\\@b.example/x", "b.example"), None);
    assert_eq!(NameMatching::uri_within("http://a.example\\@b.example/x", "a.example"), None);
    // `@` is not in the userinfo either (§3.2.1), so the authority below has no host of RFC 3986.
    assert_eq!(NameMatching::uri_within("http://a.example@b@c.example/", "c.example"), None);
    // A userinfo of unreserved characters, sub-delims and `:` is valid (§3.2.1).
    assert_eq!(NameMatching::uri_within("http://user:pa;ss@host.example.com:8443/", ".example.com"), Some(true));
    // The port is digits (§3.2.3).
    assert_eq!(NameMatching::uri_within("http://host.example.com:80a/", ".example.com"), None);
    // Characters outside the grammar (§2).
    assert_eq!(NameMatching::uri_within("http://host.example.com/a b", ".example.com"), None);
    assert_eq!(NameMatching::uri_within("http://host.example.com\\/", ".example.com"), None);
    // A percent-encoded host is a registered name, but not a domain name in preferred syntax.
    assert_eq!(NameMatching::uri_within("http://host%2Eexample.com/", ".example.com"), None);
    // An IPv6 literal (§3.2.2) is not a domain name.
    assert_eq!(NameMatching::uri_within("http://[2001:db8::1]/", ".example.com"), None);
    // A reference without a scheme is not a URI (§4.2.1.6: not relative).
    assert_eq!(NameMatching::uri_within("//host.example.com/", ".example.com"), None);
    // The host is compared without case (§7.4), and an empty path is a path (§3.3).
    assert_eq!(NameMatching::uri_within("HTTP://HOST.EXAMPLE.COM", "host.example.com"), Some(true));
    assert_eq!(NameMatching::uri_host("https://user@host.example.com:8443/p?q#f").as_deref(), Some("host.example.com"));
    // §4.2.1.10: an address and a CIDR mask; the example 192.0.2.0/24.
    let class_c = [0xC0, 0x00, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0x00];
    assert_eq!(NameMatching::ip_within(&[192, 0, 2, 1], &class_c), Some(true));
    assert_eq!(NameMatching::ip_within(&[192, 0, 3, 1], &class_c), Some(false));
    assert_eq!(NameMatching::ip_within(&[0; 16], &class_c), Some(false), "another family");
    assert_eq!(NameMatching::ip_within(&[192, 0, 2, 1], &[192, 0, 2, 0, 255, 0, 255, 0]), None, "not a CIDR mask");
}

#[test]
fn identities_match_as_rfc_9525_defines() {
    use umilib::auth::cert::path::{NameMatching, ServiceIdentity};
    use umilib::auth::cert::x509::GeneralName;
    // §6.3: labels compared without case; a wildcard is the whole first label and stands for one label.
    assert!(NameMatching::dns_matches("www.example.com", "WWW.Example.COM"));
    assert!(NameMatching::dns_matches("*.example.com", "foo.example.com"));
    assert!(!NameMatching::dns_matches("*.example.com", "bar.foo.example.com"));
    assert!(!NameMatching::dns_matches("*.example.com", "example.com"));
    assert!(!NameMatching::dns_matches("f*o.example.com", "foo.example.com"), "a wildcard only as a whole label");
    assert!(!NameMatching::dns_matches("www.*.com", "www.example.com"), "a wildcard only first");
    assert!(!NameMatching::dns_matches("*", "localhost"));
    assert!(!NameMatching::dns_matches("*.com", "example.com"), "two labels after the wildcard");
    // §6.4: addresses octet for octet; mailboxes with an exact local part.
    let address = ServiceIdentity::IPAddress(vec![127, 0, 0, 1]);
    assert!(address.matches_name(&GeneralName::IPAddress(std::borrow::Cow::Borrowed(&[127, 0, 0, 1]))));
    assert!(!address.matches_name(&GeneralName::DNSName(std::borrow::Cow::Borrowed("127.0.0.1"))));
    let mailbox = ServiceIdentity::Email("user@EXAMPLE.com".to_string());
    assert!(mailbox.matches_name(&GeneralName::RFC822Name(std::borrow::Cow::Borrowed("user@example.com"))));
    assert!(!mailbox.matches_name(&GeneralName::RFC822Name(std::borrow::Cow::Borrowed("User@example.com"))));
}

#[test]
fn distinguished_names_match_as_rfc_5280_section_7_1_defines() {
    use std::borrow::Cow;
    use umilib::auth::cert::x509::{AttributeTypeAndValue, Name, NameAttribute, RelativeDistinguishedName};
    let common = |tag: u8, text: &str| {
        let mut value = vec![tag, text.len() as u8];
        value.extend_from_slice(text.as_bytes());
        AttributeTypeAndValue::new(NameAttribute::CommonName.oid(), Cow::Owned(value)).unwrap()
    };
    let name = |attributes: &[AttributeTypeAndValue<'_>]| {
        let rdns: Vec<RelativeDistinguishedName<'static>> = attributes
            .iter()
            .map(|attribute| RelativeDistinguishedName::new(std::slice::from_ref(attribute)).unwrap())
            .collect();
        Name::new(&rdns).unwrap()
    };
    // caseIgnoreMatch after LDAP preparation (RFC 4518): case, insignificant spaces, PrintableString and UTF8String alike.
    let utf8 = name(&[common(0x0C, "  Example   CA ")]);
    let printable = name(&[common(0x13, "example ca")]);
    assert!(utf8.matches(&printable));
    assert_ne!(utf8, printable, "the encodings differ");
    assert!(!utf8.matches(&name(&[common(0x13, "example  cb")])));
    // The same number of relative names, in the same order; a subtree is a prefix.
    let country = AttributeTypeAndValue::from_text(NameAttribute::Country, "JP").unwrap();
    let longer = name(&[country.clone(), common(0x0C, "Example CA")]);
    let base = name(std::slice::from_ref(&country));
    assert!(!longer.matches(&base));
    assert!(longer.is_within(&base));
    assert!(!base.is_within(&longer));
    assert!(!name(&[common(0x0C, "Example CA"), country]).is_within(&base), "order matters");
    // A relative name is a set: its attributes match in any order, whatever the order DER gives them.
    let units = |upper: bool| {
        let attributes: Vec<AttributeTypeAndValue<'static>> = (0..2000)
            .map(|index| {
                let text = format!("unit {index} {}", if upper { "ABC" } else { "abc" });
                AttributeTypeAndValue::from_text(NameAttribute::OrganizationalUnit, &text).unwrap()
            })
            .collect();
        Name::new(&[RelativeDistinguishedName::new(&attributes).unwrap()]).unwrap()
    };
    assert!(units(true).matches(&units(false)));
    let mut fewer: Vec<AttributeTypeAndValue<'static>> =
        units(true).rdns().next().unwrap().attributes().map(AttributeTypeAndValue::into_owned).collect();
    fewer.pop();
    fewer.push(AttributeTypeAndValue::from_text(NameAttribute::OrganizationalUnit, "other").unwrap());
    let other = Name::new(&[RelativeDistinguishedName::new(&fewer).unwrap()]).unwrap();
    assert!(!units(false).matches(&other));
}

/// CRLs of the root of the OCSP fixtures, for the tests of RFC 5280 §6.3.
struct CRLs;

impl CRLs {
    fn certificate(name: &str) -> Certificate<'static> {
        Certificate::from_der(&super::Fixtures::OCSP.bytes(&format!("{name}.der"))).unwrap().into_owned()
    }

    fn time(year: u16, month: u8, day: u8, hour: u8) -> ASN1Time {
        ASN1Time::new(year, month, day, hour, 0, 0, 0).unwrap()
    }

    /// A CRL in the root's name signed by the key `signer`, with SHA-256 or `hash`, listing `serials`.
    fn list(
        signer: &str,
        hash: umilib::auth::cert::key::HashAlgorithm,
        next_update: Option<ASN1Time>,
        serials: &[&[u8]],
        extensions: umilib::auth::cert::x509::Extensions<'static>,
        entry_extensions: &[umilib::auth::cert::x509::Extensions<'static>],
    ) -> CertificateList<'static> {
        use std::borrow::Cow;
        use umilib::auth::cert::key::{PrivateKey, SignatureAlgorithm};
        use umilib::auth::cert::x509::{Extensions, RevokedCertificate, SerialNumber, TBSCertList, Time, Version};
        let key = PrivateKey::from_pem(&super::Fixtures::OCSP.text(&format!("{signer}.key"))).unwrap();
        let revoked_certificates = serials
            .iter()
            .enumerate()
            .map(|(index, serial)| RevokedCertificate {
                serial_number: SerialNumber::new(Cow::Owned(serial.to_vec())).unwrap(),
                revocation_date: Time::new(CRLs::time(2026, 12, 1, 0)).unwrap(),
                extensions: entry_extensions.get(index).cloned().unwrap_or_else(Extensions::new),
            })
            .collect();
        let algorithm = SignatureAlgorithm::ECDSA(hash);
        let tbs = TBSCertList {
            version: Version::V2,
            signature: algorithm.identifier().unwrap(),
            issuer: CRLs::certificate("root").tbs_certificate().subject.clone().into_owned(),
            this_update: Time::new(CRLs::time(2026, 12, 31, 12)).unwrap(),
            next_update: next_update.map(|next| Time::new(next).unwrap()),
            revoked_certificates,
            extensions,
        };
        // Signed directly rather than by `TBSCertList::sign`, which refuses what a conforming CA must
        // not issue (a CRL without nextUpdate): these CRLs test what a relying party accepts.
        let tbs = tbs.to_der().unwrap();
        let signature = key.sign(&algorithm, &tbs, &mut super::random()).unwrap();
        let bit_string = [&[0u8][..], &signature].concat();
        let der = super::DER::sequence(&[
            &tbs,
            &algorithm.identifier().unwrap().to_der().unwrap(),
            &super::DER::element(0x03, &bit_string),
        ]);
        CertificateList::from_der(&der).unwrap().into_owned()
    }

    /// A CRL of the root, current until 2027-02-01, listing `serials`.
    fn simple(signer: &str, serials: &[&[u8]]) -> CertificateList<'static> {
        let next = Some(CRLs::time(2027, 2, 1, 0));
        CRLs::list(signer, umilib::auth::cert::key::HashAlgorithm::SHA256, next, serials, Default::default(), &[])
    }

    /// The validation of the certificate `name` with `crls` under the algorithm, revocation required.
    fn validate(name: &str, crls: &[CertificateList<'static>], config: &PathConfig) -> Result<(), PathErrorReason> {
        let anchors = [TrustAnchor::from_certificate(CRLs::certificate("root"), &KeyLimits::default()).unwrap()];
        let target = CRLs::certificate(name);
        PathValidator::new(config, &anchors, &[], crls).validate(&target).map(|_| ()).map_err(|error| error.reason)
    }

    fn config(day: u8) -> PathConfig {
        PathConfig {
            profile: PathProfile::Algorithm,
            revocation: RevocationConfig::REQUIRED,
            ..PathConfig::new(CRLs::time(2027, 1, day, 0))
        }
    }
}

#[test]
fn revocation_follows_rfc_5280_section_6_3() {
    use umilib::auth::cert::key::HashAlgorithm;
    use umilib::auth::cert::x509::{
        CRLNumber, CRLReason, CertificateIssuer, DeltaCRLIndicator, Extension, Extensions, GeneralName,
    };
    let config = CRLs::config(1);
    let (empty, listing) = (CRLs::simple("root", &[]), CRLs::simple("root", &[&[0x11]]));
    let revoked = Err(PathErrorReason::Revoked(CRLReason::Unspecified));
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&empty), &config), Ok(()));
    assert_eq!(CRLs::validate("revoked", std::slice::from_ref(&listing), &config), revoked);
    // Every usable CRL in scope is read: a CRL that omits a revocation does not hide one that lists it.
    assert_eq!(CRLs::validate("revoked", &[empty.clone(), listing.clone()], &config), revoked);
    assert_eq!(CRLs::validate("revoked", &[listing.clone(), empty.clone()], &config), revoked);
    // A CRL without a valid signer (§6.3.3 (f), (g)) is not used: it hides nothing, and alone the status is unknown.
    let forged = CRLs::simple("other-root", &[]);
    assert_eq!(CRLs::validate("revoked", &[forged.clone(), listing.clone()], &config), revoked);
    assert_eq!(CRLs::validate("good", &[forged.clone(), empty.clone()], &config), Ok(()));
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&forged), &config), Err(PathErrorReason::InvalidCRL));
    let checked =
        PathConfig { revocation: RevocationConfig { require: false, ..RevocationConfig::REQUIRED }, ..CRLs::config(1) };
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&forged), &checked), Err(PathErrorReason::InvalidCRL));
    // A CRL without nextUpdate is current for the configured lifetime after its thisUpdate (2026-12-31T12:00Z).
    let undated = CRLs::list("root", HashAlgorithm::SHA256, None, &[], Extensions::new(), &[]);
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&undated), &config), Ok(()));
    let late = CRLs::config(3);
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&undated), &late), Err(PathErrorReason::RevocationUnknown));
    // A CRL signed with SHA-1 is refused unless the configuration accepts SHA-1.
    let sha1 = CRLs::list("root", HashAlgorithm::SHA1, Some(CRLs::time(2027, 2, 1, 0)), &[], Extensions::new(), &[]);
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&sha1), &config), Err(PathErrorReason::InvalidCRL));
    let accepting = PathConfig { accept_sha1: true, ..CRLs::config(1) };
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&sha1), &accepting), Ok(()));
    // The signatures of CRLs are part of the work of a validation: the certificate's and the CRL's.
    let one = PathConfig { maximum_signatures: 1, ..CRLs::config(1) };
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&empty), &one), Err(PathErrorReason::Work));
    let two = PathConfig { maximum_signatures: 2, ..CRLs::config(1) };
    assert_eq!(CRLs::validate("good", std::slice::from_ref(&empty), &two), Ok(()));
    // In a CRL that is not indirect, every entry is a certificate of its issuer (§5.3.3).
    let other = CRLs::certificate("other-root").tbs_certificate().subject.clone().into_owned();
    let mut elsewhere = Extensions::new();
    let issuer = CertificateIssuer { names: vec![GeneralName::DirectoryName(other)] };
    elsewhere.push(Extension::new(&issuer, true).unwrap()).unwrap();
    let next = Some(CRLs::time(2027, 2, 1, 0));
    let direct = CRLs::list("root", HashAlgorithm::SHA256, next, &[&[0x42], &[0x11]], Extensions::new(), &[elsewhere]);
    assert_eq!(CRLs::validate("revoked", std::slice::from_ref(&direct), &config), revoked);
    // A delta CRL (§5.2.4) updates its complete CRL; one without a valid signer is skipped.
    let numbered = |number: u64, base: Option<u64>| {
        let mut extensions = Extensions::new();
        extensions.push(Extension::new(&CRLNumber::from_u64(number), false).unwrap()).unwrap();
        if let Some(base) = base {
            extensions.push(Extension::new(&DeltaCRLIndicator::from_u64(base), true).unwrap()).unwrap();
        }
        extensions
    };
    let complete = CRLs::list("root", HashAlgorithm::SHA256, next, &[], numbered(1, None), &[]);
    let delta = CRLs::list("root", HashAlgorithm::SHA256, next, &[&[0x11]], numbered(2, Some(1)), &[]);
    let forged_delta = CRLs::list("other-root", HashAlgorithm::SHA256, next, &[&[0x11]], numbered(2, Some(1)), &[]);
    assert_eq!(CRLs::validate("revoked", &[complete.clone(), delta], &config), revoked);
    assert_eq!(CRLs::validate("revoked", &[complete.clone(), forged_delta], &config), Ok(()));
    assert_eq!(CRLs::validate("revoked", std::slice::from_ref(&complete), &config), Ok(()));
}

#[test]
fn the_policy_graph_grows_linearly() {
    use umilib::auth::cert::path::PolicyGraph;
    use umilib::auth::cert::x509::{CertificatePolicies, PolicyInformation, PolicyMapping, PolicyMappings};
    // RFC 9618 §3.2: each certificate asserts OID1 and OID2 and maps each to both; the tree of
    // RFC 5280 doubles at each depth, the graph keeps two nodes.
    let oid = |text: &str| ObjectIdentifier::parse(text).unwrap();
    let (first, second) = (oid("1.2.3.1"), oid("1.2.3.2"));
    let policies = CertificatePolicies {
        policies: vec![
            PolicyInformation { identifier: first.clone(), qualifiers: Vec::new() },
            PolicyInformation { identifier: second.clone(), qualifiers: Vec::new() },
        ],
    };
    let mut mappings = Vec::new();
    for issuer in [&first, &second] {
        for subject in [&first, &second] {
            mappings
                .push(PolicyMapping { issuer_domain_policy: issuer.clone(), subject_domain_policy: subject.clone() });
        }
    }
    let mappings = PolicyMappings { mappings };
    let mut graph = PolicyGraph::new();
    for _ in 0..64 {
        graph.process(&policies, true);
        graph.map(&mappings, true);
    }
    graph.process(&policies, true);
    assert_eq!(graph.depth(), 65);
    assert!(graph.levels.iter().skip(1).all(|level| level.len() == 2));
    assert!(graph.levels[2].iter().all(|node| node.parents.len() == 2), "one node, two parents");
    assert_eq!(graph.user_constrained_policies(None), [first.clone(), second.clone()]);
    assert_eq!(graph.user_constrained_policies(Some(std::slice::from_ref(&second))), std::slice::from_ref(&second));
}
