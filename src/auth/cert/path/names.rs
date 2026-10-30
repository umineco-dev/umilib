/// The comparisons of the forms of `GeneralName` that RFC 5280 §4.2.1.10
/// and §7 and RFC 9525 §6 define: well-formed names, names within the
/// subtrees of name constraints, and names matching an identity.
pub struct NameMatching;

impl NameMatching {
    /// Whether `name` is a DNS name of the preferred name syntax (RFC 1034
    /// §3.5, with RFC 1123 §2.1 allowing a digit first): labels of 1 to 63
    /// letters, digits and hyphens, not beginning or ending with a hyphen,
    /// at most 253 characters, the last label not all digits (which would
    /// be an IPv4 address). With `wildcard`, the first label may be `*`
    /// (RFC 9525 §6.3) if two labels follow it.
    pub fn is_dns_name(name: &str, wildcard: bool) -> bool {
        let rest = match name.strip_prefix("*.") {
            Some(rest) if wildcard => {
                if rest.split('.').count() < 2 {
                    return false;
                }
                rest
            }
            _ => name,
        };
        if rest.is_empty() || rest.len() > 253 {
            return false;
        }
        let label = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        };
        let last = rest.rsplit('.').next().unwrap_or(rest);
        rest.split('.').all(label) && !last.bytes().all(|byte| byte.is_ascii_digit())
    }

    /// Whether the labels of `name` end with those of `suffix`, compared without case.
    pub fn ends_with_labels(name: &str, suffix: &str) -> bool {
        if suffix.is_empty() {
            return true;
        }
        let (name, suffix) = (name.as_bytes(), suffix.as_bytes());
        if name.len() < suffix.len() || !name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix) {
            return false;
        }
        name.len() == suffix.len() || name[name.len() - suffix.len() - 1] == b'.'
    }

    /// Whether the DNS name `name` is within the DNS constraint
    /// `constraint` (RFC 5280 §4.2.1.10): equal to it or ending with its
    /// labels, compared without case; the empty constraint has every name.
    /// A wildcard name (`*.` and labels) is within when every name it
    /// stands for is.
    pub fn dns_within(name: &str, constraint: &str) -> bool {
        NameMatching::ends_with_labels(name, constraint)
    }

    /// Whether `constraint` is a well-formed DNS constraint: empty, or a
    /// DNS name (RFC 5280 §4.2.1.10 allows no leading period and no wildcard).
    pub fn is_dns_constraint(constraint: &str) -> bool {
        constraint.is_empty() || NameMatching::is_dns_name(constraint, false)
    }

    /// Whether a name the DNS name `name` stands for (itself, or with a
    /// wildcard any one label for it) is within `constraint`.
    pub fn dns_meets(name: &str, constraint: &str) -> bool {
        if NameMatching::dns_within(name, constraint) {
            return true;
        }
        let Some(rest) = name.strip_prefix("*.") else { return false };
        // The wildcard may stand for the first label of the constraint.
        match constraint.split_once('.') {
            Some((label, domain)) => label != "*" && !label.is_empty() && domain.eq_ignore_ascii_case(rest),
            None => false,
        }
    }

    /// The local part and the domain of the mailbox `address`, if it is one
    /// (RFC 5321 §4.1.2: a non-empty local part, `@`, and a domain name).
    pub fn mailbox(address: &str) -> Option<(&str, &str)> {
        let (local, domain) = address.rsplit_once('@')?;
        let quoted = local.len() >= 2 && local.starts_with('"') && local.ends_with('"');
        if local.is_empty() || (!quoted && local.contains('@')) || !NameMatching::is_dns_name(domain, false) {
            return None;
        }
        Some((local, domain))
    }

    /// Whether `constraint` is a well-formed rfc822Name constraint: a
    /// mailbox, a host, or a domain beginning with a period.
    pub fn is_email_constraint(constraint: &str) -> bool {
        if constraint.contains('@') {
            return NameMatching::mailbox(constraint).is_some();
        }
        NameMatching::is_dns_name(constraint.strip_prefix('.').unwrap_or(constraint), false)
    }

    /// Whether `constraint` is a well-formed URI constraint: a host, or a
    /// domain beginning with a period.
    pub fn is_uri_constraint(constraint: &str) -> bool {
        NameMatching::is_dns_name(constraint.strip_prefix('.').unwrap_or(constraint), false)
    }

    /// Whether the mailbox `address` is within the rfc822Name constraint
    /// `constraint` (RFC 5280 §4.2.1.10, §7.5): a mailbox (the same local
    /// part, the same domain without case), a host (any mailbox at it), or
    /// a domain beginning with a period (any mailbox at its subdomains).
    pub fn email_within(address: &str, constraint: &str) -> Option<bool> {
        let (local, domain) = NameMatching::mailbox(address)?;
        Some(match constraint.rsplit_once('@') {
            Some((constraint_local, constraint_domain)) => {
                local == constraint_local && domain.eq_ignore_ascii_case(constraint_domain)
            }
            None if constraint.starts_with('.') => {
                domain.len() > constraint.len() - 1 && NameMatching::ends_with_labels(domain, &constraint[1..])
            }
            None => domain.eq_ignore_ascii_case(constraint),
        })
    }

    /// The host of the URI `uri` if it is a domain name (RFC 3986 §3.2.2):
    /// `None` for a URI without an authority or with an IP literal.
    pub fn uri_host(uri: &str) -> Option<&str> {
        let (scheme, rest) = uri.split_once(':')?;
        if scheme.is_empty() || !scheme.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte)) {
            return None;
        }
        let authority = rest.strip_prefix("//")?;
        let authority = authority.split(['/', '?', '#']).next().unwrap_or(authority);
        let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        if host.starts_with('[') {
            return None;
        }
        let host = host
            .rsplit_once(':')
            .map_or(host, |(host, port)| if port.bytes().all(|byte| byte.is_ascii_digit()) { host } else { "" });
        NameMatching::is_dns_name(host, false).then_some(host)
    }

    /// Whether the URI `uri` is within the URI constraint `constraint` (RFC
    /// 5280 §4.2.1.10): its host equal to the constraint without case, or,
    /// for a constraint beginning with a period, a subdomain of it. `None`
    /// for a URI whose host is not a domain name, which the constraint
    /// cannot be applied to.
    pub fn uri_within(uri: &str, constraint: &str) -> Option<bool> {
        let host = NameMatching::uri_host(uri)?;
        Some(if let Some(domain) = constraint.strip_prefix('.') {
            host.len() > domain.len() && NameMatching::ends_with_labels(host, domain)
        } else {
            host.eq_ignore_ascii_case(constraint)
        })
    }

    /// Whether the mask of an iPAddress constraint (its second half) is a
    /// CIDR mask: ones followed by zeros (RFC 4632).
    pub fn is_cidr_mask(mask: &[u8]) -> bool {
        let mut zeros = false;
        for &byte in mask {
            for bit in (0..8).rev() {
                let one = byte & (1 << bit) != 0;
                if one && zeros {
                    return false;
                }
                zeros |= !one;
            }
        }
        true
    }

    /// Whether the address `address` (4 or 16 octets) is within the
    /// iPAddress constraint `constraint` (an address and a CIDR mask, 8 or
    /// 32 octets). `None` if the constraint is malformed; `Some(false)` for
    /// an address of the other family.
    pub fn ip_within(address: &[u8], constraint: &[u8]) -> Option<bool> {
        if constraint.len() != 8 && constraint.len() != 32 {
            return None;
        }
        let (base, mask) = constraint.split_at(constraint.len() / 2);
        if !NameMatching::is_cidr_mask(mask) {
            return None;
        }
        if address.len() != base.len() {
            return Some(false);
        }
        Some(address.iter().zip(base).zip(mask).all(|((address, base), mask)| address & mask == base & mask))
    }

    /// Whether the presented DNS identifier `presented` (a dNSName) matches
    /// the reference identifier `reference` (RFC 9525 §6.3): the same
    /// labels without case, or a wildcard `*` as the whole first label of
    /// `presented` standing for exactly one label. A presented identifier
    /// that is not well formed matches nothing.
    pub fn dns_matches(presented: &str, reference: &str) -> bool {
        if !NameMatching::is_dns_name(presented, true) {
            return false;
        }
        match presented.strip_prefix("*.") {
            Some(rest) => match reference.split_once('.') {
                Some((label, domain)) => !label.is_empty() && domain.eq_ignore_ascii_case(rest),
                None => false,
            },
            None => presented.eq_ignore_ascii_case(reference),
        }
    }
}
