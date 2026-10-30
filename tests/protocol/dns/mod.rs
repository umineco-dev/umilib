//! Tests of `umilib::protocol::dns` against the examples and rules of RFC
//! 1035, RFC 3597, RFC 4034, RFC 4035, RFC 5155, RFC 6891, RFC 7873,
//! RFC 9460 and RFC 9619.

mod authority;
mod codec;
#[cfg(umilib_feature = "protocol-dns-dnssec")]
mod dnssec;
mod resolver;
mod transport;
#[cfg(umilib_feature = "protocol-dns-dnssec")]
mod validation;

use umilib::protocol::dns::{DNSClass, DNSName, DNSQuestion, DNSRecord, DNSType, DNSZoneFile};

use crate::{RFC, Vectors};

pub fn name(text: &str) -> DNSName {
    DNSName::parse(text, None).unwrap()
}

/// The records of zone-file `text`, its lines dedented by the indentation
/// of its first line (which an RFC adds to its examples; a zone file reads
/// it as the owner of the record before).
pub fn zone(text: &str) -> Vec<DNSRecord> {
    let first = text.lines().find(|line| !line.trim().is_empty()).unwrap_or_default();
    let indentation = first.len() - first.trim_start().len();
    let dedented: Vec<&str> = text
        .lines()
        .map(|line| {
            let spaces = line.len() - line.trim_start_matches(' ').len();
            &line[spaces.min(indentation)..]
        })
        .collect();
    let text = dedented.join("\n");
    DNSZoneFile { origin: None, default_ttl: Some(3600) }
        .parse(&text)
        .unwrap_or_else(|error| panic!("{error:?} in {text}"))
}

/// The lines of an RFC without its page breaks (form feeds, headers and footers).
pub fn rfc(path: &str) -> Vec<String> {
    Vectors::read(path).lines().filter(|line| !RFC::is_page_break(line)).map(|line| line.replace('\u{c}', "")).collect()
}

/// Whether `line` of an RFC is prose: text at the indentation of
/// paragraphs whose first word is not an absolute name, as the first word
/// of a record of the examples is.
pub fn is_prose(line: &str) -> bool {
    let indentation = line.len() - line.trim_start().len();
    let first = line.split_whitespace().next().unwrap_or_default();
    indentation <= 3 && !first.is_empty() && !first.ends_with('.') && !first.starts_with(';')
}

/// The records of the zone example of an RFC: from the line that starts
/// with `first` (trimmed) to the prose after it.
pub fn example_zone(path: &str, first: &str) -> Vec<DNSRecord> {
    let lines = rfc(path);
    let start = lines.iter().position(|line| line.trim_start().starts_with(first)).unwrap();
    let text: Vec<&str> = lines[start..].iter().map(String::as_str).take_while(|line| !is_prose(line)).collect();
    zone(&text.join("\n"))
}

/// An example response of an RFC (as RFC 4035 Appendix B writes them).
pub struct Response {
    /// The AA flag and the RCODE of its header line (";; Header: QR AA DO RCODE=0").
    pub authoritative: bool,
    pub rcode: u16,
    pub question: DNSQuestion,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

impl Response {
    /// The response of the section whose heading starts with `heading`
    /// ("B.2.  ").
    pub fn of(path: &str, heading: &str) -> Response {
        Response::parse(&rfc(path), heading)
    }

    /// The response of the section of `lines` whose heading starts with `heading`.
    pub fn parse(lines: &[String], heading: &str) -> Response {
        let start = lines.iter().position(|line| line.starts_with(heading)).unwrap_or_else(|| panic!("no {heading}"));
        let mut sections: [String; 4] = Default::default();
        let mut current = None;
        let mut header = "";
        for line in &lines[start + 1..] {
            if let Some(flags) = line.trim().strip_prefix(";; Header:") {
                header = flags;
            }
            if Response::is_heading(line) {
                break;
            }
            let trimmed = line.trim();
            match trimmed {
                ";; Question" => current = Some(0),
                ";; Answer" => current = Some(1),
                ";; Authority" => current = Some(2),
                ";; Additional" => current = Some(3),
                _ if trimmed.starts_with(";;") || is_prose(line) => {
                    if is_prose(line) {
                        current = None;
                    }
                }
                _ => {
                    if let Some(index) = current {
                        sections[index].push_str(line);
                        sections[index].push('\n');
                    }
                }
            }
        }
        let fields: Vec<&str> = sections[0].split_whitespace().collect();
        let question =
            DNSQuestion { name: name(fields[0]), kind: DNSType::parse(fields[2]).unwrap(), class: DNSClass::IN };
        let flags: Vec<&str> = header.split_whitespace().collect();
        let rcode = flags.iter().find_map(|flag| flag.strip_prefix("RCODE=")).map_or(0, |code| code.parse().unwrap());
        Response {
            authoritative: flags.contains(&"AA"),
            rcode,
            question,
            answers: zone(&sections[1]),
            authorities: zone(&sections[2]),
            additionals: zone(&sections[3]),
        }
    }

    /// Whether `line` is the heading of a section: a number such as
    /// "B.2.1." or "Appendix", then two spaces.
    pub fn is_heading(line: &str) -> bool {
        let number = line.split("  ").next().unwrap_or_default();
        number.starts_with("Appendix")
            || number.ends_with('.') && number.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '.')
    }

    /// Every record of the response.
    pub fn records(&self) -> Vec<DNSRecord> {
        self.answers.iter().chain(&self.authorities).chain(&self.additionals).cloned().collect()
    }
}
