use alloc::vec::Vec;

use super::{
    DNSCompression, DNSEDNS, DNSError, DNSHeader, DNSName, DNSOpcode, DNSQuestion, DNSRecord, DNSResponseCode, DNSType,
};

/// A DNS message (RFC 1035 §4.1): its header, its question, and the
/// records of its three sections. The OPT pseudo-record is [`DNSMessage::edns`],
/// not one of the additional records.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct DNSMessage {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
    pub edns: Option<DNSEDNS>,
}

impl DNSMessage {
    /// The size of a message over UDP without EDNS (RFC 1035 §2.3.4).
    pub const UDP_SIZE: usize = 512;
    /// The largest message over TCP (a 2-byte length, RFC 1035 §4.2.2).
    pub const MAXIMUM_SIZE: usize = 65535;

    /// A query of `id` for `question`, with recursion desired.
    pub fn query(id: u16, question: DNSQuestion) -> DNSMessage {
        DNSMessage {
            header: DNSHeader { id, recursion_desired: true, ..DNSHeader::default() },
            questions: alloc::vec![question],
            ..DNSMessage::default()
        }
    }

    /// The response to `query` (its ID, opcode, RD, CD and question), with
    /// `rcode` and EDNS if the query had it (RFC 6891 §7).
    pub fn response(query: &DNSMessage, rcode: DNSResponseCode) -> DNSMessage {
        let mut response = DNSMessage {
            header: DNSHeader {
                id: query.header.id,
                response: true,
                opcode: query.header.opcode,
                recursion_desired: query.header.recursion_desired,
                checking_disabled: query.header.checking_disabled,
                ..DNSHeader::default()
            },
            questions: query.questions.clone(),
            edns: query.edns.as_ref().map(|edns| DNSEDNS { dnssec_ok: edns.dnssec_ok, ..DNSEDNS::default() }),
            ..DNSMessage::default()
        };
        response.set_rcode(rcode);
        response
    }

    /// The question; a query (OPCODE 0) has exactly one (RFC 9619 §3).
    pub fn question(&self) -> Option<&DNSQuestion> {
        self.questions.first()
    }

    /// The response code: the header's 4 bits and the EDNS's upper 8 (RFC 6891 §6.1.3).
    pub fn rcode(&self) -> DNSResponseCode {
        let upper = self.edns.as_ref().map_or(0, |edns| u16::from(edns.extended_rcode));
        DNSResponseCode(upper << 4 | u16::from(self.header.rcode))
    }

    /// Sets the response code; one above 15 needs EDNS, which is added.
    pub fn set_rcode(&mut self, rcode: DNSResponseCode) {
        self.header.rcode = (rcode.0 & 0xF) as u8;
        let upper = (rcode.0 >> 4) as u8;
        if upper != 0 {
            self.edns.get_or_insert_with(DNSEDNS::default).extended_rcode = upper;
        } else if let Some(edns) = &mut self.edns {
            edns.extended_rcode = 0;
        }
    }

    /// The message of `bytes`, whole. More than one OPT, an OPT not in the
    /// additional section or not owned by the root, or a query of other
    /// than one question is FORMERR (RFC 6891 §6.1.1, RFC 9619 §3).
    pub fn decode(bytes: &[u8]) -> Result<DNSMessage, DNSError> {
        let (header, counts) = DNSHeader::decode(bytes)?;
        let mut offset = DNSHeader::LENGTH;
        let mut questions = Vec::with_capacity(usize::from(counts[0]).min(16));
        for _ in 0..counts[0] {
            let (question, next) = DNSQuestion::decode(bytes, offset)?;
            questions.push(question);
            offset = next;
        }
        if header.opcode == DNSOpcode::QUERY && questions.len() > 1 {
            return Err(DNSError::Malformed("a query of more than one question"));
        }
        let mut sections: [Vec<DNSRecord>; 3] = Default::default();
        let mut edns = None;
        for (index, section) in sections.iter_mut().enumerate() {
            for _ in 0..counts[index + 1] {
                let (record, next, rdata) = DNSRecord::decode(bytes, offset)?;
                offset = next;
                if record.kind == DNSType::OPT {
                    if index != 2 || edns.is_some() {
                        return Err(DNSError::Malformed("an OPT out of place or repeated"));
                    }
                    edns = Some(DNSEDNS::from_record(&record, &bytes[rdata])?);
                    continue;
                }
                section.push(record);
            }
        }
        if offset != bytes.len() {
            return Err(DNSError::Malformed("bytes after the message"));
        }
        let [answers, authorities, additionals] = sections;
        Ok(DNSMessage { header, questions, answers, authorities, additionals, edns })
    }

    /// The message, names compressed (RFC 1035 §4.1.4), in at most `limit`
    /// bytes: whole RRsets that do not fit are left out, from the end (RFC
    /// 2181 §9). Leaving out records of the answer or authority section
    /// sets TC; of the additional section only, it does not. The OPT
    /// record always stays (RFC 6891 §7). Fails if not even the question fits.
    pub fn encode(&self, limit: usize) -> Result<Vec<u8>, DNSError> {
        let limit = limit.min(DNSMessage::MAXIMUM_SIZE);
        let mut out = Vec::with_capacity(512);
        let mut compression = DNSCompression::new();
        DNSHeader::default().encode([0; 4], &mut out);
        for question in &self.questions {
            question.encode(&mut out, Some(&mut compression));
        }
        let reserved = self.edns.as_ref().map_or(0, DNSEDNS::encoded_length);
        if out.len() + reserved > limit {
            return Err(DNSError::TooLarge("a question longer than the limit"));
        }
        let mut counts = [self.questions.len() as u16, 0, 0, 0];
        let mut truncated = self.header.truncated;
        'sections: for (index, section) in [&self.answers, &self.authorities, &self.additionals].iter().enumerate() {
            let mut start = 0;
            while start < section.len() {
                let end = start + section[start..].iter().take_while(|record| record.same_set(&section[start])).count();
                // An RRset goes whole or not at all.
                let before = out.len();
                for record in &section[start..end] {
                    record.encode(&mut out, Some(&mut compression));
                }
                if out.len() + reserved > limit {
                    out.truncate(before);
                    truncated |= index < 2;
                    break 'sections;
                }
                counts[index + 1] += (end - start) as u16;
                start = end;
            }
        }
        if let Some(edns) = &self.edns {
            edns.encode(&mut out);
            counts[3] += 1;
        }
        let mut header = Vec::with_capacity(DNSHeader::LENGTH);
        DNSHeader { truncated, ..self.header }.encode(counts, &mut header);
        out[..DNSHeader::LENGTH].copy_from_slice(&header);
        Ok(out)
    }

    /// The largest response over UDP to this query: 512 bytes without EDNS
    /// (RFC 1035 §2.3.4), else the payload it offers (at least 512, RFC
    /// 6891 §6.2.3), up to the responder's `maximum` (§6.2.5, RFC 9715 §3.2).
    pub fn udp_response_limit(&self, maximum: u16) -> usize {
        match &self.edns {
            Some(edns) => edns.payload_size().min(usize::from(maximum.max(512))),
            None => DNSMessage::UDP_SIZE,
        }
    }

    /// The records of every section whose owner is `name` and type `kind`.
    pub fn records<'a>(&'a self, name: &'a DNSName, kind: DNSType) -> impl Iterator<Item = &'a DNSRecord> + 'a {
        self.answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
            .filter(move |record| record.kind == kind && record.name == *name)
    }
}
