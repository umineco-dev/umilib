use core::cmp::Ordering;

use super::{DERElement, DERReader};
use crate::codec::asn1::ASN1Error;

/// Follows the order of the components of a SET as they are read.
///
/// DER orders the components of a SET by their tags (X.690 section 10.3,
/// which X.680 section 8.6 defines; the tags are distinct) and those of a SET
/// OF by their encodings (section 11.6). Both have the same tag, so without
/// the schema a component list is valid if it follows either order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DERSetOrder<'a> {
    previous: Option<DERElement<'a>>,
    by_tag: bool,
    by_encoding: bool,
}

impl<'a> DERSetOrder<'a> {
    pub const fn new() -> DERSetOrder<'a> {
        DERSetOrder { previous: None, by_tag: true, by_encoding: true }
    }

    /// Whether the components so far have strictly ascending tags, as in a SET.
    pub fn is_tag_order(&self) -> bool {
        self.by_tag
    }

    /// Whether the components so far have ascending encodings, as in a SET OF.
    pub fn is_encoding_order(&self) -> bool {
        self.by_encoding
    }

    /// Adds the next component; fails with `NonCanonical` once the components
    /// follow neither order.
    pub fn push(&mut self, component: &DERElement<'a>) -> Result<(), ASN1Error> {
        if let Some(previous) = self.previous {
            self.by_tag &= previous.tag.compare_order(&component.tag) == Ordering::Less;
            self.by_encoding &=
                DERReader::compare_encodings(previous.encoding, component.encoding) != Ordering::Greater;
        }
        self.previous = Some(*component);
        if !self.by_tag && !self.by_encoding {
            return Err(ASN1Error::NonCanonical { position: component.position });
        }
        Ok(())
    }
}

impl Default for DERSetOrder<'_> {
    fn default() -> Self {
        DERSetOrder::new()
    }
}
