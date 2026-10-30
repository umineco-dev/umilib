/// The labels defined by RFC 7468 sections 5 to 13.
pub struct PEMLabel;

impl PEMLabel {
    pub const CERTIFICATE: &'static str = "CERTIFICATE";
    pub const X509_CRL: &'static str = "X509 CRL";
    pub const CERTIFICATE_REQUEST: &'static str = "CERTIFICATE REQUEST";
    pub const PKCS7: &'static str = "PKCS7";
    pub const CMS: &'static str = "CMS";
    pub const PRIVATE_KEY: &'static str = "PRIVATE KEY";
    pub const ENCRYPTED_PRIVATE_KEY: &'static str = "ENCRYPTED PRIVATE KEY";
    pub const ATTRIBUTE_CERTIFICATE: &'static str = "ATTRIBUTE CERTIFICATE";
    pub const PUBLIC_KEY: &'static str = "PUBLIC KEY";

    /// Whether `label` follows `label = [ labelchar *( ["-" / SP] labelchar ) ]`,
    /// where `labelchar` is a printable character other than `-`.
    pub fn is_valid(label: &str) -> bool {
        let bytes = label.as_bytes();
        let is_labelchar = |byte: u8| (0x21..=0x7E).contains(&byte) && byte != b'-';
        if bytes.is_empty() {
            return true;
        }
        if !is_labelchar(bytes[0]) || !is_labelchar(bytes[bytes.len() - 1]) {
            return false;
        }
        // A separator (`-` or a space) is single and between label characters.
        bytes.windows(2).all(|pair| is_labelchar(pair[0]) || is_labelchar(pair[1]))
            && bytes.iter().all(|&byte| is_labelchar(byte) || byte == b'-' || byte == b' ')
    }
}
