use alloc::string::String;

use super::SASLError;

/// The channel binding flag of a GS2 header (RFC 5801 §4, RFC 5802 §6).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum GS2ChannelBinding {
    /// `n`: the client does not support channel binding.
    Unsupported,
    /// `y`: the client supports channel binding but thinks the server does not.
    NotOffered,
    /// `p=<cb-name>`: the client uses channel binding of this type, as
    /// `tls-unique`, `tls-server-end-point` (RFC 5929) or `tls-exporter`
    /// (RFC 9266).
    Required(String),
}

impl GS2ChannelBinding {
    /// The channel binding types of RFC 5929 and RFC 9266.
    pub const TLS_UNIQUE: &'static str = "tls-unique";
    pub const TLS_SERVER_END_POINT: &'static str = "tls-server-end-point";
    pub const TLS_EXPORTER: &'static str = "tls-exporter";

    /// Whether `name` has the syntax of a channel binding type (RFC 5056 §7):
    /// letters, digits, `.` and `-`.
    pub fn is_name(name: &str) -> bool {
        !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    }
}

/// A GS2 header (RFC 5801 §4): the non-standard flag, the channel binding
/// flag and the authorization identity, as SCRAM and OAUTHBEARER begin
/// their first message with it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GS2Header {
    /// `F`: the GSS-API mechanism is not standard; SCRAM never sets it.
    pub nonstandard: bool,
    pub channel_binding: GS2ChannelBinding,
    pub authzid: Option<String>,
}

impl GS2Header {
    /// A standard header.
    pub fn new(channel_binding: GS2ChannelBinding, authzid: Option<&str>) -> GS2Header {
        GS2Header { nonstandard: false, channel_binding, authzid: authzid.map(String::from) }
    }

    /// The text of the header: `F,` if non-standard, the flag, `,`, `a=` and the escaped
    /// authorization identity if any, and `,`. Fails with [`SASLError::Format`]
    /// for a channel binding type or an authorization identity that cannot
    /// be written (an empty one, or one with NUL).
    pub fn encode(&self) -> Result<String, SASLError> {
        let mut text = String::new();
        if self.nonstandard {
            text.push_str("F,");
        }
        match &self.channel_binding {
            GS2ChannelBinding::Unsupported => text.push('n'),
            GS2ChannelBinding::NotOffered => text.push('y'),
            GS2ChannelBinding::Required(name) if GS2ChannelBinding::is_name(name) => {
                text.push_str("p=");
                text.push_str(name);
            }
            GS2ChannelBinding::Required(_) => return Err(SASLError::Format),
        }
        text.push(',');
        if let Some(authzid) = &self.authzid {
            text.push_str("a=");
            text.push_str(&GS2Header::escape(authzid)?);
        }
        text.push(',');
        Ok(text)
    }

    /// The header at the start of `message` and the rest of the message.
    pub fn decode(message: &str) -> Result<(GS2Header, &str), SASLError> {
        let (nonstandard, rest) = match message.strip_prefix("F,") {
            Some(rest) => (true, rest),
            None => (false, message),
        };
        let (flag, rest) = rest.split_once(',').ok_or(SASLError::Format)?;
        let channel_binding = match flag {
            "n" => GS2ChannelBinding::Unsupported,
            "y" => GS2ChannelBinding::NotOffered,
            _ => match flag.strip_prefix("p=") {
                Some(name) if GS2ChannelBinding::is_name(name) => GS2ChannelBinding::Required(String::from(name)),
                _ => return Err(SASLError::Format),
            },
        };
        let (authzid, rest) = rest.split_once(',').ok_or(SASLError::Format)?;
        let authzid = match authzid {
            "" => None,
            _ => Some(GS2Header::unescape(authzid.strip_prefix("a=").ok_or(SASLError::Format)?)?),
        };
        Ok((GS2Header { nonstandard, channel_binding, authzid }, rest))
    }

    /// `name` as a `saslname` (RFC 5801 §4, RFC 5802 §7): `,` as `=2C` and
    /// `=` as `=3D`; fails with [`SASLError::Format`] for an empty name or
    /// one with NUL.
    pub fn escape(name: &str) -> Result<String, SASLError> {
        if name.is_empty() || name.contains('\0') {
            return Err(SASLError::Format);
        }
        Ok(name.replace('=', "=3D").replace(',', "=2C"))
    }

    /// The name a `saslname` stands for; fails with [`SASLError::Format`]
    /// for `=` followed by anything but `2C` or `3D`, for `,`, NUL, or an
    /// empty name.
    pub fn unescape(text: &str) -> Result<String, SASLError> {
        if text.is_empty() || text.contains(',') || text.contains('\0') {
            return Err(SASLError::Format);
        }
        let mut name = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(index) = rest.find('=') {
            name.push_str(&rest[..index]);
            match rest.get(index..index + 3) {
                Some("=2C") => name.push(','),
                Some("=3D") => name.push('='),
                _ => return Err(SASLError::Format),
            }
            rest = &rest[index + 3..];
        }
        name.push_str(rest);
        Ok(name)
    }
}
