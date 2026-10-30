//! The Internet Message Format (RFC 5322, with UTF-8 of RFC 6532) and
//! MIME: header fields ([`MailFields`]), addresses ([`MailAddress`],
//! [`MailMailbox`]), dates ([`MailDate`]), message identifiers
//! ([`MailMessageID`]), messages ([`MailMessage`]); media types and their
//! parameters ([`MIMEContentType`], [`MIMEParameters`] with RFC 2231),
//! dispositions ([`MIMEDisposition`], RFC 2183), transfer encodings
//! ([`MIMETransferEncoding`], [`MIMEQuotedPrintable`]), encoded words
//! ([`MIMEEncodedWord`], RFC 2047), character sets ([`MIMECharset`]), and
//! the structure of a message ([`MIMEEntity`], [`MIMEMultipart`]), every
//! limit of which is configurable ([`MailConfig`]).

mod address;
mod charset;
mod config;
mod content_type;
mod date;
mod disposition;
mod encoded_word;
mod encoding;
mod entity;
mod error;
mod field;
mod message;
mod message_id;
mod parameter;
mod quoted_printable;
mod reader;

pub use address::{MailAddress, MailMailbox};
pub use charset::MIMECharset;
pub use config::MailConfig;
pub use content_type::MIMEContentType;
pub use date::MailDate;
pub use disposition::MIMEDisposition;
pub use encoded_word::{MIMEEncodedWord, MIMEWordEncoding};
pub use encoding::MIMETransferEncoding;
pub use entity::{MIMEEntity, MIMEMultipart};
pub use error::MailError;
pub use field::{MailField, MailFields};
pub use message::MailMessage;
pub use message_id::MailMessageID;
pub use parameter::{MIMEParameter, MIMEParameterSection, MIMEParameters};
pub use quoted_printable::MIMEQuotedPrintable;
pub use reader::MailReader;
