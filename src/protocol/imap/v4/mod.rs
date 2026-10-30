//! IMAP4rev2 (RFC 9051) without I/O, with the compatibility of IMAP4rev1
//! (RFC 3501, RFC 9051 Appendix E): a client ([`IMAPClient`]) and a server
//! ([`IMAPServer`]); commands ([`IMAPCommand`]) and responses
//! ([`IMAPResponse`]); the productions of the grammar ([`IMAPReader`],
//! [`IMAPWriter`]) and whole lines with their literals ([`IMAPLineReader`],
//! RFC 7888); sequence sets, dates, mailbox names with modified UTF-7
//! ([`IMAPSequenceSet`], [`IMAPDateTime`], [`IMAPMailbox`]); FETCH and its
//! sections ([`IMAPFetchAttribute`], [`IMAPFetchItem`], [`IMAPSection`]);
//! envelopes and body structures made from messages read by `codec-mail`
//! ([`IMAPEnvelope`], [`IMAPBody`]); and SEARCH ([`IMAPSearch`]). The
//! mailboxes, the SASL exchange of AUTHENTICATE and TLS are the user's.

mod body;
mod client;
mod command;
mod config;
mod date;
mod envelope;
mod error;
mod fetch;
mod line;
mod mailbox;
mod reader;
mod response;
mod search;
mod section;
mod sequence;
mod server;
mod writer;

pub use body::{IMAPBody, IMAPBodyDisposition, IMAPBodyExtension, IMAPBodyFields, IMAPBodyParameter};
pub use client::{IMAPClient, IMAPClientCommand, IMAPClientEvent};
pub use command::{IMAPCommand, IMAPCommandBody, IMAPListReturn, IMAPState, IMAPStoreMode};
pub use config::{IMAPConfig, IMAPServerConfig};
pub use date::{IMAPDate, IMAPDateTime};
pub use envelope::{IMAPAddress, IMAPEnvelope};
pub use error::IMAPError;
pub use fetch::{IMAPFetchAttribute, IMAPFetchItem};
pub use line::{IMAPLineEvent, IMAPLineReader};
pub use mailbox::IMAPMailbox;
pub use reader::IMAPReader;
pub use response::{IMAPCondition, IMAPNamespace, IMAPResponse, IMAPResponseCode, IMAPSearchData};
pub use search::{IMAPSearch, IMAPSearchKey};
pub use section::{IMAPSection, IMAPSectionText};
pub use sequence::{IMAPSequenceNumber, IMAPSequenceSet};
pub use server::{IMAPServer, IMAPServerEvent, IMAPServerPhase};
pub use writer::{IMAPLiteralMode, IMAPWriter};
