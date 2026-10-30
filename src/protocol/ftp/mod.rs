//! FTP (RFC 959) of the control connection, without I/O: a client
//! ([`FTPClient`]) and a server ([`FTPServer`]), their commands
//! ([`FTPCommand`]) and replies ([`FTPReply`]), the features of FEAT
//! ([`FTPFeatures`], RFC 2389), the addresses of data connections
//! ([`FTPDataAddress`], PORT and PASV, EPRT and EPSV of RFC 2428), the
//! facts and times of MLST, MLSD and MDTM ([`FTPFacts`], [`FTPTime`], RFC
//! 3659), HOST (RFC 7151), UTF-8 pathnames (RFC 2640), and FTPS (AUTH
//! TLS, PBSZ, PROT and CCC of RFC 4217). The data connections, the files
//! and TLS are the user's.

mod address;
mod client;
mod command;
mod config;
mod error;
mod facts;
mod reply;
mod server;

pub use address::FTPDataAddress;
pub use client::{FTPClient, FTPClientEvent};
pub use command::FTPCommand;
pub use config::{FTPConfig, FTPServerConfig};
pub use error::FTPError;
pub use facts::{FTPFacts, FTPTime};
pub use reply::{FTPFeature, FTPFeatures, FTPReply, FTPReplyReader};
pub use server::{FTPServer, FTPServerEvent};
