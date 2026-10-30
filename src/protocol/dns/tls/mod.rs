//! DNS: `tls` — DNS over TLS (RFC 7858): the messages of a TCP stream
//! ([`super::tcp`]) as TLS application data, on port 853, the ALPN "dot"
//! if one is negotiated (no other), padded as RFC 8467 says.

use alloc::vec::Vec;
use core::fmt;

use crate::crypto::random::Random;
use crate::protocol::tls::{TLSConnection, TLSError, TLSEvent};
use crate::runtime::Instant;

use super::tcp::{DNSTCPClient, DNSTCPClientConfig, DNSTCPServer, DNSTCPServerConfig};
use super::{DNSAuthority, DNSError, DNSMessage, DNSPeer};

/// An error of DNS over TLS: of DNS, or of TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DNSTLSError {
    DNS(DNSError),
    TLS(TLSError),
}

impl fmt::Display for DNSTLSError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSTLSError::DNS(error) => write!(formatter, "{error}"),
            DNSTLSError::TLS(error) => write!(formatter, "{error}"),
        }
    }
}

impl core::error::Error for DNSTLSError {}

impl From<DNSError> for DNSTLSError {
    fn from(error: DNSError) -> DNSTLSError {
        DNSTLSError::DNS(error)
    }
}

impl From<TLSError> for DNSTLSError {
    fn from(error: TLSError) -> DNSTLSError {
        DNSTLSError::TLS(error)
    }
}

/// The constants of DNS over TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DNSTLS;

impl DNSTLS {
    /// The ALPN of DNS over TLS (IANA's TLS ALPN registry).
    pub const ALPN: &'static [u8] = b"dot";
    /// The port of DNS over TLS (RFC 7858 §3.1).
    pub const PORT: u16 = 853;

    /// Checks the application protocol `connection` negotiated: none, or "dot".
    pub fn check_protocol(connection: &TLSConnection) -> Result<(), DNSTLSError> {
        match connection.session.protocol.as_deref() {
            None => Ok(()),
            Some(protocol) if protocol == DNSTLS::ALPN => Ok(()),
            Some(_) => Err(DNSTLSError::DNS(DNSError::Config)),
        }
    }

    /// Moves the plaintext `connection` has received into `out`.
    pub fn read_all(connection: &mut TLSConnection, out: &mut Vec<u8>) {
        let mut buffer = [0u8; 4096];
        loop {
            let count = connection.read(&mut buffer);
            if count == 0 {
                break;
            }
            out.extend_from_slice(&buffer[..count]);
        }
    }

    /// Takes the events of `connection`, checking its protocol once it is connected.
    pub fn take_events(connection: &mut TLSConnection) -> Result<(), DNSTLSError> {
        while let Some(event) = connection.poll_event() {
            if event == TLSEvent::Connected {
                DNSTLS::check_protocol(connection)?;
            }
        }
        Ok(())
    }
}

/// A client's connection over TLS: [`DNSTCPClient`] over a client's
/// [`TLSConnection`], whose certificate check is the TLS configuration's
/// (RFC 8310 §8 for the name to check).
#[derive(Debug)]
pub struct DNSTLSClient {
    pub tls: TLSConnection,
    pub dns: DNSTCPClient,
}

impl DNSTLSClient {
    pub fn new(tls: TLSConnection, config: DNSTCPClientConfig, now: Instant) -> DNSTLSClient {
        DNSTLSClient { tls, dns: DNSTCPClient::new(config, now) }
    }

    /// Sends `query`; before the handshake completes, it waits.
    pub fn send<R: Random>(&mut self, handle: u64, query: DNSMessage, random: &mut R) -> Result<u16, DNSTLSError> {
        let id = self.dns.send(handle, query, random)?;
        self.flush()?;
        Ok(id)
    }

    /// Gives TLS the queries waiting, once the handshake is complete.
    pub fn flush(&mut self) -> Result<(), DNSTLSError> {
        if !self.tls.is_handshaking() && !self.dns.output.is_empty() {
            self.tls.send(&self.dns.transmit())?;
        }
        Ok(())
    }

    /// Takes `bytes` of the network.
    pub fn receive(&mut self, bytes: &[u8], now: Instant) -> Result<(), DNSTLSError> {
        self.tls.receive(bytes)?;
        DNSTLS::take_events(&mut self.tls)?;
        self.flush()?;
        let mut plaintext = Vec::new();
        DNSTLS::read_all(&mut self.tls, &mut plaintext);
        self.dns.receive(&plaintext, now)?;
        Ok(())
    }

    /// Writes the bytes to send into `out`.
    pub fn transmit(&mut self, out: &mut Vec<u8>) -> Result<usize, DNSTLSError> {
        Ok(self.tls.transmit(out)?)
    }

    pub fn poll_response(&mut self) -> Option<(u64, DNSMessage)> {
        self.dns.poll_response()
    }
}

/// A server's connection over TLS: [`DNSTCPServer`] over a server's [`TLSConnection`].
#[derive(Debug)]
pub struct DNSTLSServer {
    pub tls: TLSConnection,
    pub dns: DNSTCPServer,
}

impl DNSTLSServer {
    pub fn new(tls: TLSConnection, config: DNSTCPServerConfig, peer: DNSPeer, now: Instant) -> DNSTLSServer {
        DNSTLSServer { tls, dns: DNSTCPServer::new(config, peer, now) }
    }

    /// Takes `bytes` of the network and answers the queries they complete.
    pub fn receive(
        &mut self,
        bytes: &[u8],
        authority: &DNSAuthority,
        now: Instant,
        time: u32,
    ) -> Result<(), DNSTLSError> {
        self.tls.receive(bytes)?;
        DNSTLS::take_events(&mut self.tls)?;
        let mut plaintext = Vec::new();
        DNSTLS::read_all(&mut self.tls, &mut plaintext);
        self.dns.receive(&plaintext, authority, now, time)?;
        let output = self.dns.transmit();
        if !output.is_empty() {
            self.tls.send(&output)?;
        }
        Ok(())
    }

    pub fn transmit(&mut self, out: &mut Vec<u8>) -> Result<usize, DNSTLSError> {
        Ok(self.tls.transmit(out)?)
    }
}
