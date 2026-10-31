//! Tests of `umilib::protocol`.

#![allow(clippy::upper_case_acronyms)]

#[cfg(umilib_feature = "protocol-arp")]
mod arp;
#[cfg(umilib_feature = "protocol-coap")]
mod coap;
#[cfg(umilib_feature = "protocol-dhcp")]
mod dhcp;
#[cfg(umilib_feature = "protocol-dns")]
mod dns;
#[cfg(umilib_feature = "protocol-ethernet")]
mod ethernet;
#[cfg(umilib_feature = "protocol-ftp")]
mod ftp;
#[cfg(umilib_feature = "protocol-http")]
mod http;
#[cfg(umilib_feature = "protocol-icmp")]
mod icmp;
#[cfg(umilib_feature = "protocol-imap")]
mod imap;
#[cfg(umilib_feature = "protocol-ip")]
mod ip;
#[cfg(umilib_feature = "protocol-jwt")]
mod jwt;
#[cfg(umilib_feature = "protocol-pop")]
mod pop;
#[cfg(umilib_feature = "protocol-quic")]
mod quic;
#[cfg(umilib_feature = "protocol-smtp")]
mod smtp;
#[cfg(umilib_feature = "protocol-tcp")]
mod tcp;
#[cfg(umilib_feature = "protocol-tls")]
mod tls;
#[cfg(umilib_feature = "protocol-udp")]
mod udp;
#[cfg(umilib_feature = "protocol-websocket")]
mod websocket;

#[path = "../common/vectors.rs"]
mod vectors;

pub use vectors::{Capture, JSON, RFC, Vectors, Wycheproof};
