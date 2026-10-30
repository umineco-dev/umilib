//! The C ABI of [`crate::protocol`].

#[cfg(umilib_feature = "protocol-arp")]
pub mod arp;
#[cfg(umilib_feature = "protocol-coap")]
pub mod coap;
#[cfg(umilib_feature = "protocol-dhcp")]
pub mod dhcp;
#[cfg(umilib_feature = "protocol-dns")]
pub mod dns;
#[cfg(umilib_feature = "protocol-ethernet")]
pub mod ethernet;
#[cfg(umilib_feature = "protocol-ftp")]
pub mod ftp;
#[cfg(umilib_feature = "protocol-http")]
pub mod http;
#[cfg(umilib_feature = "protocol-icmp")]
pub mod icmp;
#[cfg(umilib_feature = "protocol-imap")]
pub mod imap;
#[cfg(umilib_feature = "protocol-ip")]
pub mod ip;
#[cfg(umilib_feature = "protocol-jwt")]
pub mod jwt;
#[cfg(umilib_feature = "protocol-pop")]
pub mod pop;
#[cfg(umilib_feature = "protocol-quic")]
pub mod quic;
#[cfg(umilib_feature = "protocol-smtp")]
pub mod smtp;
#[cfg(umilib_feature = "protocol-tcp")]
pub mod tcp;
#[cfg(umilib_feature = "protocol-tls")]
pub mod tls;
#[cfg(umilib_feature = "protocol-udp")]
pub mod udp;
#[cfg(umilib_feature = "protocol-websocket")]
pub mod websocket;

use crate::ffi::Module;

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "protocol",
    definitions: &[],
    functions: &[],
    modules: &[
        #[cfg(umilib_feature = "protocol-arp")]
        arp::MODULE,
        #[cfg(umilib_feature = "protocol-coap")]
        coap::MODULE,
        #[cfg(umilib_feature = "protocol-dhcp")]
        dhcp::MODULE,
        #[cfg(umilib_feature = "protocol-dns")]
        dns::MODULE,
        #[cfg(umilib_feature = "protocol-ethernet")]
        ethernet::MODULE,
        #[cfg(umilib_feature = "protocol-ftp")]
        ftp::MODULE,
        #[cfg(umilib_feature = "protocol-http")]
        http::MODULE,
        #[cfg(umilib_feature = "protocol-icmp")]
        icmp::MODULE,
        #[cfg(umilib_feature = "protocol-imap")]
        imap::MODULE,
        #[cfg(umilib_feature = "protocol-ip")]
        ip::MODULE,
        #[cfg(umilib_feature = "protocol-jwt")]
        jwt::MODULE,
        #[cfg(umilib_feature = "protocol-pop")]
        pop::MODULE,
        #[cfg(umilib_feature = "protocol-quic")]
        quic::MODULE,
        #[cfg(umilib_feature = "protocol-smtp")]
        smtp::MODULE,
        #[cfg(umilib_feature = "protocol-tcp")]
        tcp::MODULE,
        #[cfg(umilib_feature = "protocol-tls")]
        tls::MODULE,
        #[cfg(umilib_feature = "protocol-udp")]
        udp::MODULE,
        #[cfg(umilib_feature = "protocol-websocket")]
        websocket::MODULE,
    ],
};
