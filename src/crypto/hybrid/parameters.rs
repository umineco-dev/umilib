use crate::crypto::curve::p256::P256;
use crate::crypto::curve::p384::P384;
use crate::crypto::ecdh::{ECDH, X25519};
use crate::crypto::mlkem::{MLKEM, MLKEM768, MLKEM1024};
use crate::crypto::{KeyAgreement, KeyEncapsulation};

/// A hybrid of a post-quantum KEM and a traditional key agreement whose
/// shares and secrets are concatenated, as the groups of RFC 10024 are: a
/// type of no value, given to [`HybridKEM`](super::HybridKEM).
pub trait HybridKEMParameters: 'static {
    /// The name of the group, such as `X25519MLKEM768`.
    const NAME: &'static str;
    /// The TLS NamedGroup of RFC 10024 section 7.
    const CODEPOINT: u16;
    /// The post-quantum KEM.
    type KEM: KeyEncapsulation;
    /// The traditional key agreement, whose ephemeral share is the
    /// traditional part of the ciphertext.
    type KeyAgreement: KeyAgreement;
    /// Whether the parts of the KEM come first in the shares and the secret.
    const KEM_FIRST: bool;
}

/// X25519MLKEM768 (RFC 10024): the ML-KEM-768 part first, then X25519;
/// the shared secret is 64 bytes.
pub struct X25519MLKEM768;

impl HybridKEMParameters for X25519MLKEM768 {
    const NAME: &'static str = "X25519MLKEM768";
    const CODEPOINT: u16 = 0x11EC;
    type KEM = MLKEM<MLKEM768>;
    type KeyAgreement = X25519;
    const KEM_FIRST: bool = true;
}

/// SecP256r1MLKEM768 (RFC 10024): the uncompressed secp256r1 share first,
/// then ML-KEM-768; the shared secret is 64 bytes.
pub struct SecP256r1MLKEM768;

impl HybridKEMParameters for SecP256r1MLKEM768 {
    const NAME: &'static str = "SecP256r1MLKEM768";
    const CODEPOINT: u16 = 0x11EB;
    type KEM = MLKEM<MLKEM768>;
    type KeyAgreement = ECDH<P256>;
    const KEM_FIRST: bool = false;
}

/// SecP384r1MLKEM1024 (RFC 10024): the uncompressed secp384r1 share first,
/// then ML-KEM-1024; the shared secret is 80 bytes.
pub struct SecP384r1MLKEM1024;

impl HybridKEMParameters for SecP384r1MLKEM1024 {
    const NAME: &'static str = "SecP384r1MLKEM1024";
    const CODEPOINT: u16 = 0x11ED;
    type KEM = MLKEM<MLKEM1024>;
    type KeyAgreement = ECDH<P384>;
    const KEM_FIRST: bool = false;
}
