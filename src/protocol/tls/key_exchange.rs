use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::KeyAgreement;
use crate::crypto::curve::curve448::Curve448;
use crate::crypto::curve::curve25519::Curve25519;
use crate::crypto::curve::p256::P256;
use crate::crypto::curve::p384::P384;
use crate::crypto::curve::p521::P521;
use crate::crypto::ecdh::{ECDH, ECDHPrivateKey, XDH, XDHPrivateKey};
use crate::crypto::random::Random;
use crate::secret::Secret;

use super::{TLSAlertDescription, TLSError, TLSNamedGroup};

/// The private half of a key share: what the client keeps between its
/// ClientHello and the server's share (RFC 9846 §4.3.8, RFC 7919, RFC
/// 10024). The groups of finite fields need `crypto-dh`, the hybrids
/// `crypto-hybrid`.
pub enum TLSKeyShareSecret {
    X25519(XDHPrivateKey<Curve25519>),
    X448(XDHPrivateKey<Curve448>),
    SECP256R1(ECDHPrivateKey<P256>),
    SECP384R1(ECDHPrivateKey<P384>),
    SECP521R1(ECDHPrivateKey<P521>),
    #[cfg(umilib_feature = "crypto-dh")]
    FFDHE(TLSFiniteFieldSecret),
    /// Boxed: a hybrid's key is kilobytes, the others' tens of bytes.
    #[cfg(umilib_feature = "crypto-hybrid")]
    Hybrid(alloc::boxed::Box<TLSHybridSecret>),
}

impl core::fmt::Debug for TLSKeyShareSecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "TLSKeyShareSecret({:?})", self.group())
    }
}

/// The secret of a group of finite fields (RFC 7919).
#[cfg(umilib_feature = "crypto-dh")]
pub enum TLSFiniteFieldSecret {
    FFDHE2048(crate::crypto::dh::DHPrivateKey<crate::crypto::dh::FFDHE2048>),
    FFDHE3072(crate::crypto::dh::DHPrivateKey<crate::crypto::dh::FFDHE3072>),
    FFDHE4096(crate::crypto::dh::DHPrivateKey<crate::crypto::dh::FFDHE4096>),
    FFDHE6144(crate::crypto::dh::DHPrivateKey<crate::crypto::dh::FFDHE6144>),
    FFDHE8192(crate::crypto::dh::DHPrivateKey<crate::crypto::dh::FFDHE8192>),
}

/// The decapsulation key of a hybrid (RFC 10024).
#[cfg(umilib_feature = "crypto-hybrid")]
pub enum TLSHybridSecret {
    X25519MLKEM768(crate::crypto::hybrid::HybridDecapsulationKey<crate::crypto::hybrid::X25519MLKEM768>),
    SecP256r1MLKEM768(crate::crypto::hybrid::HybridDecapsulationKey<crate::crypto::hybrid::SecP256r1MLKEM768>),
    /// Boxed: its key is larger than the others' by a kilobyte.
    SecP384r1MLKEM1024(
        alloc::boxed::Box<crate::crypto::hybrid::HybridDecapsulationKey<crate::crypto::hybrid::SecP384r1MLKEM1024>>,
    ),
}

impl TLSKeyShareSecret {
    /// Whether this crate can exchange keys in `group`.
    pub fn supports(group: TLSNamedGroup) -> bool {
        let finite = cfg!(umilib_feature = "crypto-dh") && group.kind() == Some(super::TLSGroupKind::FFDHE);
        let hybrid = cfg!(umilib_feature = "crypto-hybrid") && group.kind() == Some(super::TLSGroupKind::Hybrid);
        group.kind() == Some(super::TLSGroupKind::ECDHE) || finite || hybrid
    }

    /// A new secret of `group` and the share to send for it (the client's
    /// `key_exchange`); fails with `internal_error` for a group this crate
    /// does not support or a failing random source.
    pub fn generate<R: Random>(group: TLSNamedGroup, random: &mut R) -> Result<(TLSKeyShareSecret, Vec<u8>), TLSError> {
        Ok(match group {
            TLSNamedGroup::X25519 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<XDH<Curve25519>, R>(random)?;
                (TLSKeyShareSecret::X25519(secret), share)
            }
            TLSNamedGroup::X448 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<XDH<Curve448>, R>(random)?;
                (TLSKeyShareSecret::X448(secret), share)
            }
            TLSNamedGroup::SECP256R1 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<ECDH<P256>, R>(random)?;
                (TLSKeyShareSecret::SECP256R1(secret), share)
            }
            TLSNamedGroup::SECP384R1 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<ECDH<P384>, R>(random)?;
                (TLSKeyShareSecret::SECP384R1(secret), share)
            }
            TLSNamedGroup::SECP521R1 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<ECDH<P521>, R>(random)?;
                (TLSKeyShareSecret::SECP521R1(secret), share)
            }
            #[cfg(umilib_feature = "crypto-dh")]
            group if group.kind() == Some(super::TLSGroupKind::FFDHE) => {
                let (secret, share) = TLSFiniteFieldSecret::generate(group, random)?;
                (TLSKeyShareSecret::FFDHE(secret), share)
            }
            #[cfg(umilib_feature = "crypto-hybrid")]
            group if group.kind() == Some(super::TLSGroupKind::Hybrid) => {
                let (secret, share) = TLSHybridSecret::generate(group, random)?;
                (TLSKeyShareSecret::Hybrid(alloc::boxed::Box::new(secret)), share)
            }
            _ => return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR)),
        })
    }

    pub fn group(&self) -> TLSNamedGroup {
        match self {
            TLSKeyShareSecret::X25519(_) => TLSNamedGroup::X25519,
            TLSKeyShareSecret::X448(_) => TLSNamedGroup::X448,
            TLSKeyShareSecret::SECP256R1(_) => TLSNamedGroup::SECP256R1,
            TLSKeyShareSecret::SECP384R1(_) => TLSNamedGroup::SECP384R1,
            TLSKeyShareSecret::SECP521R1(_) => TLSNamedGroup::SECP521R1,
            #[cfg(umilib_feature = "crypto-dh")]
            TLSKeyShareSecret::FFDHE(secret) => secret.group(),
            #[cfg(umilib_feature = "crypto-hybrid")]
            TLSKeyShareSecret::Hybrid(secret) => secret.group(),
        }
    }

    /// The shared secret from the server's share; fails with
    /// `illegal_parameter` for a share that is not valid in the group
    /// (RFC 9846 §4.3.8.1, §4.3.8.2, §7.4, RFC 10024 §4).
    pub fn complete(&self, share: &[u8]) -> Result<Secret<Vec<u8>>, TLSError> {
        match self {
            TLSKeyShareSecret::X25519(secret) => TLSKeyShareSecret::agree_with::<XDH<Curve25519>>(secret, share),
            TLSKeyShareSecret::X448(secret) => TLSKeyShareSecret::agree_with::<XDH<Curve448>>(secret, share),
            TLSKeyShareSecret::SECP256R1(secret) => TLSKeyShareSecret::agree_with::<ECDH<P256>>(secret, share),
            TLSKeyShareSecret::SECP384R1(secret) => TLSKeyShareSecret::agree_with::<ECDH<P384>>(secret, share),
            TLSKeyShareSecret::SECP521R1(secret) => TLSKeyShareSecret::agree_with::<ECDH<P521>>(secret, share),
            #[cfg(umilib_feature = "crypto-dh")]
            TLSKeyShareSecret::FFDHE(secret) => secret.complete(share),
            #[cfg(umilib_feature = "crypto-hybrid")]
            TLSKeyShareSecret::Hybrid(secret) => secret.complete(share),
        }
    }

    /// The server's side: its share for the client's `share` of `group`,
    /// and the shared secret. Diffie-Hellman generates a key and agrees;
    /// a KEM encapsulates to the client's key. Fails with
    /// `illegal_parameter` for an invalid client share.
    pub fn respond<R: Random>(
        group: TLSNamedGroup,
        share: &[u8],
        random: &mut R,
    ) -> Result<(Vec<u8>, Secret<Vec<u8>>), TLSError> {
        #[cfg(umilib_feature = "crypto-hybrid")]
        if group.kind() == Some(super::TLSGroupKind::Hybrid) {
            return TLSHybridSecret::respond(group, share, random);
        }
        let (secret, own) = TLSKeyShareSecret::generate(group, random)?;
        Ok((own, secret.complete(share)?))
    }

    /// A key pair of `K` and the encoding of its public key.
    pub fn generate_with<K: KeyAgreement, R: Random>(random: &mut R) -> Result<(K::PrivateKey, Vec<u8>), TLSError> {
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        let private = K::generate(random).map_err(internal)?;
        let mut share = vec![0; K::PUBLIC_KEY_SIZE];
        K::write_public_key(&K::public_key(&private), &mut share).map_err(internal)?;
        Ok((private, share))
    }

    /// The shared secret of `private` and the peer's public key `share`,
    /// which must have the length of the uncompressed form (RFC 9846
    /// §4.3.8.2: no other form is allowed) and pass the group's checks.
    pub fn agree_with<K: KeyAgreement>(private: &K::PrivateKey, share: &[u8]) -> Result<Secret<Vec<u8>>, TLSError> {
        if share.len() != K::PUBLIC_KEY_SIZE {
            return Err(TLSError::illegal());
        }
        let public = K::public_key_from_bytes(share).map_err(|_| TLSError::illegal())?;
        let mut shared = Secret::new(vec![0; K::SHARED_SECRET_SIZE]);
        // X25519 and X448 refuse an all-zero result (RFC 9846 §7.4.2).
        K::agree(private, &public, shared.expose_mut()).map_err(|_| TLSError::illegal())?;
        Ok(shared)
    }
}

#[cfg(umilib_feature = "crypto-dh")]
impl TLSFiniteFieldSecret {
    pub fn generate<R: Random>(
        group: TLSNamedGroup,
        random: &mut R,
    ) -> Result<(TLSFiniteFieldSecret, Vec<u8>), TLSError> {
        use crate::crypto::dh::{DH, FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192};
        Ok(match group {
            TLSNamedGroup::FFDHE2048 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<DH<FFDHE2048>, R>(random)?;
                (TLSFiniteFieldSecret::FFDHE2048(secret), share)
            }
            TLSNamedGroup::FFDHE3072 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<DH<FFDHE3072>, R>(random)?;
                (TLSFiniteFieldSecret::FFDHE3072(secret), share)
            }
            TLSNamedGroup::FFDHE4096 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<DH<FFDHE4096>, R>(random)?;
                (TLSFiniteFieldSecret::FFDHE4096(secret), share)
            }
            TLSNamedGroup::FFDHE6144 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<DH<FFDHE6144>, R>(random)?;
                (TLSFiniteFieldSecret::FFDHE6144(secret), share)
            }
            TLSNamedGroup::FFDHE8192 => {
                let (secret, share) = TLSKeyShareSecret::generate_with::<DH<FFDHE8192>, R>(random)?;
                (TLSFiniteFieldSecret::FFDHE8192(secret), share)
            }
            _ => return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR)),
        })
    }

    pub fn group(&self) -> TLSNamedGroup {
        match self {
            TLSFiniteFieldSecret::FFDHE2048(_) => TLSNamedGroup::FFDHE2048,
            TLSFiniteFieldSecret::FFDHE3072(_) => TLSNamedGroup::FFDHE3072,
            TLSFiniteFieldSecret::FFDHE4096(_) => TLSNamedGroup::FFDHE4096,
            TLSFiniteFieldSecret::FFDHE6144(_) => TLSNamedGroup::FFDHE6144,
            TLSFiniteFieldSecret::FFDHE8192(_) => TLSNamedGroup::FFDHE8192,
        }
    }

    /// The shared secret, left-padded to the length of the prime (RFC 9846
    /// §7.4.1); the peer's value must be in 2..p-2 and of the prime's
    /// length (§4.3.8.1).
    pub fn complete(&self, share: &[u8]) -> Result<Secret<Vec<u8>>, TLSError> {
        use crate::crypto::dh::{DH, FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192};
        match self {
            TLSFiniteFieldSecret::FFDHE2048(secret) => TLSKeyShareSecret::agree_with::<DH<FFDHE2048>>(secret, share),
            TLSFiniteFieldSecret::FFDHE3072(secret) => TLSKeyShareSecret::agree_with::<DH<FFDHE3072>>(secret, share),
            TLSFiniteFieldSecret::FFDHE4096(secret) => TLSKeyShareSecret::agree_with::<DH<FFDHE4096>>(secret, share),
            TLSFiniteFieldSecret::FFDHE6144(secret) => TLSKeyShareSecret::agree_with::<DH<FFDHE6144>>(secret, share),
            TLSFiniteFieldSecret::FFDHE8192(secret) => TLSKeyShareSecret::agree_with::<DH<FFDHE8192>>(secret, share),
        }
    }
}

#[cfg(umilib_feature = "crypto-hybrid")]
impl TLSHybridSecret {
    pub fn generate<R: Random>(group: TLSNamedGroup, random: &mut R) -> Result<(TLSHybridSecret, Vec<u8>), TLSError> {
        use crate::crypto::hybrid::{HybridKEM, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768};
        Ok(match group {
            TLSNamedGroup::X25519_MLKEM768 => {
                let (secret, share) = TLSHybridSecret::generate_with::<HybridKEM<X25519MLKEM768>, R>(random)?;
                (TLSHybridSecret::X25519MLKEM768(secret), share)
            }
            TLSNamedGroup::SECP256R1_MLKEM768 => {
                let (secret, share) = TLSHybridSecret::generate_with::<HybridKEM<SecP256r1MLKEM768>, R>(random)?;
                (TLSHybridSecret::SecP256r1MLKEM768(secret), share)
            }
            TLSNamedGroup::SECP384R1_MLKEM1024 => {
                let (secret, share) = TLSHybridSecret::generate_with::<HybridKEM<SecP384r1MLKEM1024>, R>(random)?;
                (TLSHybridSecret::SecP384r1MLKEM1024(alloc::boxed::Box::new(secret)), share)
            }
            _ => return Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR)),
        })
    }

    pub fn group(&self) -> TLSNamedGroup {
        match self {
            TLSHybridSecret::X25519MLKEM768(_) => TLSNamedGroup::X25519_MLKEM768,
            TLSHybridSecret::SecP256r1MLKEM768(_) => TLSNamedGroup::SECP256R1_MLKEM768,
            TLSHybridSecret::SecP384r1MLKEM1024(_) => TLSNamedGroup::SECP384R1_MLKEM1024,
        }
    }

    /// The shared secret from the server's ciphertext share.
    pub fn complete(&self, share: &[u8]) -> Result<Secret<Vec<u8>>, TLSError> {
        use crate::crypto::hybrid::{HybridKEM, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768};
        match self {
            TLSHybridSecret::X25519MLKEM768(key) => {
                TLSHybridSecret::decapsulate_with::<HybridKEM<X25519MLKEM768>>(key, share)
            }
            TLSHybridSecret::SecP256r1MLKEM768(key) => {
                TLSHybridSecret::decapsulate_with::<HybridKEM<SecP256r1MLKEM768>>(key, share)
            }
            TLSHybridSecret::SecP384r1MLKEM1024(key) => {
                TLSHybridSecret::decapsulate_with::<HybridKEM<SecP384r1MLKEM1024>>(key, share)
            }
        }
    }

    /// The server's ciphertext share and the shared secret for the client's
    /// encapsulation key `share`.
    pub fn respond<R: Random>(
        group: TLSNamedGroup,
        share: &[u8],
        random: &mut R,
    ) -> Result<(Vec<u8>, Secret<Vec<u8>>), TLSError> {
        use crate::crypto::hybrid::{HybridKEM, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519MLKEM768};
        match group {
            TLSNamedGroup::X25519_MLKEM768 => {
                TLSHybridSecret::encapsulate_with::<HybridKEM<X25519MLKEM768>, R>(share, random)
            }
            TLSNamedGroup::SECP256R1_MLKEM768 => {
                TLSHybridSecret::encapsulate_with::<HybridKEM<SecP256r1MLKEM768>, R>(share, random)
            }
            TLSNamedGroup::SECP384R1_MLKEM1024 => {
                TLSHybridSecret::encapsulate_with::<HybridKEM<SecP384r1MLKEM1024>, R>(share, random)
            }
            _ => Err(TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR)),
        }
    }

    pub fn generate_with<K: crate::crypto::KeyEncapsulation, R: Random>(
        random: &mut R,
    ) -> Result<(K::DecapsulationKey, Vec<u8>), TLSError> {
        let internal = |_| TLSError::Protocol(TLSAlertDescription::INTERNAL_ERROR);
        let key = K::generate(random).map_err(internal)?;
        let mut share = vec![0; K::ENCAPSULATION_KEY_SIZE];
        K::write_encapsulation_key(&K::encapsulation_key(&key), &mut share).map_err(internal)?;
        Ok((key, share))
    }

    /// Fails with `illegal_parameter` for a key of the wrong length or one
    /// that fails ML-KEM's or ECDH's checks (RFC 10024 §4).
    pub fn encapsulate_with<K: crate::crypto::KeyEncapsulation, R: Random>(
        share: &[u8],
        random: &mut R,
    ) -> Result<(Vec<u8>, Secret<Vec<u8>>), TLSError> {
        if share.len() != K::ENCAPSULATION_KEY_SIZE {
            return Err(TLSError::illegal());
        }
        let key = K::encapsulation_key_from_bytes(share).map_err(|_| TLSError::illegal())?;
        let mut ciphertext = vec![0; K::CIPHERTEXT_SIZE];
        let mut shared = Secret::new(vec![0; K::SHARED_SECRET_SIZE]);
        K::encapsulate(&key, random, &mut ciphertext, shared.expose_mut()).map_err(|_| TLSError::illegal())?;
        Ok((ciphertext, shared))
    }

    pub fn decapsulate_with<K: crate::crypto::KeyEncapsulation>(
        key: &K::DecapsulationKey,
        share: &[u8],
    ) -> Result<Secret<Vec<u8>>, TLSError> {
        if share.len() != K::CIPHERTEXT_SIZE {
            return Err(TLSError::illegal());
        }
        let mut shared = Secret::new(vec![0; K::SHARED_SECRET_SIZE]);
        K::decapsulate(key, share, shared.expose_mut()).map_err(|_| TLSError::illegal())?;
        Ok(shared)
    }
}
