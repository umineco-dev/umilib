use alloc::borrow::Cow;

use super::KeyError;
use crate::codec::asn1::der::{DERReader, DERWriter};
use crate::codec::asn1::{ASN1Error, ObjectIdentifier, Tag};

/// An `AlgorithmIdentifier` (RFC 5280 §4.1.1.2): an object identifier and
/// optional parameters, kept as their DER encoding (one element).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AlgorithmIdentifier<'a> {
    pub oid: ObjectIdentifier<'a>,
    pub parameters: Option<Cow<'a, [u8]>>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// The DER encoding of the parameter `NULL`.
    pub const NULL: &'static [u8] = &[0x05, 0x00];

    pub const fn new(oid: ObjectIdentifier<'a>, parameters: Option<Cow<'a, [u8]>>) -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier { oid, parameters }
    }

    /// The identifier of `oid` without parameters.
    pub const fn absent(oid: ObjectIdentifier<'a>) -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier { oid, parameters: None }
    }

    /// The identifier of `oid` with the parameter `NULL`.
    pub const fn null(oid: ObjectIdentifier<'a>) -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier { oid, parameters: Some(Cow::Borrowed(AlgorithmIdentifier::NULL)) }
    }

    /// Reads the next `AlgorithmIdentifier` of `reader`.
    pub fn decode(reader: &mut DERReader<'a>) -> Result<AlgorithmIdentifier<'a>, ASN1Error> {
        let mut sequence = reader.read_sequence()?;
        let oid = sequence.read_with(Tag::OBJECT_IDENTIFIER, |element| element.as_object_identifier())?;
        let parameters =
            if sequence.is_empty() { None } else { Some(Cow::Borrowed(sequence.read_element()?.encoding)) };
        sequence.finish()?;
        Ok(AlgorithmIdentifier { oid, parameters })
    }

    /// The identifier of the DER encoding `bytes`.
    pub fn from_der(bytes: &'a [u8]) -> Result<AlgorithmIdentifier<'a>, ASN1Error> {
        let mut reader = DERReader::new(bytes);
        let identifier = AlgorithmIdentifier::decode(&mut reader)?;
        reader.finish()?;
        Ok(identifier)
    }

    pub fn encode(&self, writer: &mut DERWriter) -> Result<(), ASN1Error> {
        writer.write_sequence(|sequence| {
            sequence.write_object_identifier(&self.oid);
            if let Some(parameters) = &self.parameters {
                sequence.write_raw(parameters);
            }
            Ok(())
        })
    }

    pub fn to_der(&self) -> Result<alloc::vec::Vec<u8>, ASN1Error> {
        let mut writer = DERWriter::new();
        self.encode(&mut writer)?;
        Ok(writer.into_bytes())
    }

    /// Whether the parameters are absent.
    pub fn has_absent_parameters(&self) -> bool {
        self.parameters.is_none()
    }

    /// Whether the parameters are `NULL` or absent (the two encodings
    /// RFC 4055 §2.1 and RFC 5754 §2 require to be accepted alike).
    pub fn has_null_or_absent_parameters(&self) -> bool {
        self.parameters.as_deref().is_none_or(|parameters| parameters == AlgorithmIdentifier::NULL)
    }

    pub fn into_owned(self) -> AlgorithmIdentifier<'static> {
        AlgorithmIdentifier {
            oid: self.oid.into_owned(),
            parameters: self.parameters.map(|parameters| Cow::Owned(parameters.into_owned())),
        }
    }
}

/// A hash function of the identifiers of signatures and keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum HashAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    SHA512_224,
    SHA512_256,
    SHA3_224,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,
    SHAKE256,
}

impl HashAlgorithm {
    pub const ALL: [HashAlgorithm; 13] = [
        HashAlgorithm::SHA1,
        HashAlgorithm::SHA224,
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512,
        HashAlgorithm::SHA512_224,
        HashAlgorithm::SHA512_256,
        HashAlgorithm::SHA3_224,
        HashAlgorithm::SHA3_256,
        HashAlgorithm::SHA3_384,
        HashAlgorithm::SHA3_512,
        HashAlgorithm::SHAKE128,
        HashAlgorithm::SHAKE256,
    ];

    /// The object identifier (id-sha1 of RFC 3279, id-sha* of NIST CSOR).
    pub const fn oid(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier::from_static(match self {
            HashAlgorithm::SHA1 => &[0x2B, 0x0E, 0x03, 0x02, 0x1A],
            HashAlgorithm::SHA224 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04],
            HashAlgorithm::SHA256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            HashAlgorithm::SHA384 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            HashAlgorithm::SHA512 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
            HashAlgorithm::SHA512_224 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05],
            HashAlgorithm::SHA512_256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06],
            HashAlgorithm::SHA3_224 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07],
            HashAlgorithm::SHA3_256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08],
            HashAlgorithm::SHA3_384 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09],
            HashAlgorithm::SHA3_512 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A],
            HashAlgorithm::SHAKE128 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
            HashAlgorithm::SHAKE256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier<'_>) -> Option<HashAlgorithm> {
        HashAlgorithm::ALL.into_iter().find(|hash| hash.oid() == *oid)
    }

    /// The hash function of `identifier`, whose parameters must be `NULL` or
    /// absent (RFC 4055 §2.1, RFC 5754 §2).
    pub fn from_identifier(identifier: &AlgorithmIdentifier<'_>) -> Result<HashAlgorithm, KeyError> {
        let hash = HashAlgorithm::from_oid(&identifier.oid).ok_or(KeyError::UnknownAlgorithm)?;
        if !identifier.has_null_or_absent_parameters() {
            return Err(KeyError::Parameters);
        }
        Ok(hash)
    }

    /// The identifier written: with the parameter `NULL`, as the
    /// identifiers of RFC 4055 §2.1 are.
    pub const fn identifier(self) -> AlgorithmIdentifier<'static> {
        AlgorithmIdentifier::null(self.oid())
    }

    /// The bytes of the digest (of the output RFC 9909 and RFC 8702 use for SHAKE128 and SHAKE256).
    pub const fn output_size(self) -> usize {
        match self {
            HashAlgorithm::SHA1 => 20,
            HashAlgorithm::SHA224 | HashAlgorithm::SHA512_224 | HashAlgorithm::SHA3_224 => 28,
            HashAlgorithm::SHA256 | HashAlgorithm::SHA512_256 | HashAlgorithm::SHA3_256 | HashAlgorithm::SHAKE128 => 32,
            HashAlgorithm::SHA384 | HashAlgorithm::SHA3_384 => 48,
            HashAlgorithm::SHA512 | HashAlgorithm::SHA3_512 | HashAlgorithm::SHAKE256 => 64,
        }
    }

    /// Whether the hash function is an extendable-output function.
    pub const fn is_xof(self) -> bool {
        matches!(self, HashAlgorithm::SHAKE128 | HashAlgorithm::SHAKE256)
    }

    /// Writes the digest of `message` (of [`HashAlgorithm::output_size`]
    /// bytes) into the first bytes of `out`; returns its length.
    pub fn digest(self, message: &[u8], out: &mut [u8; 64]) -> usize {
        use crate::hash::{Digest, ExtendableOutput, XOFReader};
        let size = self.output_size();
        with_digest!(self, H => {
            out[..size].copy_from_slice(H::digest(message).as_ref());
        }, xof => {
            if self == HashAlgorithm::SHAKE128 {
                let mut function = crate::hash::sha::v3::SHAKE128::default();
                function.update(message);
                function.finalize_xof().read(&mut out[..size]);
            } else {
                let mut function = crate::hash::sha::v3::SHAKE256::default();
                function.update(message);
                function.finalize_xof().read(&mut out[..size]);
            }
        });
        size
    }
}

/// A named elliptic curve of the `namedCurve` parameters of RFC 5480 and RFC 5639.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NamedCurve {
    /// secp256r1 (prime256v1).
    P256,
    /// secp384r1.
    P384,
    /// secp521r1.
    P521,
    Secp256k1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl NamedCurve {
    pub const ALL: [NamedCurve; 7] = [
        NamedCurve::P256,
        NamedCurve::P384,
        NamedCurve::P521,
        NamedCurve::Secp256k1,
        NamedCurve::BrainpoolP256r1,
        NamedCurve::BrainpoolP384r1,
        NamedCurve::BrainpoolP512r1,
    ];

    pub const fn oid(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier::from_static(match self {
            NamedCurve::P256 => &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
            NamedCurve::P384 => &[0x2B, 0x81, 0x04, 0x00, 0x22],
            NamedCurve::P521 => &[0x2B, 0x81, 0x04, 0x00, 0x23],
            NamedCurve::Secp256k1 => &[0x2B, 0x81, 0x04, 0x00, 0x0A],
            NamedCurve::BrainpoolP256r1 => &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
            NamedCurve::BrainpoolP384r1 => &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B],
            NamedCurve::BrainpoolP512r1 => &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier<'_>) -> Option<NamedCurve> {
        NamedCurve::ALL.into_iter().find(|curve| curve.oid() == *oid)
    }

    /// The bytes of a coordinate (and of a private key).
    pub const fn field_size(self) -> usize {
        match self {
            NamedCurve::P256 | NamedCurve::Secp256k1 | NamedCurve::BrainpoolP256r1 => 32,
            NamedCurve::P384 | NamedCurve::BrainpoolP384r1 => 48,
            NamedCurve::P521 => 66,
            NamedCurve::BrainpoolP512r1 => 64,
        }
    }
}

/// A parameter set of ML-DSA (FIPS 204, RFC 9881).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MLDSAParameterSet {
    MLDSA44,
    MLDSA65,
    MLDSA87,
}

impl MLDSAParameterSet {
    pub const ALL: [MLDSAParameterSet; 3] =
        [MLDSAParameterSet::MLDSA44, MLDSAParameterSet::MLDSA65, MLDSAParameterSet::MLDSA87];

    pub const fn oid(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier::from_static(match self {
            MLDSAParameterSet::MLDSA44 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
            MLDSAParameterSet::MLDSA65 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
            MLDSAParameterSet::MLDSA87 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier<'_>) -> Option<MLDSAParameterSet> {
        MLDSAParameterSet::ALL.into_iter().find(|set| set.oid() == *oid)
    }
}

/// A parameter set of ML-KEM (FIPS 203, RFC 9935).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MLKEMParameterSet {
    MLKEM512,
    MLKEM768,
    MLKEM1024,
}

impl MLKEMParameterSet {
    pub const ALL: [MLKEMParameterSet; 3] =
        [MLKEMParameterSet::MLKEM512, MLKEMParameterSet::MLKEM768, MLKEMParameterSet::MLKEM1024];

    pub const fn oid(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier::from_static(match self {
            MLKEMParameterSet::MLKEM512 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01],
            MLKEMParameterSet::MLKEM768 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02],
            MLKEMParameterSet::MLKEM1024 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03],
        })
    }

    pub fn from_oid(oid: &ObjectIdentifier<'_>) -> Option<MLKEMParameterSet> {
        MLKEMParameterSet::ALL.into_iter().find(|set| set.oid() == *oid)
    }
}

/// A parameter set of SLH-DSA (FIPS 205, RFC 9909).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum SLHDSAParameterSet {
    SHA2_128s,
    SHA2_128f,
    SHA2_192s,
    SHA2_192f,
    SHA2_256s,
    SHA2_256f,
    SHAKE_128s,
    SHAKE_128f,
    SHAKE_192s,
    SHAKE_192f,
    SHAKE_256s,
    SHAKE_256f,
}

impl SLHDSAParameterSet {
    /// In the order of their object identifiers (sigAlgs 20 to 31, and 35 to 46 for HashSLH-DSA).
    pub const ALL: [SLHDSAParameterSet; 12] = [
        SLHDSAParameterSet::SHA2_128s,
        SLHDSAParameterSet::SHA2_128f,
        SLHDSAParameterSet::SHA2_192s,
        SLHDSAParameterSet::SHA2_192f,
        SLHDSAParameterSet::SHA2_256s,
        SLHDSAParameterSet::SHA2_256f,
        SLHDSAParameterSet::SHAKE_128s,
        SLHDSAParameterSet::SHAKE_128f,
        SLHDSAParameterSet::SHAKE_192s,
        SLHDSAParameterSet::SHAKE_192f,
        SLHDSAParameterSet::SHAKE_256s,
        SLHDSAParameterSet::SHAKE_256f,
    ];

    /// The index of the parameter set in [`SLHDSAParameterSet::ALL`].
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The contents of the identifiers 2.16.840.1.101.3.4.3.20 to 46 (sigAlgs of NIST CSOR).
    pub fn identifiers() -> &'static [[u8; 9]; 27] {
        static IDENTIFIERS: [[u8; 9]; 27] = {
            let mut table = [[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0]; 27];
            let mut index = 0;
            while index < 27 {
                table[index][8] = 20 + index as u8;
                index += 1;
            }
            table
        };
        &IDENTIFIERS
    }

    /// id-slh-dsa-* (pure SLH-DSA): sigAlgs 20 to 31.
    pub fn oid(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier::from_static(&SLHDSAParameterSet::identifiers()[self.index()])
    }

    /// id-hash-slh-dsa-*-with-* (HashSLH-DSA): sigAlgs 35 to 46.
    pub fn hash_oid(self) -> ObjectIdentifier<'static> {
        ObjectIdentifier::from_static(&SLHDSAParameterSet::identifiers()[self.index() + 15])
    }

    /// The parameter set of pure SLH-DSA identified by `oid`.
    pub fn from_oid(oid: &ObjectIdentifier<'_>) -> Option<SLHDSAParameterSet> {
        SLHDSAParameterSet::ALL.into_iter().find(|set| set.oid() == *oid)
    }

    /// The parameter set of HashSLH-DSA identified by `oid`.
    pub fn from_hash_oid(oid: &ObjectIdentifier<'_>) -> Option<SLHDSAParameterSet> {
        SLHDSAParameterSet::ALL.into_iter().find(|set| set.hash_oid() == *oid)
    }

    /// The pre-hash of HashSLH-DSA (RFC 9909 §3): SHA-256 for the SHA2
    /// sets of 128 bits, SHA-512 for the other SHA2 sets, SHAKE128 (256
    /// bits) for the SHAKE sets of 128 bits and SHAKE256 (512 bits) for the
    /// other SHAKE sets.
    pub const fn pre_hash(self) -> HashAlgorithm {
        match self {
            SLHDSAParameterSet::SHA2_128s | SLHDSAParameterSet::SHA2_128f => HashAlgorithm::SHA256,
            SLHDSAParameterSet::SHA2_192s
            | SLHDSAParameterSet::SHA2_192f
            | SLHDSAParameterSet::SHA2_256s
            | SLHDSAParameterSet::SHA2_256f => HashAlgorithm::SHA512,
            SLHDSAParameterSet::SHAKE_128s | SLHDSAParameterSet::SHAKE_128f => HashAlgorithm::SHAKE128,
            _ => HashAlgorithm::SHAKE256,
        }
    }
}

/// The parameters of RSASSA-PSS (RFC 4055 §3.1, RFC 8017 §A.2.3): the hash
/// function, the hash function of MGF1 and the length of the salt. The
/// trailer field is always 1 (`0xBC`), the only one RFC 4055 allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PSSParameters {
    pub hash: HashAlgorithm,
    pub mask_hash: HashAlgorithm,
    pub salt_length: u32,
}

impl PSSParameters {
    /// The object identifier of RSASSA-PSS (keys and signatures).
    pub const OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A]);
    /// The object identifier of MGF1.
    pub const MGF1_OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08]);
    /// The hash functions RFC 4055 §3.1 allows.
    pub const HASHES: [HashAlgorithm; 5] = [
        HashAlgorithm::SHA1,
        HashAlgorithm::SHA224,
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512,
    ];

    /// The parameters of `hash`, MGF1 with `hash` and a salt of the size of
    /// its digest: those RFC 4055 §3.1 recommends.
    pub const fn with_hash(hash: HashAlgorithm) -> PSSParameters {
        PSSParameters { hash, mask_hash: hash, salt_length: hash.output_size() as u32 }
    }

    /// The parameters of the DER encoding `bytes` of `RSASSA-PSS-params`,
    /// with the defaults of fields left out (SHA-1, MGF1 with SHA-1, 20).
    pub fn decode(bytes: &[u8]) -> Result<PSSParameters, KeyError> {
        let mut reader = DERReader::new(bytes);
        let mut sequence = reader.read_sequence()?;
        reader.finish()?;
        let mut parameters = PSSParameters::with_hash(HashAlgorithm::SHA1);
        if let Some(mut field) = sequence.read_optional_explicit(0)? {
            parameters.hash =
                PSSParameters::allowed(HashAlgorithm::from_identifier(&AlgorithmIdentifier::decode(&mut field)?)?)?;
            field.finish()?;
        }
        if let Some(mut field) = sequence.read_optional_explicit(1)? {
            let mask = AlgorithmIdentifier::decode(&mut field)?;
            field.finish()?;
            if mask.oid != PSSParameters::MGF1_OID {
                return Err(KeyError::UnknownAlgorithm);
            }
            let hash = mask.parameters.as_deref().ok_or(KeyError::Parameters)?;
            parameters.mask_hash =
                PSSParameters::allowed(HashAlgorithm::from_identifier(&AlgorithmIdentifier::from_der(hash)?)?)?;
        }
        if let Some(mut field) = sequence.read_optional_explicit(2)? {
            let salt = field.read_integer()?;
            field.finish()?;
            parameters.salt_length = u32::try_from(salt.as_i128()?).map_err(|_| KeyError::Parameters)?;
        }
        if let Some(mut field) = sequence.read_optional_explicit(3)? {
            let trailer = field.read_integer()?;
            field.finish()?;
            if trailer.as_i128()? != 1 {
                return Err(KeyError::Parameters);
            }
        }
        sequence.finish()?;
        Ok(parameters)
    }

    /// The DER encoding of `RSASSA-PSS-params`.
    pub fn encode(&self) -> Result<alloc::vec::Vec<u8>, ASN1Error> {
        let mut writer = DERWriter::new();
        writer.write_sequence(|sequence| {
            // DER leaves out the fields of their default value.
            if self.hash != HashAlgorithm::SHA1 {
                sequence.write_explicit(0, |field| self.hash.identifier().encode(field))?;
            }
            if self.mask_hash != HashAlgorithm::SHA1 {
                let hash = self.mask_hash.identifier().to_der()?;
                let mask = AlgorithmIdentifier::new(PSSParameters::MGF1_OID, Some(Cow::Owned(hash)));
                sequence.write_explicit(1, |field| mask.encode(field))?;
            }
            if self.salt_length != 20 {
                sequence.write_explicit(2, |field| {
                    field.write_integer_i128(i128::from(self.salt_length));
                    Ok(())
                })?;
            }
            Ok(())
        })?;
        Ok(writer.into_bytes())
    }

    /// `hash` if RFC 4055 allows it in RSASSA-PSS.
    pub fn allowed(hash: HashAlgorithm) -> Result<HashAlgorithm, KeyError> {
        if PSSParameters::HASHES.contains(&hash) { Ok(hash) } else { Err(KeyError::Parameters) }
    }
}

/// A signature algorithm of certificates, CRLs, OCSP and certification requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2) with a hash function of SHA-1, SHA-2 or SHA-3.
    RSAPKCS1v15(HashAlgorithm),
    /// RSASSA-PSS (RFC 4055, RFC 8017 §8.1).
    RSAPSS(PSSParameters),
    /// ECDSA (RFC 5758, FIPS 186-5) with a hash function of SHA-1, SHA-2 or SHA-3.
    ECDSA(HashAlgorithm),
    /// Ed25519 (RFC 8410).
    Ed25519,
    /// Ed448 (RFC 8410).
    Ed448,
    /// ML-DSA with the empty context (RFC 9881).
    MLDSA(MLDSAParameterSet),
    /// Pure SLH-DSA with the empty context (RFC 9909).
    SLHDSA(SLHDSAParameterSet),
    /// HashSLH-DSA with the empty context and the pre-hash of the parameter set (RFC 9909).
    HashSLHDSA(SLHDSAParameterSet),
}

impl SignatureAlgorithm {
    /// The identifiers of RSASSA-PKCS1-v1_5 by hash function (RFC 4055 §5, RFC 8017 §A.2.4, NIST CSOR).
    pub const RSA_PKCS1_OIDS: [(HashAlgorithm, &'static [u8]); 11] = [
        (HashAlgorithm::SHA1, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05]),
        (HashAlgorithm::SHA224, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E]),
        (HashAlgorithm::SHA256, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]),
        (HashAlgorithm::SHA384, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C]),
        (HashAlgorithm::SHA512, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D]),
        (HashAlgorithm::SHA512_224, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0F]),
        (HashAlgorithm::SHA512_256, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x10]),
        (HashAlgorithm::SHA3_224, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0D]),
        (HashAlgorithm::SHA3_256, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0E]),
        (HashAlgorithm::SHA3_384, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0F]),
        (HashAlgorithm::SHA3_512, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x10]),
    ];
    /// The identifiers of ECDSA by hash function (RFC 5758 §3.2, NIST CSOR).
    pub const ECDSA_OIDS: [(HashAlgorithm, &'static [u8]); 9] = [
        (HashAlgorithm::SHA1, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01]),
        (HashAlgorithm::SHA224, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01]),
        (HashAlgorithm::SHA256, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
        (HashAlgorithm::SHA384, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]),
        (HashAlgorithm::SHA512, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04]),
        (HashAlgorithm::SHA3_224, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x09]),
        (HashAlgorithm::SHA3_256, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0A]),
        (HashAlgorithm::SHA3_384, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0B]),
        (HashAlgorithm::SHA3_512, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x0C]),
    ];
    pub const ED25519_OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x2B, 0x65, 0x70]);
    pub const ED448_OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x2B, 0x65, 0x71]);

    /// The algorithm of `identifier`, with its parameters checked as its specification requires:
    /// - RSASSA-PKCS1-v1_5: `NULL` or absent (RFC 4055 §5);
    /// - RSASSA-PSS: present (RFC 4055 §3.1);
    /// - ECDSA, EdDSA, ML-DSA and SLH-DSA: absent (RFC 5758 §3.2, RFC 8410 §6, RFC 9881 §2, RFC 9909 §3).
    pub fn from_identifier(identifier: &AlgorithmIdentifier<'_>) -> Result<SignatureAlgorithm, KeyError> {
        let oid = &identifier.oid;
        let absent = |algorithm: SignatureAlgorithm| {
            if identifier.has_absent_parameters() { Ok(algorithm) } else { Err(KeyError::Parameters) }
        };
        if let Some((hash, _)) =
            SignatureAlgorithm::RSA_PKCS1_OIDS.iter().find(|(_, content)| oid.as_bytes() == *content)
        {
            if !identifier.has_null_or_absent_parameters() {
                return Err(KeyError::Parameters);
            }
            return Ok(SignatureAlgorithm::RSAPKCS1v15(*hash));
        }
        if *oid == PSSParameters::OID {
            let parameters = identifier.parameters.as_deref().ok_or(KeyError::Parameters)?;
            return Ok(SignatureAlgorithm::RSAPSS(PSSParameters::decode(parameters)?));
        }
        if let Some((hash, _)) = SignatureAlgorithm::ECDSA_OIDS.iter().find(|(_, content)| oid.as_bytes() == *content) {
            return absent(SignatureAlgorithm::ECDSA(*hash));
        }
        if *oid == SignatureAlgorithm::ED25519_OID {
            return absent(SignatureAlgorithm::Ed25519);
        }
        if *oid == SignatureAlgorithm::ED448_OID {
            return absent(SignatureAlgorithm::Ed448);
        }
        if let Some(set) = MLDSAParameterSet::from_oid(oid) {
            return absent(SignatureAlgorithm::MLDSA(set));
        }
        if let Some(set) = SLHDSAParameterSet::from_oid(oid) {
            return absent(SignatureAlgorithm::SLHDSA(set));
        }
        if let Some(set) = SLHDSAParameterSet::from_hash_oid(oid) {
            return absent(SignatureAlgorithm::HashSLHDSA(set));
        }
        Err(KeyError::UnknownAlgorithm)
    }

    /// The identifier of the algorithm, in the form RFC 4055, RFC 5758,
    /// RFC 8410, RFC 9881 and RFC 9909 give (`NULL` parameters for
    /// RSASSA-PKCS1-v1_5, absent ones for the others but RSASSA-PSS).
    /// Fails with [`KeyError::Parameters`] for a hash function the algorithm
    /// has no identifier with.
    pub fn identifier(&self) -> Result<AlgorithmIdentifier<'static>, KeyError> {
        let find = |table: &[(HashAlgorithm, &'static [u8])], hash: HashAlgorithm| {
            table.iter().find(|(entry, _)| *entry == hash).map(|(_, content)| ObjectIdentifier::from_static(content))
        };
        Ok(match self {
            SignatureAlgorithm::RSAPKCS1v15(hash) => {
                AlgorithmIdentifier::null(find(&SignatureAlgorithm::RSA_PKCS1_OIDS, *hash).ok_or(KeyError::Parameters)?)
            }
            SignatureAlgorithm::RSAPSS(parameters) => {
                PSSParameters::allowed(parameters.hash)?;
                PSSParameters::allowed(parameters.mask_hash)?;
                AlgorithmIdentifier::new(PSSParameters::OID, Some(Cow::Owned(parameters.encode()?)))
            }
            SignatureAlgorithm::ECDSA(hash) => {
                AlgorithmIdentifier::absent(find(&SignatureAlgorithm::ECDSA_OIDS, *hash).ok_or(KeyError::Parameters)?)
            }
            SignatureAlgorithm::Ed25519 => AlgorithmIdentifier::absent(SignatureAlgorithm::ED25519_OID),
            SignatureAlgorithm::Ed448 => AlgorithmIdentifier::absent(SignatureAlgorithm::ED448_OID),
            SignatureAlgorithm::MLDSA(set) => AlgorithmIdentifier::absent(set.oid()),
            SignatureAlgorithm::SLHDSA(set) => AlgorithmIdentifier::absent(set.oid()),
            SignatureAlgorithm::HashSLHDSA(set) => AlgorithmIdentifier::absent(set.hash_oid()),
        })
    }

    /// Whether the algorithm hashes with SHA-1, which RFC 9155 and the
    /// CA/Browser Forum no longer allow for signatures.
    pub fn uses_sha1(&self) -> bool {
        match self {
            SignatureAlgorithm::RSAPKCS1v15(hash) | SignatureAlgorithm::ECDSA(hash) => *hash == HashAlgorithm::SHA1,
            SignatureAlgorithm::RSAPSS(parameters) => {
                parameters.hash == HashAlgorithm::SHA1 || parameters.mask_hash == HashAlgorithm::SHA1
            }
            _ => false,
        }
    }
}

/// The algorithm of a public or private key (the `algorithm` of
/// `SubjectPublicKeyInfo` and of `OneAsymmetricKey`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    /// rsaEncryption (RFC 3279 §2.3.1): RSA for any use.
    RSA,
    /// id-RSASSA-PSS (RFC 4055 §1.2): RSA for RSASSA-PSS only, with the
    /// parameters the signatures must use, if any.
    RSAPSS(Option<PSSParameters>),
    /// id-ecPublicKey with a named curve (RFC 5480 §2.1.1).
    EC(NamedCurve),
    X25519,
    X448,
    Ed25519,
    Ed448,
    MLDSA(MLDSAParameterSet),
    SLHDSA(SLHDSAParameterSet),
    HashSLHDSA(SLHDSAParameterSet),
    MLKEM(MLKEMParameterSet),
}

impl KeyAlgorithm {
    pub const RSA_OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]);
    pub const EC_OID: ObjectIdentifier<'static> =
        ObjectIdentifier::from_static(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
    pub const X25519_OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x2B, 0x65, 0x6E]);
    pub const X448_OID: ObjectIdentifier<'static> = ObjectIdentifier::from_static(&[0x2B, 0x65, 0x6F]);

    /// The algorithm of `identifier`, with its parameters checked:
    /// - rsaEncryption: `NULL` (RFC 3279 §2.3.1 and RFC 4055 §1.2: "MUST contain NULL");
    /// - id-RSASSA-PSS: absent or `RSASSA-PSS-params`;
    /// - id-ecPublicKey: a `namedCurve` (RFC 5480 §2.1.1 forbids the other forms);
    /// - the others: absent.
    pub fn from_identifier(identifier: &AlgorithmIdentifier<'_>) -> Result<KeyAlgorithm, KeyError> {
        let oid = &identifier.oid;
        let absent = |algorithm: KeyAlgorithm| {
            if identifier.has_absent_parameters() { Ok(algorithm) } else { Err(KeyError::Parameters) }
        };
        if *oid == KeyAlgorithm::RSA_OID {
            let null = identifier.parameters.as_deref() == Some(AlgorithmIdentifier::NULL);
            return if null { Ok(KeyAlgorithm::RSA) } else { Err(KeyError::Parameters) };
        }
        if *oid == PSSParameters::OID {
            let parameters = identifier.parameters.as_deref().map(PSSParameters::decode).transpose()?;
            return Ok(KeyAlgorithm::RSAPSS(parameters));
        }
        if *oid == KeyAlgorithm::EC_OID {
            let parameters = identifier.parameters.as_deref().ok_or(KeyError::Parameters)?;
            let mut reader = DERReader::new(parameters);
            let curve = reader.read_with(Tag::OBJECT_IDENTIFIER, |element| element.as_object_identifier());
            let curve = curve.map_err(|_| KeyError::Parameters)?;
            reader.finish()?;
            return NamedCurve::from_oid(&curve).map(KeyAlgorithm::EC).ok_or(KeyError::UnknownAlgorithm);
        }
        let simple = [
            (KeyAlgorithm::X25519_OID, KeyAlgorithm::X25519),
            (KeyAlgorithm::X448_OID, KeyAlgorithm::X448),
            (SignatureAlgorithm::ED25519_OID, KeyAlgorithm::Ed25519),
            (SignatureAlgorithm::ED448_OID, KeyAlgorithm::Ed448),
        ];
        if let Some((_, algorithm)) = simple.iter().find(|(entry, _)| entry == oid) {
            return absent(*algorithm);
        }
        if let Some(set) = MLDSAParameterSet::from_oid(oid) {
            return absent(KeyAlgorithm::MLDSA(set));
        }
        if let Some(set) = SLHDSAParameterSet::from_oid(oid) {
            return absent(KeyAlgorithm::SLHDSA(set));
        }
        if let Some(set) = SLHDSAParameterSet::from_hash_oid(oid) {
            return absent(KeyAlgorithm::HashSLHDSA(set));
        }
        if let Some(set) = MLKEMParameterSet::from_oid(oid) {
            return absent(KeyAlgorithm::MLKEM(set));
        }
        Err(KeyError::UnknownAlgorithm)
    }

    /// The identifier of the algorithm, in the form its specification gives.
    pub fn identifier(&self) -> Result<AlgorithmIdentifier<'static>, KeyError> {
        Ok(match self {
            KeyAlgorithm::RSA => AlgorithmIdentifier::null(KeyAlgorithm::RSA_OID),
            KeyAlgorithm::RSAPSS(None) => AlgorithmIdentifier::absent(PSSParameters::OID),
            KeyAlgorithm::RSAPSS(Some(parameters)) => {
                AlgorithmIdentifier::new(PSSParameters::OID, Some(Cow::Owned(parameters.encode()?)))
            }
            KeyAlgorithm::EC(curve) => {
                let mut writer = DERWriter::new();
                writer.write_object_identifier(&curve.oid());
                AlgorithmIdentifier::new(KeyAlgorithm::EC_OID, Some(Cow::Owned(writer.into_bytes())))
            }
            KeyAlgorithm::X25519 => AlgorithmIdentifier::absent(KeyAlgorithm::X25519_OID),
            KeyAlgorithm::X448 => AlgorithmIdentifier::absent(KeyAlgorithm::X448_OID),
            KeyAlgorithm::Ed25519 => AlgorithmIdentifier::absent(SignatureAlgorithm::ED25519_OID),
            KeyAlgorithm::Ed448 => AlgorithmIdentifier::absent(SignatureAlgorithm::ED448_OID),
            KeyAlgorithm::MLDSA(set) => AlgorithmIdentifier::absent(set.oid()),
            KeyAlgorithm::SLHDSA(set) => AlgorithmIdentifier::absent(set.oid()),
            KeyAlgorithm::HashSLHDSA(set) => AlgorithmIdentifier::absent(set.hash_oid()),
            KeyAlgorithm::MLKEM(set) => AlgorithmIdentifier::absent(set.oid()),
        })
    }

    /// Whether a key of this algorithm may make signatures of `signature`:
    /// - an RSA key makes both RSA signatures;
    /// - an RSASSA-PSS key makes RSASSA-PSS signatures, of its parameters if
    ///   it has some, with a salt at least as long (RFC 4055 §3.3);
    /// - an EC key makes ECDSA signatures;
    /// - the other keys make the signatures of their own algorithm.
    pub fn signs(&self, signature: &SignatureAlgorithm) -> bool {
        match (self, signature) {
            (KeyAlgorithm::RSA, SignatureAlgorithm::RSAPKCS1v15(_) | SignatureAlgorithm::RSAPSS(_)) => true,
            (KeyAlgorithm::RSAPSS(None), SignatureAlgorithm::RSAPSS(_)) => true,
            (KeyAlgorithm::RSAPSS(Some(key)), SignatureAlgorithm::RSAPSS(used)) => {
                key.hash == used.hash && key.mask_hash == used.mask_hash && used.salt_length >= key.salt_length
            }
            (KeyAlgorithm::EC(_), SignatureAlgorithm::ECDSA(_)) => true,
            (KeyAlgorithm::Ed25519, SignatureAlgorithm::Ed25519) | (KeyAlgorithm::Ed448, SignatureAlgorithm::Ed448) => {
                true
            }
            (KeyAlgorithm::MLDSA(key), SignatureAlgorithm::MLDSA(used)) => key == used,
            (KeyAlgorithm::SLHDSA(key), SignatureAlgorithm::SLHDSA(used)) => key == used,
            (KeyAlgorithm::HashSLHDSA(key), SignatureAlgorithm::HashSLHDSA(used)) => key == used,
            _ => false,
        }
    }
}
