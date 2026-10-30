//! The one-step KDF of SP 800-56C Rev. 2 against the KDA OneStep vectors of NIST ACVP.

use umilib::crypto::concatkdf::{ConcatKDF, HashFunction};
use umilib::crypto::hmac::HMAC;
use umilib::hash::sha::v2::{SHA224, SHA512};
use umilib::hash::sha::v3::SHA3_512;

use crate::Json;

/// The derived keying material of `length` bytes for the auxiliary function `name` of ACVP.
fn derive(name: &str, salt: &[u8], z: &[u8], fixed_info: &[u8], length: usize) -> Option<Vec<u8>> {
    let mut out = vec![0; length];
    match name {
        "SHA2-224" => ConcatKDF::<HashFunction<SHA224>>::hash().derive(z, fixed_info, &mut out),
        "SHA2-512" => ConcatKDF::<HashFunction<SHA512>>::hash().derive(z, fixed_info, &mut out),
        "SHA3-512" => ConcatKDF::<HashFunction<SHA3_512>>::hash().derive(z, fixed_info, &mut out),
        "HMAC-SHA2-224" => ConcatKDF::new(HMAC::<SHA224>::new(salt)).derive(z, fixed_info, &mut out),
        "HMAC-SHA2-512" => ConcatKDF::new(HMAC::<SHA512>::new(salt)).derive(z, fixed_info, &mut out),
        "HMAC-SHA3-512" => ConcatKDF::new(HMAC::<SHA3_512>::new(salt)).derive(z, fixed_info, &mut out),
        // KMAC (option 3) is not part of the library yet.
        _ => return None,
    }
    .unwrap();
    Some(out)
}

/// The party information of ACVP: the party identifier, then the ephemeral data if any.
fn party(party: &Json) -> Vec<u8> {
    let mut info = party.bytes("partyId");
    if party.get("ephemeralData").is_some() {
        info.extend(party.bytes("ephemeralData"));
    }
    info
}

#[test]
fn kda_one_step_of_nist_acvp() {
    let file = Json::read("crypto/concatkdf/KDA-OneStep-Sp800-56Cr2.json");
    let mut checked = 0;
    for group in file.field("testGroups").items() {
        let configuration = group.field("kdfConfiguration");
        assert_eq!(configuration.field("fixedInfoPattern").as_str(), "t||uPartyInfo||vPartyInfo||l");
        assert_eq!(configuration.field("fixedInfoEncoding").as_str(), "concatenation");
        let validation = group.field("testType").as_str() == "VAL";
        for test in group.field("tests").items() {
            let parameter = test.field("kdfParameter");
            let bits = parameter.field("l").as_usize();
            // FixedInfo = t || uPartyInfo || vPartyInfo || L, L in bits as 32 bits.
            let fixed_info = [
                parameter.bytes("t"),
                party(test.field("fixedInfoPartyU")),
                party(test.field("fixedInfoPartyV")),
                (bits as u32).to_be_bytes().to_vec(),
            ]
            .concat();
            let salt = if parameter.get("salt").is_some() { parameter.bytes("salt") } else { Vec::new() };
            let name = parameter.field("auxFunction").as_str();
            let Some(derived) = derive(name, &salt, &parameter.bytes("z"), &fixed_info, bits / 8) else { continue };
            let expected = test.bytes("dkm");
            if validation {
                let passed = matches!(test.field("testPassed"), Json::Bool(true));
                assert_eq!(derived == expected, passed, "{name} {}", test.field("tcId").as_usize());
            } else {
                assert_eq!(derived, expected, "{name} {}", test.field("tcId").as_usize());
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 450, "every test but those of KMAC");
}

#[test]
fn the_counter_is_32_bits() {
    // SP 800-56C Rev. 2 §4.1: at most 2^32 − 1 repetitions of H, the counter starting at 1.
    let kdf = ConcatKDF::<HashFunction<SHA224>>::hash();
    let mut out = [0u8; 56];
    kdf.derive(b"z", b"info", &mut out).unwrap();
    let mut first = [0u8; 28];
    kdf.derive(b"z", b"info", &mut first).unwrap();
    assert_eq!(out[..28], first, "outputs are prefixes of longer outputs");
    let manual = {
        use umilib::hash::Digest;
        let mut hash = SHA224::default();
        hash.update(&2u32.to_be_bytes());
        hash.update(b"z");
        hash.update(b"info");
        hash.finalize()
    };
    assert_eq!(out[28..], manual[..], "K(2) = H([2]_32 || Z || FixedInfo)");
}
