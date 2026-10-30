//! XTS against NIST CAVP (XTSVS), whose data units of 200 bits exercise the
//! ciphertext stealing, and vector 1 of IEEE 1619 appendix B.

use umilib::crypto::aes::{AES128, AES192, AES256};
use umilib::crypto::mode::xts::XTS;
use umilib::crypto::{CryptoError, KeyInit};

use crate::{Record, Vectors, Wycheproof};

fn run(key: &[u8], tweak: &[u8; 16], data: &mut [u8], encrypt: bool) {
    match key.len() {
        32 => XTS::<AES128>::new_from_slice(key).unwrap().process(tweak, data, encrypt).unwrap(),
        48 => XTS::<AES192>::new_from_slice(key).unwrap().process(tweak, data, encrypt).unwrap(),
        _ => XTS::<AES256>::new_from_slice(key).unwrap().process(tweak, data, encrypt).unwrap(),
    }
}

#[test]
fn xts_follows_the_cavp_vectors() {
    let mut checked = 0;
    for file in ["XTSGenAES128", "XTSGenAES256", "XTSGenAES128Sequence", "XTSGenAES256Sequence"] {
        let path = format!("crypto/mode/xts/{file}.rsp");
        for record in Record::all(&path) {
            let bits: usize = record.field("DataUnitLen").parse().unwrap();
            if !bits.is_multiple_of(8) {
                // Data units of bits that do not fill whole bytes are not supported.
                continue;
            }
            let tweak = match record.get("i") {
                Some(value) => Vectors::hex(value).try_into().unwrap(),
                None => XTS::<AES128>::tweak_of(record.field("DataUnitSeqNumber").parse().unwrap()),
            };
            let encrypt = record.header.contains_key("ENCRYPT");
            let (input, output) = if encrypt { ("PT", "CT") } else { ("CT", "PT") };
            let mut data = record.bytes(input);
            run(&record.bytes("Key"), &tweak, &mut data, encrypt);
            assert_eq!(data, record.bytes(output), "{path} {:?}", record.fields);
            checked += 1;
        }
    }
    assert!(checked > 2000, "{checked}");
}

#[test]
fn xts_follows_ieee1619_appendix_b() {
    // Vector 1: zero keys, data unit 0, 32 zero bytes. Equal keys are refused by
    // `new_from_slice` (SP 800-38E), so the ciphers are given directly.
    let mut data = [0u8; 32];
    let xts = XTS::new(AES128::new(&[0; 16]), AES128::new(&[0; 16]));
    xts.encrypt(&XTS::<AES128>::tweak_of(0), &mut data).unwrap();
    assert_eq!(data.to_vec(), Vectors::hex("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"));
}

#[test]
fn xts_rejects_short_units_and_equal_keys() {
    let xts = XTS::<AES128>::new_from_slice(&(0..32).collect::<Vec<u8>>()).unwrap();
    assert_eq!(xts.encrypt(&[0; 16], &mut [0u8; 15]), Err(CryptoError::InputLength { length: 15 }));
    // SP 800-38E section 4: a data unit has at most 2^20 blocks.
    let mut unit = vec![0u8; 16 << 20];
    assert!(xts.encrypt(&[0; 16], &mut unit).is_ok());
    unit.push(0);
    assert_eq!(xts.encrypt(&[0; 16], &mut unit), Err(CryptoError::InputLength { length: (16 << 20) + 1 }));
    assert_eq!(XTS::<AES128>::new_from_slice(&[7; 32]).unwrap_err(), CryptoError::InvalidParameter);
    assert!(XTS::<AES128>::new_from_slice(&[7; 31]).is_err());
    // Every length from one block on decrypts to itself.
    for length in 16..80 {
        let original: Vec<u8> = (0..length as u8).collect();
        let mut data = original.clone();
        xts.encrypt(&[3; 16], &mut data).unwrap();
        assert_ne!(data, original);
        xts.decrypt(&[3; 16], &mut data).unwrap();
        assert_eq!(data, original, "{length}");
    }
}

/// Wycheproof gives the tweak as an IV of 8 to 16 bytes; the tweak is the
/// IV followed by zeros, which every test of the file confirms.
#[test]
fn xts_follows_the_wycheproof_vectors() {
    let tests = Wycheproof::tests("crypto/mode/xts/aes_xts_test.json");
    assert_eq!(tests.len(), 123);
    for (_, test) in tests {
        let label = format!("tcId {}: {}", test.field("tcId").as_usize(), test.field("comment").as_str());
        let (key, iv, message, ciphertext) = (test.bytes("key"), test.bytes("iv"), test.bytes("msg"), test.bytes("ct"));
        assert_eq!(test.field("result").as_str(), "valid", "{label}");
        let mut tweak = [0u8; 16];
        tweak[..iv.len()].copy_from_slice(&iv);
        let mut buffer = message.clone();
        run(&key, &tweak, &mut buffer, true);
        assert_eq!(buffer, ciphertext, "{label}");
        run(&key, &tweak, &mut buffer, false);
        assert_eq!(buffer, message, "{label}");
    }
}
