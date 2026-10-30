//! Camellia against RFC 3713 and Project Wycheproof.

use umilib::crypto::camellia::{Camellia128, Camellia192, Camellia256, CamelliaComponents};
use umilib::crypto::{BlockCipher, KeyInit};

use crate::{Vectors, wycheproof};

#[test]
fn camellia_sboxes_follow_section_2_4_1() {
    assert_eq!(CamelliaComponents::SBOX1.get(0x3D), 86);
    for x in 0..=255u8 {
        let s1 = CamelliaComponents::SBOX1.get(x as usize) as u8;
        assert_eq!(s1, CamelliaComponents::SBOX1_BYTES[x as usize]);
        assert_eq!(CamelliaComponents::SBOX2.get(x as usize) as u8, s1.rotate_left(1));
        assert_eq!(CamelliaComponents::SBOX3.get(x as usize) as u8, s1.rotate_left(7));
        assert_eq!(
            CamelliaComponents::SBOX4.get(x as usize) as u8,
            CamelliaComponents::SBOX1_BYTES[x.rotate_left(1) as usize]
        );
    }
    // FLINV is the inverse of FL.
    for (input, key) in
        [(0u64, 0u64), (0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210), (u64::MAX, 0x5555_AAAA_0F0F_F0F0)]
    {
        assert_eq!(CamelliaComponents::fl_inverse(CamelliaComponents::fl(input, key), key), input);
    }
}

#[test]
fn camellia_follows_rfc3713_appendix_a() {
    let plaintext: [u8; 16] = Vectors::hex("0123456789abcdeffedcba9876543210").try_into().unwrap();
    let key = Vectors::hex("0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff");
    let check = |cipher: &dyn Fn(&mut [u8; 16], bool), expected: &str| {
        let mut block = plaintext;
        cipher(&mut block, true);
        assert_eq!(block.to_vec(), Vectors::hex(expected));
        cipher(&mut block, false);
        assert_eq!(block, plaintext);
    };
    let camellia = Camellia128::new_from_slice(&key[..16]).unwrap();
    check(
        &|block, encrypt| if encrypt { camellia.encrypt_block(block) } else { camellia.decrypt_block(block) },
        "67673138549669730857065648eabe43",
    );
    let camellia = Camellia192::new_from_slice(&key[..24]).unwrap();
    check(
        &|block, encrypt| if encrypt { camellia.encrypt_block(block) } else { camellia.decrypt_block(block) },
        "b4993401b3e996f84ee5cee7d79b09b9",
    );
    let camellia = Camellia256::new_from_slice(&key).unwrap();
    check(
        &|block, encrypt| if encrypt { camellia.encrypt_block(block) } else { camellia.decrypt_block(block) },
        "9acc237dff16d76c20ef7c919e3a7509",
    );
    assert!(Camellia128::new_from_slice(&key[..24]).is_err());
}

#[test]
fn camellia_follows_the_wycheproof_vectors() {
    assert!(
        wycheproof!("crypto/camellia/camellia_ccm_test.json", ccm, { 16 => Camellia128, 24 => Camellia192, 32 => Camellia256 })
            > 200
    );
    assert_eq!(
        wycheproof!("crypto/camellia/camellia_cbc_pkcs5_test.json", cbc_pkcs5, { 16 => Camellia128, 24 => Camellia192, 32 => Camellia256 }),
        216
    );
    assert!(
        wycheproof!("crypto/camellia/camellia_cmac_test.json", cmac, { 16 => Camellia128, 24 => Camellia192, 32 => Camellia256 })
            > 200
    );
}
