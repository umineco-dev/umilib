//! Magma and Kuznyechik against RFC 8891 and RFC 7801.

use umilib::crypto::BlockCipher;
#[cfg(umilib_feature = "crypto-gost-kuznyechik")]
use umilib::crypto::gost::kuznyechik::Kuznyechik;
#[cfg(umilib_feature = "crypto-gost-magma")]
use umilib::crypto::gost::magma::Magma;

#[cfg(umilib_feature = "crypto-gost-magma")]
#[test]
fn magma_follows_rfc8891_appendix_a() {
    // A.1 and A.2.
    for (input, output) in
        [(0xfdb97531, 0x2a196f34), (0x2a196f34, 0xebd9f03a), (0xebd9f03a, 0xb039bb3d), (0xb039bb3d, 0x68695433)]
    {
        assert_eq!(Magma::t(input), output, "t({input:08x})");
    }
    for (key, input, output) in [
        (0x87654321, 0xfedcba98, 0xfdcbc20c),
        (0xfdcbc20c, 0x87654321, 0x7e791a4b),
        (0x7e791a4b, 0xfdcbc20c, 0xc76549ec),
        (0xc76549ec, 0x7e791a4b, 0x9791c849),
    ] {
        assert_eq!(Magma::g(key, input), output, "g[{key:08x}]({input:08x})");
    }
    // A.3.
    let key: [u8; 32] = umilib_hex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let magma = Magma::new(&key);
    let words = [0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff];
    let expected: Vec<u32> =
        (0..32).map(|index| if index < 24 { words[index % 8] } else { words[31 - index] }).collect();
    assert_eq!(magma.round_keys().to_vec(), expected);
    assert_eq!(magma.round_keys()[24], 0xfcfdfeff);
    assert_eq!(magma.round_keys()[31], 0xffeeddcc);
    // A.4: the states after G[K_1] to G[K_31], then the ciphertext.
    let states: [u32; 32] = [
        0x76543210, 0x28da3b14, 0xb14337a5, 0x633a7c68, 0xea89c02c, 0x11fe726d, 0xad0310a4, 0x37d97f25, 0x46324615,
        0xce995f2a, 0x93c1f449, 0x4811c7ad, 0xc4b3edca, 0x44ca5ce1, 0xfef51b68, 0x2098cd86, 0x4f15b0bb, 0xe32805bc,
        0xe7116722, 0x89cadf21, 0xbac8444d, 0x11263a21, 0x625434c3, 0x8025c0a5, 0xb0d66514, 0x47b1d5f4, 0xc78e6d50,
        0x80251e99, 0x2b96eca6, 0x05ef4401, 0x239a4577, 0xc2d8ca3d,
    ];
    let (mut a1, mut a0) = (0xfedcba98u32, 0x76543210u32);
    for round in 0..31 {
        let next = Magma::g(magma.round_keys()[round], a0) ^ a1;
        a1 = a0;
        a0 = next;
        assert_eq!((a1, a0), (states[round], states[round + 1]), "G[K_{}]", round + 1);
    }
    let mut block = *b"\xfe\xdc\xba\x98\x76\x54\x32\x10";
    magma.encrypt_block(&mut block);
    assert_eq!(block, *b"\x4e\xe9\x01\xe5\xc2\xd8\xca\x3d");
    // A.5.
    magma.decrypt_block(&mut block);
    assert_eq!(block, *b"\xfe\xdc\xba\x98\x76\x54\x32\x10");
}

#[cfg(umilib_feature = "crypto-gost-kuznyechik")]
fn value(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}

#[cfg(umilib_feature = "crypto-gost-kuznyechik")]
#[test]
fn kuznyechik_follows_rfc7801_transformations() {
    // Section 5.1.
    let chain = [
        "ffeeddccbbaa99881122334455667700",
        "b66cd8887d38e8d77765aeea0c9a7efc",
        "559d8dd7bd06cbfe7e7b262523280d39",
        "0c3322fed531e4630d80ef5c5a81c50b",
        "23ae65633f842d29c5df529c13f5acda",
    ];
    for pair in chain.windows(2) {
        assert_eq!(Kuznyechik::substitute(value(pair[0]), false), value(pair[1]));
        assert_eq!(Kuznyechik::substitute(value(pair[1]), true), value(pair[0]));
    }
    // Section 5.2.
    let chain = [
        "00000000000000000000000000000100",
        "94000000000000000000000000000001",
        "a5940000000000000000000000000000",
        "64a59400000000000000000000000000",
        "0d64a594000000000000000000000000",
    ];
    for pair in chain.windows(2) {
        assert_eq!(Kuznyechik::r(value(pair[0])), value(pair[1]));
        assert_eq!(Kuznyechik::r_inverse(value(pair[1])), value(pair[0]));
    }
    // Section 5.3, with the matrix and by the definition L = R^16.
    let chain = [
        "64a59400000000000000000000000000",
        "d456584dd0e3e84cc3166e4b7fa2890d",
        "79d26221b87b584cd42fbc4ffea5de9a",
        "0e93691a0cfc60408b7b68f66b513c13",
        "e6a8094fee0aa204fd97bcb0b44b8580",
    ];
    for pair in chain.windows(2) {
        assert_eq!(Kuznyechik::linear(value(pair[0])), value(pair[1]));
        assert_eq!(Kuznyechik::linear_by_definition(value(pair[0]), false), value(pair[1]));
        assert_eq!(Kuznyechik::linear_inverse(value(pair[1])), value(pair[0]));
    }
    // The matrices agree with the definitions on other values.
    let mut state = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
    for _ in 0..64 {
        state = state.rotate_left(37).wrapping_mul(0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835) ^ 0x5555;
        assert_eq!(Kuznyechik::linear(state), Kuznyechik::linear_by_definition(state, false));
        assert_eq!(Kuznyechik::linear_inverse(state), Kuznyechik::linear_by_definition(state, true));
        assert_eq!(Kuznyechik::linear_inverse(Kuznyechik::linear(state)), state);
    }
}

#[cfg(umilib_feature = "crypto-gost-kuznyechik")]
#[test]
fn kuznyechik_follows_rfc7801_examples() {
    // Section 5.4.
    let key: [u8; 32] = umilib_hex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
    let constants = [
        "6ea276726c487ab85d27bd10dd849401",
        "dc87ece4d890f4b3ba4eb92079cbeb02",
        "b2259a96b4d88e0be7690430a44f7f03",
        "7bcd1b0b73e32ba5b79cb140f2551504",
        "156f6d791fab511deabb0c502fd18105",
        "a74af7efab73df160dd208608b9efe06",
        "c9e8819dc73ba5ae50f5b570561a6a07",
        "f6593616e6055689adfba18027aa2a08",
    ];
    for (index, constant) in constants.iter().enumerate() {
        assert_eq!(Kuznyechik::linear(index as u128 + 1), value(constant), "C_{}", index + 1);
    }
    assert_eq!(
        Kuznyechik::round(value(constants[0]), value("8899aabbccddeeff0011223344556677")),
        value("3d0940999db75d6a9257071d5e6144a6")
    );
    let round_keys = [
        "8899aabbccddeeff0011223344556677",
        "fedcba98765432100123456789abcdef",
        "db31485315694343228d6aef8cc78c44",
        "3d4553d8e9cfec6815ebadc40a9ffd04",
        "57646468c44a5e28d3e59246f429f1ac",
        "bd079435165c6432b532e82834da581b",
        "51e640757e8745de705727265a0098b1",
        "5a7925017b9fdd3ed72a91a22286f984",
        "bb44e25378c73123a5f32f73cdb6e517",
        "72e9dd7416bcf45b755dbaa88e4a4043",
    ];
    let kuznyechik = Kuznyechik::new(&key);
    assert_eq!(kuznyechik.round_keys().to_vec(), round_keys.iter().map(|key| value(key)).collect::<Vec<_>>());
    // Section 5.5: the states after LSX[K_1] to LSX[K_9].
    let states = [
        "e297b686e355b0a1cf4a2f9249140830",
        "285e497a0862d596b36f4258a1c69072",
        "0187a3a429b567841ad50d29207cc34e",
        "ec9bdba057d4f4d77c5d70619dcad206",
        "1357fd11de9257290c2a1473eb6bcde1",
        "28ae31e7d4c2354261027ef0b32897df",
        "07e223d56002c013d3f5e6f714b86d2d",
        "cd8ef6cd97e0e092a8e4cca61b38bf65",
        "0d8e40e4a800d06b2f1b37ea379ead8e",
    ];
    let mut state = value("1122334455667700ffeeddccbbaa9988");
    for (round, expected) in states.iter().enumerate() {
        state = Kuznyechik::round(kuznyechik.round_keys()[round], state);
        assert_eq!(state, value(expected), "LSX[K_{}]", round + 1);
    }
    let mut block: [u8; 16] = value("1122334455667700ffeeddccbbaa9988").to_be_bytes();
    kuznyechik.encrypt_block(&mut block);
    assert_eq!(u128::from_be_bytes(block), value("7f679d90bebc24305a468d42b9d4edcd"));
    // Section 5.6.
    kuznyechik.decrypt_block(&mut block);
    assert_eq!(u128::from_be_bytes(block), value("1122334455667700ffeeddccbbaa9988"));
}

fn umilib_hex<const N: usize>(hex: &str) -> [u8; N] {
    crate::Vectors::hex(hex).try_into().unwrap()
}
