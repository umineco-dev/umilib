use umilib::hash::Digest;
use umilib::hash::ripemd::{RIPEMD128, RIPEMD160, RIPEMD256, RIPEMD320};

use crate::Vectors;

fn check<H: Digest + Default>(bits: &str) {
    let text = Vectors::read("hash/ripemd/ripemd.txt");
    let mut checked = 0;
    for line in text.lines().filter(|line| line.starts_with(&format!("{bits} "))) {
        let fields: Vec<&str> = line.split(' ').collect();
        let count: usize = fields[1].parse().unwrap();
        let message = if fields[2] == "-" { Vec::new() } else { Vectors::hex(fields[2]) };
        let mut hash = H::default();
        for _ in 0..count {
            hash.update(&message);
        }
        assert_eq!(hash.finalize().as_ref(), Vectors::hex(fields[3]), "RIPEMD-{line}");
        checked += 1;
    }
    assert_eq!(checked, 9);
}

#[test]
fn ripemd_follows_the_designers_test_values() {
    check::<RIPEMD128>("128");
    check::<RIPEMD160>("160");
    check::<RIPEMD256>("256");
    check::<RIPEMD320>("320");
    assert_eq!(
        (RIPEMD128::OUTPUT_SIZE, RIPEMD160::OUTPUT_SIZE, RIPEMD256::OUTPUT_SIZE, RIPEMD320::OUTPUT_SIZE),
        (16, 20, 32, 40)
    );
}
