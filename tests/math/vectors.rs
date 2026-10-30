//! The vectors of `tests/vectors/math/python.txt`, computed with Python's
//! integers, checked with both `Uint` and `BoxedUint` of every precision.

use umilib::math::bigint::{BoxedUint, Limbs, Uint};
use umilib::math::modular::{BoxedModulus, Modulus};

use crate::Vectors;

/// One line: the operation, the precision in bits, the operands and the results.
struct Vector {
    operation: String,
    precision: u32,
    operands: Vec<String>,
    results: Vec<String>,
}

impl Vector {
    fn all() -> Vec<Vector> {
        Vectors::read("math/python.txt")
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| {
                let (left, right) = line.split_once(" = ").expect("a vector line");
                let mut words = left.split(' ');
                let operation = words.next().unwrap().to_string();
                let precision = words.next().unwrap().parse().unwrap();
                Vector {
                    operation,
                    precision,
                    operands: words.map(String::from).collect(),
                    results: right.split(' ').map(String::from).collect(),
                }
            })
            // Miri interprets the code: a subset keeps it within time and memory.
            .filter(|vector| !cfg!(miri) || (vector.precision <= 256 && vector.operation != "mod_pow"))
            .collect()
    }

    fn boxed(&self, text: &str, precision: u32) -> BoxedUint {
        BoxedUint::from_hex_vartime(text, precision).unwrap_or_else(|error| panic!("{text}: {error}"))
    }

    /// Checks the vector with `BoxedUint` and `BoxedModulus`.
    fn check_boxed(&self) {
        let bits = self.precision;
        let operand = |index: usize| self.boxed(&self.operands[index], bits);
        let result = |index: usize, precision: u32| self.boxed(&self.results[index], precision);
        let context = format!("{} {bits} {:?}", self.operation, self.operands);
        match self.operation.as_str() {
            "div_rem" => {
                let (quotient, remainder) = operand(0).div_rem(&operand(1)).unwrap();
                assert_eq!((quotient, remainder), (result(0, bits), result(1, bits)), "{context}");
            }
            "mul" => {
                let (low, high) = operand(0).widening_mul(&operand(1));
                let product = result(0, 2 * bits);
                assert_eq!(low, product.resize(2 * bits).unwrap().and_low(bits), "{context}");
                assert_eq!(high, product.shr(bits), "{context}");
            }
            _ => self.check_modular_boxed(&context),
        }
    }

    fn check_modular_boxed(&self, context: &str) {
        let bits = self.precision;
        let operand = |index: usize| self.boxed(&self.operands[index], bits);
        let field = BoxedModulus::new(operand(0)).unwrap();
        let a = field.residue(&operand(1));
        let value = match self.operation.as_str() {
            "mod_mul" => field.mul(&a, &field.residue(&operand(2))).unwrap(),
            "mod_add" => field.add(&a, &field.residue(&operand(2))).unwrap(),
            "mod_sub" => field.sub(&a, &field.residue(&operand(2))).unwrap(),
            "mod_pow" => {
                let power = field.pow(&a, &operand(2)).unwrap();
                assert_eq!(field.pow_vartime(&a, &operand(2)).unwrap(), power, "{context}");
                power
            }
            "mod_invert" => match field.invert(&a) {
                Ok(inverse) => inverse,
                Err(_) => {
                    assert_eq!(self.results[0], "none", "{context}");
                    return;
                }
            },
            operation => panic!("unknown operation {operation}"),
        };
        assert_eq!(field.retrieve(&value).unwrap(), self.boxed(&self.results[0], bits), "{context}");
    }

    /// Checks the modular vectors with `Uint<N>` and `Modulus<N>`.
    fn check_fixed<const N: usize>(&self) {
        let operand = |index: usize| Uint::<N>::from_hex_vartime(&self.operands[index]).unwrap();
        let result = |index: usize| Uint::<N>::from_hex_vartime(&self.results[index]).unwrap();
        let context = format!("{} {} {:?}", self.operation, self.precision, self.operands);
        match self.operation.as_str() {
            "div_rem" => assert_eq!(operand(0).div_rem(&operand(1)).unwrap(), (result(0), result(1)), "{context}"),
            "mul" => {
                let (low, high) = operand(0).widening_mul(&operand(1));
                let product = BoxedUint::from_hex_vartime(&self.results[0], 2 * self.precision).unwrap();
                assert_eq!(BoxedUint::from_uint(&low).unwrap(), product.and_low(self.precision), "{context}");
                assert_eq!(BoxedUint::from_uint(&high).unwrap(), product.shr(self.precision), "{context}");
            }
            _ => {
                let field = Modulus::new(operand(0)).unwrap();
                let a = field.residue(&operand(1));
                let value = match self.operation.as_str() {
                    "mod_mul" => field.mul(&a, &field.residue(&operand(2))),
                    "mod_add" => field.add(&a, &field.residue(&operand(2))),
                    "mod_sub" => field.sub(&a, &field.residue(&operand(2))),
                    "mod_pow" => field.pow(&a, &operand(2)),
                    _ => match field.invert(&a) {
                        Ok(inverse) => inverse,
                        Err(_) => {
                            assert_eq!(self.results[0], "none", "{context}");
                            return;
                        }
                    },
                };
                assert_eq!(field.retrieve(&value), result(0), "{context}");
            }
        }
    }
}

/// The low `bits` bits of a value, for comparing halves of a product.
trait LowBits {
    fn and_low(&self, bits: u32) -> BoxedUint;
}

impl LowBits for BoxedUint {
    fn and_low(&self, bits: u32) -> BoxedUint {
        self.shl(self.precision() - bits).shr(self.precision() - bits).resize(bits).unwrap()
    }
}

#[test]
fn boxed_arithmetic_matches_python() {
    let vectors = Vector::all();
    assert!(vectors.len() > if cfg!(miri) { 100 } else { 500 });
    for vector in &vectors {
        vector.check_boxed();
    }
}

#[test]
fn fixed_arithmetic_matches_python() {
    for vector in Vector::all() {
        match vector.precision {
            64 => vector.check_fixed::<{ Limbs::count(64) }>(),
            128 => vector.check_fixed::<{ Limbs::count(128) }>(),
            256 => vector.check_fixed::<{ Limbs::count(256) }>(),
            384 => vector.check_fixed::<{ Limbs::count(384) }>(),
            576 => vector.check_fixed::<{ Limbs::count(576) }>(),
            1024 => vector.check_fixed::<{ Limbs::count(1024) }>(),
            2048 => vector.check_fixed::<{ Limbs::count(2048) }>(),
            precision => panic!("no Uint for {precision} bits"),
        }
    }
}
