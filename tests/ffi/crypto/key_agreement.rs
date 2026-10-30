//! ECDH, X25519/X448 and DH through the C ABI: the Project Wycheproof
//! vectors of SEC 1 points and of RFC 7748, and the keys of the C ABI
//! against those of `umilib::crypto`.

use umilib::crypto::KeyAgreement;
use umilib::crypto::dh::{DH, FFDHE2048};
use umilib::ffi::Status;
use umilib::ffi::crypto::dh::dh;
use umilib::ffi::crypto::ecdh::{ecdh, xdh};

use super::Generator;
use crate::Check;
use crate::vectors::{Vectors, Wycheproof};

type Sizes = unsafe extern "C" fn(*const u8, usize, *mut usize) -> *const Status;
type Generate =
    unsafe extern "C" fn(*const u8, usize, *mut core::ffi::c_void, *const u8, usize, *mut u8, usize) -> *const Status;
type PublicKey = unsafe extern "C" fn(*const u8, usize, *const u8, usize, *mut u8, usize) -> *const Status;
type CheckPublicKey = unsafe extern "C" fn(*const u8, usize, *const u8, usize) -> *const Status;
type Agree =
    unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize, *mut u8, usize) -> *const Status;

/// The functions of one key agreement of the C ABI, with the name of an instance.
struct Scheme {
    name: &'static [u8],
    sizes: Sizes,
    generate: Generate,
    public_key: PublicKey,
    check_public_key: CheckPublicKey,
    agree: Agree,
}

impl Scheme {
    fn ecdh(name: &'static [u8]) -> Scheme {
        Scheme {
            name,
            sizes: ecdh::sizes,
            generate: ecdh::generate,
            public_key: ecdh::public_key,
            check_public_key: ecdh::check_public_key,
            agree: ecdh::agree,
        }
    }

    fn xdh(name: &'static [u8]) -> Scheme {
        Scheme {
            name,
            sizes: xdh::sizes,
            generate: xdh::generate,
            public_key: xdh::public_key,
            check_public_key: xdh::check_public_key,
            agree: xdh::agree,
        }
    }

    fn dh(name: &'static [u8]) -> Scheme {
        Scheme {
            name,
            sizes: dh::sizes,
            generate: dh::generate,
            public_key: dh::public_key,
            check_public_key: dh::check_public_key,
            agree: dh::agree,
        }
    }

    /// The sizes of a private key, a public key and a shared secret.
    fn sizes(&self) -> [usize; 3] {
        let mut sizes = [0; 3];
        Check::ok(unsafe { (self.sizes)(self.name.as_ptr(), self.name.len(), sizes.as_mut_ptr()) });
        sizes
    }

    /// The shared secret of `private` and `public`, or the status of the refusal.
    fn agree(&self, private: &[u8], public: &[u8]) -> Result<Vec<u8>, *const Status> {
        let mut shared = vec![0; self.sizes()[2]];
        let status = unsafe {
            (self.agree)(
                self.name.as_ptr(),
                self.name.len(),
                private.as_ptr(),
                private.len(),
                public.as_ptr(),
                public.len(),
                shared.as_mut_ptr(),
                shared.len(),
            )
        };
        if status.is_null() { Ok(shared) } else { Err(status) }
    }

    /// A private key from the generator and its public key.
    fn key_pair(&self, generator: &Generator) -> (Vec<u8>, Vec<u8>) {
        let [private_size, public_size, _] = self.sizes();
        let (mut private, mut public) = (vec![0; private_size], vec![0; public_size]);
        unsafe {
            Check::ok((self.generate)(
                self.name.as_ptr(),
                self.name.len(),
                generator.handle(),
                Generator::TYPE.as_ptr(),
                Generator::TYPE.len(),
                private.as_mut_ptr(),
                private.len(),
            ));
            Check::ok((self.public_key)(
                self.name.as_ptr(),
                self.name.len(),
                private.as_ptr(),
                private.len(),
                public.as_mut_ptr(),
                public.len(),
            ));
            Check::ok((self.check_public_key)(self.name.as_ptr(), self.name.len(), public.as_ptr(), public.len()));
        }
        (private, public)
    }

    /// Two parties agree, and every function refuses an unknown name and buffers of other sizes.
    fn check_round_trip(&self) {
        let generator = Generator::new(b"key agreement");
        let (a, public_a) = self.key_pair(&generator);
        let (b, public_b) = self.key_pair(&generator);
        assert_eq!(self.agree(&a, &public_b).unwrap(), self.agree(&b, &public_a).unwrap());
        let unknown = b"umilib_crypto_curve_unknown_Unknown";
        let mut sizes = [0usize; 3];
        unsafe {
            Check::fails((self.sizes)(unknown.as_ptr(), unknown.len(), sizes.as_mut_ptr()), "ffi", "InvalidArgument");
            Check::fails(
                (self.check_public_key)(unknown.as_ptr(), unknown.len(), public_a.as_ptr(), public_a.len()),
                "ffi",
                "InvalidArgument",
            );
            let mut short = vec![0; self.sizes()[2] - 1];
            Check::fails(
                (self.agree)(
                    self.name.as_ptr(),
                    self.name.len(),
                    a.as_ptr(),
                    a.len(),
                    public_b.as_ptr(),
                    public_b.len(),
                    short.as_mut_ptr(),
                    short.len(),
                ),
                "crypto",
                "InputLength",
            );
            Check::fails(
                (self.check_public_key)(self.name.as_ptr(), self.name.len(), public_a.as_ptr(), public_a.len() - 1),
                "crypto",
                "InvalidKey",
            );
        }
    }

    /// The Wycheproof file `file` of raw public keys: valid results are computed, invalid ones refused,
    /// and acceptable ones, if computed, right.
    fn check_wycheproof(&self, file: &str) {
        let tests = Wycheproof::tests(&format!("crypto/ecdh/{file}"));
        assert!(!tests.is_empty(), "{file}");
        let size = self.sizes()[0];
        for (_, test) in &tests {
            let label = format!("{file} {}", test.field("tcId").as_usize());
            let bytes = Vectors::hex(test.field("private").as_str());
            let significant: Vec<u8> = bytes.iter().copied().skip_while(|byte| *byte == 0).collect();
            let mut private = vec![0; size.saturating_sub(significant.len())];
            private.extend(significant);
            let result = self.agree(&private, &test.bytes("public"));
            match test.field("result").as_str() {
                "valid" => assert_eq!(result.ok(), Some(test.bytes("shared")), "{label}"),
                "invalid" => assert!(result.is_err(), "{label}"),
                _ => {
                    if let Ok(shared) = result {
                        assert_eq!(shared, test.bytes("shared"), "{label}");
                    }
                }
            }
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn ecdh_wycheproof() {
    for (name, file) in [
        (&b"umilib_crypto_curve_p256_P256"[..], "ecdh_secp256r1_ecpoint_test.json"),
        (b"umilib_crypto_curve_p384_P384", "ecdh_secp384r1_ecpoint_test.json"),
        (b"umilib_crypto_curve_p521_P521", "ecdh_secp521r1_ecpoint_test.json"),
    ] {
        let scheme = Scheme::ecdh(name);
        scheme.check_round_trip();
        scheme.check_wycheproof(file);
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn xdh_wycheproof() {
    for (name, file, sizes) in [
        (&b"umilib_crypto_curve_curve25519_Curve25519"[..], "x25519_test.json", [32, 32, 32]),
        (b"umilib_crypto_curve_curve448_Curve448", "x448_test.json", [56, 56, 56]),
    ] {
        let scheme = Scheme::xdh(name);
        assert_eq!(scheme.sizes(), sizes);
        scheme.check_round_trip();
        scheme.check_wycheproof(file);
    }
}

/// The C ABI computes the keys and the secret of `umilib::crypto` (RFC 7919 group ffdhe2048).
#[test]
#[cfg_attr(miri, ignore = "slow under Miri")]
fn dh_matches_the_rust_api() {
    type Rust = DH<FFDHE2048>;
    let scheme = Scheme::dh(b"umilib_crypto_dh_FFDHE2048");
    assert_eq!(scheme.sizes(), [Rust::PRIVATE_KEY_SIZE, Rust::PUBLIC_KEY_SIZE, Rust::SHARED_SECRET_SIZE]);
    scheme.check_round_trip();
    let generator = Generator::new(b"dh");
    let (a, public_a) = scheme.key_pair(&generator);
    let (b, _) = scheme.key_pair(&generator);
    let rust_a = Rust::private_key_from_bytes(&a).unwrap();
    let mut encoded = vec![0; Rust::PUBLIC_KEY_SIZE];
    Rust::write_public_key(&Rust::public_key(&rust_a), &mut encoded).unwrap();
    assert_eq!(encoded, public_a);
    let rust_b = Rust::private_key_from_bytes(&b).unwrap();
    let mut shared = vec![0; Rust::SHARED_SECRET_SIZE];
    Rust::agree(&rust_b, &Rust::public_key(&rust_a), &mut shared).unwrap();
    let mut public_b = vec![0; Rust::PUBLIC_KEY_SIZE];
    Rust::write_public_key(&Rust::public_key(&rust_b), &mut public_b).unwrap();
    assert_eq!(scheme.agree(&a, &public_b).unwrap(), shared);
    // RFC 7919 section 5.1: 1 and p - 1 are not public keys.
    let mut one = vec![0; Rust::PUBLIC_KEY_SIZE];
    *one.last_mut().unwrap() = 1;
    assert!(scheme.agree(&a, &one).is_err());
}
