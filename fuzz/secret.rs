//! Fuzz targets of `umilib::secret`.

use umilib::platform::fuzz::{FuzzFunction, FuzzTarget};
use umilib::secret::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Checks that constant-time equality and selection agree with their ordinary counterparts.
pub const EQUALITY: FuzzFunction<fn(&[u8])> = FuzzFunction::new("secret-equality", |data| {
    let (a, b) = data.split_at(data.len() / 2);
    assert_eq!(a.ct_eq(b).into_bool(), a == b);
    let b = &b[..a.len().min(b.len())];
    let a = &a[..b.len()];
    assert_eq!(a.ct_eq(b).into_bool(), a == b);
    for (x, y) in a.iter().zip(b) {
        let choice = Choice::from_bit(*x);
        let selected = u8::select(x, y, choice);
        assert_eq!(selected, if x & 1 == 1 { *y } else { *x });
    }
});

pub const TARGETS: &[&dyn FuzzTarget] = &[&EQUALITY];
