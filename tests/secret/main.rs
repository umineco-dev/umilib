//! Tests of `umilib::secret`: constant-time operations give the same results
//! as their ordinary counterparts, and zeroization leaves only zeros.

use umilib::secret::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeTable, Secret, Zeroize};

#[test]
fn choice_follows_boolean_logic() {
    for a in [false, true] {
        for b in [false, true] {
            let (x, y) = (Choice::from(a), Choice::from(b));
            assert_eq!((x & y).into_bool(), a & b);
            assert_eq!((x | y).into_bool(), a | b);
            assert_eq!((x ^ y).into_bool(), a ^ b);
            assert_eq!(x.ct_eq(&y).into_bool(), a == b);
        }
        assert_eq!((!Choice::from(a)).into_bool(), !a);
    }
    assert_eq!(Choice::from_bit(0xFE).bit(), 0);
    assert_eq!(Choice::from_bit(0x03).bit(), 1);
    assert!(Choice::TRUE.into_bool());
    assert!(!Choice::FALSE.into_bool());
    let mut choice = Choice::TRUE;
    choice &= Choice::FALSE;
    assert!(!choice.into_bool());
    choice |= Choice::TRUE;
    choice ^= Choice::TRUE;
    assert!(!choice.into_bool());
}

#[test]
fn integer_equality_matches_ordinary_equality() {
    let values: [u64; 8] = [0, 1, 2, 0x80, 0xFF, 1 << 63, u64::MAX - 1, u64::MAX];
    for &a in &values {
        for &b in &values {
            assert_eq!(a.ct_eq(&b).into_bool(), a == b);
            assert_eq!(a.ct_ne(&b).into_bool(), a != b);
            assert_eq!((a as u8).ct_eq(&(b as u8)).into_bool(), a as u8 == b as u8);
            assert_eq!((a as u16).ct_eq(&(b as u16)).into_bool(), a as u16 == b as u16);
            assert_eq!((a as u32).ct_eq(&(b as u32)).into_bool(), a as u32 == b as u32);
            assert_eq!((a as i64).ct_eq(&(b as i64)).into_bool(), a == b);
            assert_eq!((a as u128).ct_eq(&(b as u128)).into_bool(), a == b);
            assert_eq!((a as usize).ct_eq(&(b as usize)).into_bool(), a as usize == b as usize);
        }
    }
}

#[test]
fn slice_equality_matches_ordinary_equality() {
    let a: &[u8] = b"secret value";
    assert!(a.ct_eq(b"secret value").into_bool());
    assert!(!a.ct_eq(b"secret valuE").into_bool());
    assert!(!a.ct_eq(b"Secret value").into_bool());
    assert!(!a.ct_eq(b"secret valu").into_bool());
    assert!(<[u8]>::ct_eq(b"", b"").into_bool());
    assert!([1u32, 2, 3].ct_eq(&[1, 2, 3]).into_bool());
    assert!(![1u32, 2, 3].ct_eq(&[1, 2, 4]).into_bool());
}

#[test]
fn selection_returns_the_chosen_value() {
    assert_eq!(u32::select(&10, &20, Choice::FALSE), 10);
    assert_eq!(u32::select(&10, &20, Choice::TRUE), 20);
    assert_eq!(i8::select(&-1, &5, Choice::TRUE), 5);
    assert_eq!(u128::select(&u128::MAX, &0, Choice::FALSE), u128::MAX);
    assert_eq!(<[u8; 3]>::select(&[1, 2, 3], &[4, 5, 6], Choice::TRUE), [4, 5, 6]);
    assert!(Choice::select(&Choice::FALSE, &Choice::TRUE, Choice::TRUE).into_bool());

    let mut value = 1u16;
    value.conditional_assign(&2, Choice::FALSE);
    assert_eq!(value, 1);
    value.conditional_assign(&2, Choice::TRUE);
    assert_eq!(value, 2);

    let (mut a, mut b) = (1u64, 2u64);
    u64::conditional_swap(&mut a, &mut b, Choice::FALSE);
    assert_eq!((a, b), (1, 2));
    u64::conditional_swap(&mut a, &mut b, Choice::TRUE);
    assert_eq!((a, b), (2, 1));
}

#[test]
fn zeroize_overwrites_every_byte() {
    let mut array = [0xAAu8; 32];
    array.zeroize();
    assert_eq!(array, [0; 32]);

    let mut words = [u64::MAX; 4];
    words.zeroize();
    assert_eq!(words, [0; 4]);

    let mut flag = true;
    flag.zeroize();
    assert!(!flag);

    let mut vector = vec![0x55u8; 100];
    vector.truncate(10);
    vector.zeroize();
    assert!(vector.is_empty());
    // The allocation, including the part beyond the length, is zeroed.
    assert!(vector.capacity() >= 100);
    // SAFETY: the first 100 bytes of the allocation were initialized when the vector was created.
    unsafe { vector.set_len(100) };
    assert!(vector.iter().all(|&byte| byte == 0));

    let mut text = String::from("password");
    text.zeroize();
    assert!(text.is_empty());

    let mut option = Some([1u8; 4]);
    option.zeroize();
    assert_eq!(option, None);
}

#[test]
fn secret_hides_its_value_and_compares_in_constant_time() {
    let mut secret = Secret::new([1u8, 2, 3]);
    assert_eq!(format!("{secret:?}"), "Secret(..)");
    assert_eq!(secret.expose(), &[1, 2, 3]);
    secret.expose_mut()[0] = 9;
    assert_eq!(secret.expose(), &[9, 2, 3]);
    let copy = secret.clone();
    assert!(secret.ct_eq(&copy).into_bool());
    assert!(!secret.ct_eq(&Secret::new([0, 0, 0])).into_bool());
    assert_eq!(Secret::<u32>::default().expose(), &0);
    assert_eq!(Secret::from(7u8).expose(), &7);
}

#[test]
fn choice_never_prints_its_value() {
    assert_eq!(format!("{:?}", Choice::TRUE), "Choice(..)");
    assert_eq!(format!("{:?}", Choice::FALSE), "Choice(..)");
}

#[test]
fn vectors_of_any_zeroizable_type_are_zeroized() {
    let mut words = vec![u32::MAX; 8];
    words.truncate(2);
    words.zeroize();
    assert!(words.is_empty());
    assert!(words.capacity() >= 8);
    // SAFETY: the first 8 elements of the allocation were initialized when the vector was created.
    unsafe { words.set_len(8) };
    assert!(words.iter().all(|&word| word == 0));
}

#[test]
fn data_independent_timing_guards_restore_the_previous_mode() {
    use umilib::secret::DataIndependentTiming;
    let before = DataIndependentTiming::is_enabled();
    {
        let _outer = DataIndependentTiming::enable();
        assert_eq!(DataIndependentTiming::is_enabled(), DataIndependentTiming::AVAILABLE);
        {
            let _inner = DataIndependentTiming::enable();
            assert_eq!(DataIndependentTiming::is_enabled(), DataIndependentTiming::AVAILABLE);
        }
        // The inner guard found the mode set and leaves it set.
        assert_eq!(DataIndependentTiming::is_enabled(), DataIndependentTiming::AVAILABLE);
    }
    assert_eq!(DataIndependentTiming::is_enabled(), before);
    // aarch64 Apple targets enable the `dit` target feature by default;
    // Miri cannot run the instructions.
    assert_eq!(DataIndependentTiming::AVAILABLE, cfg!(all(target_arch = "aarch64", target_feature = "dit", not(miri))));
}

/// The entries of a table of `WORDS` words of `BITS`-bit entries agree with a plain array through every operation.
fn table_matches_an_array<const WORDS: usize, const BITS: u32>() {
    let entries = ConstantTimeTable::<WORDS, BITS>::ENTRIES;
    let mask = ((1u64 << BITS) - 1) as u32;
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut array: Vec<u32> = (0..entries).map(|_| next() as u32 & mask).collect();
    let mut table = ConstantTimeTable::<WORDS, BITS>::from_entries(&array);
    for (index, value) in array.iter().enumerate() {
        assert_eq!(table.get(index), *value, "{WORDS} words of {BITS} bits, entry {index}");
        // An index is taken modulo the number of entries.
        assert_eq!(table.get(index + entries), *value);
    }
    for _ in 0..4 * entries {
        let (index, value) = (next() as usize % entries, next() as u32);
        table.set(index, value);
        array[index] = value & mask;
        let (first, second) = (next() as usize % entries, next() as usize % entries);
        table.swap(first, second);
        array.swap(first, second);
    }
    assert_eq!(table.words(), ConstantTimeTable::<WORDS, BITS>::from_entries(&array).words());
    if BITS <= 8 {
        let bytes: Vec<u8> = array.iter().map(|&value| value as u8).collect();
        assert_eq!(ConstantTimeTable::<WORDS, BITS>::from_bytes(&bytes).words(), table.words());
    }
    table.zeroize();
    assert_eq!(table.words(), ConstantTimeTable::<WORDS, BITS>::new().words());
}

#[test]
fn constant_time_table_matches_an_array() {
    table_matches_an_array::<1, 1>();
    table_matches_an_array::<2, 2>();
    table_matches_an_array::<1, 4>();
    table_matches_an_array::<4, 4>();
    table_matches_an_array::<32, 8>();
    table_matches_an_array::<16, 16>();
    table_matches_an_array::<8, 32>();
    assert_eq!(ConstantTimeTable::<32, 8>::ENTRIES, 256);
    assert_eq!(ConstantTimeTable::<1, 4>::ENTRIES_PER_WORD, 16);
    for (a, b) in [(0, 0), (1, 0), (0, usize::MAX), (usize::MAX, usize::MAX), (1 << (usize::BITS - 1), 0)] {
        assert_eq!(ConstantTimeTable::<1, 8>::mask(a, b), if a == b { u64::MAX } else { 0 });
    }
    assert_eq!(format!("{:?}", ConstantTimeTable::<32, 8>::new()), "ConstantTimeTable(256 entries of 8 bits, ..)");
}
