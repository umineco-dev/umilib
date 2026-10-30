use std::ptr;

use umilib::ffi::secret::*;
use umilib::secret::Secret;

use super::Check;

#[test]
fn choices_follow_boolean_logic() {
    unsafe {
        assert_eq!(umilib_secret_choice_from_bit(3), 1);
        assert_eq!(umilib_secret_choice_and(1, 0), 0);
        assert_eq!(umilib_secret_choice_or(1, 0), 1);
        assert_eq!(umilib_secret_choice_xor(1, 1), 0);
        assert_eq!(umilib_secret_choice_not(0), 1);
        assert!(umilib_secret_choice_into_bool(1));
    }
}

#[test]
fn byte_equality_and_selection() {
    let (a, b) = (*b"abcd", *b"abce");
    let mut out = 9u8;
    unsafe {
        Check::ok(umilib_secret_constant_time_eq_ct_eq(a.as_ptr(), 4, a.as_ptr(), 4, &mut out));
        assert_eq!(out, 1);
        Check::ok(umilib_secret_constant_time_eq_ct_eq(a.as_ptr(), 4, b.as_ptr(), 4, &mut out));
        assert_eq!(out, 0);
        Check::ok(umilib_secret_constant_time_eq_ct_ne(a.as_ptr(), 4, b.as_ptr(), 3, &mut out));
        assert_eq!(out, 1);

        let mut selected = [0u8; 4];
        Check::ok(umilib_secret_conditionally_selectable_select(a.as_ptr(), b.as_ptr(), 4, 1, selected.as_mut_ptr()));
        assert_eq!(&selected, b"abce");
        Check::ok(umilib_secret_conditionally_selectable_conditional_assign(selected.as_mut_ptr(), a.as_ptr(), 4, 0));
        assert_eq!(&selected, b"abce");
        Check::ok(umilib_secret_conditionally_selectable_conditional_assign(selected.as_mut_ptr(), a.as_ptr(), 4, 1));
        assert_eq!(&selected, b"abcd");

        let (mut x, mut y) = (*b"xx", *b"yy");
        Check::ok(umilib_secret_conditionally_selectable_conditional_swap(x.as_mut_ptr(), y.as_mut_ptr(), 2, 1));
        assert_eq!((&x, &y), (b"yy", b"xx"));
        // Identical ranges are allowed; partially overlapping ones are rejected.
        // One raw pointer per array: a second `as_mut_ptr` would invalidate the first.
        let pointer = x.as_mut_ptr();
        Check::ok(umilib_secret_conditionally_selectable_conditional_swap(pointer, pointer, 2, 1));
        assert_eq!(&x, b"yy");
        Check::fails(
            umilib_secret_conditionally_selectable_conditional_swap(pointer, pointer.add(1), 2, 1),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            umilib_secret_conditionally_selectable_conditional_swap(ptr::null_mut(), ptr::null_mut(), 2, 1),
            "ffi",
            "NullPointer",
        );
    }
}

#[test]
fn selection_accepts_the_output_as_an_input() {
    let mut a = *b"aaaa";
    let b = *b"bbbb";
    unsafe {
        let pointer = a.as_mut_ptr();
        Check::ok(umilib_secret_conditionally_selectable_select(pointer, b.as_ptr(), 4, 1, pointer));
        assert_eq!(&a, b"bbbb");
        let pointer = a.as_mut_ptr();
        Check::ok(umilib_secret_conditionally_selectable_conditional_assign(pointer, pointer, 4, 1));
        assert_eq!(&a, b"bbbb");
        let pointer = a.as_mut_ptr();
        Check::fails(
            umilib_secret_conditionally_selectable_select(pointer.add(1), b.as_ptr(), 3, 1, pointer),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            umilib_secret_conditionally_selectable_conditional_assign(pointer, pointer.add(1), 3, 1),
            "ffi",
            "InvalidArgument",
        );
        Check::fails(
            umilib_secret_conditionally_selectable_select(ptr::null(), b.as_ptr(), 4, 1, pointer),
            "ffi",
            "NullPointer",
        );
    }
}

#[test]
fn zeroize_and_secret_handles() {
    let mut data = [0xAAu8; 8];
    unsafe {
        Check::ok(umilib_secret_zeroize_zeroize(data.as_mut_ptr(), data.len()));
        assert_eq!(data, [0; 8]);

        let mut secret: *mut Secret<Vec<u8>> = ptr::null_mut();
        Check::ok(umilib_secret_secret_new(b"key".as_ptr(), 3, &mut secret));
        let (mut pointer, mut length): (*mut u8, usize) = (ptr::null_mut(), 0);
        Check::ok(umilib_secret_secret_expose_mut(secret, &mut pointer, &mut length));
        *pointer = b'K';
        let (mut view, mut view_length): (*const u8, usize) = (ptr::null(), 0);
        Check::ok(umilib_secret_secret_expose(secret, &mut view, &mut view_length));
        assert_eq!(std::slice::from_raw_parts(view, view_length), b"Key");
        umilib_secret_secret_free(secret);
        umilib_secret_secret_free(ptr::null_mut());
    }
}

#[test]
fn choices_other_than_zero_and_one_are_rejected() {
    let (a, b) = (*b"ab", *b"cd");
    let mut out = [0u8; 2];
    unsafe {
        for choice in [2u8, 0xFF] {
            Check::fails(
                umilib_secret_conditionally_selectable_select(a.as_ptr(), b.as_ptr(), 2, choice, out.as_mut_ptr()),
                "ffi",
                "InvalidArgument",
            );
            Check::fails(
                umilib_secret_conditionally_selectable_conditional_assign(out.as_mut_ptr(), a.as_ptr(), 2, choice),
                "ffi",
                "InvalidArgument",
            );
        }
    }
    assert_eq!(out, [0, 0]);
}

#[test]
fn data_independent_timing_guards_nest() {
    use umilib::secret::DataIndependentTiming;
    unsafe {
        let available = umilib_secret_data_independent_timing_available();
        assert_eq!(available, DataIndependentTiming::AVAILABLE);
        let before = umilib_secret_data_independent_timing_is_enabled();
        let (mut outer, mut inner) = (ptr::null_mut(), ptr::null_mut());
        Check::ok(umilib_secret_data_independent_timing_enable(&mut outer));
        assert_eq!(umilib_secret_data_independent_timing_is_enabled(), available);
        Check::ok(umilib_secret_data_independent_timing_enable(&mut inner));
        umilib_secret_data_independent_timing_free(inner);
        assert_eq!(umilib_secret_data_independent_timing_is_enabled(), available);
        umilib_secret_data_independent_timing_free(outer);
        assert_eq!(umilib_secret_data_independent_timing_is_enabled(), before);
        Check::fails(umilib_secret_data_independent_timing_enable(ptr::null_mut()), "ffi", "NullPointer");
    }
}

#[test]
fn constant_time_tables_read_write_and_pack_their_entries() {
    // A permutation of the bytes, so that every entry differs from its index.
    let entries: Vec<u8> = (0..=255u8).map(|index| index.wrapping_mul(167).wrapping_add(13)).collect();
    unsafe {
        let mut table = ptr::null_mut();
        Check::fails(
            umilib_secret_constant_time_table32_8_from_bytes(entries.as_ptr(), 255, &mut table),
            "ffi",
            "InvalidArgument",
        );
        Check::ok(umilib_secret_constant_time_table32_8_from_bytes(entries.as_ptr(), 256, &mut table));
        let mut value = 0u32;
        for (index, &entry) in entries.iter().enumerate() {
            Check::ok(umilib_secret_constant_time_table32_8_get(table, index, &mut value));
            assert_eq!(value, entry as u32, "{index}");
            // The index is taken modulo the 256 entries.
            Check::ok(umilib_secret_constant_time_table32_8_get(table, index + 256, &mut value));
            assert_eq!(value, entry as u32, "{index} + 256");
        }
        // Entry i is bits 8 × (i mod 8) and up of word i / 8.
        let mut words = [0u64; 32];
        Check::ok(umilib_secret_constant_time_table32_8_words(table, words.as_mut_ptr()));
        for (index, &entry) in entries.iter().enumerate() {
            assert_eq!((words[index / 8] >> (8 * (index % 8))) as u8, entry, "{index}");
        }
        // A write keeps the low 8 bits and changes only its entry.
        let mut copy = ptr::null_mut();
        Check::ok(umilib_secret_constant_time_table32_8_clone(table, &mut copy));
        Check::ok(umilib_secret_constant_time_table32_8_set(table, 77, 0x1AB));
        Check::ok(umilib_secret_constant_time_table32_8_get(table, 77, &mut value));
        assert_eq!(value, 0xAB);
        Check::ok(umilib_secret_constant_time_table32_8_swap(table, 3, 200));
        for index in 0..256 {
            let expected = match index {
                77 => 0xAB,
                3 => entries[200],
                200 => entries[3],
                _ => entries[index],
            };
            Check::ok(umilib_secret_constant_time_table32_8_get(table, index, &mut value));
            assert_eq!(value, expected as u32, "{index}");
            Check::ok(umilib_secret_constant_time_table32_8_get(copy, index, &mut value));
            assert_eq!(value, entries[index] as u32, "copy {index}");
        }
        umilib_secret_constant_time_table32_8_free(copy);
        umilib_secret_constant_time_table32_8_free(table);
        Check::ok(umilib_secret_constant_time_table32_8_new(&mut table));
        Check::ok(umilib_secret_constant_time_table32_8_get(table, 9, &mut value));
        assert_eq!(value, 0);
        umilib_secret_constant_time_table32_8_free(table);
        assert_eq!(umilib_secret_constant_time_table32_8_mask(5, 5), u64::MAX);
        assert_eq!(umilib_secret_constant_time_table32_8_mask(5, 6), 0);
    }
}
