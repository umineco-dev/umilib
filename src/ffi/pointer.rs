use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::{Buffer, Char, Status};

/// Conversions between C pointers and Rust references, checking for null.
///
/// Every conversion is `unsafe` because a non-null pointer cannot be checked
/// for validity: the caller of the C API guarantees that it points to live,
/// properly aligned memory of the right type and size for the duration of the
/// call, and that memory passed as mutable is not accessed by anything else.
pub struct Pointer;

impl Pointer {
    /// Borrows `length` bytes at `data`. `data` may be null when `length` is zero.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn slice<'a>(data: *const u8, length: usize) -> Result<&'a [u8], &'static Status> {
        if length == 0 {
            return Ok(&[]);
        }
        if data.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        if length > isize::MAX as usize {
            return Err(&Status::INVALID_ARGUMENT);
        }
        // SAFETY: guaranteed by the caller; `data` is non-null and `length` fits in `isize`.
        Ok(unsafe { core::slice::from_raw_parts(data, length) })
    }

    /// Borrows `length` bytes at `data` mutably. `data` may be null when `length` is zero.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn slice_mut<'a>(data: *mut u8, length: usize) -> Result<&'a mut [u8], &'static Status> {
        if length == 0 {
            return Ok(&mut []);
        }
        if data.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        if length > isize::MAX as usize {
            return Err(&Status::INVALID_ARGUMENT);
        }
        // SAFETY: guaranteed by the caller; `data` is non-null and `length` fits in `isize`.
        Ok(unsafe { core::slice::from_raw_parts_mut(data, length) })
    }

    /// Borrows `length` bytes at `data` as UTF-8 text.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn text<'a>(data: *const u8, length: usize) -> Result<&'a str, &'static Status> {
        // SAFETY: guaranteed by the caller.
        let bytes = unsafe { Pointer::slice(data, length) }?;
        core::str::from_utf8(bytes).map_err(|_| &Status::INVALID_UTF8)
    }

    /// Copies `count` NUL-terminated UTF-8 strings from the array at `strings`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`]; every string must be NUL-terminated.
    pub unsafe fn strings(strings: *const *const Char, count: usize) -> Result<Vec<String>, &'static Status> {
        // SAFETY: guaranteed by the caller; the length of the array is checked.
        let pointers = unsafe { Pointer::slice_of(strings, count) }?;
        let mut copied = Vec::new();
        copied.try_reserve_exact(count).map_err(|_| &Status::INVALID_ARGUMENT)?;
        for &string in pointers {
            if string.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            // SAFETY: guaranteed by the caller; the string is NUL-terminated.
            let text = unsafe { core::ffi::CStr::from_ptr(string.cast()) };
            copied.push(String::from(text.to_str().map_err(|_| &Status::INVALID_UTF8)?));
        }
        Ok(copied)
    }

    /// Borrows `count` byte sequences: the `index`-th starts at `inputs[index]`
    /// and is `lengths[index]` bytes long.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn slices<'a>(
        inputs: *const *const u8,
        lengths: *const usize,
        count: usize,
    ) -> Result<Vec<&'a [u8]>, &'static Status> {
        if count == 0 {
            return Ok(Vec::new());
        }
        // SAFETY: guaranteed by the caller.
        let pointers = unsafe { Pointer::slice_of(inputs, count) }?;
        let lengths = unsafe { Pointer::slice_of(lengths, count) }?;
        let mut slices = Vec::new();
        slices.try_reserve_exact(count).map_err(|_| &Status::INVALID_ARGUMENT)?;
        for (&data, &length) in pointers.iter().zip(lengths) {
            // SAFETY: guaranteed by the caller.
            slices.push(unsafe { Pointer::slice(data, length) }?);
        }
        Ok(slices)
    }

    /// Borrows an array of `count` values at `data`. `data` may be null when `count` is zero.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn slice_of<'a, T>(data: *const T, count: usize) -> Result<&'a [T], &'static Status> {
        if count == 0 {
            return Ok(&[]);
        }
        if data.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        if count.checked_mul(core::mem::size_of::<T>()).is_none_or(|size| size > isize::MAX as usize) {
            return Err(&Status::INVALID_ARGUMENT);
        }
        // SAFETY: guaranteed by the caller; `data` is non-null and the size fits in `isize`.
        Ok(unsafe { core::slice::from_raw_parts(data, count) })
    }

    /// Borrows an array of `count` values at `data` mutably. `data` may be null when `count` is zero.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn slice_of_mut<'a, T>(data: *mut T, count: usize) -> Result<&'a mut [T], &'static Status> {
        if count == 0 {
            return Ok(&mut []);
        }
        if data.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        if count.checked_mul(core::mem::size_of::<T>()).is_none_or(|size| size > isize::MAX as usize) {
            return Err(&Status::INVALID_ARGUMENT);
        }
        // SAFETY: guaranteed by the caller; `data` is non-null and the size fits in `isize`.
        Ok(unsafe { core::slice::from_raw_parts_mut(data, count) })
    }

    /// Borrows the value at `pointer`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn reference<'a, T>(pointer: *const T) -> Result<&'a T, &'static Status> {
        // SAFETY: guaranteed by the caller; null is rejected by `as_ref`.
        unsafe { pointer.as_ref() }.ok_or(&Status::NULL_POINTER)
    }

    /// Borrows the value at `pointer` mutably.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn reference_mut<'a, T>(pointer: *mut T) -> Result<&'a mut T, &'static Status> {
        // SAFETY: guaranteed by the caller; null is rejected by `as_mut`.
        unsafe { pointer.as_mut() }.ok_or(&Status::NULL_POINTER)
    }

    /// Stores `value` at `pointer`, which may hold uninitialized memory.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write<T>(pointer: *mut T, value: T) -> Result<(), &'static Status> {
        if pointer.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        // SAFETY: guaranteed by the caller; `pointer` is non-null.
        unsafe { pointer.write(value) };
        Ok(())
    }

    /// Checks that `length` elements at `data` can be accessed: `data` is
    /// non-null unless `length` is zero, and the size fits in `isize`.
    pub fn check_range<T>(data: *const T, length: usize) -> Result<(), &'static Status> {
        if length == 0 {
            return Ok(());
        }
        if data.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        if length.checked_mul(core::mem::size_of::<T>()).is_none_or(|size| size > isize::MAX as usize) {
            return Err(&Status::INVALID_ARGUMENT);
        }
        Ok(())
    }

    /// Whether the `length` bytes at `a` and at `b` share at least one byte.
    pub fn overlaps<T, U>(a: *const T, a_length: usize, b: *const U, b_length: usize) -> bool {
        let (a, b) = (a as usize, b as usize);
        a_length > 0 && b_length > 0 && a < b.saturating_add(b_length) && b < a.saturating_add(a_length)
    }

    /// Fails with `InvalidArgument` if the `a_count` elements at `a` and the
    /// `b_count` elements at `b` share a byte, so that a function can read one
    /// range while writing the other without the two aliasing.
    pub fn check_disjoint<T, U>(
        a: *const T,
        a_count: usize,
        b: *const U,
        b_count: usize,
    ) -> Result<(), &'static Status> {
        let a_length = a_count.saturating_mul(core::mem::size_of::<T>());
        let b_length = b_count.saturating_mul(core::mem::size_of::<U>());
        if Pointer::overlaps(a, a_length, b, b_length) {
            return Err(&Status::INVALID_ARGUMENT);
        }
        Ok(())
    }

    /// Fails with `InvalidArgument` if a range of `outputs` shares a byte with
    /// a range of `inputs` or with another output: the check of a function that
    /// reads the `inputs` while writing the `outputs`, each `(address, bytes)`.
    pub fn check_ranges(inputs: &[(*const u8, usize)], outputs: &[(*const u8, usize)]) -> Result<(), &'static Status> {
        for (index, &(output, output_length)) in outputs.iter().enumerate() {
            let others = inputs.iter().chain(&outputs[index + 1..]);
            for &(other, other_length) in others {
                if Pointer::overlaps(output, output_length, other, other_length) {
                    return Err(&Status::INVALID_ARGUMENT);
                }
            }
        }
        Ok(())
    }

    /// The `(address, bytes)` of the `count` elements at `data`, as
    /// [`Pointer::check_ranges`] takes it. A null `data` is an empty range: it
    /// holds no memory to share, and the function reports it as null.
    pub fn range<T>(data: *const T, count: usize) -> (*const u8, usize) {
        let length = if data.is_null() { 0 } else { count.saturating_mul(core::mem::size_of::<T>()) };
        (data.cast(), length)
    }

    /// Moves `value` to the heap and stores the owning handle at `out`.
    /// Nothing is allocated if `out` is null.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write_handle<T>(out: *mut *mut T, value: T) -> Result<(), &'static Status> {
        if out.is_null() {
            return Err(&Status::NULL_POINTER);
        }
        // SAFETY: guaranteed by the caller; `out` is non-null.
        unsafe { out.write(Pointer::into_handle(value)) };
        Ok(())
    }

    /// Moves `value` to the heap and returns an owning handle for C.
    pub fn into_handle<T>(value: T) -> *mut T {
        Box::into_raw(Box::new(value))
    }

    /// Borrows the text at `data` (see [`Pointer::text`]), or `None` for a
    /// null `data`: the C form of an optional string.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn optional_text<'a>(data: *const u8, length: usize) -> Result<Option<&'a str>, &'static Status> {
        if data.is_null() {
            return Ok(None);
        }
        // SAFETY: guaranteed by the caller; `data` is non-null.
        Ok(Some(unsafe { Pointer::text(data, length) }?))
    }

    /// Borrows the value at `pointer`, or `None` for null: the C form of
    /// an optional handle.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn optional_reference<'a, T>(pointer: *const T) -> Result<Option<&'a T>, &'static Status> {
        if pointer.is_null() {
            return Ok(None);
        }
        // SAFETY: guaranteed by the caller; `pointer` is non-null.
        Ok(Some(unsafe { Pointer::reference(pointer) }?))
    }

    /// Stores the UTF-8 of `text` in a buffer at `out`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write_text(out: *mut Buffer, text: String) -> Result<(), &'static Status> {
        // SAFETY: guaranteed by the caller.
        unsafe { Pointer::write(out, Buffer::from_vec(text.into_bytes())) }
    }

    /// Stores whether `text` is present at `out_has` and its UTF-8 (empty
    /// when absent) in a buffer at `out`.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write_optional_text(
        out_has: *mut bool,
        out: *mut Buffer,
        text: Option<&str>,
    ) -> Result<(), &'static Status> {
        // Both are checked before either is written: a failure writes nothing.
        Pointer::check_ranges(&[], &[Pointer::range(out_has, 1), Pointer::range(out, 1)])?;
        Pointer::check_range(out_has, 1)?;
        Pointer::check_range(out, 1)?;
        // SAFETY: guaranteed by the caller; both pointers are non-null.
        unsafe { Pointer::write(out_has, text.is_some()) }?;
        unsafe { Pointer::write_text(out, String::from(text.unwrap_or_default())) }
    }

    /// Stores whether `value` is present at `out_found` and the value (its
    /// default when absent) at `out`: the C form of an optional output.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write_optional<T: Default>(
        value: Option<T>,
        out_found: *mut bool,
        out: *mut T,
    ) -> Result<(), &'static Status> {
        Pointer::check_ranges(&[], &[Pointer::range(out_found, 1), Pointer::range(out, 1)])?;
        Pointer::check_range(out_found, 1)?;
        Pointer::check_range(out, 1)?;
        // SAFETY: guaranteed by the caller; both pointers are non-null.
        unsafe { Pointer::write(out_found, value.is_some()) }?;
        unsafe { Pointer::write(out, value.unwrap_or_default()) }
    }

    /// Drops the value owned by `handle`. Does nothing if `handle` is null.
    ///
    /// # Safety
    ///
    /// `handle` must be null or come from [`Pointer::into_handle`] with the
    /// same `T`, and must not be used afterwards.
    pub unsafe fn free<T>(handle: *mut T) {
        if !handle.is_null() {
            // SAFETY: guaranteed by the caller.
            drop(unsafe { Box::from_raw(handle) });
        }
    }
}
