use alloc::vec::Vec;
use core::mem::ManuallyDrop;

/// Bytes allocated by umilib and handed to the caller.
///
/// The caller owns the structure itself and releases the bytes with
/// `umilib_ffi_buffer_free`, which overwrites them with zeros, because they
/// may be secret, and resets the structure to empty. An empty buffer has a
/// null `data` pointer.
#[repr(C)]
#[derive(Debug)]
pub struct Buffer {
    data: *mut u8,
    length: usize,
    capacity: usize,
}

impl Buffer {
    /// A buffer that holds nothing and owns no allocation.
    pub const EMPTY: Buffer = Buffer { data: core::ptr::null_mut(), length: 0, capacity: 0 };

    /// Transfers ownership of the bytes of `vector` into a buffer.
    pub fn from_vec(vector: Vec<u8>) -> Buffer {
        if vector.capacity() == 0 {
            return Buffer::EMPTY;
        }
        let mut vector = ManuallyDrop::new(vector);
        Buffer { data: vector.as_mut_ptr(), length: vector.len(), capacity: vector.capacity() }
    }

    /// The bytes held by the buffer.
    pub fn as_slice(&self) -> &[u8] {
        if self.data.is_null() {
            return &[];
        }
        // SAFETY: a non-null `data` always comes from `from_vec` and points to
        // `length` initialized bytes owned by this buffer.
        unsafe { core::slice::from_raw_parts(self.data, self.length) }
    }

    /// Takes the bytes back as a vector, leaving the buffer empty.
    ///
    /// # Safety
    ///
    /// The fields must be unchanged since the buffer was created by
    /// [`Buffer::from_vec`] (the caller of the C API must not modify them).
    pub unsafe fn take(&mut self) -> Vec<u8> {
        let buffer = ManuallyDrop::new(core::mem::replace(self, Buffer::EMPTY));
        if buffer.data.is_null() {
            return Vec::new();
        }
        // SAFETY: guaranteed by the caller; the fields describe an allocation
        // made by `Vec<u8>` with the global allocator.
        unsafe { Vec::from_raw_parts(buffer.data, buffer.length, buffer.capacity) }
    }

    /// Overwrites the bytes and frees them, leaving the buffer empty.
    ///
    /// # Safety
    ///
    /// The same as [`Buffer::take`].
    pub unsafe fn release(&mut self) {
        // SAFETY: guaranteed by the caller.
        let mut vector = unsafe { self.take() };
        let data = vector.as_mut_ptr();
        for index in 0..vector.capacity() {
            // SAFETY: `as_mut_ptr` is valid for writes to the whole capacity,
            // initialized or not.
            unsafe { core::ptr::write_volatile(data.add(index), 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Default for Buffer {
    fn default() -> Buffer {
        Buffer::EMPTY
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: the fields of a buffer owned by Rust code are only set by `from_vec`.
        unsafe { self.release() };
    }
}
