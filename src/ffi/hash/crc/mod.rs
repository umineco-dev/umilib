//! The C ABI of [`crate::hash::crc`].
//!
//! C cannot name the register type `W` of [`CRCTable<W>`] and [`CRC<W>`],
//! so one table type and one computation type hold any of them, and every
//! value is passed as `umilib_ffi_U128`. A table is created from its
//! parameters or found in the catalogue by its name; a computation
//! ([`CRC`]) keeps a copy of its table.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, Type, U128, Value};
use crate::hash::crc::{CRC, CRCCatalogue, CRCParameters as RustParameters, CRCRegister, CRCTable as RustTable};

/// The parameters of a CRC with 128-bit values, the C form of
/// [`CRCParameters`](crate::hash::crc::CRCParameters) without its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CRCParameters {
    pub width: u32,
    pub polynomial: U128,
    pub initial: U128,
    pub reflect_input: bool,
    pub reflect_output: bool,
    pub xor_output: U128,
    pub check: U128,
    pub residue: U128,
}

impl CRCParameters {
    /// The parameters of `parameters`.
    pub fn from_rust<W: CRCRegister + Into<u128>>(parameters: &RustParameters<W>) -> CRCParameters {
        CRCParameters {
            width: parameters.width,
            polynomial: U128::from(parameters.polynomial.into()),
            initial: U128::from(parameters.initial.into()),
            reflect_input: parameters.reflect_input,
            reflect_output: parameters.reflect_output,
            xor_output: U128::from(parameters.xor_output.into()),
            check: U128::from(parameters.check.into()),
            residue: U128::from(parameters.residue.into()),
        }
    }

    /// The parameters in the register type `W`, named `name`; fails if a value does not fit.
    pub fn to_rust<W: TryFrom<u128>>(&self, name: &'static str) -> Result<RustParameters<W>, &'static Status> {
        let convert =
            |value: U128| W::try_from(u128::from(value)).map_err(|_| &crate::ffi::hash::HashStatus::INVALID_PARAMETER);
        Ok(RustParameters {
            name,
            width: self.width,
            polynomial: convert(self.polynomial)?,
            initial: convert(self.initial)?,
            reflect_input: self.reflect_input,
            reflect_output: self.reflect_output,
            xor_output: convert(self.xor_output)?,
            check: convert(self.check)?,
            residue: convert(self.residue)?,
        })
    }
}

impl Value for CRCParameters {
    const TYPE: Type = Type::Named("umilib_hash_crc_CRCParameters");
}

/// A [`CRCTable`](crate::hash::crc::CRCTable) with the smallest register that
/// holds its width.
/// The tables are boxed, so that a handle takes the memory of its own register size.
#[derive(Clone, Debug)]
pub enum CRCTable {
    U8(Box<RustTable<u8>>),
    U16(Box<RustTable<u16>>),
    U32(Box<RustTable<u32>>),
    U64(Box<RustTable<u64>>),
    U128(Box<RustTable<u128>>),
}

impl CRCTable {
    /// The table of `parameters`, named `name`.
    pub fn new(parameters: &CRCParameters, name: &'static str) -> Result<CRCTable, &'static Status> {
        let invalid = |_| &crate::ffi::hash::HashStatus::INVALID_PARAMETER;
        Ok(match parameters.width {
            0..=8 => CRCTable::U8(Box::new(RustTable::<u8>::new(parameters.to_rust(name)?).map_err(invalid)?)),
            9..=16 => CRCTable::U16(Box::new(RustTable::<u16>::new(parameters.to_rust(name)?).map_err(invalid)?)),
            17..=32 => CRCTable::U32(Box::new(RustTable::<u32>::new(parameters.to_rust(name)?).map_err(invalid)?)),
            33..=64 => CRCTable::U64(Box::new(RustTable::<u64>::new(parameters.to_rust(name)?).map_err(invalid)?)),
            _ => CRCTable::U128(Box::new(RustTable::<u128>::new(parameters.to_rust(name)?).map_err(invalid)?)),
        })
    }

    /// A copy of the catalogue table named `name`, such as `CRC-32/ISO-HDLC`.
    pub fn find(name: &str) -> Option<CRCTable> {
        macro_rules! search {
            ($($tables:expr => $variant:ident),*) => {$(
                if let Some(table) = $tables.iter().find(|table| table.parameters().name == name) {
                    return Some(CRCTable::$variant(Box::new((*table).clone())));
                }
            )*};
        }
        search!(
            CRCCatalogue::TABLES_U8 => U8,
            CRCCatalogue::TABLES_U16 => U16,
            CRCCatalogue::TABLES_U32 => U32,
            CRCCatalogue::TABLES_U64 => U64,
            CRCCatalogue::TABLES_U128 => U128
        );
        None
    }

    /// The names of the catalogue, in its order.
    pub fn catalogue_names() -> impl Iterator<Item = &'static str> {
        (CRCCatalogue::TABLES_U8.iter().map(|table| table.parameters().name))
            .chain(CRCCatalogue::TABLES_U16.iter().map(|table| table.parameters().name))
            .chain(CRCCatalogue::TABLES_U32.iter().map(|table| table.parameters().name))
            .chain(CRCCatalogue::TABLES_U64.iter().map(|table| table.parameters().name))
            .chain(CRCCatalogue::TABLES_U128.iter().map(|table| table.parameters().name))
    }

    pub fn parameters(&self) -> CRCParameters {
        match self {
            CRCTable::U8(table) => CRCParameters::from_rust(table.parameters()),
            CRCTable::U16(table) => CRCParameters::from_rust(table.parameters()),
            CRCTable::U32(table) => CRCParameters::from_rust(table.parameters()),
            CRCTable::U64(table) => CRCParameters::from_rust(table.parameters()),
            CRCTable::U128(table) => CRCParameters::from_rust(table.parameters()),
        }
    }

    /// The CRC of `data`, without copying the table.
    pub fn checksum(&self, data: &[u8]) -> u128 {
        match self {
            CRCTable::U8(table) => CRC::checksum(table, data).into(),
            CRCTable::U16(table) => CRC::checksum(table, data).into(),
            CRCTable::U32(table) => CRC::checksum(table, data).into(),
            CRCTable::U64(table) => CRC::checksum(table, data).into(),
            CRCTable::U128(table) => CRC::checksum(table, data),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            CRCTable::U8(table) => table.parameters().name,
            CRCTable::U16(table) => table.parameters().name,
            CRCTable::U32(table) => table.parameters().name,
            CRCTable::U64(table) => table.parameters().name,
            CRCTable::U128(table) => table.parameters().name,
        }
    }
}

impl Value for CRCTable {
    const TYPE: Type = Type::Named("umilib_hash_crc_CRCTable");
}

/// A [`CRC`] computation that owns a copy of its [`CRCTable`], so that no
/// table it was made from has to outlive it. The register is held in 128 bits
/// and used in the register type of the table.
#[derive(Clone, Debug)]
pub struct CRCState {
    table: CRCTable,
    register: u128,
}

impl CRCState {
    /// A computation over a copy of `table`.
    pub fn new(table: &CRCTable) -> CRCState {
        let table = table.clone();
        let register = match &table {
            CRCTable::U8(table) => table.initial_register().into(),
            CRCTable::U16(table) => table.initial_register().into(),
            CRCTable::U32(table) => table.initial_register().into(),
            CRCTable::U64(table) => table.initial_register().into(),
            CRCTable::U128(table) => table.initial_register(),
        };
        CRCState { table, register }
    }

    pub fn table(&self) -> &CRCTable {
        &self.table
    }

    /// The register after `data` from `register`, in the register type `W` of `table`.
    pub fn step<W: CRCRegister + Into<u128> + TryFrom<u128>>(
        table: &RustTable<W>,
        register: u128,
        data: &[u8],
    ) -> u128 {
        // The register always holds a value of the table's register type.
        let mut value = W::try_from(register).unwrap_or(W::ZERO);
        for &byte in data {
            value = table.step(value, byte);
        }
        value.into()
    }

    /// The remainder and the CRC of `register` with `table`.
    pub fn output<W: CRCRegister + Into<u128> + TryFrom<u128>>(table: &RustTable<W>, register: u128) -> (u128, u128) {
        let remainder = table.remainder(W::try_from(register).unwrap_or(W::ZERO));
        (remainder.into(), (remainder ^ table.parameters().xor_output).into())
    }

    pub fn update(&mut self, data: &[u8]) {
        self.register = match &self.table {
            CRCTable::U8(table) => CRCState::step(table, self.register, data),
            CRCTable::U16(table) => CRCState::step(table, self.register, data),
            CRCTable::U32(table) => CRCState::step(table, self.register, data),
            CRCTable::U64(table) => CRCState::step(table, self.register, data),
            CRCTable::U128(table) => CRCState::step(table, self.register, data),
        };
    }

    /// The remainder and the CRC of the input so far.
    pub fn outputs(&self) -> (u128, u128) {
        match &self.table {
            CRCTable::U8(table) => CRCState::output(table, self.register),
            CRCTable::U16(table) => CRCState::output(table, self.register),
            CRCTable::U32(table) => CRCState::output(table, self.register),
            CRCTable::U64(table) => CRCState::output(table, self.register),
            CRCTable::U128(table) => CRCState::output(table, self.register),
        }
    }

    pub fn value(&self) -> u128 {
        self.outputs().1
    }

    pub fn remainder(&self) -> u128 {
        self.outputs().0
    }

    pub fn reset(&mut self) {
        *self = CRCState::new(&self.table);
    }
}

impl Value for CRCState {
    const TYPE: Type = Type::Named("umilib_hash_crc_CRC");
}

crate::ffi_functions! {
    /// Creates the table of `parameters`; fails unless the width is 1 to 128 and every value fits it.
    /// The table has an empty name.
    pub unsafe extern "C" fn umilib_hash_crc_crc_table_new(parameters: *const CRCParameters, out: *mut *mut CRCTable) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a readable structure and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            let table = CRCTable::new(parameters, "")?;
            unsafe { Pointer::write_handle(out, table) }
        })())
    }

    /// Creates a copy of the catalogue table named by the UTF-8 text at `name`, such as
    /// `CRC-32/ISO-HDLC`; fails with InvalidArgument if there is none.
    pub unsafe extern "C" fn umilib_hash_crc_crc_catalogue_find(name: *const u8, length: usize, out: *mut *mut CRCTable) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable pointer.
            let name = unsafe { Pointer::text(name, length) }?;
            let table = CRCTable::find(name).ok_or(&Status::INVALID_ARGUMENT)?;
            unsafe { Pointer::write_handle(out, table) }
        })())
    }

    /// Writes the names of the catalogue, each followed by a line feed, into `out`.
    pub unsafe extern "C" fn umilib_hash_crc_crc_catalogue_names(out: *mut Buffer) -> *const Status {
        let mut names = Vec::new();
        for name in CRCTable::catalogue_names() {
            names.extend_from_slice(name.as_bytes());
            names.push(b'\n');
        }
        // SAFETY: the caller passes a writable `umilib_ffi_Buffer`.
        Status::from_result(unsafe { Pointer::write(out, Buffer::from_vec(names)) })
    }

    /// Releases a table. Does nothing if `table` is null.
    pub unsafe extern "C" fn umilib_hash_crc_crc_table_free(table: *mut CRCTable) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(table) }
    }

    /// Writes a copy of `table` into `out`.
    pub unsafe extern "C" fn umilib_hash_crc_crc_table_clone(table: *const CRCTable, out: *mut *mut CRCTable) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write_handle(out, table.clone()) }
        })())
    }

    /// Writes the parameters of `table` into `out`.
    pub unsafe extern "C" fn umilib_hash_crc_crc_table_parameters(table: *const CRCTable, out: *mut CRCParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable structure.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write(out, table.parameters()) }
        })())
    }

    /// Writes the name of `table` as UTF-8 into `out`; empty for a table not from the catalogue.
    pub unsafe extern "C" fn umilib_hash_crc_crc_table_name(table: *const CRCTable, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable `umilib_ffi_Buffer`.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(Vec::from(table.name().as_bytes()))) }
        })())
    }

    /// Creates a computation over a copy of `table`, which may be released afterwards.
    pub unsafe extern "C" fn umilib_hash_crc_crc_new(table: *const CRCTable, out: *mut *mut CRCState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            unsafe { Pointer::write_handle(out, CRCState::new(table)) }
        })())
    }

    /// Writes the CRC of the `length` bytes at `data` with `table` into `out`.
    pub unsafe extern "C" fn umilib_hash_crc_crc_checksum(table: *const CRCTable, data: *const u8, length: usize, out: *mut U128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let table = unsafe { Pointer::reference(table) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            unsafe { Pointer::write(out, U128::from(table.checksum(data))) }
        })())
    }

    /// Releases a computation. Does nothing if `state` is null.
    pub unsafe extern "C" fn umilib_hash_crc_crc_free(state: *mut CRCState) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(state) }
    }

    /// Writes a copy of `state`, over the same table, into `out`.
    pub unsafe extern "C" fn umilib_hash_crc_crc_clone(state: *const CRCState, out: *mut *mut CRCState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write_handle(out, state.clone()) }
        })())
    }

    /// Adds the `length` bytes at `data` to the input.
    pub unsafe extern "C" fn umilib_hash_crc_crc_update(state: *mut CRCState, data: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let state = unsafe { Pointer::reference_mut(state) }?;
            state.update(unsafe { Pointer::slice(data, length) }?);
            Ok(())
        })())
    }

    /// Writes the CRC of the input so far into `out`.
    pub unsafe extern "C" fn umilib_hash_crc_crc_value(state: *const CRCState, out: *mut U128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(out, U128::from(state.value())) }
        })())
    }

    /// Writes the CRC of the input so far before the final xor into `out`: after an error-free
    /// codeword, the residue of the parameters.
    pub unsafe extern "C" fn umilib_hash_crc_crc_remainder(state: *const CRCState, out: *mut U128) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(out, U128::from(state.remainder())) }
        })())
    }

    /// Returns to the empty input.
    pub unsafe extern "C" fn umilib_hash_crc_crc_reset(state: *mut CRCState) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle.
            unsafe { Pointer::reference_mut(state) }?.reset();
            Ok(())
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "crc",
    definitions: &[
        Definition::Structure {
            name: "umilib_hash_crc_CRCParameters",
            documentation: " The parameters of a CRC in the Rocksoft model, with 128-bit values.",
            fields: &[
                Parameter { name: "width", value: <u32 as Value>::TYPE },
                Parameter { name: "polynomial", value: <U128 as Value>::TYPE },
                Parameter { name: "initial", value: <U128 as Value>::TYPE },
                Parameter { name: "reflect_input", value: <bool as Value>::TYPE },
                Parameter { name: "reflect_output", value: <bool as Value>::TYPE },
                Parameter { name: "xor_output", value: <U128 as Value>::TYPE },
                Parameter { name: "check", value: <U128 as Value>::TYPE },
                Parameter { name: "residue", value: <U128 as Value>::TYPE },
            ],
        },
        Definition::Opaque {
            name: "umilib_hash_crc_CRCTable",
            documentation: " The parameters of a CRC and its table, with any register size.",
        },
        Definition::Opaque {
            name: "umilib_hash_crc_CRC",
            documentation: " A CRC computation over its own copy of a table.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
