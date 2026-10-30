//! The C ABI of [`crate::codec::filter::bcj`]. Architectures are numbers,
//! their indices in [`BCJArchitecture::ALL`] ([`BCJArchitectureKind`]).

use crate::codec::filter::bcj::{BCJArchitecture, BCJFilter};
use crate::ffi::{Definition, Function, Module, Pointer, Status, ToStatus};

/// The numbers of [`BCJArchitecture`] in the C ABI.
pub struct BCJArchitectureKind;

impl BCJArchitectureKind {
    pub const X86: u8 = 0;
    pub const POWER_PC: u8 = 1;
    pub const IA64: u8 = 2;
    pub const ARM: u8 = 3;
    pub const ARM_THUMB: u8 = 4;
    pub const SPARC: u8 = 5;
    pub const ARM64: u8 = 6;
    pub const RISCV: u8 = 7;

    pub fn decode(kind: u8) -> Result<BCJArchitecture, &'static Status> {
        BCJArchitecture::ALL.get(kind as usize).copied().ok_or(&Status::INVALID_ARGUMENT)
    }

    pub fn encode(architecture: BCJArchitecture) -> u8 {
        BCJArchitecture::ALL.iter().position(|item| *item == architecture).expect("every architecture") as u8
    }
}

crate::ffi_functions! {
    const CONSTRUCTORS;

    /// Writes a new BCJ filter of `architecture` (0 x86, 1 PowerPC, 2 IA-64, 3 ARM, 4 ARM Thumb,
    /// 5 SPARC, 6 ARM64, 7 RISC-V) whose first byte is at `start_offset` (a multiple of the
    /// architecture's alignment) into `out`.
    pub unsafe extern "C" fn umilib_codec_filter_bcj_bcj_filter_new(architecture: u8, start_offset: u32, out: *mut *mut BCJFilter) -> *const Status {
        Status::from_result((|| {
            let architecture = BCJArchitectureKind::decode(architecture)?;
            let filter = BCJFilter::new(architecture, start_offset).map_err(|error| error.to_status())?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_handle(out, filter) }
        })())
    }

    /// Writes the alignment of `architecture` (as for `_bcj_filter_new`) into `out`.
    pub unsafe extern "C" fn umilib_codec_filter_bcj_bcj_architecture_alignment(architecture: u8, out: *mut u32) -> *const Status {
        Status::from_result((|| {
            let architecture = BCJArchitectureKind::decode(architecture)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, architecture.alignment()) }
        })())
    }

    /// Writes the architecture and the start offset of `state` into `architecture` and `start_offset`.
    pub unsafe extern "C" fn umilib_codec_filter_bcj_bcj_filter_parameters(state: *const BCJFilter, architecture: *mut u8, start_offset: *mut u32) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let state = unsafe { Pointer::reference(state) }?;
            unsafe { Pointer::write(architecture, BCJArchitectureKind::encode(state.architecture())) }?;
            unsafe { Pointer::write(start_offset, state.start_offset()) }
        })())
    }
}

crate::ffi_filter!(filter; BCJFilter, "umilib_codec_filter_bcj_bcj_filter", "umilib_codec_filter_bcj_BCJFilter");

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "bcj",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_filter_bcj_BCJFilter",
        documentation: " A branch/call/jump filter of one architecture (.xz format specification, section 5.3.2).",
    }],
    functions: &Function::concat::<{ CONSTRUCTORS.len() + filter::FUNCTIONS.len() }>(&[
        CONSTRUCTORS,
        filter::FUNCTIONS,
    ]),
    modules: &[],
};
