//! The C ABI of [`crate::codec::stringprep`].
//!
//! Text is UTF-8 and code points are `uint32_t`. Normalization forms,
//! tables, the handling of unassigned code points, LDAP matching rules and
//! LDAP string kinds are the codes of [`NormalizationFormKind`],
//! [`StringPrepTableKind`], [`UnassignedKind`], [`LDAPMatchingKind`] and
//! [`LDAPStringKind`]. Profiles are handles.

use crate::codec::stringprep::{
    LDAPMatching, LDAPPrep, LDAPString, NormalizationForm, StringPrepError, StringPrepProfile, StringPrepTable,
    Unassigned,
};
use crate::ffi::{Buffer, Definition, Module, Pointer, Status, ToStatus, Type, Value};

/// The statuses of [`StringPrepError`], one per variant.
pub struct StringPrepStatus;

impl StringPrepStatus {
    pub const PROHIBITED: Status =
        Status::new(c"codec.stringprep", c"Prohibited", c"a code point the profile prohibits");
    pub const UNASSIGNED: Status =
        Status::new(c"codec.stringprep", c"Unassigned", c"a code point unassigned in Unicode 3.2");
    pub const BIDI: Status =
        Status::new(c"codec.stringprep", c"Bidi", c"right-to-left text that breaks the rules of RFC 3454 section 6");

    /// The character of the code point `point`.
    pub fn character(point: u32) -> Result<char, &'static Status> {
        char::from_u32(point).ok_or(&Status::INVALID_ARGUMENT)
    }
}

impl ToStatus for StringPrepError {
    fn to_status(&self) -> &'static Status {
        match self {
            StringPrepError::Prohibited(_) => &StringPrepStatus::PROHIBITED,
            StringPrepError::Unassigned(_) => &StringPrepStatus::UNASSIGNED,
            StringPrepError::Bidi => &StringPrepStatus::BIDI,
        }
    }
}

/// The [`NormalizationForm`] values of the C ABI.
pub struct NormalizationFormKind;

impl NormalizationFormKind {
    pub const NFD: u8 = 0;
    pub const NFC: u8 = 1;
    pub const NFKD: u8 = 2;
    pub const NFKC: u8 = 3;

    pub fn decode(kind: u8) -> Result<NormalizationForm, &'static Status> {
        match kind {
            NormalizationFormKind::NFD => Ok(NormalizationForm::NFD),
            NormalizationFormKind::NFC => Ok(NormalizationForm::NFC),
            NormalizationFormKind::NFKD => Ok(NormalizationForm::NFKD),
            NormalizationFormKind::NFKC => Ok(NormalizationForm::NFKC),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// The [`StringPrepTable`] values of the C ABI: the tables of RFC 3454 in
/// the order of the RFC, A.1 being 0 and D.2 being 16.
pub struct StringPrepTableKind;

impl StringPrepTableKind {
    pub const TABLES: [StringPrepTable; 17] = [
        StringPrepTable::A1,
        StringPrepTable::B1,
        StringPrepTable::B2,
        StringPrepTable::B3,
        StringPrepTable::C11,
        StringPrepTable::C12,
        StringPrepTable::C21,
        StringPrepTable::C22,
        StringPrepTable::C3,
        StringPrepTable::C4,
        StringPrepTable::C5,
        StringPrepTable::C6,
        StringPrepTable::C7,
        StringPrepTable::C8,
        StringPrepTable::C9,
        StringPrepTable::D1,
        StringPrepTable::D2,
    ];

    pub fn decode(kind: u8) -> Result<StringPrepTable, &'static Status> {
        StringPrepTableKind::TABLES.get(kind as usize).copied().ok_or(&Status::INVALID_ARGUMENT)
    }
}

/// The [`Unassigned`] values of the C ABI.
pub struct UnassignedKind;

impl UnassignedKind {
    pub const ALLOWED: u8 = 0;
    pub const PROHIBITED: u8 = 1;

    pub fn decode(kind: u8) -> Result<Unassigned, &'static Status> {
        match kind {
            UnassignedKind::ALLOWED => Ok(Unassigned::Allowed),
            UnassignedKind::PROHIBITED => Ok(Unassigned::Prohibited),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// The [`LDAPMatching`] values of the C ABI.
pub struct LDAPMatchingKind;

impl LDAPMatchingKind {
    pub const CASE_IGNORE: u8 = 0;
    pub const EXACT: u8 = 1;
    pub const NUMERIC: u8 = 2;
    pub const TELEPHONE_NUMBER: u8 = 3;

    pub fn decode(kind: u8) -> Result<LDAPMatching, &'static Status> {
        match kind {
            LDAPMatchingKind::CASE_IGNORE => Ok(LDAPMatching::CaseIgnore),
            LDAPMatchingKind::EXACT => Ok(LDAPMatching::Exact),
            LDAPMatchingKind::NUMERIC => Ok(LDAPMatching::Numeric),
            LDAPMatchingKind::TELEPHONE_NUMBER => Ok(LDAPMatching::TelephoneNumber),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

/// The [`LDAPString`] values of the C ABI.
pub struct LDAPStringKind;

impl LDAPStringKind {
    pub const VALUE: u8 = 0;
    pub const INITIAL_SUBSTRING: u8 = 1;
    pub const ANY_SUBSTRING: u8 = 2;
    pub const FINAL_SUBSTRING: u8 = 3;

    pub fn decode(kind: u8) -> Result<LDAPString, &'static Status> {
        match kind {
            LDAPStringKind::VALUE => Ok(LDAPString::Value),
            LDAPStringKind::INITIAL_SUBSTRING => Ok(LDAPString::InitialSubstring),
            LDAPStringKind::ANY_SUBSTRING => Ok(LDAPString::AnySubstring),
            LDAPStringKind::FINAL_SUBSTRING => Ok(LDAPString::FinalSubstring),
            _ => Err(&Status::INVALID_ARGUMENT),
        }
    }
}

impl Value for StringPrepProfile {
    const TYPE: Type = Type::Named("umilib_codec_stringprep_StringPrepProfile");
}

crate::ffi_functions! {
    const FUNCTIONS;

    /// Writes `text` (`length` bytes) in the normalization form `form` of Unicode 3.2 into `out`.
    pub unsafe extern "C" fn umilib_codec_stringprep_normalization_form_normalize(form: u8, text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let form = NormalizationFormKind::decode(form)?;
            // SAFETY: the caller passes readable text and a writable buffer.
            let text = unsafe { Pointer::text(text, length) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(form.normalize(text).into_bytes())) }
        })())
    }

    /// Writes the canonical combining class of the code point `character` in Unicode 3.2 into `out`.
    pub unsafe extern "C" fn umilib_codec_stringprep_normalization_form_combining_class(character: u32, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            let character = StringPrepStatus::character(character)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, NormalizationForm::combining_class(character)) }
        })())
    }

    /// Writes whether the table `table` has the code point `character` into `out`.
    pub unsafe extern "C" fn umilib_codec_stringprep_string_prep_table_contains(table: u8, character: u32, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            let table = StringPrepTableKind::decode(table)?;
            let character = StringPrepStatus::character(character)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write(out, table.contains(character)) }
        })())
    }

    /// Writes whether the mapping table `table` (B.1, B.2 or B.3) maps the code point `character`
    /// into `out_mapped` and, if it does, the UTF-8 text it maps it to into `out` (empty otherwise).
    pub unsafe extern "C" fn umilib_codec_stringprep_string_prep_table_mapping(table: u8, character: u32, out_mapped: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            if out_mapped.is_null() || out.is_null() {
                return Err(&Status::NULL_POINTER);
            }
            let table = StringPrepTableKind::decode(table)?;
            let character = StringPrepStatus::character(character)?;
            let mapping = table.mapping(character);
            // SAFETY: the caller passes writable pointers.
            unsafe { Pointer::write(out_mapped, mapping.is_some()) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(mapping.unwrap_or_default().as_bytes().to_vec())) }
        })())
    }

    /// Writes the SASLprep profile (RFC 4013) into `out`.
    pub unsafe extern "C" fn umilib_codec_stringprep_string_prep_profile_saslprep(out: *mut *mut StringPrepProfile) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, StringPrepProfile::SASLPREP) })
    }

    /// Writes the "trace" profile of SASL ANONYMOUS (RFC 4505 §3) into `out`.
    pub unsafe extern "C" fn umilib_codec_stringprep_string_prep_profile_trace(out: *mut *mut StringPrepProfile) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, StringPrepProfile::TRACE) })
    }

    /// Writes `text` (`length` bytes) prepared by `profile` into `out`; `unassigned` says whether
    /// unassigned code points are allowed (a query) or prohibited (a stored string).
    pub unsafe extern "C" fn umilib_codec_stringprep_string_prep_profile_prepare(profile: *const StringPrepProfile, text: *const u8, length: usize, unassigned: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable text and a writable buffer.
            let profile = unsafe { Pointer::reference(profile) }?;
            let text = unsafe { Pointer::text(text, length) }?;
            let unassigned = UnassignedKind::decode(unassigned)?;
            let prepared = profile.prepare(text, unassigned).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(prepared.into_bytes())) }
        })())
    }

    /// Succeeds if `text` (`length` bytes) follows the rules of bidirectional text of RFC 3454 section 6.
    pub unsafe extern "C" fn umilib_codec_stringprep_string_prep_profile_check_bidi(text: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text.
            let text = unsafe { Pointer::text(text, length) }?;
            StringPrepProfile::check_bidi(text).map_err(|error| error.to_status())
        })())
    }

    /// Releases a profile. Does nothing if `profile` is null.
    pub unsafe extern "C" fn umilib_codec_stringprep_string_prep_profile_free(profile: *mut StringPrepProfile) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(profile) }
    }

    /// Writes `text` (`length` bytes) prepared by LDAPPrep (RFC 4518) for the matching rule
    /// `matching` as the kind of string `kind` into `out`.
    pub unsafe extern "C" fn umilib_codec_stringprep_ldap_prep_prepare(text: *const u8, length: usize, matching: u8, kind: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text and a writable buffer.
            let text = unsafe { Pointer::text(text, length) }?;
            let matching = LDAPMatchingKind::decode(matching)?;
            let kind = LDAPStringKind::decode(kind)?;
            let prepared = LDAPPrep::prepare(text, matching, kind).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(prepared.into_bytes())) }
        })())
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "stringprep",
    definitions: &[Definition::Opaque {
        name: "umilib_codec_stringprep_StringPrepProfile",
        documentation: " A profile of stringprep (RFC 3454).",
    }],
    functions: FUNCTIONS,
    modules: &[],
};
