"""String preparation (stringprep, RFC 3454) and its profiles. Mirrors ``umilib::codec::stringprep``.

The repertoire is Unicode 3.2, the version stringprep is defined with:
:class:`NormalizationForm` normalizes as Unicode 3.2 does, which differs from
:mod:`unicodedata` for code points assigned later. Profiles are
:class:`StringPrepProfile` handles (SASLprep, RFC 4013); :class:`LDAPPrep`
prepares strings for the matching rules of LDAP (RFC 4518). Errors are
:class:`StringPrepError`.
"""

from __future__ import annotations

import ctypes
import enum

from umilib.ffi import Buffer, FFIError, Handle, Library, Preset, Text


class StringPrepError(FFIError):
    """A string that cannot be prepared: ``Prohibited``, ``Unassigned`` or ``Bidi``."""


Library.register_error("codec.stringprep", StringPrepError)


class NormalizationForm(enum.IntEnum):
    """A normalization form of Unicode 3.2."""

    NFD = 0
    NFC = 1
    NFKD = 2
    NFKC = 3

    def normalize(self, text: str) -> str:
        return Library.default().output("umilib_codec_stringprep_normalization_form_normalize", int(self), *Text.encode(text)).decode("utf-8")

    @staticmethod
    def combining_class(character: str) -> int:
        """The canonical combining class of the code point ``character`` in Unicode 3.2."""
        return Library.default().value("umilib_codec_stringprep_normalization_form_combining_class", ctypes.c_uint8, ord(character))


class StringPrepTable(enum.IntEnum):
    """A table of RFC 3454: a set of code points (A.1, C.*, D.*) or a mapping (B.1, B.2, B.3)."""

    A1 = 0
    B1 = 1
    B2 = 2
    B3 = 3
    C11 = 4
    C12 = 5
    C21 = 6
    C22 = 7
    C3 = 8
    C4 = 9
    C5 = 10
    C6 = 11
    C7 = 12
    C8 = 13
    C9 = 14
    D1 = 15
    D2 = 16

    def contains(self, character: str) -> bool:
        return Library.default().value("umilib_codec_stringprep_string_prep_table_contains", ctypes.c_bool, int(self), ord(character))

    def mapping(self, character: str) -> str | None:
        """What the mapping table maps ``character`` to, or ``None`` if it does not map it."""
        mapped = Library.default().optional("umilib_codec_stringprep_string_prep_table_mapping", Buffer, int(self), ord(character))
        return None if mapped is None else mapped.decode("utf-8")


class Unassigned(enum.IntEnum):
    """Whether a string may hold code points unassigned in Unicode 3.2 (RFC 3454 §7)."""

    Allowed = 0
    Prohibited = 1


class StringPrepProfile(Handle):
    """A profile of stringprep: its mappings, normalization, prohibited tables and bidirectional check."""

    FREE = "umilib_codec_stringprep_string_prep_profile_free"
    SASLPREP = Preset(lambda: StringPrepProfile(Handle.create("umilib_codec_stringprep_string_prep_profile_saslprep")))
    #: The "trace" profile of SASL ANONYMOUS (RFC 4505 section 3).
    TRACE = Preset(lambda: StringPrepProfile(Handle.create("umilib_codec_stringprep_string_prep_profile_trace")))

    def prepare(self, text: str, unassigned: Unassigned) -> str:
        """``text`` prepared; ``Unassigned.Allowed`` for a query, ``Unassigned.Prohibited`` for a stored string."""
        return self.library.output("umilib_codec_stringprep_string_prep_profile_prepare", self.handle, *Text.encode(text), int(unassigned)).decode("utf-8")

    @staticmethod
    def check_bidi(text: str) -> None:
        """Returns if ``text`` follows the rules of bidirectional text of RFC 3454 §6; raises ``Bidi`` otherwise."""
        Library.default().call("umilib_codec_stringprep_string_prep_profile_check_bidi", *Text.encode(text))


class LDAPMatching(enum.IntEnum):
    """The matching rule a string is prepared for (RFC 4518 §2.2, §2.6)."""

    CaseIgnore = 0
    Exact = 1
    Numeric = 2
    TelephoneNumber = 3


class LDAPString(enum.IntEnum):
    """What a prepared string is: a value, or a part of a substring assertion (RFC 4518 §2.6.1)."""

    Value = 0
    InitialSubstring = 1
    AnySubstring = 2
    FinalSubstring = 3


class LDAPPrep:
    """The string preparation of LDAP (RFC 4518), which makes distinguished names comparable (RFC 5280 §7.1)."""

    @staticmethod
    def prepare(text: str, matching: LDAPMatching, kind: LDAPString) -> str:
        return Library.default().output("umilib_codec_stringprep_ldap_prep_prepare", *Text.encode(text), int(matching), int(kind)).decode("utf-8")


__all__ = [
    "LDAPMatching",
    "LDAPPrep",
    "LDAPString",
    "NormalizationForm",
    "StringPrepError",
    "StringPrepProfile",
    "StringPrepTable",
    "Unassigned",
]
