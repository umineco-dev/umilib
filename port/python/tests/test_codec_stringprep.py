"""Tests of umilib.codec.stringprep against RFC 3454, RFC 4013 (SASLprep) and RFC 4518 (LDAPPrep)."""

import pytest

from umilib.codec.stringprep import (
    LDAPMatching,
    LDAPPrep,
    LDAPString,
    NormalizationForm,
    StringPrepError,
    StringPrepProfile,
    StringPrepTable,
    Unassigned,
)


def test_saslprep_examples_of_rfc_4013_section_3():
    saslprep = StringPrepProfile.SASLPREP
    assert saslprep.prepare("I­X", Unassigned.Prohibited) == "IX"  # SOFT HYPHEN mapped to nothing
    assert saslprep.prepare("user", Unassigned.Prohibited) == "user"
    assert saslprep.prepare("USER", Unassigned.Prohibited) == "USER"  # case preserved
    assert saslprep.prepare("ª", Unassigned.Prohibited) == "a"  # NFKC
    assert saslprep.prepare("Ⅸ", Unassigned.Prohibited) == "IX"  # NFKC
    with pytest.raises(StringPrepError) as error:
        saslprep.prepare("\u0007", Unassigned.Prohibited)  # prohibited character
    assert error.value.name == "Prohibited"
    with pytest.raises(StringPrepError) as error:
        saslprep.prepare("ا1", Unassigned.Prohibited)  # bidi check
    assert error.value.name == "Bidi"


def test_saslprep_maps_non_ascii_spaces_and_handles_unassigned_code_points():
    saslprep = StringPrepProfile.SASLPREP
    # RFC 4013 §2.1: non-ASCII spaces (C.1.2) map to SPACE.
    assert saslprep.prepare("a b　c", Unassigned.Prohibited) == "a b c"
    # RFC 3454 §7: unassigned code points are allowed in queries, prohibited in stored strings. U+0221 was unassigned in Unicode 3.2.
    assert saslprep.prepare("ȡ", Unassigned.Allowed) == "ȡ"
    with pytest.raises(StringPrepError) as error:
        saslprep.prepare("ȡ", Unassigned.Prohibited)
    assert error.value.name == "Unassigned"
    StringPrepProfile.check_bidi("اب")
    with pytest.raises(StringPrepError):
        StringPrepProfile.check_bidi("اaب")  # RandALCat and LCat together (RFC 3454 §6)


def test_tables_of_rfc_3454():
    assert StringPrepTable.C11.contains(" ")
    assert StringPrepTable.C12.contains(" ")
    assert not StringPrepTable.C12.contains(" ")
    assert StringPrepTable.C21.contains("\u007f")
    assert StringPrepTable.C3.contains("")
    assert StringPrepTable.D1.contains("א")
    assert StringPrepTable.D2.contains("a")
    assert StringPrepTable.A1.contains("ȡ")
    assert StringPrepTable.B1.mapping("­") == ""
    assert StringPrepTable.B2.mapping("A") == "a"
    assert StringPrepTable.B2.mapping("ß") == "ss"
    assert StringPrepTable.B3.mapping("a") is None


def test_normalization_of_unicode_3_2():
    assert NormalizationForm.NFD.normalize("é") == "é"
    assert NormalizationForm.NFC.normalize("é") == "é"
    assert NormalizationForm.NFKD.normalize("ﬁ") == "fi"
    assert NormalizationForm.NFKC.normalize("Ⅸ") == "IX"
    assert NormalizationForm.NFC.normalize("각") == "각"  # Hangul composition
    assert NormalizationForm.combining_class("́") == 230
    assert NormalizationForm.combining_class("a") == 0


def test_ldapprep_of_rfc_4518():
    value = LDAPString.Value
    # §2.6.1: a value becomes a space, its words separated by two spaces, and a space.
    assert LDAPPrep.prepare("  Foo   Bar ", LDAPMatching.CaseIgnore, value) == " foo  bar "
    assert LDAPPrep.prepare("Foo Bar", LDAPMatching.Exact, value) == " Foo  Bar "
    assert LDAPPrep.prepare("", LDAPMatching.CaseIgnore, value) == "  "
    assert LDAPPrep.prepare("   ", LDAPMatching.CaseIgnore, value) == "  "
    # §2.6.2 and §2.6.3: numeric strings lose every space, telephone numbers every space and hyphen.
    assert LDAPPrep.prepare(" 1 2 3 ", LDAPMatching.Numeric, value) == "123"
    assert LDAPPrep.prepare("+1 555-0100", LDAPMatching.TelephoneNumber, value) == "+15550100"
    # §2.2: SOFT HYPHEN is mapped to nothing, and §2.4: prohibited characters fail.
    assert LDAPPrep.prepare("Co­op", LDAPMatching.CaseIgnore, value) == " coop "
    with pytest.raises(StringPrepError):
        LDAPPrep.prepare("", LDAPMatching.CaseIgnore, value)
