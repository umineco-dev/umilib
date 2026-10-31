"""Tests of umilib.auth.totp: HOTP and TOTP against the values of RFC 4226 and RFC 6238."""

import pytest

from umilib.auth.totp import HOTP, TOTP, OTPCode, OTPStatusError, TOTPConfig
from umilib.hash.md.v5 import MD5
from umilib.hash.sha.v1 import SHA1
from umilib.hash.sha.v2 import SHA256, SHA512


def secret(length):
    """The secret of the RFCs, "1234567890" repeated to ``length`` bytes."""
    return (b"1234567890" * 7)[:length]


def test_rfc4226_appendix_d():
    hotp = HOTP[SHA1](secret(20))
    expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [hotp.generate(count) for count in range(10)] == expected
    assert HOTP[SHA1](secret(20), 10).generate(0) == "1284755224"
    assert hotp.verify("254676", 3, 2) == 5
    assert hotp.verify(b"254676", 3, 1) is None


def test_rfc6238_appendix_b():
    config = TOTPConfig(digits=8)
    rows = [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ]
    generators = [TOTP[SHA1](secret(20), config), TOTP[SHA256](secret(32), config), TOTP[SHA512](secret(64), config)]
    for time, *passwords in rows:
        assert [totp.generate(time) for totp in generators] == passwords
    assert generators[0].counter(1111111109) == 0x23523EC
    assert generators[0].verify("07081804", 1111111111, behind=1, ahead=0) == 0x23523EC
    assert generators[0].verify("07081804", 1111111111, behind=0, ahead=0) is None


def test_digits():
    # RFC 4226 R4 and §5.3: 6 to 10 digits.
    assert (OTPCode.MINIMUM_DIGITS, OTPCode.MAXIMUM_DIGITS) == (6, 10)


def test_errors():
    for make, name in [
        (lambda: HOTP[SHA1](b"short"), "KeyTooShort"),
        (lambda: HOTP[SHA1](secret(20), 5), "Digits"),
        (lambda: HOTP[MD5](secret(20)), "Hash"),
        (lambda: TOTP[SHA1](secret(20), TOTPConfig(period=0)), "Period"),
        (lambda: TOTP[SHA1](secret(20), TOTPConfig(origin=1000)).generate(999), "Time"),
    ]:
        with pytest.raises(OTPStatusError) as error:
            make()
        assert error.value.name == name
    with pytest.raises(TypeError):
        HOTP[int]
    with pytest.raises(TypeError):
        HOTP(secret(20))
