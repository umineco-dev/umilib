"""Tests of umilib.math against Python's own integers, which serve as an independent oracle."""

import random
import re
import threading
from pathlib import Path

import pytest

from umilib.math.bigint import BoxedUint, MathError
from umilib.math.modular import BoxedModulus, BoxedResidue
from umilib.secret import Choice

RFC3526 = (Path(__file__).resolve().parents[3] / "tests" / "vectors" / "math" / "modular" / "rfc3526.txt").read_text()
PRECISIONS = [64, 128, 192, 256, 384, 521, 1024, 2048, 4096]


def value(generator: random.Random, bits: int) -> int:
    """A random value of up to ``bits`` bits, often at a boundary."""
    choice = generator.randrange(8)
    if choice == 0:
        return 0
    if choice == 1:
        return (1 << bits) - 1
    if choice == 2:
        return 1 << generator.randrange(bits)
    return generator.getrandbits(bits) >> generator.randrange(bits)


def rounded(precision: int) -> int:
    return max(64, -(-precision // 64) * 64)


def test_precision_constants_and_rounding():
    assert BoxedUint.PRECISION_UNIT == 64
    assert BoxedUint.MAXIMUM_PRECISION == 1 << 30
    for precision in [0, 1, 64, 65, 521, 2048]:
        assert BoxedUint.zero(precision).precision() == rounded(precision)
        assert BoxedUint.zero(precision).bytes() == rounded(precision) // 8
    with pytest.raises(MathError) as error:
        BoxedUint.zero(BoxedUint.MAXIMUM_PRECISION + 1)
    assert error.value.name == "InvalidPrecision"


def test_arithmetic_matches_python_integers():
    generator = random.Random(1)
    for precision in PRECISIONS:
        bits = rounded(precision)
        mask = (1 << bits) - 1
        for _ in range(60):
            a, b = value(generator, bits), value(generator, bits)
            x, y = BoxedUint.from_int(a, precision), BoxedUint.from_int(b, precision)
            assert int(x) == a
            total, carry = x.overflowing_add(y)
            assert (int(total), carry.into_bool()) == ((a + b) & mask, a + b > mask)
            difference, borrow = x.overflowing_sub(y)
            assert (int(difference), borrow.into_bool()) == ((a - b) & mask, a < b)
            low, high = x.widening_mul(y)
            assert int(low) | (int(high) << bits) == a * b
            assert int(x.wrapping_mul(y)) == (a * b) & mask
            if b == 0:
                with pytest.raises(MathError) as error:
                    x.div_rem(y)
                assert error.value.name == "DivisionByZero"
            else:
                quotient, remainder = x.div_rem(y)
                assert (int(quotient), int(remainder)) == (a // b, a % b)
                m = BoxedUint.from_int(odd_modulus(generator, bits), precision)
                assert int(BoxedUint.rem_wide(x, y, m)) == (a + (b << bits)) % int(m)
            assert x.ct_lt(y).into_bool() == (a < b)
            assert x.ct_gt(y).into_bool() == (a > b)
            assert (x == y) == (a == b)
            assert x.compare_vartime(y) == (a > b) - (a < b)
            assert x.bit_length() == a.bit_length()
            assert x.is_zero().into_bool() == (a == 0)
            assert x.is_odd().into_bool() == (a % 2 == 1)
            assert int(x & y) == a & b and int(x | y) == a | b and int(x ^ y) == a ^ b
            assert int(~x) == ~a & mask
            shift = generator.randrange(bits + 20)
            assert int(x.shl(shift)) == (a << shift) & mask
            assert int(x.shr(shift)) == a >> shift
            index = generator.randrange(bits + 8)
            assert x.bit(index).into_bool() == bool((a >> index) & 1)


def test_mixed_precisions_are_zero_extended():
    small, large = BoxedUint.from_int(2**64 - 1, 64), BoxedUint.from_int(1, 256)
    total, carry = small.overflowing_add(large)
    assert (total.precision(), int(total), carry.into_bool()) == (256, 2**64, False)
    assert BoxedUint.from_int(5, 64) == BoxedUint.from_int(5, 512)
    quotient, remainder = large.div_rem(BoxedUint.from_int(3, 64))
    assert (quotient.precision(), remainder.precision()) == (256, 64)


def test_bytes_and_text():
    generator = random.Random(2)
    for precision in PRECISIONS:
        bits = rounded(precision)
        a = value(generator, bits)
        x = BoxedUint.from_int(a, precision)
        assert x.to_be_bytes() == a.to_bytes(bits // 8, "big")
        assert x.to_le_bytes() == a.to_bytes(bits // 8, "little")
        assert BoxedUint.from_le_bytes(x.to_le_bytes(), precision) == x
        assert format(x, "x") == f"{a:0{bits // 4}x}"
        assert format(x, "X") == f"{a:0{bits // 4}X}"
        assert BoxedUint.from_hex_vartime(f"{a:x}", precision) == x
        out = bytearray(bits // 8 + 3)
        x.write_be_bytes(out)
        assert bytes(out) == a.to_bytes(len(out), "big")
    with pytest.raises(MathError) as error:
        BoxedUint.from_be_bytes(b"\x01" * 9, 64)
    assert error.value.name == "Overflow"
    with pytest.raises(MathError) as error:
        BoxedUint.from_hex_vartime("12g", 64)
    assert error.value.name == "InvalidDigit"
    with pytest.raises(MathError):
        BoxedUint.from_int(-1, 64)
    out = bytearray(1)
    with pytest.raises(MathError):
        BoxedUint.from_int(256, 64).write_be_bytes(out)
    assert repr(BoxedUint.one(64)) == "BoxedUint(0x0000000000000001)"
    assert int(BoxedUint.from_u64(7, 64).resize(128)) == 7


def test_conditional_selection_and_zeroization():
    a, b = BoxedUint.from_int(1, 64), BoxedUint.from_int(2, 64)
    BoxedUint.conditional_swap(a, b, Choice.TRUE)
    assert (int(a), int(b)) == (2, 1)
    a.conditional_assign(b, Choice.FALSE)
    assert int(a) == 2
    a.conditional_assign(a, Choice.TRUE)
    assert int(a) == 2
    with pytest.raises(MathError) as error:
        a.conditional_assign(BoxedUint.zero(128), Choice.TRUE)
    assert error.value.name == "SizeMismatch"
    a.zeroize()
    assert int(a) == 0 and a.precision() == 64


def odd_modulus(generator: random.Random, bits: int) -> int:
    return max(3, value(generator, bits) | 1)


def test_modular_arithmetic_matches_python_integers():
    generator = random.Random(3)
    for precision in PRECISIONS:
        bits = rounded(precision)
        for _ in range(12):
            m = odd_modulus(generator, bits)
            field = BoxedModulus(BoxedUint.from_int(m, precision))
            a, b = value(generator, bits), value(generator, bits)
            x, y = field.residue(BoxedUint.from_int(a, precision)), field.residue(BoxedUint.from_int(b, precision))
            assert int(field.retrieve(x)) == a % m
            assert int(field.retrieve(field.add(x, y))) == (a + b) % m
            assert int(field.retrieve(field.sub(x, y))) == (a - b) % m
            assert int(field.retrieve(field.neg(x))) == -a % m
            assert int(field.retrieve(field.mul(x, y))) == a * b % m
            assert int(field.retrieve(field.square(x))) == a * a % m
            exponent = value(generator, min(bits, 512))
            power = field.pow(x, BoxedUint.from_int(exponent, min(bits, 512)))
            assert int(field.retrieve(power)) == pow(a, exponent, m)
            assert field.pow_vartime(x, BoxedUint.from_int(exponent, 1024)) == power
            try:
                expected = pow(a, -1, m)
            except ValueError:
                with pytest.raises(MathError) as error:
                    field.invert(x)
                assert error.value.name == "NotInvertible"
            else:
                assert int(field.retrieve(field.invert(x))) == expected
            # The Montgomery form is x * R mod m with R = 2^precision.
            assert int(x.as_montgomery()) == a * (1 << bits) % m
            assert field.from_montgomery(x.as_montgomery()) == x


def test_residues_of_large_values_and_errors():
    field = BoxedModulus(BoxedUint.from_int(1_000_003, 64))
    large = 2**500 + 12345
    assert int(field.retrieve(field.residue(BoxedUint.from_int(large, 512)))) == large % 1_000_003
    for invalid in [0, 1, 2, 10]:
        with pytest.raises(MathError) as error:
            BoxedModulus(BoxedUint.from_int(invalid, 64))
        assert error.value.name == "InvalidModulus"
    other = BoxedModulus(BoxedUint.from_int(1_000_003, 128))
    with pytest.raises(MathError) as error:
        other.mul(field.one(), other.one())
    assert error.value.name == "SizeMismatch"
    with pytest.raises(MathError) as error:
        field.from_montgomery(BoxedUint.from_int(1_000_003, 64))
    assert error.value.name == "Overflow"
    assert field.clone() == field and field.value() == BoxedUint.from_int(1_000_003, 64)
    unchecked = BoxedResidue.from_montgomery_unchecked(BoxedUint.from_int(5, 128))
    with pytest.raises(MathError):
        field.check(unchecked)


def test_modp_groups_of_rfc3526():
    primes = [int(re.sub(r"\s", "", match), 16) for match in re.findall(r"hexadecimal value is:\n\n((?:\s+[0-9A-F ]+\n)+)", RFC3526)]
    assert [prime.bit_length() for prime in primes] == [1536, 2048, 3072, 4096, 6144, 8192]
    generator = random.Random(4)
    for prime in primes[:4]:
        bits = prime.bit_length()
        field = BoxedModulus(BoxedUint.from_int(prime, bits))
        two = field.residue(BoxedUint.from_int(2, 64))
        exponent = generator.getrandbits(bits)
        power = field.pow(two, BoxedUint.from_int(exponent, bits))
        assert int(field.retrieve(power)) == pow(2, exponent, prime)
        assert field.pow(two, BoxedUint.from_int((prime - 1) // 2, bits)) == field.one()


def test_residues_select_without_branching():
    field = BoxedModulus(BoxedUint.from_int(101, 64))
    a, b = field.residue(BoxedUint.from_int(3, 64)), field.one()
    BoxedResidue.conditional_swap(a, b, Choice.TRUE)
    assert a == field.one() and int(field.retrieve(b)) == 3
    a.conditional_assign(b, Choice.TRUE)
    assert int(field.retrieve(a)) == 3
    with pytest.raises(MathError) as error:
        a.conditional_assign(BoxedModulus(BoxedUint.from_int(101, 128)).one(), Choice.TRUE)
    assert error.value.name == "SizeMismatch"


def test_data_independent_timing_is_held_by_a_block():
    from umilib.secret import DataIndependentTiming

    before = DataIndependentTiming.is_enabled()
    with DataIndependentTiming():
        assert DataIndependentTiming.is_enabled() == DataIndependentTiming.AVAILABLE
        with DataIndependentTiming():
            assert DataIndependentTiming.is_enabled() == DataIndependentTiming.AVAILABLE
    assert DataIndependentTiming.is_enabled() == before


def test_mutations_from_threads_are_serialized():
    # Swapping two values back and forth from many threads keeps them a pair
    # of the original values: every call holds both objects.
    a, b = BoxedUint.from_int(1, 2048), BoxedUint.from_int(2, 2048)

    def work() -> None:
        for _ in range(300):
            BoxedUint.conditional_swap(a, b, Choice.TRUE)
            assert {int(a), int(b)} <= {1, 2}

    threads = [threading.Thread(target=work) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted([int(a), int(b)]) == [1, 2]


def test_values_can_be_shared_between_threads():
    field = BoxedModulus(BoxedUint.from_int(2**127 - 1, 128))
    base = field.residue(BoxedUint.from_int(3, 64))
    exponent = BoxedUint.from_int(2**126, 128)
    results: list[BoxedResidue] = []

    def work() -> None:
        for _ in range(20):
            results.append(field.pow(base, exponent))

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    expected = pow(3, 2**126, 2**127 - 1)
    assert all(int(field.retrieve(result)) == expected for result in results)
