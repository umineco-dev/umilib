//! HOTP (RFC 4226) and TOTP (RFC 6238) against the test values of their RFCs.

use umilib::auth::totp::{HOTP, OTPCode, OTPError, TOTP, TOTPConfig};
use umilib::hash::sha::v1::SHA1;
use umilib::hash::sha::v2::{SHA256, SHA512};

const RFC4226: &str = include_str!("../vectors/auth/totp/rfc4226.txt");
const RFC6238: &str = include_str!("../vectors/auth/totp/rfc6238.txt");

/// The secret of the RFCs, "12345678901234567890" repeated to `length` bytes
/// (RFC 6238 appendix A uses 20, 32 and 64 bytes for SHA-1, SHA-256 and SHA-512).
fn secret(length: usize) -> Vec<u8> {
    b"1234567890".iter().copied().cycle().take(length).collect()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap()).collect()
}

/// The rows of the table of RFC 4226 appendix D that follows `header`, split into words.
fn rfc4226_table(header: &str) -> Vec<Vec<&'static str>> {
    let start = RFC4226.find(header).unwrap_or_else(|| panic!("{header} in RFC 4226"));
    let rows: Vec<Vec<&str>> = RFC4226[start + header.len()..]
        .lines()
        .skip(1)
        .take_while(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), 10, "{header}: the counts 0 to 9");
    rows
}

#[test]
fn rfc4226_appendix_d() {
    let hotp = HOTP::<SHA1>::new(&secret(20), 6).unwrap();
    let hmacs = rfc4226_table("Count    Hexadecimal HMAC-SHA-1(secret, count)");
    let values = rfc4226_table("Count    Hexadecimal    Decimal        HOTP");
    for (count, (hmac, value)) in hmacs.iter().zip(&values).enumerate() {
        assert_eq!(hmac[0].parse::<usize>().unwrap(), count);
        assert_eq!(value[0].parse::<usize>().unwrap(), count);
        let truncated: u32 = value[2].parse().unwrap();
        assert_eq!(u32::from_str_radix(value[1], 16).unwrap(), truncated);
        assert_eq!(HOTP::<SHA1>::truncate(&hex(hmac[1])), Some(truncated), "count {count}");
        let code = hotp.generate(count as u64);
        assert_eq!(code.to_string(), value[3], "count {count}");
        assert_eq!(code.digits(), 6);
        // With 10 digits the password is the whole truncated value (below 2^31).
        let ten = HOTP::<SHA1>::new(&secret(20), 10).unwrap().generate(count as u64);
        assert_eq!(ten.value(), truncated);
        assert_eq!(ten.to_string(), format!("{truncated:010}"));
    }
}

#[test]
fn rfc6238_appendix_b() {
    let header = "|  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |";
    let start = RFC6238.find(header).expect("table 1 of RFC 6238") + header.len();
    let mut rows = 0;
    for line in RFC6238[start..].lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        if line.trim().starts_with("+---") && rows > 0 {
            break;
        }
        if cells.len() != 7 || cells[1].is_empty() {
            continue;
        }
        let (time, step, password, mode) = (cells[1].parse::<u64>().unwrap(), cells[3], cells[4], cells[5]);
        let config = TOTPConfig { digits: 8, period: 30, origin: 0 };
        let (counter, code) = match mode {
            "SHA1" => {
                let totp = TOTP::<SHA1>::new(&secret(20), &config).unwrap();
                (totp.counter(time).unwrap(), totp.generate(time).unwrap())
            }
            "SHA256" => {
                let totp = TOTP::<SHA256>::new(&secret(32), &config).unwrap();
                (totp.counter(time).unwrap(), totp.generate(time).unwrap())
            }
            "SHA512" => {
                let totp = TOTP::<SHA512>::new(&secret(64), &config).unwrap();
                (totp.counter(time).unwrap(), totp.generate(time).unwrap())
            }
            other => panic!("mode {other}"),
        };
        assert_eq!(counter, u64::from_str_radix(step, 16).unwrap(), "{time} {mode}");
        assert_eq!(code.to_string(), password, "{time} {mode}");
        rows += 1;
    }
    assert_eq!(rows, 18, "six times for three modes");
}

#[test]
fn keys_digits_and_hash_functions_are_checked() {
    // RFC 4226 R6: keys of at least 128 bits; R4: at least 6 digits.
    assert_eq!(HOTP::<SHA1>::new(&[0; 15], 6).unwrap_err(), OTPError::KeyTooShort);
    assert!(HOTP::<SHA1>::new(&[0; 16], 6).is_ok());
    assert_eq!(HOTP::<SHA1>::new(&secret(20), 5).unwrap_err(), OTPError::Digits);
    assert_eq!(HOTP::<SHA1>::new(&secret(20), 11).unwrap_err(), OTPError::Digits);
    // The dynamic truncation reads up to byte 18: shorter digests cannot be used.
    assert_eq!(HOTP::<umilib::hash::md::v5::MD5>::new(&secret(20), 6).unwrap_err(), OTPError::Hash);
    assert_eq!(HOTP::<SHA1>::truncate(&[0; 18]), None);
    let config = TOTPConfig { period: 0, ..TOTPConfig::default() };
    assert_eq!(TOTP::<SHA1>::new(&secret(20), &config).unwrap_err(), OTPError::Period);
    assert_eq!(TOTPConfig::default(), TOTPConfig { digits: 6, period: 30, origin: 0 });
}

#[test]
fn hotp_verification_looks_ahead_and_returns_the_counter() {
    let hotp = HOTP::<SHA1>::new(&secret(20), 6).unwrap();
    // Counter 5 gives 254676 (RFC 4226 appendix D).
    assert_eq!(hotp.verify(b"254676", 5, 0), Some(5));
    assert_eq!(hotp.verify(b"254676", 3, 2), Some(5));
    assert_eq!(hotp.verify(b"254676", 3, 1), None);
    assert_eq!(hotp.verify(b"254676", 6, 10), None);
    assert_eq!(hotp.verify(b"25467", 5, 0), None);
    assert_eq!(hotp.verify(b"0254676", 5, 0), None);
    assert_eq!(hotp.verify(b"", 0, 9), None);
    // The window stops at the largest counter.
    assert_eq!(hotp.verify(b"254676", u64::MAX - 1, 5), None);
}

#[test]
fn totp_steps_and_windows() {
    let config = TOTPConfig { digits: 8, period: 30, origin: 0 };
    let totp = TOTP::<SHA1>::new(&secret(20), &config).unwrap();
    // 1111111109 and 1111111111 are in steps 0x23523EC and 0x23523ED (RFC 6238 appendix B).
    assert_eq!(totp.verify(b"07081804", 1111111109, 0, 0), Ok(Some(0x23523EC)));
    assert_eq!(totp.verify(b"07081804", 1111111111, 0, 0), Ok(None));
    assert_eq!(totp.verify(b"07081804", 1111111111, 1, 0), Ok(Some(0x23523EC)));
    assert_eq!(totp.verify(b"14050471", 1111111109, 0, 1), Ok(Some(0x23523ED)));
    // At time 59 (step 1) the window behind stops at step 0.
    assert_eq!(totp.verify(b"94287082", 59, 5, 0), Ok(Some(1)));
    // An origin moves the steps; times before it are refused.
    let shifted = TOTP::<SHA1>::new(&secret(20), &TOTPConfig { digits: 8, period: 30, origin: 1000 }).unwrap();
    assert_eq!(shifted.counter(1059), Ok(1));
    assert_eq!(shifted.generate(1059).unwrap().to_string(), "94287082");
    assert_eq!(shifted.counter(999), Err(OTPError::Time));
    assert_eq!(shifted.verify(b"94287082", 999, 0, 0), Err(OTPError::Time));
    // Another period.
    let minute = TOTP::<SHA1>::new(&secret(20), &TOTPConfig { digits: 8, period: 60, origin: 0 }).unwrap();
    assert_eq!(minute.counter(119), Ok(1));
}

#[test]
fn codes_are_written_with_leading_zeros_and_not_printed_by_debug() {
    let code = OTPCode::new(7081804, 8);
    assert_eq!(code.to_string(), "07081804");
    assert_eq!(&code.to_ascii()[..8], b"07081804");
    assert_eq!(OTPCode::new(0, 6).to_string(), "000000");
    assert_eq!(format!("{code:?}"), "OTPCode(8 digits)");
    let hotp = HOTP::<SHA1>::new(&secret(20), 6).unwrap();
    assert!(!format!("{hotp:?}").contains("1234"));
}
