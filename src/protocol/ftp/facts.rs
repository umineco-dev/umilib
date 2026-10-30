use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use super::FTPError;
use crate::calendar::Date;

/// A time of RFC 3659 §2.3 (MDTM, the modify and create facts):
/// `YYYYMMDDHHMMSS[.fraction]`, of UTC; seconds since 1970 and nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FTPTime {
    pub seconds: i64,
    pub nanoseconds: u32,
}

/// An entry of MLST and MLSD (RFC 3659 §7.2): its facts, names in lower
/// case as they compare without case, and its pathname.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FTPFacts {
    pub facts: Vec<(String, String)>,
    pub pathname: String,
}

impl FTPTime {
    pub fn new(seconds: i64, nanoseconds: u32) -> FTPTime {
        FTPTime { seconds, nanoseconds }
    }

    pub fn parse(text: &str) -> Result<FTPTime, FTPError> {
        let invalid = FTPError::Syntax { reason: "not a time-val" };
        let (whole, fraction) = text.split_once('.').map_or((text, None), |(whole, fraction)| (whole, Some(fraction)));
        if whole.len() != 14 || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid);
        }
        let number = |range: core::ops::Range<usize>| whole[range].parse::<i64>().map_err(|_| invalid);
        let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
        let (hour, minute, second) = (number(8..10)?, number(10..12)?, number(12..14)?);
        // The month and the day have two digits, which fit u8.
        let date = Date::new(year, month as u8, day as u8);
        let date = date.filter(|_| hour <= 23 && minute <= 59 && second <= 60).ok_or(invalid)?;
        let nanoseconds = match fraction {
            None => 0,
            Some(fraction) if !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()) => {
                let digits: String = fraction.chars().chain(core::iter::repeat('0')).take(9).collect();
                digits.parse().map_err(|_| invalid)?
            }
            Some(_) => return Err(invalid),
        };
        let seconds = date.days() * 86_400 + hour * 3_600 + minute * 60 + second.min(59);
        Ok(FTPTime { seconds, nanoseconds })
    }
}

impl fmt::Display for FTPTime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every day of i64 seconds is of a date (`Date::MIN_YEAR`).
        let date = Date::from_days(self.seconds.div_euclid(86_400)).ok_or(fmt::Error)?;
        let time = self.seconds.rem_euclid(86_400);
        write!(
            formatter,
            "{:04}{:02}{:02}{:02}{:02}{:02}",
            date.year(),
            date.month(),
            date.day(),
            time / 3_600,
            time / 60 % 60,
            time % 60
        )?;
        if self.nanoseconds > 0 {
            let fraction = alloc::format!("{:09}", self.nanoseconds);
            write!(formatter, ".{}", fraction.trim_end_matches('0'))?;
        }
        Ok(())
    }
}

impl FTPFacts {
    pub fn new(pathname: &str) -> FTPFacts {
        FTPFacts { facts: Vec::new(), pathname: String::from(pathname) }
    }

    /// The value of the fact `name`, in any case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.facts.iter().find(|(fact, _)| fact.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }

    pub fn set(&mut self, name: &str, value: &str) {
        let name = name.to_ascii_lowercase();
        match self.facts.iter_mut().find(|(fact, _)| *fact == name) {
            Some((_, slot)) => *slot = String::from(value),
            None => self.facts.push((name, String::from(value))),
        }
    }

    /// The size fact (§7.5.7).
    pub fn size(&self) -> Option<u64> {
        self.get("size")?.parse().ok()
    }

    /// The modify fact (§7.5.3).
    pub fn modify(&self) -> Option<FTPTime> {
        FTPTime::parse(self.get("modify")?).ok()
    }

    /// The entry of a line of MLSD, or of the line after the first of MLST without its leading
    /// space: facts, each `name=value;`, a space, the pathname (§7.2).
    pub fn parse(line: &str) -> Result<FTPFacts, FTPError> {
        let invalid = FTPError::Syntax { reason: "not an entry of facts" };
        let (facts, pathname) = line.split_once(' ').ok_or(invalid)?;
        if pathname.is_empty() || pathname.contains(['\r', '\n']) {
            return Err(invalid);
        }
        let mut entry = FTPFacts::new(pathname);
        if !facts.is_empty() {
            let facts = facts.strip_suffix(';').ok_or(invalid)?;
            for fact in facts.split(';') {
                let (name, value) = fact.split_once('=').ok_or(invalid)?;
                let name_valid = !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_graphic() && byte != b'=');
                if !name_valid || value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte) && byte < 0x80) {
                    return Err(invalid);
                }
                entry.facts.push((name.to_ascii_lowercase(), String::from(value)));
            }
        }
        Ok(entry)
    }
}

impl fmt::Display for FTPFacts {
    /// The entry as a line of MLSD: `name=value;...` and the pathname.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, value) in &self.facts {
            write!(formatter, "{name}={value};")?;
        }
        write!(formatter, " {}", self.pathname)
    }
}
