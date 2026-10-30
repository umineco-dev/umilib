# The calendar

`umilib::calendar::Date` is the one implementation of the proleptic
Gregorian calendar in the crate. This document records why it exists, where
it lives and why its interface is what it is.

## Why one type

Before it, the calendar (days from a date and back, days in a month, leap
years) was written four times: `MailDate::days_from_civil` and
`civil_from_days` (which FTP and IMAP also called), `DNSToken::days_in_month`,
`days_from_civil` and `civil_from_days` (which the DNSSEC trust anchors also
called), `ASN1Time::days_in_month`, `days_from_epoch` and the conversion inside
`ASN1Time::from_unix_seconds`, and the checks of `FTPTime::parse` and
`IMAPDate::is_valid` repeated the leap-year rule a fifth and sixth time. A
review found the copies agreed, but the DNS copy had accepted 31 February
until it was fixed, which is the failure that copies invite. The users now
call `Date`, and none of them keeps a calendar of its own.

## Where it lives

`calendar` is a top-level feature with no dependencies (`src/calendar`,
`umilib::calendar`). `codec-asn1-der`, `codec-mail`, every `protocol-dns-*`
feature, `protocol-ftp` and `protocol-imap-v4` depend on it.
`protocol-ftp` used `codec-mail` only for its calendar, and no longer depends
on it.

Considered and not taken:

- **Inside one of its users** (`codec-mail`, `codec-asn1`, `protocol-dns`),
  the others depending on that feature: DNS and ASN.1 would compile a mail
  parser (or the reverse) to count days, and a module would hold code that is
  not about its subject, which the design rules forbid.
- **`time` as the top-level name** (`umilib::time::Date`): it would leave room
  for times and date-times, but it reads as the sibling of `runtime::time`
  (the monotonic clock and timers), which is a different thing, and nothing
  else of time is shared yet. A future type of time of day or of date-time can
  be a feature of its own that depends on `calendar`.
- **`math-calendar`**: every module of `math` is the arithmetic of
  cryptography (big integers, curves, lattices, pairings) and depends on
  `secret`; a calendar is neither, and would be found in the wrong place.

## Interface

- **Private fields and a checked constructor.** `Date::new` returns `None`
  for a day the calendar does not have, so every `Date` is a valid date and
  `days()` needs no check. The protocol types around it (`ASN1Time`,
  `IMAPDate`) keep their public fields, so they convert with `Date::new` and
  decide what an invalid value of theirs means: `IMAPDate::days` became
  `Option<i64>`; `ASN1Time::to_unix_seconds` stays an `i64` (many callers,
  and the C ABI, use it) and counts a date that `ASN1Time::new` would have
  refused as 1970-01-01, documented there. Such a value can only come from a
  struct literal.
- **`Option`, not an error type.** There is one way to fail, so a module
  error enum would add nothing; the C ABI maps `None` to `InvalidArgument`.
- **`i64` years limited to ±999,999,999,999.** `i64` seconds since 1970 reach
  years -292,277,022,657 to 292,277,026,596. `MailDate`, `FTPTime` and
  `IMAPDateTime` hold any `i64` seconds and format them without failing, so
  `from_days` must have a date for each; an `i32` year (8 bytes instead of
  16) would have made their `Display` fail for far times. The limit is a
  round number above that range, far below where the arithmetic of the days
  would overflow `i64` (about ±2.5 × 10^16 years), so neither direction needs
  checked arithmetic. A range of the whole `i64` of days was considered: it
  needs 128-bit arithmetic or a careful split at the two ends, which is not
  worth it for dates no protocol has.
- **Howard Hinnant's algorithms** (`days_from_civil`, `civil_from_days`,
  public domain, <https://howardhinnant.github.io/date_algorithms.html>):
  the year starts in March so the leap day is the last day of a year, and
  eras of 400 years (146,097 days) make every step a constant-time division.
  The four copies used them already.
- **What it does not have.** No day of the week (only `MailDate` uses one,
  and `(days + 3).rem_euclid(7)` is short), no formatting (each protocol
  writes dates its own way), no time of day, leap seconds or zones. These
  belong to the protocol types, or to a later feature that depends on this one.

## Users that cannot fail

`MailDate`, `FTPTime` and `IMAPDateTime` format with `Date::from_days`, which
cannot be `None` for the day of `i64` seconds (`every_second_of_i64_is_of_a_date`
tests this). Their `Display` returns `fmt::Error` there rather than panic;
`IMAPDateTime::date` and `DNSToken::format_time` (of `u32` seconds) use
`expect` with the reason.
