//! The C ABI of the choice of the hosts of a domain's mail (RFC 5321 §5.1), of
//! the MX records of [`crate::protocol::dns`].

use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::ffi::crypto::random::RandomSource;
use crate::ffi::protocol::dns::DNSStatus;
use crate::ffi::{Buffer, Char, Pointer, Status, ToStatus};
use crate::protocol::dns::DNSName;
use crate::protocol::smtp::SMTPMailExchanger;

crate::ffi_functions! {
    /// Writes the hosts of the mail of the domain at `domain`, in the order to try them, one a line
    /// of its preference and name, into `out`: of the MX records of the zone-file text at `records`
    /// (absolute names), without the hosts at or after the preference of the `local_count` names at
    /// `local` (this host), those of one preference in an order drawn from `random`. Fails with NoMail
    /// for a null MX (RFC 7505) and when no host is left.
    pub unsafe extern "C" fn umilib_protocol_smtp_smtp_mail_exchanger_order(domain: *const u8, domain_length: usize, records: *const u8, records_length: usize, local: *const *const Char, local_count: usize, random: *mut c_void, random_type: *const u8, random_type_length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable text, an array of strings, a generator of the named
            // type and a writable pointer.
            let domain = unsafe { DNSStatus::name(domain, domain_length) }?;
            let records = DNSStatus::records(unsafe { Pointer::text(records, records_length) }?)?;
            let local = unsafe { Pointer::strings(local, local_count) }?
                .iter()
                .map(|name| DNSName::parse(name, None).map_err(|error| error.to_status()))
                .collect::<Result<Vec<DNSName>, _>>()?;
            let mut random = unsafe { RandomSource::from_handle(random, random_type, random_type_length) }?;
            Pointer::check_range(out, 1)?;
            let hosts = SMTPMailExchanger::order(&domain, &records, &local, &mut random).map_err(|error| error.to_status())?;
            let lines: Vec<String> = hosts.iter().map(|host| alloc::format!("{} {}", host.preference, host.host)).collect();
            unsafe { Pointer::write_text(out, lines.join("\n")) }
        })())
    }
}
