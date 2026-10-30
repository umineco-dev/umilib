//! The C ABI of [`crate::codec::mail`].
//!
//! Fields, address lists, identifier lists, parameters, media types,
//! dispositions, entities and the parts of a multipart are handles; the
//! configuration and dates are structures passed by value; character sets
//! and the encodings of encoded words are their numbers, transfer encodings
//! their names. Ranges of an entity or a multipart are byte offsets in the
//! text it was read from. [`MailReader`](crate::codec::mail::MailReader) and
//! [`MIMEParameterSection`](crate::codec::mail::MIMEParameterSection), the
//! pieces the parsers are made of, borrow the text and are not exported.

use alloc::string::String;
use alloc::vec::Vec;

use crate::codec::mail::{
    MIMECharset, MIMEContentType, MIMEDisposition, MIMEEncodedWord, MIMEEntity, MIMEMultipart, MIMEParameter,
    MIMEParameters, MIMEQuotedPrintable, MIMETransferEncoding, MIMEWordEncoding, MailAddress, MailConfig, MailDate,
    MailError, MailField, MailFields, MailMailbox, MailMessage, MailMessageID,
};
use crate::ffi::{Buffer, Definition, Module, Parameter, Pointer, Status, ToStatus, Type, Value};

/// The statuses of [`MailError`], one per variant, and of the calls of this module.
pub struct MailStatus;

impl MailStatus {
    pub const SYNTAX: Status = Status::new(c"codec.mail", c"Syntax", c"text not of the grammar of what was read");
    pub const TOO_LONG: Status =
        Status::new(c"codec.mail", c"TooLong", c"a line, a field or a message longer than the configuration takes");
    pub const TOO_MANY: Status =
        Status::new(c"codec.mail", c"TooMany", c"more fields, parts or nesting than the configuration takes");
    pub const CHARSET: Status = Status::new(c"codec.mail", c"Charset", c"a character set that is not converted");
    pub const ENCODING: Status = Status::new(c"codec.mail", c"Encoding", c"a transfer encoding that is not decoded");
    pub const BASE64: Status = Status::new(c"codec.mail", c"Base64", c"base64 data that cannot be decoded");
    pub const NO_SUCH_ENTRY: Status = Status::new(c"codec.mail", c"NoSuchEntry", c"no entry of that index");
    pub const NOT_A_GROUP: Status =
        Status::new(c"codec.mail", c"NotAGroup", c"a member added to a list whose last address is no group");
    pub const UNKNOWN_VALUE: Status =
        Status::new(c"codec.mail", c"UnknownValue", c"a number of no character set or word encoding");

    /// The character set of number `value`.
    pub fn charset(value: u8) -> Result<MIMECharset, &'static Status> {
        MIMECharset::from_u8(value).ok_or(&MailStatus::UNKNOWN_VALUE)
    }

    /// The entry `index` of `entries`.
    pub fn entry<T>(entries: &[T], index: usize) -> Result<&T, &'static Status> {
        entries.get(index).ok_or(&MailStatus::NO_SUCH_ENTRY)
    }

    /// The mailbox `member` of the address `index` of `addresses`.
    pub fn mailbox(addresses: &[MailAddress], index: usize, member: usize) -> Result<&MailMailbox, &'static Status> {
        MailStatus::entry(MailStatus::entry(addresses, index)?.mailboxes(), member)
    }

    /// A mailbox of an optional name, a local part and a domain, given as C text.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn mailbox_of(
        name: *const u8,
        name_length: usize,
        local: *const u8,
        local_length: usize,
        domain: *const u8,
        domain_length: usize,
    ) -> Result<MailMailbox, &'static Status> {
        // SAFETY: guaranteed by the caller.
        let name = unsafe { Pointer::optional_text(name, name_length) }?;
        let local = unsafe { Pointer::text(local, local_length) }?;
        let domain = unsafe { Pointer::text(domain, domain_length) }?;
        Ok(MailMailbox::new(name, local, domain))
    }

    /// Writes a range as its start and end.
    ///
    /// # Safety
    ///
    /// See [`Pointer`].
    pub unsafe fn write_range(
        range: &core::ops::Range<usize>,
        out_start: *mut usize,
        out_end: *mut usize,
    ) -> Result<(), &'static Status> {
        Pointer::check_range(out_start, 1)?;
        Pointer::check_range(out_end, 1)?;
        // SAFETY: guaranteed by the caller.
        unsafe { Pointer::write(out_start, range.start) }?;
        unsafe { Pointer::write(out_end, range.end) }
    }
}

impl ToStatus for MailError {
    fn to_status(&self) -> &'static Status {
        match self {
            MailError::Syntax { .. } => &MailStatus::SYNTAX,
            MailError::TooLong { .. } => &MailStatus::TOO_LONG,
            MailError::TooMany { .. } => &MailStatus::TOO_MANY,
            MailError::Charset => &MailStatus::CHARSET,
            MailError::Encoding => &MailStatus::ENCODING,
            MailError::Base64(_) => &MailStatus::BASE64,
        }
    }
}

impl Value for MailConfig {
    const TYPE: Type = Type::Named("umilib_codec_mail_MailConfig");
}

impl Value for MailDate {
    const TYPE: Type = Type::Named("umilib_codec_mail_MailDate");
}

impl Value for MailFields {
    const TYPE: Type = Type::Named("umilib_codec_mail_MailFields");
}

impl Value for Vec<MailAddress> {
    const TYPE: Type = Type::Named("umilib_codec_mail_MailAddresses");
}

impl Value for Vec<MailMessageID> {
    const TYPE: Type = Type::Named("umilib_codec_mail_MailMessageIDs");
}

impl Value for MIMEParameters {
    const TYPE: Type = Type::Named("umilib_codec_mail_MIMEParameters");
}

impl Value for MIMEContentType {
    const TYPE: Type = Type::Named("umilib_codec_mail_MIMEContentType");
}

impl Value for MIMEDisposition {
    const TYPE: Type = Type::Named("umilib_codec_mail_MIMEDisposition");
}

impl Value for MIMEEntity {
    const TYPE: Type = Type::Named("umilib_codec_mail_MIMEEntity");
}

impl Value for MIMEMultipart {
    const TYPE: Type = Type::Named("umilib_codec_mail_MIMEMultipart");
}

crate::ffi_functions! {
    /// Writes the default configuration into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_config_default(out: *mut MailConfig) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write(out, MailConfig::default()) })
    }

    /// Writes whether the UTF-8 text at `name` is a field name into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_field_is_name(name: *const u8, length: usize, out: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let name = unsafe { Pointer::text(name, length) }?;
            unsafe { Pointer::write(out, MailField::is_name(name)) }
        })())
    }

    /// Writes the field value at `value` unfolded into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_field_unfolded(value: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let value = unsafe { Pointer::slice(value, length) }?;
            let field = MailField { name: String::new(), value: value.to_vec() };
            unsafe { Pointer::write(out, Buffer::from_vec(field.unfolded())) }
        })())
    }

    /// Writes an empty list of fields into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_new(out: *mut *mut MailFields) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, MailFields::new()) })
    }

    /// Reads the header section that begins the `length` bytes at `text`; writes its fields
    /// into `out` and where the body begins into `out_body`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_decode(text: *const u8, length: usize, config: MailConfig, out: *mut *mut MailFields, out_body: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            Pointer::check_range(out_body, 1)?;
            let (fields, body) = MailFields::decode(text, &config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_body, body) }?;
            unsafe { Pointer::write_handle(out, fields) }
        })())
    }

    /// Writes the number of fields into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_count(fields: *const MailFields, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let fields = unsafe { Pointer::reference(fields) }?;
            unsafe { Pointer::write(out, fields.entries.len()) }
        })())
    }

    /// Writes the name of the field `index` into `out_name` and its value into `out_value`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_get(fields: *const MailFields, index: usize, out_name: *mut Buffer, out_value: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let fields = unsafe { Pointer::reference(fields) }?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_value, 1)?;
            let field = MailStatus::entry(&fields.entries, index)?;
            unsafe { Pointer::write_text(out_name, field.name.clone()) }?;
            unsafe { Pointer::write(out_value, Buffer::from_vec(field.value.clone())) }
        })())
    }

    /// Adds the field of the UTF-8 name at `name` and the unfolded value at `value` at the end.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_push(fields: *mut MailFields, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::slice(value, value_length) }?;
            fields.push(name, value).map_err(|error| error.to_status())
        })())
    }

    /// Replaces the fields named `name` by one of `value`, where the first was, or at the end.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_set(fields: *mut MailFields, name: *const u8, name_length: usize, value: *const u8, value_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::slice(value, value_length) }?;
            fields.set(name, value).map_err(|error| error.to_status())
        })())
    }

    /// Removes the fields named `name`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_remove(fields: *mut MailFields, name: *const u8, name_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let fields = unsafe { Pointer::reference_mut(fields) }?;
            fields.remove(unsafe { Pointer::text(name, name_length) }?);
            Ok(())
        })())
    }

    /// Writes the fields, each a line, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_encode(fields: *const MailFields, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let fields = unsafe { Pointer::reference(fields) }?;
            Pointer::check_range(out, 1)?;
            let mut text = Vec::new();
            fields.encode(&mut text);
            unsafe { Pointer::write(out, Buffer::from_vec(text)) }
        })())
    }

    /// Releases a list of fields. Does nothing if `fields` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mail_fields_free(fields: *mut MailFields) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(fields) }
    }

    /// Reads the message of the `length` bytes at `text`: writes its fields into `out_fields`
    /// and its body into `out_body`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_decode(text: *const u8, length: usize, config: MailConfig, out_fields: *mut *mut MailFields, out_body: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out_fields, 1)?;
            Pointer::check_range(out_body, 1)?;
            let message = MailMessage::decode(text, &config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_body, Buffer::from_vec(message.body)) }?;
            unsafe { Pointer::write_handle(out_fields, message.fields) }
        })())
    }

    /// Writes the message of `fields` and the body at `body` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_encode(fields: *const MailFields, body: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let fields = unsafe { Pointer::reference(fields) }?;
            let body = unsafe { Pointer::slice(body, length) }?;
            Pointer::check_range(out, 1)?;
            let message = MailMessage::new(fields.clone(), body.to_vec());
            unsafe { Pointer::write(out, Buffer::from_vec(message.encode())) }
        })())
    }

    /// Checks the message of `fields` and the body at `body` as RFC 5322 requires.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_validate(fields: *const MailFields, body: *const u8, length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let fields = unsafe { Pointer::reference(fields) }?;
            let body = unsafe { Pointer::slice(body, length) }?;
            MailMessage::new(fields.clone(), body.to_vec()).validate().map_err(|error| error.to_status())
        })())
    }

    /// Reads the date-time at `text` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_date_parse(text: *const u8, length: usize, out: *mut MailDate) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let date = MailDate::parse(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, date) }
        })())
    }

    /// Writes `date` as RFC 5322 §3.3 writes it into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_date_format(date: MailDate, out: *mut Buffer) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_text(out, date.format()) })
    }

    /// Writes the addresses of the address list at `text` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_address_parse_list(text: *const u8, length: usize, utf8: bool, out: *mut *mut Vec<MailAddress>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let addresses = MailAddress::parse_list(text, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, addresses) }
        })())
    }

    /// Writes the one address at `text`, as a list of one, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_address_parse(text: *const u8, length: usize, utf8: bool, out: *mut *mut Vec<MailAddress>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let address = MailAddress::parse(text, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, alloc::vec![address]) }
        })())
    }

    /// Writes the mailboxes of the mailbox list at `text`, as a list of addresses, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_mailbox_parse_list(text: *const u8, length: usize, utf8: bool, out: *mut *mut Vec<MailAddress>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let mailboxes = MailMailbox::parse_list(text, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, mailboxes.into_iter().map(MailAddress::Mailbox).collect::<Vec<_>>()) }
        })())
    }

    /// Writes the one mailbox at `text`, as a list of one address, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_mailbox_parse(text: *const u8, length: usize, utf8: bool, out: *mut *mut Vec<MailAddress>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let mailbox = MailMailbox::parse(text, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, alloc::vec![MailAddress::Mailbox(mailbox)]) }
        })())
    }

    /// Writes the UTF-8 text at `text` as it is if it is a dot-atom (`dotted`) or atoms and
    /// spaces, else quoted, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_mailbox_quote_if_needed(text: *const u8, length: usize, dotted: bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            unsafe { Pointer::write_text(out, MailMailbox::quote_if_needed(text, dotted)) }
        })())
    }

    /// Writes an empty list of addresses into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_new(out: *mut *mut Vec<MailAddress>) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, Vec::<MailAddress>::new()) })
    }

    /// Writes the number of addresses into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_count(addresses: *const Vec<MailAddress>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let addresses = unsafe { Pointer::reference(addresses) }?;
            unsafe { Pointer::write(out, addresses.len()) }
        })())
    }

    /// Writes whether the address `index` is a group into `out_group`, its name (of the group,
    /// or of the mailbox) into `out_has_name` and `out_name`, and its number of mailboxes into
    /// `out_members`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_get(addresses: *const Vec<MailAddress>, index: usize, out_group: *mut bool, out_has_name: *mut bool, out_name: *mut Buffer, out_members: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let addresses = unsafe { Pointer::reference(addresses) }?;
            Pointer::check_range(out_group, 1)?;
            Pointer::check_range(out_has_name, 1)?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_members, 1)?;
            let address = MailStatus::entry(addresses, index)?;
            let (group, name) = match address {
                MailAddress::Mailbox(mailbox) => (false, mailbox.name.as_deref()),
                MailAddress::Group { name, .. } => (true, Some(name.as_str())),
            };
            unsafe { Pointer::write(out_group, group) }?;
            unsafe { Pointer::write(out_members, address.mailboxes().len()) }?;
            unsafe { Pointer::write_optional_text(out_has_name, out_name, name) }
        })())
    }

    /// Writes the name, local part and domain of the mailbox `member` of the address `index`
    /// (member 0 of a mailbox is itself) into the outputs.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_mailbox(addresses: *const Vec<MailAddress>, index: usize, member: usize, out_has_name: *mut bool, out_name: *mut Buffer, out_local: *mut Buffer, out_domain: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let addresses = unsafe { Pointer::reference(addresses) }?;
            Pointer::check_range(out_has_name, 1)?;
            Pointer::check_range(out_name, 1)?;
            Pointer::check_range(out_local, 1)?;
            Pointer::check_range(out_domain, 1)?;
            let mailbox = MailStatus::mailbox(addresses, index, member)?;
            unsafe { Pointer::write_text(out_local, mailbox.local.clone()) }?;
            unsafe { Pointer::write_text(out_domain, mailbox.domain.clone()) }?;
            unsafe { Pointer::write_optional_text(out_has_name, out_name, mailbox.name.as_deref()) }
        })())
    }

    /// Writes the address (local part quoted if need be, `@`, domain) of the mailbox `member` of
    /// the address `index` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_address(addresses: *const Vec<MailAddress>, index: usize, member: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let addresses = unsafe { Pointer::reference(addresses) }?;
            Pointer::check_range(out, 1)?;
            let mailbox = MailStatus::mailbox(addresses, index, member)?;
            unsafe { Pointer::write_text(out, mailbox.address()) }
        })())
    }

    /// Adds the mailbox of the optional UTF-8 name at `name` (null for none), the local part
    /// and the domain at the end.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_push_mailbox(addresses: *mut Vec<MailAddress>, name: *const u8, name_length: usize, local: *const u8, local_length: usize, domain: *const u8, domain_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let addresses = unsafe { Pointer::reference_mut(addresses) }?;
            let mailbox = unsafe { MailStatus::mailbox_of(name, name_length, local, local_length, domain, domain_length) }?;
            addresses.push(MailAddress::Mailbox(mailbox));
            Ok(())
        })())
    }

    /// Adds an empty group of the UTF-8 name at `name` at the end.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_push_group(addresses: *mut Vec<MailAddress>, name: *const u8, name_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let addresses = unsafe { Pointer::reference_mut(addresses) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            addresses.push(MailAddress::Group { name: String::from(name), members: Vec::new() });
            Ok(())
        })())
    }

    /// Adds a mailbox to the group at the end of the list; fails with NotAGroup if the last
    /// address is no group.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_push_member(addresses: *mut Vec<MailAddress>, name: *const u8, name_length: usize, local: *const u8, local_length: usize, domain: *const u8, domain_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let addresses = unsafe { Pointer::reference_mut(addresses) }?;
            let mailbox = unsafe { MailStatus::mailbox_of(name, name_length, local, local_length, domain, domain_length) }?;
            match addresses.last_mut() {
                Some(MailAddress::Group { members, .. }) => {
                    members.push(mailbox);
                    Ok(())
                }
                _ => Err(&MailStatus::NOT_A_GROUP),
            }
        })())
    }

    /// Writes the addresses as an address list, separated by commas, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_format(addresses: *const Vec<MailAddress>, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let addresses = unsafe { Pointer::reference(addresses) }?;
            Pointer::check_range(out, 1)?;
            unsafe { Pointer::write_text(out, MailAddress::format_list(addresses)) }
        })())
    }

    /// Releases a list of addresses. Does nothing if `addresses` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mail_addresses_free(addresses: *mut Vec<MailAddress>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(addresses) }
    }

    /// Writes the message identifiers at `text` (Message-ID, In-Reply-To, References) into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_id_parse_list(text: *const u8, length: usize, utf8: bool, out: *mut *mut Vec<MailMessageID>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let identifiers = MailMessageID::parse_list(text, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, identifiers) }
        })())
    }

    /// Writes the one message identifier at `text`, as a list of one, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_id_parse(text: *const u8, length: usize, utf8: bool, out: *mut *mut Vec<MailMessageID>) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let identifier = MailMessageID::parse(text, utf8).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, alloc::vec![identifier]) }
        })())
    }

    /// Writes the number of identifiers into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_ids_count(identifiers: *const Vec<MailMessageID>, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let identifiers = unsafe { Pointer::reference(identifiers) }?;
            unsafe { Pointer::write(out, identifiers.len()) }
        })())
    }

    /// Writes the two halves of the identifier `index` into `out_left` and `out_right`.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_ids_get(identifiers: *const Vec<MailMessageID>, index: usize, out_left: *mut Buffer, out_right: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let identifiers = unsafe { Pointer::reference(identifiers) }?;
            Pointer::check_range(out_left, 1)?;
            Pointer::check_range(out_right, 1)?;
            let identifier = MailStatus::entry(identifiers, index)?;
            unsafe { Pointer::write_text(out_left, identifier.left.clone()) }?;
            unsafe { Pointer::write_text(out_right, identifier.right.clone()) }
        })())
    }

    /// Releases a list of identifiers. Does nothing if `identifiers` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mail_message_ids_free(identifiers: *mut Vec<MailMessageID>) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(identifiers) }
    }

    /// Writes whether the UTF-8 name at `name` is of a character set converted into
    /// `out_has`, and its number into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_charset_from_name(name: *const u8, length: usize, out_has: *mut bool, out: *mut u8) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let name = unsafe { Pointer::text(name, length) }?;
            Pointer::check_range(out_has, 1)?;
            Pointer::check_range(out, 1)?;
            let charset = MIMECharset::from_name(name);
            unsafe { Pointer::write(out, charset.map_or(0, |charset| charset as u8)) }?;
            unsafe { Pointer::write(out_has, charset.is_some()) }
        })())
    }

    /// Writes the preferred MIME name of the character set of number `charset` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_charset_preferred_name(charset: u8, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let charset = MailStatus::charset(charset)?;
            // SAFETY: the caller passes a writable pointer.
            unsafe { Pointer::write_text(out, String::from(charset.preferred_name())) }
        })())
    }

    /// Writes the UTF-8 text of the bytes at `data` of the character set `charset` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_charset_decode(charset: u8, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let charset = MailStatus::charset(charset)?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let text = charset.decode(data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Writes the UTF-8 text at `text` in the character set `charset` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_charset_encode(charset: u8, text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            let charset = MailStatus::charset(charset)?;
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            Pointer::check_range(out, 1)?;
            let data = charset.encode(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes the UTF-8 text of the bytes at `data` of the character set named at `name`
    /// into `out` (MIMECharset::decode_named).
    pub unsafe extern "C" fn umilib_codec_mail_mime_charset_decode_named(name: *const u8, name_length: usize, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let name = unsafe { Pointer::text(name, name_length) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let text = MIMECharset::decode_named(name, data).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Reads the encoded word at `word`: writes its character set, its language if it has one,
    /// the number of its encoding and its data into the outputs.
    pub unsafe extern "C" fn umilib_codec_mail_mime_encoded_word_parse(word: *const u8, length: usize, out_charset: *mut Buffer, out_has_language: *mut bool, out_language: *mut Buffer, out_encoding: *mut u8, out_data: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let word = unsafe { Pointer::slice(word, length) }?;
            Pointer::check_range(out_charset, 1)?;
            Pointer::check_range(out_has_language, 1)?;
            Pointer::check_range(out_language, 1)?;
            Pointer::check_range(out_encoding, 1)?;
            Pointer::check_range(out_data, 1)?;
            let word = MIMEEncodedWord::parse(word).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out_encoding, word.encoding as u8) }?;
            unsafe { Pointer::write_text(out_charset, word.charset) }?;
            unsafe { Pointer::write(out_data, Buffer::from_vec(word.data)) }?;
            unsafe { Pointer::write_optional_text(out_has_language, out_language, word.language.as_deref()) }
        })())
    }

    /// Writes the encoded word of the character set at `charset`, the language at `language`
    /// (null for none), the encoding of number `encoding` and the data at `data` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_encoded_word_encode(charset: *const u8, charset_length: usize, language: *const u8, language_length: usize, encoding: u8, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let charset = unsafe { Pointer::text(charset, charset_length) }?;
            let language = unsafe { Pointer::optional_text(language, language_length) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            let encoding = MIMEWordEncoding::from_u8(encoding).ok_or(&MailStatus::UNKNOWN_VALUE)?;
            let word = MIMEEncodedWord { charset: String::from(charset), language: language.map(String::from), encoding, data: data.to_vec() };
            unsafe { Pointer::write_text(out, word.encode()) }
        })())
    }

    /// Writes the bytes of the Q-encoded text at `text` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_encoded_word_decode_q(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let data = MIMEEncodedWord::decode_q(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes the unstructured header text at `text` unfolded, its encoded words decoded, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_encoded_word_decode_text(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let decoded = MIMEEncodedWord::decode_text(text).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, decoded) }
        })())
    }

    /// Writes the UTF-8 text at `text` for a header of US-ASCII, in encoded words if need be, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_encoded_word_encode_text(text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::text(text, length) }?;
            unsafe { Pointer::write_text(out, MIMEEncodedWord::encode_text(text)) }
        })())
    }

    /// Writes the bytes at `data` Quoted-Printable encoded (their line breaks too if `binary`) into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_quoted_printable_encode(binary: bool, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let mut text = Vec::new();
            MIMEQuotedPrintable::new(binary).encode(data, &mut text);
            unsafe { Pointer::write(out, Buffer::from_vec(text)) }
        })())
    }

    /// Writes the data of the Quoted-Printable text at `text` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_quoted_printable_decode(binary: bool, text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            unsafe { Pointer::write(out, Buffer::from_vec(MIMEQuotedPrintable::new(binary).decode(text))) }
        })())
    }

    /// Writes the name of the transfer encoding of the field value at `value` (in lower case if
    /// it is one of RFC 2045) into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_transfer_encoding_parse(value: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let value = unsafe { Pointer::slice(value, length) }?;
            Pointer::check_range(out, 1)?;
            let encoding = MIMETransferEncoding::parse(value).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_text(out, String::from(encoding.name())) }
        })())
    }

    /// Writes the data of the body at `body` of the transfer encoding named at `name` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_transfer_encoding_decode(name: *const u8, name_length: usize, body: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let name = unsafe { Pointer::slice(name, name_length) }?;
            let body = unsafe { Pointer::slice(body, length) }?;
            Pointer::check_range(out, 1)?;
            let encoding = MIMETransferEncoding::parse(name).map_err(|error| error.to_status())?;
            let data = encoding.decode(body).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes the data at `data` in the transfer encoding named at `name` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_transfer_encoding_encode(name: *const u8, name_length: usize, data: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let name = unsafe { Pointer::slice(name, name_length) }?;
            let data = unsafe { Pointer::slice(data, length) }?;
            Pointer::check_range(out, 1)?;
            let encoding = MIMETransferEncoding::parse(name).map_err(|error| error.to_status())?;
            let mut body = Vec::new();
            encoding.encode(data, &mut body).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(body)) }
        })())
    }

    /// Writes an empty list of parameters into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_parameters_new(out: *mut *mut MIMEParameters) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, MIMEParameters::new()) })
    }

    /// Writes the number of parameters into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_parameters_count(parameters: *const MIMEParameters, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            unsafe { Pointer::write(out, parameters.entries.len()) }
        })())
    }

    /// Writes the name, the value, and the character set and language (each if given) of the
    /// parameter `index` into the outputs.
    pub unsafe extern "C" fn umilib_codec_mail_mime_parameters_get(parameters: *const MIMEParameters, index: usize, out_name: *mut Buffer, out_value: *mut Buffer, out_has_charset: *mut bool, out_charset: *mut Buffer, out_has_language: *mut bool, out_language: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            for out in [out_name, out_value, out_charset, out_language] {
                Pointer::check_range(out, 1)?;
            }
            Pointer::check_range(out_has_charset, 1)?;
            Pointer::check_range(out_has_language, 1)?;
            let parameter = MailStatus::entry(&parameters.entries, index)?;
            unsafe { Pointer::write_text(out_name, parameter.name.clone()) }?;
            unsafe { Pointer::write(out_value, Buffer::from_vec(parameter.value.clone())) }?;
            unsafe { Pointer::write_optional_text(out_has_charset, out_charset, parameter.charset.as_deref()) }?;
            unsafe { Pointer::write_optional_text(out_has_language, out_language, parameter.language.as_deref()) }
        })())
    }

    /// Replaces the parameter of the UTF-8 name at `name`, or adds it at the end, with the value
    /// at `value` and the optional character set and language (null for none).
    pub unsafe extern "C" fn umilib_codec_mail_mime_parameters_set(parameters: *mut MIMEParameters, name: *const u8, name_length: usize, value: *const u8, value_length: usize, charset: *const u8, charset_length: usize, language: *const u8, language_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let parameters = unsafe { Pointer::reference_mut(parameters) }?;
            let name = unsafe { Pointer::text(name, name_length) }?;
            let value = unsafe { Pointer::slice(value, value_length) }?;
            let charset = unsafe { Pointer::optional_text(charset, charset_length) }?;
            let language = unsafe { Pointer::optional_text(language, language_length) }?;
            let mut parameter = MIMEParameter::new(name, value);
            parameter.charset = charset.map(String::from);
            parameter.language = language.map(String::from);
            parameters.set(parameter);
            Ok(())
        })())
    }

    /// Removes the parameter of the UTF-8 name at `name`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_parameters_remove(parameters: *mut MIMEParameters, name: *const u8, name_length: usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and readable bytes.
            let parameters = unsafe { Pointer::reference_mut(parameters) }?;
            parameters.remove(unsafe { Pointer::text(name, name_length) }?);
            Ok(())
        })())
    }

    /// Writes the parameters, each `; name=value`, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_parameters_encode(parameters: *const MIMEParameters, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let parameters = unsafe { Pointer::reference(parameters) }?;
            Pointer::check_range(out, 1)?;
            let mut text = String::new();
            parameters.encode(&mut text);
            unsafe { Pointer::write_text(out, text) }
        })())
    }

    /// Releases a list of parameters. Does nothing if `parameters` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mime_parameters_free(parameters: *mut MIMEParameters) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(parameters) }
    }

    /// Writes the type of the UTF-8 type and subtype at `kind` and `subtype`, without
    /// parameters, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_new(kind: *const u8, kind_length: usize, subtype: *const u8, subtype_length: usize, out: *mut *mut MIMEContentType) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let kind = unsafe { Pointer::text(kind, kind_length) }?;
            let subtype = unsafe { Pointer::text(subtype, subtype_length) }?;
            unsafe { Pointer::write_handle(out, MIMEContentType::new(kind, subtype)) }
        })())
    }

    /// Writes the type of the field value at `value` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_parse(value: *const u8, length: usize, out: *mut *mut MIMEContentType) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let value = unsafe { Pointer::slice(value, length) }?;
            Pointer::check_range(out, 1)?;
            let content_type = MIMEContentType::parse(value).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, content_type) }
        })())
    }

    /// Writes `text/plain; charset=us-ascii` (RFC 2045 §5.2) into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_default_text(out: *mut *mut MIMEContentType) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, MIMEContentType::default_text()) })
    }

    /// Writes `message/rfc822` (RFC 2046 §5.1.5) into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_default_digest(out: *mut *mut MIMEContentType) -> *const Status {
        // SAFETY: the caller passes a writable pointer.
        Status::from_result(unsafe { Pointer::write_handle(out, MIMEContentType::default_digest()) })
    }

    /// Writes the type into `out_kind` and the subtype into `out_subtype`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_kind(content_type: *const MIMEContentType, out_kind: *mut Buffer, out_subtype: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let content_type = unsafe { Pointer::reference(content_type) }?;
            Pointer::check_range(out_kind, 1)?;
            Pointer::check_range(out_subtype, 1)?;
            unsafe { Pointer::write_text(out_kind, content_type.kind.clone()) }?;
            unsafe { Pointer::write_text(out_subtype, content_type.subtype.clone()) }
        })())
    }

    /// Writes a copy of the parameters into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_parameters(content_type: *const MIMEContentType, out: *mut *mut MIMEParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let content_type = unsafe { Pointer::reference(content_type) }?;
            unsafe { Pointer::write_handle(out, content_type.parameters.clone()) }
        })())
    }

    /// Replaces the parameters by a copy of `parameters`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_set_parameters(content_type: *mut MIMEContentType, parameters: *const MIMEParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let content_type = unsafe { Pointer::reference_mut(content_type) }?;
            content_type.parameters = unsafe { Pointer::reference(parameters) }?.clone();
            Ok(())
        })())
    }

    /// Writes whether the type has a valid boundary into `out_has` and the boundary into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_boundary(content_type: *const MIMEContentType, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let content_type = unsafe { Pointer::reference(content_type) }?;
            Pointer::check_range(out_has, 1)?;
            Pointer::check_range(out, 1)?;
            let boundary = content_type.boundary();
            unsafe { Pointer::write(out, Buffer::from_vec(boundary.unwrap_or_default().to_vec())) }?;
            unsafe { Pointer::write(out_has, boundary.is_some()) }
        })())
    }

    /// Writes the type as a field value is into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_format(content_type: *const MIMEContentType, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let content_type = unsafe { Pointer::reference(content_type) }?;
            unsafe { Pointer::write_text(out, content_type.format()) }
        })())
    }

    /// Releases a type. Does nothing if `content_type` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mime_content_type_free(content_type: *mut MIMEContentType) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(content_type) }
    }

    /// Writes the disposition of the UTF-8 type at `kind`, without parameters, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_new(kind: *const u8, length: usize, out: *mut *mut MIMEDisposition) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let kind = unsafe { Pointer::text(kind, length) }?;
            unsafe { Pointer::write_handle(out, MIMEDisposition::new(kind)) }
        })())
    }

    /// Writes the disposition of the field value at `value` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_parse(value: *const u8, length: usize, out: *mut *mut MIMEDisposition) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let value = unsafe { Pointer::slice(value, length) }?;
            Pointer::check_range(out, 1)?;
            let disposition = MIMEDisposition::parse(value).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, disposition) }
        })())
    }

    /// Writes the type of the disposition into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_kind(disposition: *const MIMEDisposition, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let disposition = unsafe { Pointer::reference(disposition) }?;
            unsafe { Pointer::write_text(out, disposition.kind.clone()) }
        })())
    }

    /// Writes a copy of the parameters into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_parameters(disposition: *const MIMEDisposition, out: *mut *mut MIMEParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let disposition = unsafe { Pointer::reference(disposition) }?;
            unsafe { Pointer::write_handle(out, disposition.parameters.clone()) }
        })())
    }

    /// Replaces the parameters by a copy of `parameters`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_set_parameters(disposition: *mut MIMEDisposition, parameters: *const MIMEParameters) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes valid handles.
            let disposition = unsafe { Pointer::reference_mut(disposition) }?;
            disposition.parameters = unsafe { Pointer::reference(parameters) }?.clone();
            Ok(())
        })())
    }

    /// Writes whether the disposition suggests a file name into `out_has`, and the name (its
    /// last path component) into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_filename(disposition: *const MIMEDisposition, out_has: *mut bool, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let disposition = unsafe { Pointer::reference(disposition) }?;
            unsafe { Pointer::write_optional_text(out_has, out, disposition.filename().as_deref()) }
        })())
    }

    /// Writes the disposition as a field value is into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_format(disposition: *const MIMEDisposition, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let disposition = unsafe { Pointer::reference(disposition) }?;
            unsafe { Pointer::write_text(out, disposition.format()) }
        })())
    }

    /// Releases a disposition. Does nothing if `disposition` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mime_disposition_free(disposition: *mut MIMEDisposition) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(disposition) }
    }

    /// Writes the entity of the message of the `length` bytes at `text` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_decode(text: *const u8, length: usize, config: MailConfig, out: *mut *mut MIMEEntity) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let entity = MIMEEntity::decode(text, &config).map_err(|error| error.to_status())?;
            unsafe { Pointer::write_handle(out, entity) }
        })())
    }

    /// Writes where the header section begins and ends, and where the body does, in the text read.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_ranges(entity: *const MIMEEntity, out_header_start: *mut usize, out_header_end: *mut usize, out_body_start: *mut usize, out_body_end: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let entity = unsafe { Pointer::reference(entity) }?;
            unsafe { MailStatus::write_range(&entity.header, out_header_start, out_header_end) }?;
            unsafe { MailStatus::write_range(&entity.body, out_body_start, out_body_end) }
        })())
    }

    /// Writes a copy of the fields into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_fields(entity: *const MIMEEntity, out: *mut *mut MailFields) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let entity = unsafe { Pointer::reference(entity) }?;
            unsafe { Pointer::write_handle(out, entity.fields.clone()) }
        })())
    }

    /// Writes a copy of the type into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_content_type(entity: *const MIMEEntity, out: *mut *mut MIMEContentType) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let entity = unsafe { Pointer::reference(entity) }?;
            unsafe { Pointer::write_handle(out, entity.content_type.clone()) }
        })())
    }

    /// Writes the name of the transfer encoding into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_encoding(entity: *const MIMEEntity, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let entity = unsafe { Pointer::reference(entity) }?;
            unsafe { Pointer::write_text(out, String::from(entity.encoding.name())) }
        })())
    }

    /// Writes the number of parts into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_part_count(entity: *const MIMEEntity, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let entity = unsafe { Pointer::reference(entity) }?;
            unsafe { Pointer::write(out, entity.parts.len()) }
        })())
    }

    /// Writes a copy of the part `index` into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_part(entity: *const MIMEEntity, index: usize, out: *mut *mut MIMEEntity) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let entity = unsafe { Pointer::reference(entity) }?;
            Pointer::check_range(out, 1)?;
            let part = MailStatus::entry(&entity.parts, index)?;
            unsafe { Pointer::write_handle(out, part.clone()) }
        })())
    }

    /// Writes whether the entity encapsulates a message into `out_has`, and a copy of the message
    /// into `out` (null if it has none).
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_message(entity: *const MIMEEntity, out_has: *mut bool, out: *mut *mut MIMEEntity) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let entity = unsafe { Pointer::reference(entity) }?;
            Pointer::check_range(out_has, 1)?;
            Pointer::check_range(out, 1)?;
            let message = entity.message.as_deref().map(|message| Pointer::into_handle(message.clone()));
            unsafe { Pointer::write(out, message.unwrap_or(core::ptr::null_mut())) }?;
            unsafe { Pointer::write(out_has, message.is_some()) }
        })())
    }

    /// Writes the data of the body, in the `length` bytes at `text` the entity was read from,
    /// decoded from its transfer encoding, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_data(entity: *const MIMEEntity, text: *const u8, length: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle, readable bytes and a writable pointer.
            let entity = unsafe { Pointer::reference(entity) }?;
            let text = unsafe { Pointer::slice(text, length) }?;
            Pointer::check_range(out, 1)?;
            let body = text.get(entity.body.clone()).ok_or(&Status::INVALID_ARGUMENT)?;
            let data = entity.encoding.decode(body).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(data)) }
        })())
    }

    /// Writes whether the entity has a readable Content-Disposition into `out_has`, and the
    /// disposition into `out` (null if it has none).
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_disposition(entity: *const MIMEEntity, out_has: *mut bool, out: *mut *mut MIMEDisposition) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let entity = unsafe { Pointer::reference(entity) }?;
            Pointer::check_range(out_has, 1)?;
            Pointer::check_range(out, 1)?;
            let disposition = entity.disposition().map(Pointer::into_handle);
            unsafe { Pointer::write(out, disposition.unwrap_or(core::ptr::null_mut())) }?;
            unsafe { Pointer::write(out_has, disposition.is_some()) }
        })())
    }

    /// Releases an entity. Does nothing if `entity` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mime_entity_free(entity: *mut MIMEEntity) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(entity) }
    }

    /// Writes the parts of the body from `body_start` to `body_end` of the `length` bytes at
    /// `text`, delimited by the boundary at `boundary`, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_multipart_split(text: *const u8, length: usize, body_start: usize, body_end: usize, boundary: *const u8, boundary_length: usize, out: *mut *mut MIMEMultipart) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let text = unsafe { Pointer::slice(text, length) }?;
            let boundary = unsafe { Pointer::slice(boundary, boundary_length) }?;
            if body_start > body_end || body_end > text.len() {
                return Err(&Status::INVALID_ARGUMENT);
            }
            unsafe { Pointer::write_handle(out, MIMEMultipart::split(text, body_start..body_end, boundary)) }
        })())
    }

    /// Writes where the preamble and the epilogue begin and end, and whether the close
    /// delimiter was found, into the outputs.
    pub unsafe extern "C" fn umilib_codec_mail_mime_multipart_ranges(multipart: *const MIMEMultipart, out_preamble_start: *mut usize, out_preamble_end: *mut usize, out_epilogue_start: *mut usize, out_epilogue_end: *mut usize, out_closed: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let multipart = unsafe { Pointer::reference(multipart) }?;
            Pointer::check_range(out_closed, 1)?;
            unsafe { MailStatus::write_range(&multipart.preamble, out_preamble_start, out_preamble_end) }?;
            unsafe { MailStatus::write_range(&multipart.epilogue, out_epilogue_start, out_epilogue_end) }?;
            unsafe { Pointer::write(out_closed, multipart.closed) }
        })())
    }

    /// Writes the number of parts into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_multipart_part_count(multipart: *const MIMEMultipart, out: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and a writable pointer.
            let multipart = unsafe { Pointer::reference(multipart) }?;
            unsafe { Pointer::write(out, multipart.parts.len()) }
        })())
    }

    /// Writes where the part `index` begins and ends into `out_start` and `out_end`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_multipart_part(multipart: *const MIMEMultipart, index: usize, out_start: *mut usize, out_end: *mut usize) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes a valid handle and writable pointers.
            let multipart = unsafe { Pointer::reference(multipart) }?;
            let part = MailStatus::entry(&multipart.parts, index)?;
            unsafe { MailStatus::write_range(part, out_start, out_end) }
        })())
    }

    /// Writes whether the line at `line` is a delimiter of the boundary at `boundary` into
    /// `out_delimiter`, and whether it is the close delimiter into `out_close`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_multipart_delimiter(line: *const u8, length: usize, boundary: *const u8, boundary_length: usize, out_delimiter: *mut bool, out_close: *mut bool) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and writable pointers.
            let line = unsafe { Pointer::slice(line, length) }?;
            let boundary = unsafe { Pointer::slice(boundary, boundary_length) }?;
            Pointer::check_range(out_delimiter, 1)?;
            Pointer::check_range(out_close, 1)?;
            let delimiter = MIMEMultipart::delimiter(line, boundary);
            unsafe { Pointer::write(out_close, delimiter == Some(true)) }?;
            unsafe { Pointer::write(out_delimiter, delimiter.is_some()) }
        })())
    }

    /// Writes the multipart body of the `count` parts at `parts` (each of `lengths[i]` bytes),
    /// delimited by the boundary at `boundary`, into `out`.
    pub unsafe extern "C" fn umilib_codec_mail_mime_multipart_encode(boundary: *const u8, boundary_length: usize, parts: *const *const u8, lengths: *const usize, count: usize, out: *mut Buffer) -> *const Status {
        Status::from_result((|| {
            // SAFETY: the caller passes readable bytes and a writable pointer.
            let boundary = unsafe { Pointer::slice(boundary, boundary_length) }?;
            let parts = unsafe { Pointer::slices(parts, lengths, count) }?;
            Pointer::check_range(out, 1)?;
            let mut body = Vec::new();
            MIMEMultipart::encode(boundary, &parts, &mut body).map_err(|error| error.to_status())?;
            unsafe { Pointer::write(out, Buffer::from_vec(body)) }
        })())
    }

    /// Releases the parts of a multipart. Does nothing if `multipart` is null.
    pub unsafe extern "C" fn umilib_codec_mail_mime_multipart_free(multipart: *mut MIMEMultipart) {
        // SAFETY: the caller passes null or a handle created by this module.
        unsafe { Pointer::free(multipart) }
    }
}

/// The manifest node of this module.
pub const MODULE: Module = Module {
    name: "mail",
    definitions: &[
        Definition::Structure {
            name: "umilib_codec_mail_MailConfig",
            documentation: " The limits of reading messages.",
            fields: &[
                Parameter { name: "maximum_length", value: Type::USize },
                Parameter { name: "maximum_field_length", value: Type::USize },
                Parameter { name: "maximum_fields", value: Type::USize },
                Parameter { name: "maximum_parts", value: Type::USize },
                Parameter { name: "maximum_depth", value: Type::USize },
                Parameter { name: "utf8", value: Type::Bool },
            ],
        },
        Definition::Structure {
            name: "umilib_codec_mail_MailDate",
            documentation: " A date-time: seconds since 1970 (UTC), the offset of its zone in minutes east, and whether its local time is unknown (-0000).",
            fields: &[
                Parameter { name: "seconds", value: Type::I64 },
                Parameter { name: "offset", value: Type::I16 },
                Parameter { name: "zone_unknown", value: Type::Bool },
            ],
        },
        Definition::Opaque { name: "umilib_codec_mail_MailFields", documentation: " The fields of a header section." },
        Definition::Opaque { name: "umilib_codec_mail_MailAddresses", documentation: " A list of addresses." },
        Definition::Opaque {
            name: "umilib_codec_mail_MailMessageIDs",
            documentation: " A list of message identifiers.",
        },
        Definition::Opaque {
            name: "umilib_codec_mail_MIMEParameters",
            documentation: " The parameters of a MIME field.",
        },
        Definition::Opaque {
            name: "umilib_codec_mail_MIMEContentType",
            documentation: " A media type and its parameters.",
        },
        Definition::Opaque { name: "umilib_codec_mail_MIMEDisposition", documentation: " A Content-Disposition." },
        Definition::Opaque {
            name: "umilib_codec_mail_MIMEEntity",
            documentation: " An entity of a message, its parts and the message it encapsulates.",
        },
        Definition::Opaque {
            name: "umilib_codec_mail_MIMEMultipart",
            documentation: " The preamble, parts and epilogue of a multipart body.",
        },
    ],
    functions: FUNCTIONS,
    modules: &[],
};
