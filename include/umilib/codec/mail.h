/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_CODEC_MAIL_H
#define UMILIB_CODEC_MAIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The limits of reading messages.
 */
typedef struct umilib_codec_mail_MailConfig {
    size_t maximum_length;
    size_t maximum_field_length;
    size_t maximum_fields;
    size_t maximum_parts;
    size_t maximum_depth;
    bool utf8;
} umilib_codec_mail_MailConfig;

/**
 * A date-time: seconds since 1970 (UTC), the offset of its zone in minutes east, and whether its local time is unknown (-0000).
 */
typedef struct umilib_codec_mail_MailDate {
    int64_t seconds;
    int16_t offset;
    bool zone_unknown;
} umilib_codec_mail_MailDate;

/**
 * The fields of a header section.
 */
typedef struct umilib_codec_mail_MailFields umilib_codec_mail_MailFields;

/**
 * A list of addresses.
 */
typedef struct umilib_codec_mail_MailAddresses umilib_codec_mail_MailAddresses;

/**
 * A list of message identifiers.
 */
typedef struct umilib_codec_mail_MailMessageIDs umilib_codec_mail_MailMessageIDs;

/**
 * The parameters of a MIME field.
 */
typedef struct umilib_codec_mail_MIMEParameters umilib_codec_mail_MIMEParameters;

/**
 * A media type and its parameters.
 */
typedef struct umilib_codec_mail_MIMEContentType umilib_codec_mail_MIMEContentType;

/**
 * A Content-Disposition.
 */
typedef struct umilib_codec_mail_MIMEDisposition umilib_codec_mail_MIMEDisposition;

/**
 * An entity of a message, its parts and the message it encapsulates.
 */
typedef struct umilib_codec_mail_MIMEEntity umilib_codec_mail_MIMEEntity;

/**
 * The preamble, parts and epilogue of a multipart body.
 */
typedef struct umilib_codec_mail_MIMEMultipart umilib_codec_mail_MIMEMultipart;

/**
 * Writes the default configuration into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_config_default(umilib_codec_mail_MailConfig* out);

/**
 * Writes whether the UTF-8 text at `name` is a field name into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_field_is_name(const uint8_t* name, size_t length, bool* out);

/**
 * Writes the field value at `value` unfolded into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_field_unfolded(const uint8_t* value, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes an empty list of fields into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_new(umilib_codec_mail_MailFields** out);

/**
 * Reads the header section that begins the `length` bytes at `text`; writes its fields
 * into `out` and where the body begins into `out_body`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_decode(const uint8_t* text, size_t length, umilib_codec_mail_MailConfig config, umilib_codec_mail_MailFields** out, size_t* out_body);

/**
 * Writes the number of fields into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_count(const umilib_codec_mail_MailFields* fields, size_t* out);

/**
 * Writes the name of the field `index` into `out_name` and its value into `out_value`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_get(const umilib_codec_mail_MailFields* fields, size_t index, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out_value);

/**
 * Adds the field of the UTF-8 name at `name` and the unfolded value at `value` at the end.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_push(umilib_codec_mail_MailFields* fields, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Replaces the fields named `name` by one of `value`, where the first was, or at the end.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_set(umilib_codec_mail_MailFields* fields, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length);

/**
 * Removes the fields named `name`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_remove(umilib_codec_mail_MailFields* fields, const uint8_t* name, size_t name_length);

/**
 * Writes the fields, each a line, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_fields_encode(const umilib_codec_mail_MailFields* fields, umilib_ffi_Buffer* out);

/**
 * Releases a list of fields. Does nothing if `fields` is null.
 */
void umilib_codec_mail_mail_fields_free(umilib_codec_mail_MailFields* fields);

/**
 * Reads the message of the `length` bytes at `text`: writes its fields into `out_fields`
 * and its body into `out_body`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_message_decode(const uint8_t* text, size_t length, umilib_codec_mail_MailConfig config, umilib_codec_mail_MailFields** out_fields, umilib_ffi_Buffer* out_body);

/**
 * Writes the message of `fields` and the body at `body` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_message_encode(const umilib_codec_mail_MailFields* fields, const uint8_t* body, size_t length, umilib_ffi_Buffer* out);

/**
 * Checks the message of `fields` and the body at `body` as RFC 5322 requires.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_message_validate(const umilib_codec_mail_MailFields* fields, const uint8_t* body, size_t length);

/**
 * Reads the date-time at `text` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_date_parse(const uint8_t* text, size_t length, umilib_codec_mail_MailDate* out);

/**
 * Writes `date` as RFC 5322 §3.3 writes it into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_date_format(umilib_codec_mail_MailDate date, umilib_ffi_Buffer* out);

/**
 * Writes the addresses of the address list at `text` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_address_parse_list(const uint8_t* text, size_t length, bool utf8, umilib_codec_mail_MailAddresses** out);

/**
 * Writes the one address at `text`, as a list of one, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_address_parse(const uint8_t* text, size_t length, bool utf8, umilib_codec_mail_MailAddresses** out);

/**
 * Writes the mailboxes of the mailbox list at `text`, as a list of addresses, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_mailbox_parse_list(const uint8_t* text, size_t length, bool utf8, umilib_codec_mail_MailAddresses** out);

/**
 * Writes the one mailbox at `text`, as a list of one address, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_mailbox_parse(const uint8_t* text, size_t length, bool utf8, umilib_codec_mail_MailAddresses** out);

/**
 * Writes the UTF-8 text at `text` as it is if it is a dot-atom (`dotted`) or atoms and
 * spaces, else quoted, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_mailbox_quote_if_needed(const uint8_t* text, size_t length, bool dotted, umilib_ffi_Buffer* out);

/**
 * Writes an empty list of addresses into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_new(umilib_codec_mail_MailAddresses** out);

/**
 * Writes the number of addresses into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_count(const umilib_codec_mail_MailAddresses* addresses, size_t* out);

/**
 * Writes whether the address `index` is a group into `out_group`, its name (of the group,
 * or of the mailbox) into `out_has_name` and `out_name`, and its number of mailboxes into
 * `out_members`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_get(const umilib_codec_mail_MailAddresses* addresses, size_t index, bool* out_group, bool* out_has_name, umilib_ffi_Buffer* out_name, size_t* out_members);

/**
 * Writes the name, local part and domain of the mailbox `member` of the address `index`
 * (member 0 of a mailbox is itself) into the outputs.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_mailbox(const umilib_codec_mail_MailAddresses* addresses, size_t index, size_t member, bool* out_has_name, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out_local, umilib_ffi_Buffer* out_domain);

/**
 * Writes the address (local part quoted if need be, `@`, domain) of the mailbox `member` of
 * the address `index` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_address(const umilib_codec_mail_MailAddresses* addresses, size_t index, size_t member, umilib_ffi_Buffer* out);

/**
 * Adds the mailbox of the optional UTF-8 name at `name` (null for none), the local part
 * and the domain at the end.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_push_mailbox(umilib_codec_mail_MailAddresses* addresses, const uint8_t* name, size_t name_length, const uint8_t* local, size_t local_length, const uint8_t* domain, size_t domain_length);

/**
 * Adds an empty group of the UTF-8 name at `name` at the end.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_push_group(umilib_codec_mail_MailAddresses* addresses, const uint8_t* name, size_t name_length);

/**
 * Adds a mailbox to the group at the end of the list; fails with NotAGroup if the last
 * address is no group.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_push_member(umilib_codec_mail_MailAddresses* addresses, const uint8_t* name, size_t name_length, const uint8_t* local, size_t local_length, const uint8_t* domain, size_t domain_length);

/**
 * Writes the addresses as an address list, separated by commas, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_addresses_format(const umilib_codec_mail_MailAddresses* addresses, umilib_ffi_Buffer* out);

/**
 * Releases a list of addresses. Does nothing if `addresses` is null.
 */
void umilib_codec_mail_mail_addresses_free(umilib_codec_mail_MailAddresses* addresses);

/**
 * Writes the message identifiers at `text` (Message-ID, In-Reply-To, References) into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_message_id_parse_list(const uint8_t* text, size_t length, bool utf8, umilib_codec_mail_MailMessageIDs** out);

/**
 * Writes the one message identifier at `text`, as a list of one, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_message_id_parse(const uint8_t* text, size_t length, bool utf8, umilib_codec_mail_MailMessageIDs** out);

/**
 * Writes the number of identifiers into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_message_ids_count(const umilib_codec_mail_MailMessageIDs* identifiers, size_t* out);

/**
 * Writes the two halves of the identifier `index` into `out_left` and `out_right`.
 */
const umilib_ffi_Status* umilib_codec_mail_mail_message_ids_get(const umilib_codec_mail_MailMessageIDs* identifiers, size_t index, umilib_ffi_Buffer* out_left, umilib_ffi_Buffer* out_right);

/**
 * Releases a list of identifiers. Does nothing if `identifiers` is null.
 */
void umilib_codec_mail_mail_message_ids_free(umilib_codec_mail_MailMessageIDs* identifiers);

/**
 * Writes whether the UTF-8 name at `name` is of a character set converted into
 * `out_has`, and its number into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_charset_from_name(const uint8_t* name, size_t length, bool* out_has, uint8_t* out);

/**
 * Writes the preferred MIME name of the character set of number `charset` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_charset_preferred_name(uint8_t charset, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 text of the bytes at `data` of the character set `charset` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_charset_decode(uint8_t charset, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 text at `text` in the character set `charset` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_charset_encode(uint8_t charset, const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 text of the bytes at `data` of the character set named at `name`
 * into `out` (MIMECharset::decode_named).
 */
const umilib_ffi_Status* umilib_codec_mail_mime_charset_decode_named(const uint8_t* name, size_t name_length, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Reads the encoded word at `word`: writes its character set, its language if it has one,
 * the number of its encoding and its data into the outputs.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_encoded_word_parse(const uint8_t* word, size_t length, umilib_ffi_Buffer* out_charset, bool* out_has_language, umilib_ffi_Buffer* out_language, uint8_t* out_encoding, umilib_ffi_Buffer* out_data);

/**
 * Writes the encoded word of the character set at `charset`, the language at `language`
 * (null for none), the encoding of number `encoding` and the data at `data` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_encoded_word_encode(const uint8_t* charset, size_t charset_length, const uint8_t* language, size_t language_length, uint8_t encoding, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the bytes of the Q-encoded text at `text` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_encoded_word_decode_q(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the unstructured header text at `text` unfolded, its encoded words decoded, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_encoded_word_decode_text(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the UTF-8 text at `text` for a header of US-ASCII, in encoded words if need be, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_encoded_word_encode_text(const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the bytes at `data` Quoted-Printable encoded (their line breaks too if `binary`) into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_quoted_printable_encode(bool binary, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the data of the Quoted-Printable text at `text` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_quoted_printable_decode(bool binary, const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the name of the transfer encoding of the field value at `value` (in lower case if
 * it is one of RFC 2045) into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_transfer_encoding_parse(const uint8_t* value, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the data of the body at `body` of the transfer encoding named at `name` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_transfer_encoding_decode(const uint8_t* name, size_t name_length, const uint8_t* body, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes the data at `data` in the transfer encoding named at `name` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_transfer_encoding_encode(const uint8_t* name, size_t name_length, const uint8_t* data, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes an empty list of parameters into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_parameters_new(umilib_codec_mail_MIMEParameters** out);

/**
 * Writes the number of parameters into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_parameters_count(const umilib_codec_mail_MIMEParameters* parameters, size_t* out);

/**
 * Writes the name, the value, and the character set and language (each if given) of the
 * parameter `index` into the outputs.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_parameters_get(const umilib_codec_mail_MIMEParameters* parameters, size_t index, umilib_ffi_Buffer* out_name, umilib_ffi_Buffer* out_value, bool* out_has_charset, umilib_ffi_Buffer* out_charset, bool* out_has_language, umilib_ffi_Buffer* out_language);

/**
 * Replaces the parameter of the UTF-8 name at `name`, or adds it at the end, with the value
 * at `value` and the optional character set and language (null for none).
 */
const umilib_ffi_Status* umilib_codec_mail_mime_parameters_set(umilib_codec_mail_MIMEParameters* parameters, const uint8_t* name, size_t name_length, const uint8_t* value, size_t value_length, const uint8_t* charset, size_t charset_length, const uint8_t* language, size_t language_length);

/**
 * Removes the parameter of the UTF-8 name at `name`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_parameters_remove(umilib_codec_mail_MIMEParameters* parameters, const uint8_t* name, size_t name_length);

/**
 * Writes the parameters, each `; name=value`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_parameters_encode(const umilib_codec_mail_MIMEParameters* parameters, umilib_ffi_Buffer* out);

/**
 * Releases a list of parameters. Does nothing if `parameters` is null.
 */
void umilib_codec_mail_mime_parameters_free(umilib_codec_mail_MIMEParameters* parameters);

/**
 * Writes the type of the UTF-8 type and subtype at `kind` and `subtype`, without
 * parameters, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_new(const uint8_t* kind, size_t kind_length, const uint8_t* subtype, size_t subtype_length, umilib_codec_mail_MIMEContentType** out);

/**
 * Writes the type of the field value at `value` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_parse(const uint8_t* value, size_t length, umilib_codec_mail_MIMEContentType** out);

/**
 * Writes `text/plain; charset=us-ascii` (RFC 2045 §5.2) into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_default_text(umilib_codec_mail_MIMEContentType** out);

/**
 * Writes `message/rfc822` (RFC 2046 §5.1.5) into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_default_digest(umilib_codec_mail_MIMEContentType** out);

/**
 * Writes the type into `out_kind` and the subtype into `out_subtype`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_kind(const umilib_codec_mail_MIMEContentType* content_type, umilib_ffi_Buffer* out_kind, umilib_ffi_Buffer* out_subtype);

/**
 * Writes a copy of the parameters into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_parameters(const umilib_codec_mail_MIMEContentType* content_type, umilib_codec_mail_MIMEParameters** out);

/**
 * Replaces the parameters by a copy of `parameters`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_set_parameters(umilib_codec_mail_MIMEContentType* content_type, const umilib_codec_mail_MIMEParameters* parameters);

/**
 * Writes whether the type has a valid boundary into `out_has` and the boundary into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_boundary(const umilib_codec_mail_MIMEContentType* content_type, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes the type as a field value is into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_content_type_format(const umilib_codec_mail_MIMEContentType* content_type, umilib_ffi_Buffer* out);

/**
 * Releases a type. Does nothing if `content_type` is null.
 */
void umilib_codec_mail_mime_content_type_free(umilib_codec_mail_MIMEContentType* content_type);

/**
 * Writes the disposition of the UTF-8 type at `kind`, without parameters, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_disposition_new(const uint8_t* kind, size_t length, umilib_codec_mail_MIMEDisposition** out);

/**
 * Writes the disposition of the field value at `value` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_disposition_parse(const uint8_t* value, size_t length, umilib_codec_mail_MIMEDisposition** out);

/**
 * Writes the type of the disposition into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_disposition_kind(const umilib_codec_mail_MIMEDisposition* disposition, umilib_ffi_Buffer* out);

/**
 * Writes a copy of the parameters into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_disposition_parameters(const umilib_codec_mail_MIMEDisposition* disposition, umilib_codec_mail_MIMEParameters** out);

/**
 * Replaces the parameters by a copy of `parameters`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_disposition_set_parameters(umilib_codec_mail_MIMEDisposition* disposition, const umilib_codec_mail_MIMEParameters* parameters);

/**
 * Writes whether the disposition suggests a file name into `out_has`, and the name (its
 * last path component) into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_disposition_filename(const umilib_codec_mail_MIMEDisposition* disposition, bool* out_has, umilib_ffi_Buffer* out);

/**
 * Writes the disposition as a field value is into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_disposition_format(const umilib_codec_mail_MIMEDisposition* disposition, umilib_ffi_Buffer* out);

/**
 * Releases a disposition. Does nothing if `disposition` is null.
 */
void umilib_codec_mail_mime_disposition_free(umilib_codec_mail_MIMEDisposition* disposition);

/**
 * Writes the entity of the message of the `length` bytes at `text` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_decode(const uint8_t* text, size_t length, umilib_codec_mail_MailConfig config, umilib_codec_mail_MIMEEntity** out);

/**
 * Writes where the header section begins and ends, and where the body does, in the text read.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_ranges(const umilib_codec_mail_MIMEEntity* entity, size_t* out_header_start, size_t* out_header_end, size_t* out_body_start, size_t* out_body_end);

/**
 * Writes a copy of the fields into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_fields(const umilib_codec_mail_MIMEEntity* entity, umilib_codec_mail_MailFields** out);

/**
 * Writes a copy of the type into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_content_type(const umilib_codec_mail_MIMEEntity* entity, umilib_codec_mail_MIMEContentType** out);

/**
 * Writes the name of the transfer encoding into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_encoding(const umilib_codec_mail_MIMEEntity* entity, umilib_ffi_Buffer* out);

/**
 * Writes the number of parts into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_part_count(const umilib_codec_mail_MIMEEntity* entity, size_t* out);

/**
 * Writes a copy of the part `index` into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_part(const umilib_codec_mail_MIMEEntity* entity, size_t index, umilib_codec_mail_MIMEEntity** out);

/**
 * Writes whether the entity encapsulates a message into `out_has`, and a copy of the message
 * into `out` (null if it has none).
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_message(const umilib_codec_mail_MIMEEntity* entity, bool* out_has, umilib_codec_mail_MIMEEntity** out);

/**
 * Writes the data of the body, in the `length` bytes at `text` the entity was read from,
 * decoded from its transfer encoding, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_data(const umilib_codec_mail_MIMEEntity* entity, const uint8_t* text, size_t length, umilib_ffi_Buffer* out);

/**
 * Writes whether the entity has a readable Content-Disposition into `out_has`, and the
 * disposition into `out` (null if it has none).
 */
const umilib_ffi_Status* umilib_codec_mail_mime_entity_disposition(const umilib_codec_mail_MIMEEntity* entity, bool* out_has, umilib_codec_mail_MIMEDisposition** out);

/**
 * Releases an entity. Does nothing if `entity` is null.
 */
void umilib_codec_mail_mime_entity_free(umilib_codec_mail_MIMEEntity* entity);

/**
 * Writes the parts of the body from `body_start` to `body_end` of the `length` bytes at
 * `text`, delimited by the boundary at `boundary`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_multipart_split(const uint8_t* text, size_t length, size_t body_start, size_t body_end, const uint8_t* boundary, size_t boundary_length, umilib_codec_mail_MIMEMultipart** out);

/**
 * Writes where the preamble and the epilogue begin and end, and whether the close
 * delimiter was found, into the outputs.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_multipart_ranges(const umilib_codec_mail_MIMEMultipart* multipart, size_t* out_preamble_start, size_t* out_preamble_end, size_t* out_epilogue_start, size_t* out_epilogue_end, bool* out_closed);

/**
 * Writes the number of parts into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_multipart_part_count(const umilib_codec_mail_MIMEMultipart* multipart, size_t* out);

/**
 * Writes where the part `index` begins and ends into `out_start` and `out_end`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_multipart_part(const umilib_codec_mail_MIMEMultipart* multipart, size_t index, size_t* out_start, size_t* out_end);

/**
 * Writes whether the line at `line` is a delimiter of the boundary at `boundary` into
 * `out_delimiter`, and whether it is the close delimiter into `out_close`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_multipart_delimiter(const uint8_t* line, size_t length, const uint8_t* boundary, size_t boundary_length, bool* out_delimiter, bool* out_close);

/**
 * Writes the multipart body of the `count` parts at `parts` (each of `lengths[i]` bytes),
 * delimited by the boundary at `boundary`, into `out`.
 */
const umilib_ffi_Status* umilib_codec_mail_mime_multipart_encode(const uint8_t* boundary, size_t boundary_length, const uint8_t* const* parts, const size_t* lengths, size_t count, umilib_ffi_Buffer* out);

/**
 * Releases the parts of a multipart. Does nothing if `multipart` is null.
 */
void umilib_codec_mail_mime_multipart_free(umilib_codec_mail_MIMEMultipart* multipart);

#ifdef __cplusplus
}
#endif

#endif
