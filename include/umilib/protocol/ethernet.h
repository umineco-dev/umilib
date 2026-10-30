/* Generated from the umilib FFI manifest by tests/ffi. Do not edit. */
#ifndef UMILIB_PROTOCOL_ETHERNET_H
#define UMILIB_PROTOCOL_ETHERNET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "umilib/ffi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A 48-bit MAC address, in transmission byte order.
 */
typedef struct umilib_protocol_ethernet_MACAddress {
    uint8_t octets[6];
} umilib_protocol_ethernet_MACAddress;

/**
 * A VLAN tag (IEEE 802.1Q): tag protocol identifier, priority, drop eligible, identifier.
 */
typedef struct umilib_protocol_ethernet_VLANTag {
    uint16_t protocol;
    uint8_t priority;
    bool drop_eligible;
    uint16_t identifier;
} umilib_protocol_ethernet_VLANTag;

/**
 * The header of an Ethernet frame; the first tag_count tags, outermost first, are present.
 */
typedef struct umilib_protocol_ethernet_EthernetHeader {
    umilib_protocol_ethernet_MACAddress destination;
    umilib_protocol_ethernet_MACAddress source;
    umilib_protocol_ethernet_VLANTag tags[2];
    uint8_t tag_count;
    uint16_t ether_type;
} umilib_protocol_ethernet_EthernetHeader;

/**
 * Reads six hexadecimal pairs separated by colons or hyphens from the UTF-8 text at `text` into
 * `out`; fails with Syntax.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_mac_address_parse(const uint8_t* text, size_t length, umilib_protocol_ethernet_MACAddress* out);

/**
 * Writes the lowercase text of `address`, separated by colons, into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_mac_address_to_string(umilib_protocol_ethernet_MACAddress address, umilib_ffi_Buffer* out);

/**
 * Whether the Individual/Group bit is set.
 */
bool umilib_protocol_ethernet_mac_address_is_multicast(umilib_protocol_ethernet_MACAddress address);

/**
 * ff:ff:ff:ff:ff:ff.
 */
bool umilib_protocol_ethernet_mac_address_is_broadcast(umilib_protocol_ethernet_MACAddress address);

/**
 * Whether the Universal/Local bit is set.
 */
bool umilib_protocol_ethernet_mac_address_is_local(umilib_protocol_ethernet_MACAddress address);

/**
 * Writes the 8 bytes of the modified EUI-64 interface identifier of `address` into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_mac_address_modified_eui64(umilib_protocol_ethernet_MACAddress address, uint8_t* out);

/**
 * Writes the address the IPv4 multicast address of the 4 bytes at `address` maps to into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_mac_address_from_ipv4_multicast(const uint8_t* address, umilib_protocol_ethernet_MACAddress* out);

/**
 * Writes the address the IPv6 multicast address of the 16 bytes at `address` maps to into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_mac_address_from_ipv6_multicast(const uint8_t* address, umilib_protocol_ethernet_MACAddress* out);

/**
 * Whether the type field `value` is the length of an IEEE 802.3 frame's data.
 */
bool umilib_protocol_ethernet_ether_type_is_length(uint16_t value);

/**
 * Whether the type field `value` is an EtherType.
 */
bool umilib_protocol_ethernet_ether_type_is_ether_type(uint16_t value);

/**
 * Whether the EtherType `value` is that of a VLAN tag.
 */
bool umilib_protocol_ethernet_ether_type_is_tag(uint16_t value);

/**
 * The tag of the tag protocol identifier `protocol` and the tag control information `control`.
 */
umilib_protocol_ethernet_VLANTag umilib_protocol_ethernet_vlan_tag_from_control(uint16_t protocol, uint16_t control);

/**
 * Writes the tag control information of `tag` into `out`; fails with Tag if a field does not fit.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_vlan_tag_control(umilib_protocol_ethernet_VLANTag tag, uint16_t* out);

/**
 * Reads the header at the start of the `length` bytes at `bytes` into `out` and the offset and
 * length of its data into `out_offset` and `out_length`; fails with Length, Tag or EtherType.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_ethernet_header_decode(const uint8_t* bytes, size_t length, umilib_protocol_ethernet_EthernetHeader* out, size_t* out_offset, size_t* out_length);

/**
 * Writes the bytes of the header into `out`; fails with Tag or EtherType.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_ethernet_header_encode(const umilib_protocol_ethernet_EthernetHeader* header, umilib_ffi_Buffer* out);

/**
 * Writes the 4 bytes of the frame check sequence of the `length` bytes at `frame` (the header
 * and the data) into `out`, in the order they are sent.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_ethernet_frame_fcs(const uint8_t* frame, size_t length, uint8_t* out);

/**
 * Writes whether the `length` bytes at `frame` end with the right frame check sequence into `out`.
 */
const umilib_ffi_Status* umilib_protocol_ethernet_ethernet_frame_verify(const uint8_t* frame, size_t length, bool* out);

/**
 * The zero bytes to append to a header and data of `length` bytes to make the smallest frame.
 */
size_t umilib_protocol_ethernet_ethernet_frame_padding(size_t length);

#ifdef __cplusplus
}
#endif

#endif
