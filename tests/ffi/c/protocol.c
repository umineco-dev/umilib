/* Signs, encrypts, verifies and decrypts JWTs (RFC 7519) with JWS and JWE through the generated headers,
   and checks the refusals of RFC 8725; reads and writes IP addresses (RFC 5952), checksums (RFC 1071),
   IPv4 and IPv6 headers with their fragmentation and reassembly, Ethernet frames and ARP packets. */
#include <stdio.h>
#include <string.h>

#include "umilib.h"

#define CHECK(condition)                                                                       \
    do {                                                                                       \
        if (!(condition)) {                                                                    \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition);      \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

#define TEXT(text) (const uint8_t*)(text), strlen(text)

/* The indices of the algorithms in the Rust constants ALL. */
enum { HS256 = 0, HS512 = 2, A128GCM = 3, A128KW = 4 };

static int jwt(void) {
    umilib_crypto_random_HMACDRBG* random = NULL;
    CHECK(umilib_crypto_random_hmac_drbg_new(TEXT("umilib_hash_sha_v2_SHA256"), TEXT("0123456789abcdef0123456789abcdef"), TEXT("nonce of 16 byte"), TEXT(""), &random) == NULL);
    const char* random_type = "umilib_crypto_random_HMACDRBG";

    umilib_protocol_jwt_JWTClaims* claims = NULL;
    CHECK(umilib_protocol_jwt_jwt_claims_new(&claims) == NULL);
    CHECK(umilib_protocol_jwt_jwt_claims_set_string(claims, TEXT("iss"), TEXT("https://issuer.example")) == NULL);
    CHECK(umilib_protocol_jwt_jwt_claims_set_numeric_date(claims, TEXT("exp"), 2000000000) == NULL);
    umilib_protocol_jwt_JOSEHeader* header = NULL;
    CHECK(umilib_protocol_jwt_jose_header_decode(TEXT("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"), &header) == NULL);
    static const uint8_t secret[32] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
    umilib_protocol_jwt_JWK* key = NULL;
    CHECK(umilib_protocol_jwt_jwk_symmetric(secret, sizeof secret, &key) == NULL);

    umilib_ffi_Buffer token = {0};
    CHECK(umilib_protocol_jwt_jwt_sign(claims, header, key, random, TEXT(random_type), &token) == NULL);
    const uint8_t hs256[] = {HS256};
    const uint8_t hs512[] = {HS512};
    umilib_protocol_jwt_JWSConfig* config = NULL;
    umilib_protocol_jwt_JWSConfig* other = NULL;
    CHECK(umilib_protocol_jwt_jws_config_new(hs256, 1, &config) == NULL);
    CHECK(umilib_protocol_jwt_jws_config_new(hs512, 1, &other) == NULL);
    umilib_protocol_jwt_JWTValidation* validation = NULL;
    CHECK(umilib_protocol_jwt_jwt_validation_new(1999999999, &validation) == NULL);
    CHECK(umilib_protocol_jwt_jwt_validation_set_issuer(validation, TEXT("https://issuer.example")) == NULL);
    CHECK(umilib_protocol_jwt_jwt_validation_set_token_type(validation, TEXT("JWT")) == NULL);
    umilib_protocol_jwt_JWT* verified = NULL;
    CHECK(umilib_protocol_jwt_jwt_verify(token.data, token.length, key, config, validation, &verified) == NULL);
    umilib_protocol_jwt_JWTClaims* read = NULL;
    CHECK(umilib_protocol_jwt_jwt_claims(verified, &read) == NULL);
    umilib_ffi_Buffer text = {0};
    CHECK(umilib_protocol_jwt_jwt_claims_encode(read, &text) == NULL);
    CHECK(text.length == strlen("{\"iss\":\"https://issuer.example\",\"exp\":2000000000}"));
    CHECK(memcmp(text.data, "{\"iss\":\"https://issuer.example\",\"exp\":2000000000}", text.length) == 0);
    umilib_ffi_buffer_free(&text);
    umilib_protocol_jwt_jwt_claims_free(read);
    umilib_protocol_jwt_jwt_free(verified);

    /* RFC 8725 section 3.1: only the algorithms allowed; RFC 7519 section 4.1.4: exp. */
    umilib_protocol_jwt_JWT* refused = NULL;
    const umilib_ffi_Status* status = umilib_protocol_jwt_jwt_verify(token.data, token.length, key, other, validation, &refused);
    CHECK(status != NULL && strcmp(status->name, "AlgorithmNotAllowed") == 0);
    umilib_protocol_jwt_JWTValidation* late = NULL;
    CHECK(umilib_protocol_jwt_jwt_validation_new(2000000000, &late) == NULL);
    status = umilib_protocol_jwt_jwt_verify(token.data, token.length, key, config, late, &refused);
    CHECK(status != NULL && strcmp(status->name, "Expired") == 0 && strcmp(status->domain, "protocol.jwt") == 0);
    umilib_ffi_buffer_free(&token);

    /* A JWE of the claims with AES Key Wrap and AES-GCM, and its JSON serialization. */
    umilib_protocol_jwt_JOSEHeader* encryption = NULL;
    CHECK(umilib_protocol_jwt_jose_header_decode(TEXT("{\"alg\":\"A128KW\",\"enc\":\"A128GCM\",\"typ\":\"JWT\"}"), &encryption) == NULL);
    umilib_protocol_jwt_JWK* wrapping = NULL;
    CHECK(umilib_protocol_jwt_jwk_symmetric(secret, 16, &wrapping) == NULL);
    CHECK(umilib_protocol_jwt_jwt_encrypt(claims, encryption, wrapping, random, TEXT(random_type), &token) == NULL);
    const uint8_t algorithms[] = {A128KW};
    const uint8_t encryptions[] = {A128GCM};
    umilib_protocol_jwt_JWEConfig* decryption = NULL;
    CHECK(umilib_protocol_jwt_jwe_config_new(algorithms, 1, encryptions, 1, &decryption) == NULL);
    umilib_protocol_jwt_JWT* decrypted = NULL;
    CHECK(umilib_protocol_jwt_jwt_decrypt(token.data, token.length, wrapping, decryption, validation, random, TEXT(random_type), &decrypted) == NULL);
    umilib_protocol_jwt_jwt_free(decrypted);
    umilib_protocol_jwt_JWE* jwe = NULL;
    CHECK(umilib_protocol_jwt_jwe_from_compact(token.data, token.length, &jwe) == NULL);
    umilib_ffi_Buffer json = {0};
    CHECK(umilib_protocol_jwt_jwe_to_json(jwe, true, &json) == NULL);
    umilib_protocol_jwt_JWE* again = NULL;
    CHECK(umilib_protocol_jwt_jwe_from_json(json.data, json.length, &again) == NULL);
    umilib_ffi_Buffer plaintext = {0};
    size_t recipient = 1;
    CHECK(umilib_protocol_jwt_jwe_decrypt(again, wrapping, decryption, random, TEXT(random_type), &plaintext, &recipient) == NULL);
    CHECK(recipient == 0 && plaintext.length > 0 && ((const char*)plaintext.data)[0] == '{');
    umilib_ffi_buffer_free(&plaintext);
    umilib_ffi_buffer_free(&json);
    umilib_ffi_buffer_free(&token);

    umilib_protocol_jwt_jwe_free(again);
    umilib_protocol_jwt_jwe_free(jwe);
    umilib_protocol_jwt_jwe_config_free(decryption);
    umilib_protocol_jwt_jwk_free(wrapping);
    umilib_protocol_jwt_jose_header_free(encryption);
    umilib_protocol_jwt_jwt_validation_free(late);
    umilib_protocol_jwt_jwt_validation_free(validation);
    umilib_protocol_jwt_jws_config_free(other);
    umilib_protocol_jwt_jws_config_free(config);
    umilib_protocol_jwt_jwk_free(key);
    umilib_protocol_jwt_jose_header_free(header);
    umilib_protocol_jwt_jwt_claims_free(claims);
    umilib_crypto_random_hmac_drbg_free(random);
    return 0;
}

static int ip(void) {
    /* RFC 5952 section 4: the canonical text of an address. */
    umilib_protocol_ip_IPv6Address v6;
    CHECK(umilib_protocol_ip_ipv6_address_parse(TEXT("2001:0DB8:0:0:1:0:0:1"), &v6) == NULL);
    umilib_ffi_Buffer text = {0};
    CHECK(umilib_protocol_ip_ipv6_address_to_string(v6, &text) == NULL);
    CHECK(text.length == strlen("2001:db8::1:0:0:1") && memcmp(text.data, "2001:db8::1:0:0:1", text.length) == 0);
    umilib_ffi_buffer_free(&text);
    CHECK(umilib_protocol_ip_ipv6_address_is_documentation(v6));
    umilib_protocol_ip_IPv4Address source;
    umilib_protocol_ip_IPv4Address destination;
    CHECK(umilib_protocol_ip_ipv4_address_parse(TEXT("192.0.2.1"), &source) == NULL);
    CHECK(umilib_protocol_ip_ipv4_address_parse(TEXT("192.0.2.2"), &destination) == NULL);
    CHECK(umilib_protocol_ip_ipv4_address_parse(TEXT("192.0.2.01"), &source) != NULL);
    CHECK(source.octets[3] == 1);

    /* RFC 1071 section 3: the sum of the example is ddf2. */
    static const uint8_t example[8] = {0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7};
    umilib_protocol_ip_InternetChecksum checksum = {0};
    CHECK(umilib_protocol_ip_internet_checksum_update(&checksum, example, 3) == NULL);
    CHECK(umilib_protocol_ip_internet_checksum_update(&checksum, example + 3, 5) == NULL);
    CHECK(umilib_protocol_ip_internet_checksum_sum16(checksum) == 0xDDF2);
    /* RFC 1624 section 4. */
    CHECK(umilib_protocol_ip_internet_checksum_adjust(0xDD2F, 0x5555, 0x3285) == 0x0000);

    /* A datagram of 100 bytes cut for an MTU of 48 (24 data bytes a fragment, the last 28), reassembled in reverse order. */
    uint8_t data[100];
    for (size_t index = 0; index < sizeof data; index++) {
        data[index] = (uint8_t)index;
    }
    umilib_protocol_ip_v4_IPv4Header header;
    CHECK(umilib_protocol_ip_v4_ipv4_header_new(source, destination, 17, sizeof data, &header) == NULL);
    umilib_ffi_Buffer bytes = {0};
    CHECK(umilib_protocol_ip_v4_ipv4_header_encode(&header, &bytes) == NULL);
    CHECK(bytes.length == 20 && bytes.data[0] == 0x45 && bytes.data[9] == 17);
    umilib_protocol_ip_v4_IPv4Header decoded;
    size_t offset = 0;
    size_t length = 0;
    CHECK(umilib_protocol_ip_v4_ipv4_header_decode(bytes.data, bytes.length, &decoded, &offset, &length) != NULL);
    umilib_ffi_buffer_free(&bytes);
    umilib_protocol_ip_v4_IPv4Fragmenter* fragmenter = NULL;
    CHECK(umilib_protocol_ip_v4_ipv4_fragmenter_new(&header, data, sizeof data, 48, &fragmenter) == NULL);
    umilib_protocol_ip_v4_IPv4Header fragments[8];
    size_t offsets[8];
    size_t lengths[8];
    size_t count = 0;
    bool found = true;
    while (count < 8) {
        CHECK(umilib_protocol_ip_v4_ipv4_fragmenter_next(fragmenter, &found, &fragments[count], &offsets[count], &lengths[count]) == NULL);
        if (!found) {
            break;
        }
        count++;
    }
    umilib_protocol_ip_v4_ipv4_fragmenter_free(fragmenter);
    CHECK(count == 4 && lengths[0] == 24 && lengths[3] == 28 && fragments[0].more_fragments && !fragments[3].more_fragments);
    umilib_protocol_ip_v4_IPv4ReassemblyConfig config;
    CHECK(umilib_protocol_ip_v4_ipv4_reassembly_config_default(&config) == NULL);
    CHECK(config.timeout == 60000000000ULL);
    umilib_protocol_ip_v4_IPv4Reassembler* reassembler = NULL;
    CHECK(umilib_protocol_ip_v4_ipv4_reassembler_new(config, &reassembler) == NULL);
    bool complete = false;
    umilib_protocol_ip_v4_IPv4Header whole;
    umilib_ffi_Buffer reassembled = {0};
    for (size_t index = count; index-- > 0;) {
        CHECK(umilib_protocol_ip_v4_ipv4_reassembler_receive(reassembler, &fragments[index], data + offsets[index], lengths[index], 0, &complete, &whole, &reassembled) == NULL);
        CHECK(complete == (index == 0));
    }
    CHECK(reassembled.length == sizeof data && memcmp(reassembled.data, data, sizeof data) == 0);
    CHECK(whole.total_length == 120 && !umilib_protocol_ip_v4_ipv4_header_is_fragment(whole));
    umilib_ffi_buffer_free(&reassembled);
    umilib_protocol_ip_v4_ipv4_reassembler_free(reassembler);

    /* An IPv6 header followed by a Hop-by-Hop Options header with a Router Alert. */
    static const uint8_t alert[4] = {5, 2, 0, 0};
    umilib_ffi_Buffer options = {0};
    CHECK(umilib_protocol_ip_v6_ipv6_options_header_encode(58, alert, sizeof alert, &options) == NULL);
    CHECK(options.length == 8 && options.data[0] == 58 && options.data[1] == 0);
    uint8_t next = 0;
    size_t position = 0;
    size_t header_length = 0;
    CHECK(umilib_protocol_ip_v6_ipv6_extension_headers_next(&next, options.data, options.length, &position, &found, &header_length) == NULL);
    CHECK(found && next == 58 && position == 8 && header_length == 8);
    uint8_t kind = 0;
    size_t option_offset = 0;
    umilib_ffi_Buffer option = {0};
    CHECK(umilib_protocol_ip_v6_ipv6_options_header_get(options.data, options.length, 0, &found, &kind, &option_offset, &option) == NULL);
    CHECK(found && kind == 5 && option_offset == 2 && option.length == 2);
    umilib_ffi_buffer_free(&option);
    umilib_ffi_buffer_free(&options);
    return 0;
}

static int ethernet_arp(void) {
    /* RFC 2464 section 4. */
    umilib_protocol_ethernet_MACAddress mac;
    CHECK(umilib_protocol_ethernet_mac_address_parse(TEXT("34-56-78-9A-BC-DE"), &mac) == NULL);
    uint8_t identifier[8];
    CHECK(umilib_protocol_ethernet_mac_address_modified_eui64(mac, identifier) == NULL);
    static const uint8_t expected[8] = {0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE};
    CHECK(memcmp(identifier, expected, 8) == 0);

    /* A broadcast ARP request in a frame with a VLAN tag (IEEE 802.1Q). */
    umilib_protocol_ethernet_MACAddress local;
    CHECK(umilib_protocol_ethernet_mac_address_parse(TEXT("02:00:00:00:00:0a"), &local) == NULL);
    umilib_protocol_ip_IPv4Address sender;
    umilib_protocol_ip_IPv4Address target;
    CHECK(umilib_protocol_ip_ipv4_address_parse(TEXT("192.0.2.1"), &sender) == NULL);
    CHECK(umilib_protocol_ip_ipv4_address_parse(TEXT("192.0.2.2"), &target) == NULL);
    umilib_protocol_arp_ARPPacket request = umilib_protocol_arp_arp_packet_ethernet_request(local, sender, target);
    umilib_protocol_ethernet_EthernetHeader header = {0};
    memset(header.destination.octets, 0xFF, 6);
    header.source = local;
    header.tags[0] = umilib_protocol_ethernet_vlan_tag_from_control(0x8100, 100);
    header.tag_count = 1;
    header.ether_type = 0x0806;
    umilib_ffi_Buffer frame = {0};
    CHECK(umilib_protocol_ethernet_ethernet_header_encode(&header, &frame) == NULL);
    CHECK(frame.length == 18 && frame.data[12] == 0x81 && frame.data[15] == 100 && frame.data[16] == 0x08);
    umilib_ffi_Buffer packet = {0};
    CHECK(umilib_protocol_arp_arp_packet_encode(request, &packet) == NULL);
    uint8_t bytes[46] = {0};
    memcpy(bytes, frame.data, frame.length);
    memcpy(bytes + frame.length, packet.data, packet.length);
    umilib_ffi_buffer_free(&frame);
    umilib_ffi_buffer_free(&packet);
    umilib_protocol_ethernet_EthernetHeader decoded;
    size_t offset = 0;
    size_t length = 0;
    CHECK(umilib_protocol_ethernet_ethernet_header_decode(bytes, sizeof bytes, &decoded, &offset, &length) == NULL);
    CHECK(decoded.tag_count == 1 && decoded.tags[0].identifier == 100 && decoded.ether_type == 0x0806 && offset == 18);
    umilib_protocol_arp_ARPPacket received;
    CHECK(umilib_protocol_arp_arp_packet_decode(bytes + offset, length, &received) == NULL);
    CHECK(received.operation == 1 && memcmp(received.target_protocol.octets, target.octets, 4) == 0);

    /* RFC 826: the target answers and learns the sender. */
    umilib_protocol_arp_ARPConfig config;
    CHECK(umilib_protocol_arp_arp_config_default(&config) == NULL);
    umilib_protocol_arp_ARPCache* cache = NULL;
    CHECK(umilib_protocol_arp_arp_cache_new(config, &cache) == NULL);
    umilib_protocol_ethernet_MACAddress hardware;
    CHECK(umilib_protocol_ethernet_mac_address_parse(TEXT("02:00:00:00:00:0b"), &hardware) == NULL);
    umilib_protocol_arp_ARPReception* reception = NULL;
    CHECK(umilib_protocol_arp_arp_cache_receive(cache, received, hardware, &target, 1, 0, &reception) == NULL);
    bool found = false;
    umilib_protocol_arp_ARPPacket reply;
    CHECK(umilib_protocol_arp_arp_reception_reply(reception, &found, &reply) == NULL);
    CHECK(found && reply.operation == 2 && memcmp(reply.sender_hardware.octets, hardware.octets, 6) == 0);
    CHECK(memcmp(reply.target_hardware.octets, local.octets, 6) == 0);
    umilib_protocol_arp_arp_reception_free(reception);
    umilib_protocol_ethernet_MACAddress learned;
    CHECK(umilib_protocol_arp_arp_cache_lookup(cache, sender, 0, &found, &learned) == NULL);
    CHECK(found && memcmp(learned.octets, local.octets, 6) == 0);
    umilib_protocol_arp_arp_cache_free(cache);
    return 0;
}

static int icmp(void) {
    /* RFC 792: an Echo Request and its reply, with their checksums. */
    umilib_protocol_icmp_ICMPHeader request = umilib_protocol_icmp_v4_icmpv4_message_echo_request(0x1234, 7);
    static const uint8_t data[4] = {'p', 'i', 'n', 'g'};
    umilib_ffi_Buffer bytes = {0};
    CHECK(umilib_protocol_icmp_v4_icmpv4_message_encode(request, data, sizeof data, &bytes) == NULL);
    CHECK(bytes.length == 12 && bytes.data[0] == 8 && bytes.data[4] == 0x12 && bytes.data[7] == 7);
    umilib_protocol_icmp_ICMPHeader decoded;
    CHECK(umilib_protocol_icmp_v4_icmpv4_message_decode(bytes.data, bytes.length, &decoded) == NULL);
    bytes.data[11] ^= 1;
    const umilib_ffi_Status* status = umilib_protocol_icmp_v4_icmpv4_message_decode(bytes.data, bytes.length, &decoded);
    CHECK(status != NULL && strcmp(status->name, "Checksum") == 0 && strcmp(status->domain, "protocol.icmp") == 0);
    umilib_ffi_buffer_free(&bytes);
    bool found = false;
    umilib_protocol_icmp_ICMPHeader reply;
    CHECK(umilib_protocol_icmp_v4_icmpv4_message_echo_reply(request, &found, &reply) == NULL);
    CHECK(found && reply.kind == 0 && memcmp(reply.rest, request.rest, 4) == 0);

    /* RFC 4861 section 7.2: a host resolves a neighbor with a Neighbor Solicitation. */
    umilib_protocol_ip_IPv6Address host;
    umilib_protocol_ip_IPv6Address neighbor;
    umilib_protocol_ip_IPv6Address group;
    CHECK(umilib_protocol_ip_ipv6_address_parse(TEXT("fe80::1"), &host) == NULL);
    CHECK(umilib_protocol_ip_ipv6_address_parse(TEXT("fe80::2"), &neighbor) == NULL);
    CHECK(umilib_protocol_ip_ipv6_address_parse(TEXT("ff02::1:ff00:2"), &group) == NULL);
    CHECK(umilib_protocol_icmp_v6_ndp_message_is_solicited_node(group));
    umilib_protocol_icmp_v6_NeighborConfig config;
    CHECK(umilib_protocol_icmp_v6_neighbor_config_default(&config) == NULL);
    CHECK(config.reachable_time == 30000000000u && config.maximum_multicast_solicitations == 3);
    umilib_protocol_icmp_v6_NeighborCache* cache = NULL;
    CHECK(umilib_protocol_icmp_v6_neighbor_cache_new(config, &cache) == NULL);
    static const uint8_t packet[3] = {1, 2, 3};
    uint8_t kind = 9;
    uint8_t link[6] = {0};
    CHECK(umilib_protocol_icmp_v6_neighbor_cache_resolve(cache, neighbor, packet, sizeof packet, 1, &kind, link) == NULL);
    CHECK(kind == 1);
    static const uint8_t local[6] = {2, 0, 0, 0, 0, 1};
    umilib_ffi_Buffer option = {0};
    CHECK(umilib_protocol_icmp_v6_ndp_option_encode(1, local, sizeof local, &option) == NULL);
    umilib_ffi_Buffer solicitation = {0};
    CHECK(umilib_protocol_icmp_v6_ndp_neighbor_solicitation_encode(neighbor, option.data, option.length, host, group, &solicitation) == NULL);
    umilib_ffi_buffer_free(&option);
    umilib_protocol_ip_v6_IPv6Header header;
    CHECK(umilib_protocol_ip_v6_ipv6_header_new(host, group, 58, solicitation.length, &header) == NULL);
    header.hop_limit = 255;
    CHECK(umilib_protocol_icmp_v6_icmpv6_message_decode(solicitation.data, solicitation.length, host, group, &decoded) == NULL);
    CHECK(decoded.kind == 135);
    umilib_protocol_ip_IPv6Address target;
    size_t offset = 0;
    CHECK(umilib_protocol_icmp_v6_ndp_neighbor_solicitation_decode(decoded, solicitation.data + 8, solicitation.length - 8, &header, &target, &offset) == NULL);
    CHECK(memcmp(target.octets, neighbor.octets, 16) == 0 && offset == 16);
    header.hop_limit = 254;
    status = umilib_protocol_icmp_v6_ndp_neighbor_solicitation_decode(decoded, solicitation.data + 8, solicitation.length - 8, &header, &target, &offset);
    CHECK(status != NULL && strcmp(status->name, "Invalid") == 0);
    umilib_ffi_buffer_free(&solicitation);

    /* The solicited advertisement releases the packet and resolves the neighbor. */
    static const uint8_t remote[6] = {2, 0, 0, 0, 0, 2};
    umilib_ffi_Buffer target_option = {0};
    CHECK(umilib_protocol_icmp_v6_ndp_option_encode(2, remote, sizeof remote, &target_option) == NULL);
    umilib_protocol_icmp_v6_NDPNeighborAdvertisement advertisement = {false, true, true, neighbor};
    umilib_protocol_icmp_v6_NeighborPackets* released = NULL;
    bool no_longer_router = true;
    CHECK(umilib_protocol_icmp_v6_neighbor_cache_receive_advertisement(cache, &advertisement, target_option.data, target_option.length, 2, &released, &no_longer_router) == NULL);
    CHECK(!no_longer_router);
    umilib_ffi_buffer_free(&target_option);
    size_t count = 0;
    CHECK(umilib_protocol_icmp_v6_neighbor_packets_count(released, &count) == NULL && count == 1);
    umilib_ffi_Buffer first = {0};
    CHECK(umilib_protocol_icmp_v6_neighbor_packets_get(released, 0, &first) == NULL);
    CHECK(first.length == 3 && memcmp(first.data, packet, 3) == 0);
    umilib_ffi_buffer_free(&first);
    umilib_protocol_icmp_v6_neighbor_packets_free(released);
    CHECK(umilib_protocol_icmp_v6_neighbor_cache_resolve(cache, neighbor, NULL, 0, 3, &kind, link) == NULL);
    CHECK(kind == 0 && memcmp(link, remote, 6) == 0);
    uint8_t state = 9;
    CHECK(umilib_protocol_icmp_v6_neighbor_cache_lookup(cache, neighbor, &found, &state, link) == NULL);
    CHECK(found && state == 1);

    /* RFC 4861 section 6.2.6: a Router Solicitation makes a router a host, and the change is reported. */
    umilib_protocol_icmp_v6_NeighborPackets* learned = NULL;
    CHECK(umilib_protocol_icmp_v6_neighbor_cache_learn(cache, host, local, 2, 4, &learned, &no_longer_router) == NULL);
    CHECK(!no_longer_router);
    umilib_protocol_icmp_v6_neighbor_packets_free(learned);
    CHECK(umilib_protocol_icmp_v6_neighbor_cache_learn(cache, host, NULL, 1, 5, &learned, &no_longer_router) == NULL);
    CHECK(no_longer_router);
    umilib_protocol_icmp_v6_neighbor_packets_free(learned);
    status = umilib_protocol_icmp_v6_neighbor_cache_learn(cache, host, NULL, 3, 6, &learned, &no_longer_router);
    CHECK(status != NULL && strcmp(status->name, "InvalidArgument") == 0);
    umilib_protocol_icmp_v6_neighbor_cache_free(cache);

    /* RFC 4443 section 2.4 (e.3): no error about a multicast but Packet Too Big. */
    umilib_protocol_ip_v6_IPv6Header udp;
    CHECK(umilib_protocol_ip_v6_ipv6_header_new(host, group, 17, 8, &udp) == NULL);
    static const uint8_t datagram[8] = {0};
    umilib_protocol_icmp_ICMPHeader unreachable = {1, 4, {0, 0, 0, 0}};
    umilib_protocol_icmp_ICMPHeader too_big = {2, 0, {0, 0, 5, 0}};
    bool allowed = true;
    CHECK(umilib_protocol_icmp_v6_icmpv6_message_may_report(&udp, datagram, sizeof datagram, false, unreachable, &allowed) == NULL);
    CHECK(!allowed);
    CHECK(umilib_protocol_icmp_v6_icmpv6_message_may_report(&udp, datagram, sizeof datagram, false, too_big, &allowed) == NULL);
    CHECK(allowed);

    /* RFC 4191 section 2.2: the flags without a field of their own are kept. */
    umilib_protocol_icmp_v6_NDPRouterAdvertisement router = {64, false, true, 3, 0x24, 30, 0, 0};
    umilib_ffi_Buffer advertised = {0};
    CHECK(umilib_protocol_icmp_v6_ndp_router_advertisement_encode(&router, NULL, 0, host, group, &advertised) == NULL);
    CHECK(advertised.length == 16 && advertised.data[5] == (0x40 | 0x18 | 0x24));
    umilib_protocol_ip_v6_IPv6Header carrier;
    CHECK(umilib_protocol_ip_v6_ipv6_header_new(host, group, 58, advertised.length, &carrier) == NULL);
    carrier.hop_limit = 255;
    CHECK(umilib_protocol_icmp_v6_icmpv6_message_decode(advertised.data, advertised.length, host, group, &decoded) == NULL);
    umilib_protocol_icmp_v6_NDPRouterAdvertisement read;
    CHECK(umilib_protocol_icmp_v6_ndp_router_advertisement_decode(decoded, advertised.data + 8, advertised.length - 8, &carrier, &read, &offset) == NULL);
    CHECK(read.flags == 0x24 && read.preference == 3 && read.other_flag && read.router_lifetime == 30);
    umilib_ffi_buffer_free(&advertised);
    router.flags = 0x80;
    status = umilib_protocol_icmp_v6_ndp_router_advertisement_encode(&router, NULL, 0, host, group, &advertised);
    CHECK(status != NULL && strcmp(status->name, "Invalid") == 0);
    return 0;
}

static int udp(void) {
    /* RFC 768: a datagram over IPv6 with its checksum, read back. */
    static const uint8_t source[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t destination[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    static const uint8_t payload[5] = {'h', 'e', 'l', 'l', 'o'};
    umilib_protocol_udp_UDPDatagram datagram = {40000, 53, true};
    umilib_ffi_Buffer bytes = {0};
    CHECK(umilib_protocol_udp_udp_datagram_encode(datagram, payload, sizeof payload, source, 16, destination, 16, NULL, 0, &bytes) == NULL);
    CHECK(bytes.length == 13 && bytes.data[2] == 0 && bytes.data[3] == 53 && bytes.data[5] == 13);
    umilib_protocol_udp_UDPDatagram read;
    size_t length = 0;
    CHECK(umilib_protocol_udp_udp_datagram_decode(bytes.data, bytes.length, source, 16, destination, 16, NULL, 0, &read, &length) == NULL);
    CHECK(read.source_port == 40000 && read.checksummed && length == 5);
    umilib_protocol_udp_UDPHeader header;
    CHECK(umilib_protocol_udp_udp_header_decode(bytes.data, bytes.length, &header) == NULL);
    CHECK(header.length == 13 && header.checksum != 0);
    bytes.data[12] ^= 1;
    const umilib_ffi_Status* status = umilib_protocol_udp_udp_datagram_decode(bytes.data, bytes.length, source, 16, destination, 16, NULL, 0, &read, &length);
    CHECK(status != NULL && strcmp(status->name, "Checksum") == 0 && strcmp(status->domain, "protocol.udp") == 0);
    umilib_ffi_buffer_free(&bytes);

    /* RFC 6936 section 4: no zero checksum over IPv6 but from the ports that allow it. */
    datagram.checksummed = false;
    status = umilib_protocol_udp_udp_datagram_encode(datagram, payload, sizeof payload, source, 16, destination, 16, NULL, 0, &bytes);
    CHECK(status != NULL && strcmp(status->name, "ZeroChecksum") == 0);
    static const uint16_t tunnel[1] = {40000};
    CHECK(umilib_protocol_udp_udp_datagram_header(datagram, payload, sizeof payload, source, 16, destination, 16, tunnel, 1, &header) == NULL);
    CHECK(header.checksum == 0);

    /* A rule routes by endpoints (RFC 3986 section 3.2.2 for the text). */
    umilib_protocol_ip_IPEndpoint local;
    umilib_protocol_ip_IPEndpoint remote;
    CHECK(umilib_protocol_ip_ip_endpoint_parse(TEXT("[2001:db8::2]:53"), &local) == NULL);
    CHECK(umilib_protocol_ip_ip_endpoint_parse(TEXT("192.0.2.9:40000"), &remote) == NULL);
    CHECK(local.length == 16 && local.port == 53 && remote.length == 4);
    umilib_ffi_Buffer text = {0};
    CHECK(umilib_protocol_ip_ip_endpoint_to_string(&local, &text) == NULL);
    CHECK(text.length == strlen("[2001:db8::2]:53") && memcmp(text.data, "[2001:db8::2]:53", text.length) == 0);
    umilib_ffi_buffer_free(&text);
    umilib_protocol_udp_UDPRule rule = {{{0}, 0, 0, 53, 53}, {{0}, 0, 0, 0, 65535}};
    bool matches = false;
    CHECK(umilib_protocol_udp_udp_rule_matches(&rule, &local, &remote, &matches) == NULL);
    CHECK(matches);
    rule.remote.length = 4;
    rule.remote.prefix_length = 24;
    rule.remote.octets[0] = 198;
    CHECK(umilib_protocol_udp_udp_rule_matches(&rule, &local, &remote, &matches) == NULL);
    CHECK(!matches);
    return 0;
}

/* Moves every segment `from` has to send to `to`; returns -1 on an error, else how many moved. */
static int tcp_deliver(umilib_protocol_tcp_TCPConnection* from, umilib_protocol_tcp_TCPConnection* to, const uint8_t* source, const uint8_t* destination, uint64_t now) {
    int count = 0;
    for (;;) {
        bool found = false;
        bool ect = false;
        umilib_ffi_Buffer bytes = {0};
        if (umilib_protocol_tcp_tcp_connection_transmit(from, now, &found, &bytes, &ect) != NULL) {
            return -1;
        }
        if (!found) {
            umilib_ffi_buffer_free(&bytes);
            return count;
        }
        umilib_protocol_tcp_TCPSegment segment;
        size_t options_offset = 0;
        size_t options_length = 0;
        size_t payload_offset = 0;
        size_t payload_length = 0;
        if (umilib_protocol_tcp_tcp_segment_decode(bytes.data, bytes.length, source, 4, destination, 4, &segment, &options_offset, &options_length, &payload_offset, &payload_length) != NULL) {
            return -1;
        }
        if (umilib_protocol_tcp_tcp_connection_receive(to, &segment, bytes.data + options_offset, options_length, bytes.data + payload_offset, payload_length, false, now) != NULL) {
            return -1;
        }
        umilib_ffi_buffer_free(&bytes);
        count += 1;
    }
}

static int tcp(void) {
    /* RFC 9293 section 3.5: a handshake, data, and a close, between two connections. */
    static const uint8_t client_address[4] = {192, 0, 2, 1};
    static const uint8_t server_address[4] = {192, 0, 2, 2};
    umilib_protocol_ip_IPEndpoint client;
    umilib_protocol_ip_IPEndpoint server;
    CHECK(umilib_protocol_ip_ip_endpoint_parse(TEXT("192.0.2.1:40000"), &client) == NULL);
    CHECK(umilib_protocol_ip_ip_endpoint_parse(TEXT("192.0.2.2:80"), &server) == NULL);
    umilib_protocol_tcp_TCPConfig config;
    CHECK(umilib_protocol_tcp_tcp_config_default(&config) == NULL);
    CHECK(config.mtu == 1500 && config.time_wait == 240000000000u && !config.keepalive);
    static const uint8_t key[16] = {1};
    umilib_protocol_tcp_TCPISNGenerator* isn = NULL;
    CHECK(umilib_protocol_tcp_tcp_isn_generator_new(key, &isn) == NULL);
    uint32_t iss = 0;
    CHECK(umilib_protocol_tcp_tcp_isn_generator_generate(isn, &client, &server, 0, &iss) == NULL);
    umilib_protocol_tcp_tcp_isn_generator_free(isn);
    umilib_protocol_tcp_TCPConnection* a = NULL;
    CHECK(umilib_protocol_tcp_tcp_connection_connect(&config, &client, &server, iss, 0, &a) == NULL);
    /* The SYN, read back, opens the other end as a listener would. */
    bool found = false;
    bool ect = false;
    umilib_ffi_Buffer syn = {0};
    CHECK(umilib_protocol_tcp_tcp_connection_transmit(a, 0, &found, &syn, &ect) == NULL && found && !ect);
    umilib_protocol_tcp_TCPSegment segment;
    size_t options_offset = 0;
    size_t options_length = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
    CHECK(umilib_protocol_tcp_tcp_segment_decode(syn.data, syn.length, client_address, 4, server_address, 4, &segment, &options_offset, &options_length, &payload_offset, &payload_length) == NULL);
    CHECK(segment.flags == 0x02 && segment.sequence == iss && options_length == 20);
    umilib_protocol_tcp_TCPOptionSet options;
    CHECK(umilib_protocol_tcp_tcp_option_set_decode(syn.data + options_offset, options_length, &options) == NULL);
    CHECK(options.has_mss && options.mss == 1460 && options.sack_permitted && options.has_timestamps);
    umilib_protocol_tcp_TCPConnection* b = NULL;
    CHECK(umilib_protocol_tcp_tcp_connection_accept(&config, &server, &client, &segment, syn.data + options_offset, options_length, NULL, 0, 7, 0, &b) == NULL);
    umilib_ffi_buffer_free(&syn);
    CHECK(tcp_deliver(b, a, server_address, client_address, 1) == 1);
    CHECK(tcp_deliver(a, b, client_address, server_address, 2) == 1);
    umilib_protocol_tcp_TCPConnectionInfo info;
    CHECK(umilib_protocol_tcp_tcp_connection_info(a, &info) == NULL);
    CHECK(info.state == 4 && info.sack && info.timestamps && info.window_scaling && info.mtu == 1500);
    uint8_t kind = 9;
    uint8_t reason = 9;
    CHECK(umilib_protocol_tcp_tcp_connection_poll_event(b, &found, &kind, &reason) == NULL && found && kind == 0);
    /* Data from A to B. */
    size_t taken = 0;
    CHECK(umilib_protocol_tcp_tcp_connection_send(a, (const uint8_t*)"hello, tcp", 10, false, &taken) == NULL && taken == 10);
    CHECK(tcp_deliver(a, b, client_address, server_address, 3) == 1);
    uint8_t read[16];
    size_t count = 0;
    CHECK(umilib_protocol_tcp_tcp_connection_read(b, read, sizeof read, &count) == NULL && count == 10 && memcmp(read, "hello, tcp", 10) == 0);
    /* A closes, B closes: TIME-WAIT and CLOSED (RFC 9293 Figure 12). */
    CHECK(umilib_protocol_tcp_tcp_connection_close(a) == NULL);
    CHECK(tcp_deliver(a, b, client_address, server_address, 4) == 1);
    CHECK(tcp_deliver(b, a, server_address, client_address, 5) == 1);
    CHECK(umilib_protocol_tcp_tcp_connection_close(b) == NULL);
    CHECK(tcp_deliver(b, a, server_address, client_address, 6) == 1);
    CHECK(tcp_deliver(a, b, client_address, server_address, 7) == 1);
    CHECK(umilib_protocol_tcp_tcp_connection_info(a, &info) == NULL && info.state == 10);
    umilib_protocol_tcp_TCPConnectionInfo closed;
    CHECK(umilib_protocol_tcp_tcp_connection_info(b, &closed) == NULL && closed.state == 0);
    /* The send half is closed: State. */
    const umilib_ffi_Status* status = umilib_protocol_tcp_tcp_connection_send(a, (const uint8_t*)"x", 1, false, &taken);
    CHECK(status != NULL && strcmp(status->name, "State") == 0 && strcmp(status->domain, "protocol.tcp") == 0);
    umilib_protocol_tcp_tcp_connection_free(a);
    umilib_protocol_tcp_tcp_connection_free(b);
    /* RFC 9293 section 3.10.7.1: the reset of a segment for no connection. */
    umilib_protocol_tcp_TCPSegment ack = {80, 40000, 5, 77, 0x10, 0, 0};
    umilib_protocol_tcp_TCPSegment reset;
    CHECK(umilib_protocol_tcp_tcp_segment_reset_reply(&ack, NULL, 0, NULL, 0, &found, &reset) == NULL && found);
    CHECK(reset.flags == 0x04 && reset.sequence == 77 && reset.source_port == 40000);
    /* RFC 6298: the timer. */
    umilib_protocol_tcp_TCPRetransmissionTimer timer;
    CHECK(umilib_protocol_tcp_tcp_retransmission_timer_new(1000000000u, 1000000000u, 60000000000u, 1000000u, &timer) == NULL);
    CHECK(umilib_protocol_tcp_tcp_retransmission_timer_expire(&timer) == NULL);
    CHECK(umilib_protocol_tcp_tcp_retransmission_timer_current(timer) == 2000000000u);
    /* A listener on port 80 (RFC 9293 section 3.10.7.2), and a configuration that cannot work. */
    umilib_protocol_ip_IPEndpointPattern pattern = {{0}, 0, 0, 80, 80};
    umilib_protocol_tcp_TCPListener* listener = NULL;
    CHECK(umilib_protocol_tcp_tcp_listener_new(&config, &pattern, 4, key, &listener) == NULL);
    bool matches = false;
    CHECK(umilib_protocol_tcp_tcp_listener_matches(listener, &server, &matches) == NULL && matches);
    CHECK(umilib_protocol_tcp_tcp_listener_matches(listener, &client, &matches) == NULL && !matches);
    umilib_protocol_tcp_tcp_listener_free(listener);
    umilib_protocol_tcp_TCPConfig broken = config;
    broken.receive_buffer = 0;
    status = umilib_protocol_tcp_tcp_listener_new(&broken, &pattern, 4, key, &listener);
    CHECK(status != NULL && strcmp(status->name, "Config") == 0);
    return 0;
}

int main(void) {
    if (jwt() != 0 || ip() != 0 || ethernet_arp() != 0 || icmp() != 0 || udp() != 0 || tcp() != 0) {
        return 1;
    }
    printf("protocol: ok\n");
    return 0;
}
