/* Generates and checks one-time passwords (RFC 4226 and RFC 6238 values), and keys, certificates, CRLs,
   certification requests, OCSP responses and certification paths of the X.509 public-key infrastructure
   through the generated headers. */
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

/* The keys of umilib::auth::cert::key: generation, signatures, encodings and errors. */
static int keys(void) {
    umilib_crypto_random_HMACDRBG* random = NULL;
    CHECK(umilib_crypto_random_hmac_drbg_new(TEXT("umilib_hash_sha_v2_SHA256"), TEXT("0123456789abcdef0123456789abcdef"), TEXT("nonce of 16 byte"), TEXT(""), &random) == NULL);
    const char* random_type = "umilib_crypto_random_HMACDRBG";

    /* Ed25519 (kind 5) and ECDSA on P-256 (kind 2, curve 0) with SHA-256 (hash 2). */
    umilib_auth_cert_key_KeyAlgorithm* ed25519 = NULL;
    umilib_auth_cert_key_KeyAlgorithm* p256 = NULL;
    CHECK(umilib_auth_cert_key_key_algorithm_new(5, 0, &ed25519) == NULL);
    CHECK(umilib_auth_cert_key_key_algorithm_new(2, 0, &p256) == NULL);
    CHECK(umilib_auth_cert_key_key_algorithm_new(11, 0, &p256) != NULL);
    umilib_auth_cert_key_SignatureAlgorithm* eddsa = NULL;
    umilib_auth_cert_key_SignatureAlgorithm* ecdsa = NULL;
    CHECK(umilib_auth_cert_key_signature_algorithm_ed25519(&eddsa) == NULL);
    CHECK(umilib_auth_cert_key_signature_algorithm_ecdsa(2, &ecdsa) == NULL);
    bool signs = false;
    CHECK(umilib_auth_cert_key_key_algorithm_signs(p256, ecdsa, &signs) == NULL && signs);
    CHECK(umilib_auth_cert_key_key_algorithm_signs(p256, eddsa, &signs) == NULL && !signs);

    umilib_auth_cert_key_PrivateKey* key = NULL;
    CHECK(umilib_auth_cert_key_private_key_generate(ed25519, random, TEXT(random_type), &key) == NULL);
    umilib_ffi_Buffer signature = {0};
    CHECK(umilib_auth_cert_key_private_key_sign(key, eddsa, TEXT("message"), random, TEXT(random_type), &signature) == NULL);
    CHECK(signature.length == 64);
    umilib_auth_cert_key_PublicKey* public_key = NULL;
    CHECK(umilib_auth_cert_key_private_key_public_key(key, &public_key) == NULL);
    CHECK(umilib_auth_cert_key_public_key_verify(public_key, eddsa, TEXT("message"), signature.data, signature.length) == NULL);
    const umilib_ffi_Status* status = umilib_auth_cert_key_public_key_verify(public_key, eddsa, TEXT("messagf"), signature.data, signature.length);
    CHECK(status != NULL && strcmp(status->name, "InvalidSignature") == 0);
    status = umilib_auth_cert_key_public_key_verify(public_key, ecdsa, TEXT("message"), signature.data, signature.length);
    CHECK(status != NULL && strcmp(status->name, "Mismatch") == 0);
    umilib_ffi_buffer_free(&signature);

    /* PEM of both keys, and an encrypted PKCS #8 (PRF SHA-256 = 2, AES-256-CBC = 2). */
    umilib_ffi_Buffer pem = {0};
    CHECK(umilib_auth_cert_key_public_key_to_pem(public_key, &pem) == NULL);
    umilib_auth_cert_key_PublicKey* parsed = NULL;
    CHECK(umilib_auth_cert_key_public_key_from_pem(pem.data, pem.length, &parsed) == NULL);
    umilib_ffi_buffer_free(&pem);
    umilib_auth_cert_key_PBES2Config config = {2, 2, 1000, 16, 100000};
    umilib_ffi_Buffer encrypted = {0};
    CHECK(umilib_auth_cert_key_private_key_to_encrypted_pkcs8_der(key, TEXT("password"), config, random, TEXT(random_type), &encrypted) == NULL);
    umilib_auth_cert_key_PrivateKey* decrypted = NULL;
    CHECK(umilib_auth_cert_key_private_key_from_encrypted_pkcs8_der(encrypted.data, encrypted.length, TEXT("password"), config, &decrypted) == NULL);
    umilib_auth_cert_key_PrivateKey* refused = NULL;
    status = umilib_auth_cert_key_private_key_from_encrypted_pkcs8_der(encrypted.data, encrypted.length, TEXT("wrong"), config, &refused);
    CHECK(status != NULL && strcmp(status->name, "Decryption") == 0 && refused == NULL);
    umilib_ffi_buffer_free(&encrypted);

    /* ECDSA: the signature algorithm round-trips through its DER AlgorithmIdentifier. */
    umilib_auth_cert_key_PrivateKey* ec = NULL;
    CHECK(umilib_auth_cert_key_private_key_generate(p256, random, TEXT(random_type), &ec) == NULL);
    umilib_ffi_Buffer identifier = {0};
    CHECK(umilib_auth_cert_key_signature_algorithm_to_der(ecdsa, &identifier) == NULL);
    umilib_auth_cert_key_SignatureAlgorithm* again = NULL;
    CHECK(umilib_auth_cert_key_signature_algorithm_from_der(identifier.data, identifier.length, &again) == NULL);
    umilib_ffi_buffer_free(&identifier);
    CHECK(umilib_auth_cert_key_private_key_sign(ec, again, TEXT("message"), random, TEXT(random_type), &signature) == NULL);
    umilib_auth_cert_key_PublicKey* ec_public = NULL;
    CHECK(umilib_auth_cert_key_private_key_public_key(ec, &ec_public) == NULL);
    CHECK(umilib_auth_cert_key_public_key_verify(ec_public, ecdsa, TEXT("message"), signature.data, signature.length) == NULL);
    umilib_ffi_buffer_free(&signature);
    status = umilib_auth_cert_key_public_key_from_der((const uint8_t*)"\x30\x00", 2, &parsed);
    CHECK(status != NULL && strcmp(status->name, "Encoding") == 0);

    umilib_auth_cert_key_public_key_free(ec_public);
    umilib_auth_cert_key_private_key_free(ec);
    umilib_auth_cert_key_signature_algorithm_free(again);
    umilib_auth_cert_key_private_key_free(decrypted);
    umilib_auth_cert_key_public_key_free(parsed);
    umilib_auth_cert_key_public_key_free(public_key);
    umilib_auth_cert_key_private_key_free(key);
    umilib_auth_cert_key_signature_algorithm_free(ecdsa);
    umilib_auth_cert_key_signature_algorithm_free(eddsa);
    umilib_auth_cert_key_key_algorithm_free(p256);
    umilib_auth_cert_key_key_algorithm_free(ed25519);
    umilib_crypto_random_hmac_drbg_free(random);
    umilib_auth_cert_key_private_key_free(NULL);
    return 0;
}

/* Certificates, CRLs and requests of umilib::auth::cert::x509 and csr: building, signing, reading and errors. */
static int certificates(void) {
    const int64_t january_2026 = 1767225600, january_2036 = 2082758400;
    umilib_crypto_random_HMACDRBG* random = NULL;
    CHECK(umilib_crypto_random_hmac_drbg_new(TEXT("umilib_hash_sha_v2_SHA256"), TEXT("0123456789abcdef0123456789abcdef"), TEXT("nonce of 16 byte"), TEXT(""), &random) == NULL);
    const char* random_type = "umilib_crypto_random_HMACDRBG";
    umilib_auth_cert_key_KeyAlgorithm* ed25519 = NULL;
    CHECK(umilib_auth_cert_key_key_algorithm_new(5, 0, &ed25519) == NULL);
    umilib_auth_cert_key_SignatureAlgorithm* eddsa = NULL;
    CHECK(umilib_auth_cert_key_signature_algorithm_ed25519(&eddsa) == NULL);
    umilib_auth_cert_key_PrivateKey* key = NULL;
    CHECK(umilib_auth_cert_key_private_key_generate(ed25519, random, TEXT(random_type), &key) == NULL);
    umilib_auth_cert_key_PublicKey* public_key = NULL;
    CHECK(umilib_auth_cert_key_private_key_public_key(key, &public_key) == NULL);

    /* A name of two relative names: NameAttribute::ALL[3] is the country, [0] the common name. */
    umilib_auth_cert_x509_Name *empty = NULL, *country = NULL, *name = NULL;
    CHECK(umilib_auth_cert_x509_name_empty(&empty) == NULL);
    CHECK(umilib_auth_cert_x509_name_append(empty, 3, TEXT("JP"), &country) == NULL);
    CHECK(umilib_auth_cert_x509_name_append(country, 0, TEXT("c.example"), &name) == NULL);
    umilib_auth_cert_x509_Name* refused_name = NULL;
    const umilib_ffi_Status* status = umilib_auth_cert_x509_name_append(empty, 3, TEXT("JPN"), &refused_name);
    CHECK(status != NULL && strcmp(status->name, "InvalidName") == 0);
    umilib_ffi_Buffer text = {0};
    CHECK(umilib_auth_cert_x509_name_to_rfc4514(name, &text) == NULL);
    CHECK(text.length == strlen("CN=c.example,C=JP") && memcmp(text.data, "CN=c.example,C=JP", text.length) == 0);
    umilib_ffi_buffer_free(&text);

    /* The extensions of a CA. */
    umilib_auth_cert_x509_Extensions* extensions = NULL;
    CHECK(umilib_auth_cert_x509_extensions_new(&extensions) == NULL);
    umilib_ffi_Buffer value = {0};
    CHECK(umilib_auth_cert_x509_basic_constraints_encode(true, true, 0, &value) == NULL);
    CHECK(umilib_auth_cert_x509_extensions_push(extensions, TEXT("2.5.29.19"), true, value.data, value.length) == NULL);
    status = umilib_auth_cert_x509_extensions_push(extensions, TEXT("2.5.29.19"), true, value.data, value.length);
    CHECK(status != NULL && strcmp(status->name, "DuplicateExtension") == 0);
    umilib_ffi_buffer_free(&value);
    CHECK(umilib_auth_cert_x509_key_usage_encode(0x60, &value) == NULL);
    CHECK(value.length == 4 && value.data[2] == 0x01 && value.data[3] == 0x06);
    CHECK(umilib_auth_cert_x509_extensions_push(extensions, TEXT("2.5.29.15"), true, value.data, value.length) == NULL);
    umilib_ffi_buffer_free(&value);
    umilib_auth_cert_x509_GeneralNames* names = NULL;
    CHECK(umilib_auth_cert_x509_general_names_new(&names) == NULL);
    CHECK(umilib_auth_cert_x509_general_names_push(names, 2, TEXT("c.example")) == NULL);
    const uint8_t address[4] = {192, 0, 2, 1};
    CHECK(umilib_auth_cert_x509_general_names_push(names, 7, address, sizeof address) == NULL);
    CHECK(umilib_auth_cert_x509_general_names_to_der(names, &value) == NULL);
    CHECK(umilib_auth_cert_x509_extensions_push(extensions, TEXT("2.5.29.17"), false, value.data, value.length) == NULL);
    umilib_ffi_buffer_free(&value);

    /* A self-signed certificate. */
    umilib_ffi_Buffer serial = {0};
    CHECK(umilib_auth_cert_x509_serial_number_random(random, TEXT(random_type), &serial) == NULL);
    CHECK(serial.length <= 20 && (serial.data[0] & 0x80) == 0);
    umilib_auth_cert_x509_TBSCertificate* tbs = NULL;
    CHECK(umilib_auth_cert_x509_tbs_certificate_new(2, serial.data, serial.length, eddsa, name, january_2026, january_2036, name, public_key, extensions, &tbs) == NULL);
    umilib_auth_cert_x509_Certificate* certificate = NULL;
    CHECK(umilib_auth_cert_x509_tbs_certificate_sign(tbs, key, random, TEXT(random_type), &certificate) == NULL);
    CHECK(umilib_auth_cert_x509_certificate_verify(certificate, public_key) == NULL);
    bool self_issued = false;
    CHECK(umilib_auth_cert_x509_certificate_is_self_issued(certificate, &self_issued) == NULL && self_issued);
    umilib_ffi_Buffer pem = {0};
    CHECK(umilib_auth_cert_x509_certificate_to_pem(certificate, &pem) == NULL);
    umilib_auth_cert_x509_Certificate* parsed = NULL;
    CHECK(umilib_auth_cert_x509_certificate_from_pem(pem.data, pem.length, &parsed) == NULL);
    umilib_ffi_buffer_free(&pem);
    int64_t not_before = 0, not_after = 0;
    CHECK(umilib_auth_cert_x509_certificate_validity(parsed, &not_before, &not_after) == NULL);
    CHECK(not_before == january_2026 && not_after == january_2036);
    uint8_t version = 0;
    CHECK(umilib_auth_cert_x509_certificate_version(parsed, &version) == NULL && version == 2);
    umilib_auth_cert_x509_Extensions* read = NULL;
    CHECK(umilib_auth_cert_x509_certificate_extensions(parsed, &read) == NULL);
    size_t count = 0, index = 0;
    CHECK(umilib_auth_cert_x509_extensions_count(read, &count) == NULL && count == 3);
    bool found = false;
    CHECK(umilib_auth_cert_x509_extensions_find(read, TEXT("2.5.29.19"), &found, &index) == NULL && found && index == 0);
    umilib_ffi_Buffer oid = {0};
    bool critical = false;
    CHECK(umilib_auth_cert_x509_extensions_get(read, index, &oid, &critical, &value) == NULL && critical);
    bool ca = false, has_path_length = false;
    uint32_t path_length = 99;
    CHECK(umilib_auth_cert_x509_basic_constraints_decode(value.data, value.length, &ca, &has_path_length, &path_length) == NULL);
    CHECK(ca && has_path_length && path_length == 0);
    umilib_ffi_buffer_free(&oid);
    umilib_ffi_buffer_free(&value);
    CHECK(umilib_auth_cert_x509_extensions_find(read, TEXT("2.5.29.37"), &found, &index) == NULL && !found);
    /* Outputs are written only on success: a null output fails before any is written. */
    umilib_ffi_Buffer untouched = {0};
    status = umilib_auth_cert_x509_extensions_get(read, 0, &untouched, NULL, &value);
    CHECK(status != NULL && strcmp(status->name, "NullPointer") == 0 && untouched.data == NULL && value.data == NULL);
    /* A v1 certificate cannot have extensions. */
    umilib_auth_cert_x509_TBSCertificate* v1 = NULL;
    CHECK(umilib_auth_cert_x509_tbs_certificate_new(0, serial.data, serial.length, eddsa, name, january_2026, january_2036, name, public_key, extensions, &v1) == NULL);
    status = umilib_auth_cert_x509_tbs_certificate_check(v1);
    CHECK(status != NULL && strcmp(status->name, "Version") == 0);

    /* A CRL that revokes the certificate. */
    umilib_auth_cert_x509_Extensions *crl_extensions = NULL, *entry_extensions = NULL;
    CHECK(umilib_auth_cert_x509_extensions_new(&crl_extensions) == NULL);
    const uint8_t crl_number[1] = {7};
    CHECK(umilib_auth_cert_x509_crl_number_encode(crl_number, sizeof crl_number, &value) == NULL);
    CHECK(umilib_auth_cert_x509_extensions_push(crl_extensions, TEXT("2.5.29.20"), false, value.data, value.length) == NULL);
    umilib_ffi_buffer_free(&value);
    CHECK(umilib_auth_cert_x509_extensions_new(&entry_extensions) == NULL);
    CHECK(umilib_auth_cert_x509_crl_reason_encode(1, &value) == NULL);
    CHECK(umilib_auth_cert_x509_extensions_push(entry_extensions, TEXT("2.5.29.21"), false, value.data, value.length) == NULL);
    umilib_ffi_buffer_free(&value);
    CHECK(umilib_auth_cert_x509_crl_reason_encode(7, &value) != NULL);
    umilib_auth_cert_x509_TBSCertList* tbs_list = NULL;
    CHECK(umilib_auth_cert_x509_tbs_cert_list_new(1, eddsa, name, january_2026, true, january_2036, crl_extensions, &tbs_list) == NULL);
    CHECK(umilib_auth_cert_x509_tbs_cert_list_push(tbs_list, serial.data, serial.length, january_2026, entry_extensions) == NULL);
    umilib_auth_cert_x509_CertificateList* list = NULL;
    CHECK(umilib_auth_cert_x509_tbs_cert_list_sign(tbs_list, key, random, TEXT(random_type), &list) == NULL);
    CHECK(umilib_auth_cert_x509_certificate_list_verify(list, public_key) == NULL);
    CHECK(umilib_auth_cert_x509_certificate_list_find(list, serial.data, serial.length, &found, &index) == NULL && found && index == 0);
    CHECK(umilib_auth_cert_x509_certificate_list_next_update(list, &found, &not_after) == NULL && found && not_after == january_2036);

    /* A request for the key. */
    umilib_auth_cert_csr_CertificationRequestInfo* info = NULL;
    CHECK(umilib_auth_cert_csr_certification_request_info_new(name, public_key, extensions, &info) == NULL);
    umilib_auth_cert_csr_CertificationRequest* request = NULL;
    CHECK(umilib_auth_cert_csr_certification_request_info_sign(info, key, eddsa, random, TEXT(random_type), &request) == NULL);
    CHECK(umilib_auth_cert_csr_certification_request_verify(request) == NULL);
    umilib_auth_cert_x509_Extensions* requested = NULL;
    CHECK(umilib_auth_cert_csr_certification_request_extensions(request, &requested) == NULL);
    CHECK(umilib_auth_cert_x509_extensions_count(requested, &count) == NULL && count == 3);

    umilib_auth_cert_x509_extensions_free(requested);
    umilib_auth_cert_csr_certification_request_free(request);
    umilib_auth_cert_csr_certification_request_info_free(info);
    umilib_auth_cert_x509_certificate_list_free(list);
    umilib_auth_cert_x509_tbs_cert_list_free(tbs_list);
    umilib_auth_cert_x509_extensions_free(entry_extensions);
    umilib_auth_cert_x509_extensions_free(crl_extensions);
    umilib_auth_cert_x509_tbs_certificate_free(v1);
    umilib_auth_cert_x509_extensions_free(read);
    umilib_auth_cert_x509_certificate_free(parsed);
    umilib_auth_cert_x509_certificate_free(certificate);
    umilib_auth_cert_x509_tbs_certificate_free(tbs);
    umilib_ffi_buffer_free(&serial);
    umilib_auth_cert_x509_general_names_free(names);
    umilib_auth_cert_x509_extensions_free(extensions);
    umilib_auth_cert_x509_name_free(name);
    umilib_auth_cert_x509_name_free(country);
    umilib_auth_cert_x509_name_free(empty);
    umilib_auth_cert_x509_certificate_free(NULL);
    umilib_auth_cert_key_public_key_free(public_key);
    umilib_auth_cert_key_private_key_free(key);
    umilib_auth_cert_key_signature_algorithm_free(eddsa);
    umilib_auth_cert_key_key_algorithm_free(ed25519);
    umilib_crypto_random_hmac_drbg_free(random);
    return 0;
}

/* A certificate of the subject `name`, its key `public_key` and the extensions `extensions`, issued and signed by
   `issuer_key` in the name `issuer`, valid from 2026 through 2035. */
static umilib_auth_cert_x509_Certificate* issue(umilib_auth_cert_x509_Name* issuer, umilib_auth_cert_key_PrivateKey* issuer_key, umilib_auth_cert_x509_Name* name, umilib_auth_cert_key_PublicKey* public_key, umilib_auth_cert_x509_Extensions* extensions, uint8_t serial, umilib_crypto_random_HMACDRBG* random) {
    umilib_auth_cert_key_SignatureAlgorithm* eddsa = NULL;
    umilib_auth_cert_x509_TBSCertificate* tbs = NULL;
    umilib_auth_cert_x509_Certificate* certificate = NULL;
    if (umilib_auth_cert_key_signature_algorithm_ed25519(&eddsa) == NULL &&
        umilib_auth_cert_x509_tbs_certificate_new(2, &serial, 1, eddsa, issuer, 1767225600, 2082758400, name, public_key, extensions, &tbs) == NULL) {
        umilib_auth_cert_x509_tbs_certificate_sign(tbs, issuer_key, random, TEXT("umilib_crypto_random_HMACDRBG"), &certificate);
    }
    umilib_auth_cert_x509_tbs_certificate_free(tbs);
    umilib_auth_cert_key_signature_algorithm_free(eddsa);
    return certificate;
}

/* The OCSP of umilib::auth::cert::ocsp (RFC 6960) and the path validation of umilib::auth::cert::path, with the
   response as a revocation source. */
static int statuses_and_paths(void) {
    const int64_t time = 1798761600; /* 2027-01-01 */
    umilib_crypto_random_HMACDRBG* random = NULL;
    CHECK(umilib_crypto_random_hmac_drbg_new(TEXT("umilib_hash_sha_v2_SHA256"), TEXT("0123456789abcdef0123456789abcdef"), TEXT("nonce of 16 byte"), TEXT(""), &random) == NULL);
    const char* random_type = "umilib_crypto_random_HMACDRBG";
    umilib_auth_cert_key_KeyAlgorithm* ed25519 = NULL;
    CHECK(umilib_auth_cert_key_key_algorithm_new(5, 0, &ed25519) == NULL);
    umilib_auth_cert_key_SignatureAlgorithm* eddsa = NULL;
    CHECK(umilib_auth_cert_key_signature_algorithm_ed25519(&eddsa) == NULL);
    umilib_auth_cert_key_PrivateKey *root_key = NULL, *leaf_key = NULL;
    umilib_auth_cert_key_PublicKey *root_public = NULL, *leaf_public = NULL;
    CHECK(umilib_auth_cert_key_private_key_generate(ed25519, random, TEXT(random_type), &root_key) == NULL);
    CHECK(umilib_auth_cert_key_private_key_generate(ed25519, random, TEXT(random_type), &leaf_key) == NULL);
    CHECK(umilib_auth_cert_key_private_key_public_key(root_key, &root_public) == NULL);
    CHECK(umilib_auth_cert_key_private_key_public_key(leaf_key, &leaf_public) == NULL);
    umilib_auth_cert_x509_Name *empty = NULL, *root_name = NULL, *leaf_name = NULL;
    CHECK(umilib_auth_cert_x509_name_empty(&empty) == NULL);
    CHECK(umilib_auth_cert_x509_name_append(empty, 0, TEXT("Root"), &root_name) == NULL);
    CHECK(umilib_auth_cert_x509_name_append(empty, 0, TEXT("leaf.example"), &leaf_name) == NULL);
    umilib_auth_cert_x509_Extensions *ca = NULL, *none = NULL;
    CHECK(umilib_auth_cert_x509_extensions_new(&ca) == NULL);
    CHECK(umilib_auth_cert_x509_extensions_new(&none) == NULL);
    umilib_ffi_Buffer value = {0};
    CHECK(umilib_auth_cert_x509_basic_constraints_encode(true, false, 0, &value) == NULL);
    CHECK(umilib_auth_cert_x509_extensions_push(ca, TEXT("2.5.29.19"), true, value.data, value.length) == NULL);
    umilib_ffi_buffer_free(&value);
    umilib_auth_cert_x509_Certificate* root = issue(root_name, root_key, root_name, root_public, ca, 1, random);
    umilib_auth_cert_x509_Certificate* leaf = issue(root_name, root_key, leaf_name, leaf_public, none, 2, random);
    CHECK(root != NULL && leaf != NULL);

    /* A response of the root: the leaf revoked for keyCompromise (1), by SHA-256 (2) identifiers. */
    umilib_auth_cert_ocsp_CertID* cert_id = NULL;
    CHECK(umilib_auth_cert_ocsp_cert_id_new(leaf, root_public, 2, &cert_id) == NULL);
    bool identifies = false;
    CHECK(umilib_auth_cert_ocsp_cert_id_identifies(cert_id, leaf, root_public, &identifies) == NULL && identifies);
    CHECK(umilib_auth_cert_ocsp_cert_id_identifies(cert_id, root, root_public, &identifies) == NULL && !identifies);
    umilib_auth_cert_ocsp_SingleResponse* single = NULL;
    CHECK(umilib_auth_cert_ocsp_single_response_new(cert_id, 1, time - 86400, 1, time - 60, true, time + 86400, none, &single) == NULL);
    umilib_auth_cert_ocsp_SingleResponse* refused_single = NULL;
    const umilib_ffi_Status* status = umilib_auth_cert_ocsp_single_response_new(cert_id, 3, 0, 255, time, false, 0, none, &refused_single);
    CHECK(status != NULL && strcmp(status->name, "InvalidArgument") == 0);
    umilib_auth_cert_ocsp_ResponseData* data = NULL;
    CHECK(umilib_auth_cert_ocsp_response_data_new_by_name(root_name, time - 60, &data) == NULL);
    CHECK(umilib_auth_cert_ocsp_response_data_push(data, single) == NULL);
    CHECK(umilib_auth_cert_ocsp_response_data_set_nonce(data, TEXT("0123456789abcdef")) == NULL);
    umilib_auth_cert_ocsp_BasicOCSPResponse* basic = NULL;
    CHECK(umilib_auth_cert_ocsp_response_data_sign(data, root_key, eddsa, NULL, random, TEXT(random_type), &basic) == NULL);
    umilib_auth_cert_ocsp_OCSPResponse *response = NULL, *read = NULL;
    CHECK(umilib_auth_cert_ocsp_ocsp_response_new(0, basic, &response) == NULL);
    umilib_ffi_Buffer der = {0};
    CHECK(umilib_auth_cert_ocsp_ocsp_response_to_der(response, &der) == NULL);
    CHECK(umilib_auth_cert_ocsp_ocsp_response_from_der(der.data, der.length, &read) == NULL);
    umilib_ffi_buffer_free(&der);
    uint8_t response_status = 99;
    CHECK(umilib_auth_cert_ocsp_ocsp_response_status(read, &response_status) == NULL && response_status == 0);
    umilib_auth_cert_ocsp_OCSPResponse* refused_response = NULL;
    status = umilib_auth_cert_ocsp_ocsp_response_new(0, NULL, &refused_response);
    CHECK(status != NULL && strcmp(status->name, "ResponseType") == 0);

    /* Its checks (RFC 6960 section 3.2): the nonce, the time and the signer. */
    umilib_auth_cert_ocsp_OCSPConfig* config = NULL;
    CHECK(umilib_auth_cert_ocsp_ocsp_config_new(time, &config) == NULL);
    CHECK(umilib_auth_cert_ocsp_ocsp_config_set_nonce(config, TEXT("0123456789abcdef")) == NULL);
    umilib_auth_cert_ocsp_SingleResponse* verified = NULL;
    CHECK(umilib_auth_cert_ocsp_basic_ocsp_response_verify(basic, cert_id, root_name, root_public, config, &verified) == NULL);
    uint8_t kind = 0, reason = 0;
    int64_t revoked_at = 0;
    CHECK(umilib_auth_cert_ocsp_single_response_status(verified, &kind, &revoked_at, &reason) == NULL);
    CHECK(kind == 1 && revoked_at == time - 86400 && reason == 1);
    umilib_auth_cert_ocsp_SingleResponse* refused_status = NULL;
    CHECK(umilib_auth_cert_ocsp_ocsp_config_set_nonce(config, TEXT("fedcba9876543210")) == NULL);
    status = umilib_auth_cert_ocsp_basic_ocsp_response_verify(basic, cert_id, root_name, root_public, config, &refused_status);
    CHECK(status != NULL && strcmp(status->name, "Nonce") == 0);
    CHECK(umilib_auth_cert_ocsp_ocsp_config_set_nonce(config, NULL, 0) == NULL);
    status = umilib_auth_cert_ocsp_basic_ocsp_response_verify(basic, cert_id, root_name, leaf_public, config, &refused_status);
    CHECK(status != NULL && strcmp(status->name, "Signer") == 0);
    umilib_auth_cert_ocsp_OCSPConfig* late = NULL;
    CHECK(umilib_auth_cert_ocsp_ocsp_config_new(time + 2 * 86400, &late) == NULL);
    status = umilib_auth_cert_ocsp_basic_ocsp_response_verify(basic, cert_id, root_name, root_public, late, &refused_status);
    CHECK(status != NULL && strcmp(status->name, "Time") == 0);

    /* The path from the leaf to the root, with the response as a revocation source. */
    umilib_auth_cert_path_PathConfig* path_config = NULL;
    CHECK(umilib_auth_cert_path_path_config_new(time, &path_config) == NULL);
    CHECK(umilib_auth_cert_path_path_config_set_profile(path_config, 0) == NULL);
    CHECK(umilib_auth_cert_path_path_config_set_profile(path_config, 3) != NULL);
    CHECK(umilib_auth_cert_path_path_config_set_revocation(path_config, true, true, false, 86400) == NULL);
    umilib_auth_cert_path_TrustAnchor* anchor = NULL;
    CHECK(umilib_auth_cert_path_trust_anchor_from_certificate(root, 16384, 64, &anchor) == NULL);
    umilib_auth_cert_path_TrustAnchors* anchors = NULL;
    CHECK(umilib_auth_cert_path_trust_anchors_new(&anchors) == NULL);
    CHECK(umilib_auth_cert_path_trust_anchors_push(anchors, anchor) == NULL);
    umilib_auth_cert_x509_Certificates* intermediates = NULL;
    CHECK(umilib_auth_cert_x509_certificates_new(&intermediates) == NULL);
    umilib_auth_cert_x509_CertificateLists* crls = NULL;
    CHECK(umilib_auth_cert_x509_certificate_lists_new(&crls) == NULL);
    umilib_auth_cert_path_RevocationSources* sources = NULL;
    CHECK(umilib_auth_cert_path_revocation_sources_new(&sources) == NULL);
    CHECK(umilib_auth_cert_ocsp_ocsp_response_add_to(read, sources) == NULL);
    size_t count = 0;
    CHECK(umilib_auth_cert_path_revocation_sources_count(sources, &count) == NULL && count == 1);
    umilib_auth_cert_path_PathOutcome* outcome = NULL;
    CHECK(umilib_auth_cert_path_path_validator_validate(path_config, anchors, intermediates, crls, sources, leaf, &outcome) == NULL);
    bool valid = true;
    const umilib_ffi_Status* reason_status = NULL;
    size_t index = 99;
    uint8_t revocation = 0;
    CHECK(umilib_auth_cert_path_path_outcome_error(outcome, &valid, &reason_status, &index, &revocation) == NULL);
    CHECK(!valid && reason_status != NULL && strcmp(reason_status->name, "Revoked") == 0 && index == 0 && revocation == 1);
    umilib_auth_cert_path_path_outcome_free(outcome);

    /* Without revocation checking the path validates. */
    CHECK(umilib_auth_cert_path_path_config_set_revocation(path_config, false, false, false, 86400) == NULL);
    CHECK(umilib_auth_cert_path_path_validator_validate(path_config, anchors, intermediates, crls, NULL, leaf, &outcome) == NULL);
    CHECK(umilib_auth_cert_path_path_outcome_error(outcome, &valid, &reason_status, &index, &revocation) == NULL);
    CHECK(valid && reason_status == NULL && revocation == 255);
    umilib_auth_cert_x509_Certificates* path = NULL;
    CHECK(umilib_auth_cert_path_path_outcome_certificates(outcome, &path) == NULL);
    CHECK(umilib_auth_cert_x509_certificates_count(path, &count) == NULL && count == 1);
    size_t anchor_index = 99;
    CHECK(umilib_auth_cert_path_path_outcome_anchor(outcome, &anchor_index) == NULL && anchor_index == 0);
    umilib_ffi_Buffer policies = {0};
    CHECK(umilib_auth_cert_path_path_outcome_policies(outcome, &policies) == NULL);
    /* No certificate policies in the leaf: the valid policy tree is NULL (RFC 5280 section 6.1.3 (e)), the set empty. */
    CHECK(policies.length == 0);
    umilib_ffi_buffer_free(&policies);

    umilib_auth_cert_x509_certificates_free(path);
    umilib_auth_cert_path_path_outcome_free(outcome);
    umilib_auth_cert_path_revocation_sources_free(sources);
    umilib_auth_cert_x509_certificate_lists_free(crls);
    umilib_auth_cert_x509_certificates_free(intermediates);
    umilib_auth_cert_path_trust_anchors_free(anchors);
    umilib_auth_cert_path_trust_anchor_free(anchor);
    umilib_auth_cert_path_path_config_free(path_config);
    umilib_auth_cert_ocsp_ocsp_config_free(late);
    umilib_auth_cert_ocsp_ocsp_config_free(config);
    umilib_auth_cert_ocsp_single_response_free(verified);
    umilib_auth_cert_ocsp_ocsp_response_free(read);
    umilib_auth_cert_ocsp_ocsp_response_free(response);
    umilib_auth_cert_ocsp_basic_ocsp_response_free(basic);
    umilib_auth_cert_ocsp_response_data_free(data);
    umilib_auth_cert_ocsp_single_response_free(single);
    umilib_auth_cert_ocsp_cert_id_free(cert_id);
    umilib_auth_cert_x509_certificate_free(leaf);
    umilib_auth_cert_x509_certificate_free(root);
    umilib_auth_cert_x509_extensions_free(none);
    umilib_auth_cert_x509_extensions_free(ca);
    umilib_auth_cert_x509_name_free(leaf_name);
    umilib_auth_cert_x509_name_free(root_name);
    umilib_auth_cert_x509_name_free(empty);
    umilib_auth_cert_key_public_key_free(leaf_public);
    umilib_auth_cert_key_public_key_free(root_public);
    umilib_auth_cert_key_private_key_free(leaf_key);
    umilib_auth_cert_key_private_key_free(root_key);
    umilib_auth_cert_key_signature_algorithm_free(eddsa);
    umilib_auth_cert_key_key_algorithm_free(ed25519);
    umilib_crypto_random_hmac_drbg_free(random);
    return 0;
}

/* SCRAM-SHA-256 (RFC 7677 section 3), PLAIN (RFC 4616 section 4) and the refusals of RFC 5802. */
static int sasl(void) {
    const char* hash = "umilib_hash_sha_v2_SHA256";
    const char* client_first = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    const char* server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const char* client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const char* server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
    static const uint8_t salt[16] = {0x5b, 0x6d, 0x99, 0x68, 0x9d, 0x12, 0x35, 0x8e, 0xec, 0xa0, 0x4b, 0x14, 0x12, 0x36, 0xfa, 0x81};

    umilib_auth_sasl_scram_SCRAMClient* client = NULL;
    CHECK(umilib_auth_sasl_scram_scram_client_new(TEXT(hash), TEXT("user"), TEXT("pencil"), TEXT("rOprNGfwEbeRWgbNEkqO"), &client) == NULL);
    umilib_ffi_Buffer message = {0};
    CHECK(umilib_auth_sasl_scram_scram_client_client_first(client, &message) == NULL);
    CHECK(message.length == strlen(client_first) && memcmp(message.data, client_first, message.length) == 0);
    umilib_ffi_buffer_free(&message);

    umilib_auth_sasl_scram_SCRAMServer* server = NULL;
    CHECK(umilib_auth_sasl_scram_scram_server_new(TEXT(hash), false, &server) == NULL);
    CHECK(umilib_auth_sasl_scram_scram_server_receive_client_first(server, TEXT(client_first)) == NULL);
    bool has = false;
    CHECK(umilib_auth_sasl_scram_scram_server_username(server, &has, &message) == NULL && has);
    CHECK(message.length == 4 && memcmp(message.data, "user", 4) == 0);
    umilib_ffi_buffer_free(&message);
    umilib_auth_sasl_scram_SCRAMCredentials* credentials = NULL;
    CHECK(umilib_auth_sasl_scram_scram_credentials_new(TEXT(hash), TEXT("pencil"), salt, sizeof salt, 4096, &credentials) == NULL);
    CHECK(umilib_auth_sasl_scram_scram_server_server_first(server, credentials, TEXT("%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"), &message) == NULL);
    CHECK(message.length == strlen(server_first) && memcmp(message.data, server_first, message.length) == 0);
    umilib_ffi_buffer_free(&message);
    CHECK(umilib_auth_sasl_scram_scram_client_receive_server_first(client, TEXT(server_first), &message) == NULL);
    CHECK(message.length == strlen(client_final) && memcmp(message.data, client_final, message.length) == 0);
    umilib_ffi_buffer_free(&message);
    CHECK(umilib_auth_sasl_scram_scram_server_receive_client_final(server, TEXT(client_final), &message) == NULL);
    CHECK(message.length == strlen(server_final) && memcmp(message.data, server_final, message.length) == 0);
    umilib_ffi_buffer_free(&message);
    CHECK(umilib_auth_sasl_scram_scram_client_receive_server_final(client, TEXT(server_final)) == NULL);

    /* RFC 5802 section 5.1: m= is a mandatory extension; the server reports it. */
    umilib_auth_sasl_scram_SCRAMServer* other = NULL;
    CHECK(umilib_auth_sasl_scram_scram_server_new(TEXT(hash), false, &other) == NULL);
    const umilib_ffi_Status* status = umilib_auth_sasl_scram_scram_server_receive_client_first(other, TEXT("n,,m=x,n=user,r=abc"));
    CHECK(status != NULL && strcmp(status->name, "ExtensionsNotSupported") == 0 && strcmp(status->domain, "auth.sasl.scram") == 0);

    /* RFC 4616 section 4. */
    umilib_auth_sasl_plain_PLAINMessage* plain = NULL;
    static const uint8_t first[] = {0, 't', 'i', 'm', 0, 't', 'a', 'n', 's', 't', 'a', 'a', 'f', 't', 'a', 'n', 's', 't', 'a', 'a', 'f'};
    CHECK(umilib_auth_sasl_plain_plain_message_decode(first, sizeof first, &plain) == NULL);
    bool verified = false;
    CHECK(umilib_auth_sasl_plain_plain_message_verify_password(plain, TEXT("tanstaaftanstaaf"), &verified) == NULL && verified);
    status = umilib_auth_sasl_plain_plain_message_decode((const uint8_t*)"tim", 3, &plain);
    CHECK(status != NULL && strcmp(status->name, "Format") == 0 && strcmp(status->domain, "auth.sasl") == 0);

    umilib_auth_sasl_plain_plain_message_free(plain);
    umilib_auth_sasl_scram_scram_server_free(other);
    umilib_auth_sasl_scram_scram_credentials_free(credentials);
    umilib_auth_sasl_scram_scram_server_free(server);
    umilib_auth_sasl_scram_scram_client_free(client);
    return 0;
}

int main(void) {
    const char* secret = "12345678901234567890";
    umilib_auth_totp_HOTP* hotp = NULL;
    CHECK(umilib_auth_totp_hotp_new(TEXT("umilib_hash_sha_v1_SHA1"), TEXT(secret), 6, &hotp) == NULL);
    uint8_t code[10];
    size_t written = 0;
    CHECK(umilib_auth_totp_hotp_generate(hotp, 5, code, sizeof code, &written) == NULL);
    CHECK(written == 6 && memcmp(code, "254676", 6) == 0);
    CHECK(umilib_auth_totp_hotp_generate(hotp, 5, code, 5, &written) != NULL);
    bool found = false;
    uint64_t matched = 0;
    CHECK(umilib_auth_totp_hotp_verify(hotp, TEXT("254676"), 3, 2, &found, &matched) == NULL && found && matched == 5);
    CHECK(umilib_auth_totp_hotp_verify(hotp, TEXT("254676"), 3, 1, &found, &matched) == NULL && !found);

    umilib_auth_totp_HOTP* refused = NULL;
    const umilib_ffi_Status* status = umilib_auth_totp_hotp_new(TEXT("umilib_hash_sha_v1_SHA1"), TEXT("short"), 6, &refused);
    CHECK(status != NULL && strcmp(status->name, "KeyTooShort") == 0);
    status = umilib_auth_totp_hotp_new(TEXT("umilib_hash_md_v5_MD5"), TEXT(secret), 6, &refused);
    CHECK(status != NULL && strcmp(status->name, "Hash") == 0);
    status = umilib_auth_totp_hotp_new(TEXT("no such hash"), TEXT(secret), 6, &refused);
    CHECK(status != NULL && strcmp(status->name, "InvalidArgument") == 0);

    umilib_auth_totp_TOTPConfig config = {8, 30, 0};
    umilib_auth_totp_TOTP* totp = NULL;
    CHECK(umilib_auth_totp_totp_new(TEXT("umilib_hash_sha_v2_SHA256"), TEXT("12345678901234567890123456789012"), config, &totp) == NULL);
    CHECK(umilib_auth_totp_totp_generate(totp, 1111111109, code, sizeof code, &written) == NULL);
    CHECK(written == 8 && memcmp(code, "68084774", 8) == 0);
    uint64_t counter = 0;
    CHECK(umilib_auth_totp_totp_counter(totp, 1111111109, &counter) == NULL && counter == 0x23523EC);
    CHECK(umilib_auth_totp_totp_verify(totp, TEXT("68084774"), 1111111111, 1, 0, &found, &matched) == NULL);
    CHECK(found && matched == 0x23523EC);
    umilib_auth_totp_TOTPConfig shifted = {8, 30, 1000};
    umilib_auth_totp_TOTP* late = NULL;
    CHECK(umilib_auth_totp_totp_new(TEXT("umilib_hash_sha_v1_SHA1"), TEXT(secret), shifted, &late) == NULL);
    status = umilib_auth_totp_totp_generate(late, 999, code, sizeof code, &written);
    CHECK(status != NULL && strcmp(status->name, "Time") == 0);
    umilib_auth_totp_TOTPConfig zero = {6, 0, 0};
    status = umilib_auth_totp_totp_new(TEXT("umilib_hash_sha_v1_SHA1"), TEXT(secret), zero, &late);
    CHECK(status != NULL && strcmp(status->name, "Period") == 0);

    if (keys() != 0 || certificates() != 0 || statuses_and_paths() != 0 || sasl() != 0) {
        return 1;
    }
    umilib_auth_totp_totp_free(late);
    umilib_auth_totp_totp_free(totp);
    umilib_auth_totp_hotp_free(hotp);
    umilib_auth_totp_hotp_free(NULL);
    printf("auth: ok\n");
    return 0;
}
