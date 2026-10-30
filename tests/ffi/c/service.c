/* Routes byte requests to services of C callbacks through a router of the generated headers. */
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

/* A service that answers with its name, a space and the request; or fails if its name is empty. */
typedef struct {
    const char* name;
    int calls;
    int dropped;
} Named;

static bool call_named(void* context, const uint8_t* request, size_t length, umilib_service_Response* response) {
    Named* named = context;
    named->calls++;
    if (named->name[0] == '\0') {
        return false;
    }
    return umilib_service_response_write(response, (const uint8_t*)named->name, strlen(named->name)) == NULL &&
           umilib_service_response_write(response, (const uint8_t*)" ", 1) == NULL &&
           umilib_service_response_write(response, request, length) == NULL;
}

static void drop_named(void* context) {
    ((Named*)context)->dropped++;
}

static umilib_service_Pattern* parse(const char* text) {
    umilib_service_Pattern* pattern = NULL;
    return umilib_service_pattern_parse((const uint8_t*)text, strlen(text), &pattern) == NULL ? pattern : NULL;
}

/* Calls the router with `request` and checks the answer (NULL: the status named `status`). */
static int expect(umilib_service_Router* router, const char* request, const char* answer, const char* status) {
    umilib_ffi_Buffer out = {0};
    const umilib_ffi_Status* result = umilib_service_router_call(router, (const uint8_t*)request, strlen(request), &out);
    if (answer != NULL) {
        int same = result == NULL && out.length == strlen(answer) && memcmp(out.data, answer, out.length) == 0;
        umilib_ffi_buffer_free(&out);
        return same;
    }
    return result != NULL && strcmp(result->name, status) == 0;
}

int main(void) {
    /* Patterns and their text. */
    umilib_service_Pattern* host = parse("*.example.com");
    CHECK(host != NULL);
    bool matches = false;
    CHECK(umilib_service_pattern_matches_bytes(host, (const uint8_t*)"auth.example.com", 16, &matches) == NULL && matches);
    CHECK(umilib_service_pattern_matches_bytes(host, (const uint8_t*)"auth.EXAMPLE.com", 16, &matches) == NULL && !matches);
    umilib_service_Pattern* folded = NULL;
    CHECK(umilib_service_pattern_ignoring_ascii_case(host, true, &folded) == NULL);
    CHECK(umilib_service_pattern_ignores_ascii_case(folded, &matches) == NULL && matches);
    CHECK(umilib_service_pattern_matches_bytes(folded, (const uint8_t*)"auth.EXAMPLE.com", 16, &matches) == NULL && matches);
    umilib_ffi_Buffer text = {0};
    CHECK(umilib_service_pattern_format(host, &text) == NULL);
    CHECK(text.length == 13 && memcmp(text.data, "*.example.com", 13) == 0);
    umilib_ffi_buffer_free(&text);
    /* A failed parse writes no pattern. */
    umilib_service_Pattern* bad = host;
    const umilib_ffi_Status* status = umilib_service_pattern_parse((const uint8_t*)"a*b", 3, &bad);
    CHECK(status != NULL && strcmp(status->name, "MisplacedWildcard") == 0 && bad == host);
    status = umilib_service_pattern_parse((const uint8_t*)"a\\", 2, &bad);
    CHECK(status != NULL && strcmp(status->name, "UnfinishedEscape") == 0);

    /* A router: the first matching route answers, then the fallback. */
    Named oauth = {"oauth", 0, 0}, api = {"api", 0, 0}, failing = {"", 0, 0}, fallback = {"fallback", 0, 0};
    umilib_service_Router* router = NULL;
    CHECK(umilib_service_router_new(&router) == NULL);
    umilib_service_Pattern* oauth_path = parse("/oauth/*");
    umilib_service_Pattern* api_path = parse("/api/*");
    umilib_service_Pattern* broken = parse("/broken");
    CHECK(umilib_service_router_push(router, oauth_path, call_named, drop_named, &oauth) == NULL);
    CHECK(umilib_service_router_push(router, api_path, call_named, drop_named, &api) == NULL);
    CHECK(umilib_service_router_push(router, broken, call_named, drop_named, &failing) == NULL);
    CHECK(umilib_service_router_push(router, api_path, NULL, NULL, NULL) != NULL);
    size_t routes = 0;
    CHECK(umilib_service_router_len(router, &routes) == NULL && routes == 3);
    CHECK(expect(router, "/oauth/token", "oauth /oauth/token", NULL));
    CHECK(expect(router, "/api/v1", "api /api/v1", NULL));
    CHECK(expect(router, "/broken", NULL, "Failed"));
    CHECK(expect(router, "/missing", NULL, "Unrouted"));
    /* A fallback replaced is dropped. */
    Named replaced = {"replaced", 0, 0};
    CHECK(umilib_service_router_set_fallback(router, call_named, drop_named, &replaced) == NULL);
    CHECK(umilib_service_router_set_fallback(router, call_named, drop_named, &fallback) == NULL);
    CHECK(replaced.dropped == 1 && replaced.calls == 0);
    CHECK(expect(router, "/missing", "fallback /missing", NULL));
    /* A failed push adds nothing and does not drop: the caller keeps its context. */
    Named kept = {"kept", 0, 0};
    CHECK(umilib_service_router_push(router, NULL, call_named, drop_named, &kept) != NULL);
    CHECK(umilib_service_router_len(router, &routes) == NULL && routes == 3 && kept.dropped == 0);
    CHECK(umilib_service_response_write(NULL, (const uint8_t*)"x", 1) != NULL);
    CHECK(oauth.calls == 1 && api.calls == 1 && failing.calls == 1 && fallback.calls == 1);
    /* Removing the fallback drops it. */
    CHECK(umilib_service_router_set_fallback(router, NULL, NULL, NULL) == NULL);
    CHECK(fallback.dropped == 1);
    CHECK(expect(router, "/missing", NULL, "Unrouted"));

    umilib_service_router_free(router);
    CHECK(oauth.dropped == 1 && api.dropped == 1 && failing.dropped == 1 && fallback.dropped == 1);
    umilib_service_pattern_free(oauth_path);
    umilib_service_pattern_free(api_path);
    umilib_service_pattern_free(broken);
    umilib_service_pattern_free(folded);
    umilib_service_pattern_free(host);
    umilib_service_pattern_free(NULL);
    umilib_service_router_free(NULL);
    printf("service: ok\n");
    return 0;
}
