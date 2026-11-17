/*
 * The interface between the Wafio WAF agent and a semantic engine in a shared library, version 2.
 *
 * The agent loads the library with dlopen and resolves the symbols below. Nothing else crosses: no Rust type, no
 * allocation made on one side is freed on the other. 64-bit little-endian targets only.
 *
 * Order of calls. The agent calls wafio_engine_interface_version first and stops when the number is not 2. It
 * then calls wafio_engine_identity, resolves the rest, and calls wafio_engine_init once. Only after that does it
 * create handles and scan. Every function may be called from any thread at the same time, except init.
 *
 * Status. Functions that return int32_t return 0 on success. 1 means a panic was caught inside the library and
 * the call has no result; 2 means a null pointer or an encoding the library does not understand; 3 means failure.
 * A library never lets a panic cross the boundary.
 *
 * Memory. Every pointer an argument carries is borrowed for the duration of the call only. A handle is an opaque
 * number; the agent frees the ones it creates, once, when no call uses them. Results come back in a wafio_out_buf:
 * the caller offers memory, the library writes there when the result fits, and otherwise allocates its own and sets
 * owned. The caller then reads the bytes and calls wafio_engine_buffer_free. The byte encodings are in the
 * header of crates/engine-abi/src/wire.rs and the configuration row in crates/engine-abi/src/config.rs.
 *
 * Version rule. Any change of a layout, a symbol, an encoding or the meaning of a field raises the version.
 * The agent loads a library of exactly its own version.
 */
#ifndef WAFIO_ENGINE_H
#define WAFIO_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WAFIO_ENGINE_INTERFACE_VERSION 2u
#define WAFIO_ENGINE_CONFIG_WORDS 29u

#define WAFIO_STATUS_OK 0
#define WAFIO_STATUS_PANIC 1
#define WAFIO_STATUS_BAD_ARGUMENT 2
#define WAFIO_STATUS_FAILED 3

#define WAFIO_SCAN_ALL_HEADERS (1u << 0)
#define WAFIO_SCAN_REGEX_INCOMPLETE (1u << 1)
#define WAFIO_SCAN_RUN (1u << 2)

#define WAFIO_LOG_ERROR 1u
#define WAFIO_LOG_WARN 2u
#define WAFIO_LOG_INFO 3u
#define WAFIO_LOG_DEBUG 4u

struct wafio_slice {
    const uint8_t *ptr; /* may be NULL when len is 0 */
    size_t len;
};

struct wafio_header {
    struct wafio_slice name;
    struct wafio_slice value; /* a name with several values appears once per value, in arrival order */
};

struct wafio_request {
    struct wafio_slice method;
    struct wafio_slice uri; /* the raw request target, path and query */
    struct wafio_slice content_type;
    struct wafio_slice body;
    struct wafio_slice body_scan_skipped; /* UTF-8, empty when the whole body was handed over */
    const struct wafio_header *headers; /* sorted by name bytes, the values of one name adjacent */
    size_t header_count;
};

struct wafio_scan_args {
    uint64_t config;   /* from wafio_engine_config_new */
    uint64_t baseline; /* from wafio_engine_baseline_new, or 0 */
    struct wafio_request request;
    struct wafio_slice normalized_input;
    struct wafio_slice forwarded_path;
    struct wafio_slice project_id;
    uint32_t flags;
    uint32_t reserved; /* zero */
};

struct wafio_out_buf {
    uint8_t *ptr;
    size_t cap;
    size_t len;
    uint32_t owned; /* non-zero: the library allocated ptr; call wafio_engine_buffer_free */
    uint32_t reserved;
};

struct wafio_identity {
    struct wafio_slice name;         /* "wafio-semantic-engine" for the official engine */
    struct wafio_slice version;      /* the build version of the library */
    struct wafio_slice api_revision; /* the revision of wafio-engine-api it was built against */
};

struct wafio_counters {
    uint64_t recovered_panics;
    uint64_t exhausted_parse_budgets;
};

struct wafio_bot_seeds {
    const struct wafio_slice *ja4_block;
    size_t ja4_block_len;
    const struct wafio_slice *ja4_allow;
    size_t ja4_allow_len;
};

struct wafio_config_out {
    uint64_t handle;
};

struct wafio_host_api {
    void (*log)(uint32_t level, const uint8_t *msg, size_t len); /* may be NULL */
};

_Static_assert(sizeof(struct wafio_slice) == 16, "wafio_slice");
_Static_assert(sizeof(struct wafio_header) == 32, "wafio_header");
_Static_assert(sizeof(struct wafio_request) == 96, "wafio_request");
_Static_assert(sizeof(struct wafio_scan_args) == 168, "wafio_scan_args");
_Static_assert(sizeof(struct wafio_out_buf) == 32, "wafio_out_buf");
_Static_assert(sizeof(struct wafio_identity) == 48, "wafio_identity");
_Static_assert(sizeof(struct wafio_counters) == 16, "wafio_counters");
_Static_assert(sizeof(struct wafio_bot_seeds) == 32, "wafio_bot_seeds");
_Static_assert(sizeof(struct wafio_config_out) == 8, "wafio_config_out");
_Static_assert(sizeof(struct wafio_host_api) == 8, "wafio_host_api");

/* The first call. */
uint32_t wafio_engine_interface_version(void);
/* The second call: fills name, version and api_revision with static strings of the library. */
int32_t wafio_engine_identity(struct wafio_identity *out);
/* Once, before any other call below. On failure writes a message of at most err_cap bytes and its length. */
int32_t wafio_engine_init(const struct wafio_host_api *host, uint8_t *err, size_t err_cap, size_t *err_len);

/* The extra SSRF hosts and suffixes (encoding in wire.rs). One handle can serve many configurations. */
int32_t wafio_engine_ssrf_new(const uint8_t *blob, size_t len, uint64_t *out);
void wafio_engine_ssrf_free(uint64_t handle);

/* A scan configuration: a row of WAFIO_ENGINE_CONFIG_WORDS words (config.rs), a field name (normally empty), and the
 * SSRF handle the row refers to (0 for none). */
int32_t wafio_engine_config_new(const uint64_t *words, size_t n_words, const uint8_t *field_name,
                                size_t field_name_len, uint64_t ssrf, struct wafio_config_out *out);
void wafio_engine_config_free(uint64_t handle);

/* The baseline of query parameter names of one application. */
int32_t wafio_engine_baseline_new(uint64_t *out);
int32_t wafio_engine_baseline_observe(uint64_t handle, const uint8_t *project, size_t project_len,
                                      const uint8_t *param, size_t param_len, uint8_t *is_new);
void wafio_engine_baseline_free(uint64_t handle);

/* The semantic stage of one request. The outcome is in the encoding of wire.rs. */
int32_t wafio_engine_scan_request(const struct wafio_scan_args *args, struct wafio_out_buf *out);
/* The values of a WebSocket frame worth a scan. */
int32_t wafio_engine_frame_fields(const uint8_t *payload, size_t len, struct wafio_out_buf *out);
/* One value, for the frames of a WebSocket. */
int32_t wafio_engine_scan_value(uint64_t config, const uint8_t *value, size_t len, struct wafio_out_buf *out);
/* Whether a GraphQL body holds more operations than max_batch (0: the default limit). */
int32_t wafio_engine_graphql_batch_over_limit(const uint8_t *body, size_t len, int64_t max_batch, uint8_t *over);
/* Where in the request a non-blocking decision most likely points: the bytes of the source, no framing. */
int32_t wafio_engine_guess_match_source(const struct wafio_request *request, struct wafio_out_buf *out);
/* Whether a header value holds text that looks like an attack. */
int32_t wafio_engine_header_value_looks_suspicious(const uint8_t *value, size_t len, uint8_t *suspicious);
/* Gives the calling thread the stack budget the engines may recurse into. */
int32_t wafio_engine_prepare_thread(uint64_t stack_budget_bytes);
int32_t wafio_engine_counters(struct wafio_counters *out);
/* Arrays in static memory of the library, valid until the process ends. */
int32_t wafio_engine_bot_seeds(struct wafio_bot_seeds *out);
/* Frees a buffer with owned set. */
void wafio_engine_buffer_free(struct wafio_out_buf *buf);

#ifdef __cplusplus
}
#endif

#endif
