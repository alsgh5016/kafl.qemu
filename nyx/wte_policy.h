#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WTE_FLAG_32BIT (1U << 0)
#define WTE_FLAG_EAGER_NX (1U << 1)
#define WTE_FLAG_STRICT_PT (1U << 2)

#define WTE_STRICT_REQUIRED_FEATURE_MASK UINT64_C(0x1f)
#define WTE_STRICT_ABI_VERSION_1 1U
#define WTE_STRICT_EXIT_REASON 145U
#define WTE_STRICT_EXIT_FIRST_EXEC (1U << 0)
#define WTE_STRICT_EXIT_KNOWN_FLAGS WTE_STRICT_EXIT_FIRST_EXEC
#define WTE_STRICT_MAX_RANGES 64U

struct wte_exec_policy_input {
    bool is_dynamic;
    bool first_exec_pending;
    bool written;
    uint16_t diff_count;
    bool rip_overlaps_diff;
};

struct wte_dynamic_registration_policy_input {
    bool already_dynamic;
    bool baseline_valid;
    bool first_exec_pending;
    bool content_changed;
    bool gfn_changed;
};

enum wte_exec_policy_action {
    WTE_EXEC_POLICY_ACTION_FALLTHROUGH_TO_LEGACY = 0,
    WTE_EXEC_POLICY_ACTION_DUMP_FIRST_EXEC = 1,
};

enum wte_dynamic_registration_policy_action {
    WTE_DYNAMIC_REGISTRATION_POLICY_KEEP_STATE = 0,
    WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC = 1,
    WTE_DYNAMIC_REGISTRATION_POLICY_MAPPING_REFRESH = 2,
};

enum wte_exec_policy_action
wte_exec_policy_decide(const struct wte_exec_policy_input *input);

enum wte_dynamic_registration_policy_action
wte_dynamic_registration_policy_decide(
    const struct wte_dynamic_registration_policy_input *input);

enum wte_strict_result {
    WTE_STRICT_RESULT_OK = 0,
    WTE_STRICT_RESULT_UNSUPPORTED = 1,
    WTE_STRICT_RESULT_INVALID_QUERY = 2,
    WTE_STRICT_RESULT_INVALID_FEATURES = 3,
    WTE_STRICT_RESULT_NOT_ENABLED = 4,
    WTE_STRICT_RESULT_RANGE_LIMIT = 5,
    WTE_STRICT_RESULT_INVALID_RANGE = 6,
    WTE_STRICT_RESULT_INVALID_EXIT = 7,
    WTE_STRICT_RESULT_TRACE_FAILED = 8,
    WTE_STRICT_RESULT_DUMP_FAILED = 9,
    WTE_STRICT_RESULT_ACK_FAILED = 10,
    WTE_STRICT_RESULT_ALREADY_CONSUMED = 11,
    WTE_STRICT_RESULT_CALLBACK_MISSING = 12,
};

enum wte_strict_trace_event {
    WTE_STRICT_TRACE_REGISTER_COMMIT = 0,
    WTE_STRICT_TRACE_STRICT_EXEC_EXIT = 1,
    WTE_STRICT_TRACE_QEMU_DUMP_BEGIN = 2,
    WTE_STRICT_TRACE_QEMU_DUMP_END = 3,
    WTE_STRICT_TRACE_STRICT_ACK = 4,
};

struct wte_strict_query_response {
    uint64_t features;
    uint32_t abi_min_version;
    uint32_t abi_max_version;
    uint32_t max_ranges;
    uint32_t max_pages_per_range;
    uint32_t max_vcpus;
    uint32_t exit_reason;
};

struct wte_strict_identity {
    uint64_t range_id;
    uint32_t page_index;
    uint64_t generation;
};

struct wte_strict_exit {
    uint16_t version;
    uint16_t reserved0;
    uint32_t flags;
    uint64_t session_id;
    uint64_t range_id;
    uint64_t generation;
    uint64_t gva;
    uint64_t gpa;
    uint64_t rip;
    uint64_t cr3;
    uint32_t page_index;
    uint32_t reserved1;
    uint64_t reserved[3];
};

struct wte_strict_range_state {
    bool active;
    uint64_t gva_start;
    uint64_t gva_end;
    uint64_t range_id;
};

struct wte_strict_state {
    bool enabled;
    bool reset_pending;
    uint64_t normalized_cr3;
    uint64_t session_id;
    uint64_t pe_range_id;
    uint32_t max_ranges;
    uint32_t max_pages_per_range;
    struct wte_strict_identity last_acked;
    bool has_last_acked;
    struct wte_strict_range_state ranges[WTE_STRICT_MAX_RANGES];
    size_t range_count;
};

struct wte_strict_runtime {
    void *opaque;
    enum wte_strict_result (*query)(
        void *opaque,
        struct wte_strict_query_response *response);
    enum wte_strict_result (*enable)(
        void *opaque,
        uint64_t normalized_cr3,
        uint64_t *session_id_out);
    enum wte_strict_result (*disable)(
        void *opaque,
        uint64_t session_id);
    enum wte_strict_result (*reset)(
        void *opaque,
        uint64_t session_id,
        uint64_t *new_session_id_out);
    enum wte_strict_result (*range_add)(
        void *opaque,
        uint64_t session_id,
        uint64_t gva_start,
        uint64_t gva_end,
        uint64_t *range_id_out);
    enum wte_strict_result (*range_remove)(
        void *opaque,
        uint64_t session_id,
        uint64_t range_id);
    enum wte_strict_result (*ack)(
        void *opaque,
        uint64_t session_id,
        uint64_t range_id,
        uint64_t generation,
        uint32_t page_index);
    bool (*dump_sync)(
        void *opaque,
        const struct wte_strict_exit *strict_exit);
    bool (*trace_append)(
        void *opaque,
        enum wte_strict_trace_event event,
        const struct wte_strict_identity *identity);
    bool (*trace_sync)(void *opaque);
};

bool wte_strict_mode_requested(uint32_t setup_flags);
uint64_t wte_strict_normalize_cr3(uint64_t raw_cr3);
void wte_strict_state_init(struct wte_strict_state *state);
enum wte_strict_result wte_strict_enable_session(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    bool capability_available,
    uint64_t raw_cr3);
enum wte_strict_result wte_strict_register_range(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    uint64_t gva_start,
    uint64_t gva_end,
    uint64_t *range_id);
enum wte_strict_result wte_strict_remove_range(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    uint64_t range_id);
enum wte_strict_result wte_strict_trace_append(
    const struct wte_strict_runtime *runtime,
    enum wte_strict_trace_event event,
    const struct wte_strict_identity *identity);
enum wte_strict_result wte_strict_trace_sync(
    const struct wte_strict_runtime *runtime);
enum wte_strict_result wte_strict_handle_exit(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    const struct wte_strict_exit *strict_exit);
enum wte_strict_result wte_strict_reset_session(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime);
enum wte_strict_result wte_strict_prepare_reset(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime);
enum wte_strict_result wte_strict_complete_reset(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime);
enum wte_strict_result wte_strict_disable_session(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime);
const char *wte_strict_trace_event_name(enum wte_strict_trace_event event);
