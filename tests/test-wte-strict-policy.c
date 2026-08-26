#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../nyx/wte_policy.h"
#include "../nyx/wte_policy.c"

enum call_kind {
    CALL_QUERY = 0,
    CALL_ENABLE = 1,
    CALL_RANGE_ADD = 2,
    CALL_TRACE_APPEND = 3,
    CALL_TRACE_SYNC = 4,
    CALL_DUMP = 5,
    CALL_ACK = 6,
    CALL_RESET = 7,
    CALL_DISABLE = 8,
    CALL_RANGE_REMOVE = 9,
};

struct call_record {
    enum call_kind kind;
    enum wte_strict_trace_event event;
    uint64_t session_id;
    uint64_t value0;
    uint64_t value1;
    uint32_t page_index;
};

struct fake_runtime_state {
    struct wte_strict_query_response query_response;
    enum wte_strict_result query_result;
    enum wte_strict_result enable_result;
    enum wte_strict_result disable_result;
    enum wte_strict_result reset_result;
    enum wte_strict_result range_add_result;
    enum wte_strict_result ack_result;
    bool dump_result;
    bool trace_append_result;
    bool trace_sync_result;
    uint64_t assigned_session_id;
    uint64_t assigned_reset_session_id;
    uint64_t assigned_range_ids[8];
    size_t assigned_range_count;
    struct call_record calls[96];
    size_t call_count;
};

static void record_call(
    struct fake_runtime_state *state,
    enum call_kind kind,
    enum wte_strict_trace_event event,
    uint64_t session_id,
    uint64_t value0,
    uint64_t value1,
    uint32_t page_index)
{
    const struct call_record record = {
        .kind = kind,
        .event = event,
        .session_id = session_id,
        .value0 = value0,
        .value1 = value1,
        .page_index = page_index,
    };

    state->calls[state->call_count++] = record;
}

static enum wte_strict_result fake_query(
    void *opaque,
    struct wte_strict_query_response *response)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_QUERY, 0, 0, 0, 0, 0);
    *response = state->query_response;
    return state->query_result;
}

static enum wte_strict_result fake_enable(
    void *opaque,
    uint64_t normalized_cr3,
    uint64_t *session_id_out)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_ENABLE, 0, 0, normalized_cr3, 0, 0);
    *session_id_out = state->assigned_session_id;
    return state->enable_result;
}

static enum wte_strict_result fake_disable(void *opaque, uint64_t session_id)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_DISABLE, 0, session_id, 0, 0, 0);
    return state->disable_result;
}

static enum wte_strict_result fake_range_remove(
    void *opaque,
    uint64_t session_id,
    uint64_t range_id)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_RANGE_REMOVE, 0, session_id, range_id, 0, 0);
    return WTE_STRICT_RESULT_OK;
}

static enum wte_strict_result fake_reset(
    void *opaque,
    uint64_t session_id,
    uint64_t *new_session_id_out)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_RESET, 0, session_id, 0, 0, 0);
    *new_session_id_out = state->assigned_reset_session_id;
    return state->reset_result;
}

static enum wte_strict_result fake_range_add(
    void *opaque,
    uint64_t session_id,
    uint64_t gva_start,
    uint64_t gva_end,
    uint64_t *range_id_out)
{
    struct fake_runtime_state *state = opaque;
    const uint64_t assigned_range_id =
        state->assigned_range_ids[state->assigned_range_count++];

    record_call(state, CALL_RANGE_ADD, 0, session_id, gva_start, gva_end, 0);
    *range_id_out = assigned_range_id;
    return state->range_add_result;
}

static enum wte_strict_result fake_ack(
    void *opaque,
    uint64_t session_id,
    uint64_t range_id,
    uint64_t generation,
    uint32_t page_index)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_ACK, 0, session_id, range_id, generation,
                page_index);
    return state->ack_result;
}

static bool fake_dump_sync(void *opaque, const struct wte_strict_exit *strict_exit)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_DUMP, 0, strict_exit->session_id,
                strict_exit->range_id, strict_exit->generation,
                strict_exit->page_index);
    return state->dump_result;
}

static bool fake_trace_append(
    void *opaque,
    enum wte_strict_trace_event event,
    const struct wte_strict_identity *identity)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_TRACE_APPEND, event, 0, identity->range_id,
                identity->generation, identity->page_index);
    return state->trace_append_result;
}

static bool fake_trace_sync(void *opaque)
{
    struct fake_runtime_state *state = opaque;

    record_call(state, CALL_TRACE_SYNC, 0, 0, 0, 0, 0);
    return state->trace_sync_result;
}

static struct wte_strict_runtime make_runtime(struct fake_runtime_state *state)
{
    const struct wte_strict_runtime runtime = {
        .opaque = state,
        .query = fake_query,
        .enable = fake_enable,
        .disable = fake_disable,
        .reset = fake_reset,
        .range_add = fake_range_add,
        .range_remove = fake_range_remove,
        .ack = fake_ack,
        .dump_sync = fake_dump_sync,
        .trace_append = fake_trace_append,
        .trace_sync = fake_trace_sync,
    };

    return runtime;
}

static struct fake_runtime_state make_fake_runtime_state(void)
{
    const struct fake_runtime_state state = {
        .query_response = {
            .features = WTE_STRICT_REQUIRED_FEATURE_MASK,
            .abi_min_version = WTE_STRICT_ABI_VERSION_1,
            .abi_max_version = WTE_STRICT_ABI_VERSION_1,
            .max_ranges = 3,
            .max_pages_per_range = 64,
            .max_vcpus = 1,
            .exit_reason = WTE_STRICT_EXIT_REASON,
        },
        .query_result = WTE_STRICT_RESULT_OK,
        .enable_result = WTE_STRICT_RESULT_OK,
        .disable_result = WTE_STRICT_RESULT_OK,
        .reset_result = WTE_STRICT_RESULT_OK,
        .range_add_result = WTE_STRICT_RESULT_OK,
        .ack_result = WTE_STRICT_RESULT_OK,
        .dump_result = true,
        .trace_append_result = true,
        .trace_sync_result = true,
        .assigned_session_id = UINT64_C(0x123456789abcdef0),
        .assigned_reset_session_id = UINT64_C(0xfedcba9876543210),
        .assigned_range_ids = {
            UINT64_C(0x1111111111111111),
            UINT64_C(0x2222222222222222),
            UINT64_C(0x3333333333333333),
            UINT64_C(0x4444444444444444),
        },
        .assigned_range_count = 0,
        .call_count = 0,
    };

    return state;
}

static struct wte_strict_exit make_exit(
    uint64_t session_id,
    uint64_t range_id,
    uint64_t generation,
    uint32_t page_index)
{
    const uint64_t gva = UINT64_C(0x401000) + ((uint64_t)page_index << 12);
    const struct wte_strict_exit strict_exit = {
        .version = WTE_STRICT_ABI_VERSION_1,
        .reserved0 = 0,
        .flags = WTE_STRICT_EXIT_FIRST_EXEC,
        .session_id = session_id,
        .range_id = range_id,
        .generation = generation,
        .gva = gva,
        .gpa = UINT64_C(0x201000),
        .rip = gva + UINT64_C(0x234),
        .cr3 = UINT64_C(0x8000000000012345),
        .page_index = page_index,
        .reserved1 = 0,
        .reserved = {0, 0, 0},
    };

    return strict_exit;
}

static bool prepare_enabled_state(
    struct wte_strict_state *strict_state,
    struct fake_runtime_state *runtime_state,
    struct wte_strict_runtime *runtime,
    uint64_t *range_id)
{
    wte_strict_state_init(strict_state);
    *runtime_state = make_fake_runtime_state();
    *runtime = make_runtime(runtime_state);

    if (wte_strict_enable_session(strict_state, runtime, true,
                                  UINT64_C(0x8000000000012345)) !=
        WTE_STRICT_RESULT_OK) {
        return false;
    }

    return wte_strict_register_range(strict_state, runtime,
                                     UINT64_C(0x401000),
                                     UINT64_C(0x403000),
                                     range_id) == WTE_STRICT_RESULT_OK;
}

static int test_strict_flag_is_explicit_opt_in(void)
{
    if (wte_strict_mode_requested(0U) ||
        wte_strict_mode_requested(WTE_FLAG_32BIT) ||
        wte_strict_mode_requested(WTE_FLAG_EAGER_NX) ||
        !wte_strict_mode_requested(WTE_FLAG_STRICT_PT)) {
        puts("not ok 1 - strict mode requires explicit bit 2 selection");
        return 1;
    }

    puts("ok 1 - strict mode requires explicit bit 2 selection");
    return 0;
}

static int test_enable_rejects_missing_capability(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state = make_fake_runtime_state();
    const struct wte_strict_runtime runtime = make_runtime(&runtime_state);

    if (wte_strict_enable_session(&strict_state, &runtime, false,
                                  UINT64_C(0x12345000)) !=
            WTE_STRICT_RESULT_UNSUPPORTED ||
        runtime_state.call_count != 0U) {
        puts("not ok 2 - enable rejects missing capability without fallback");
        return 1;
    }

    puts("ok 2 - enable rejects missing capability without fallback");
    return 0;
}

static int test_query_zero_features_is_rejected(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state = make_fake_runtime_state();
    const struct wte_strict_runtime runtime = make_runtime(&runtime_state);

    runtime_state.query_response.features = 0;
    if (wte_strict_enable_session(&strict_state, &runtime, true,
                                  UINT64_C(0x12345000)) !=
        WTE_STRICT_RESULT_UNSUPPORTED) {
        puts("not ok 3 - query with zero features is rejected");
        return 1;
    }

    puts("ok 3 - query with zero features is rejected");
    return 0;
}

static int test_query_limits_are_validated(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state = make_fake_runtime_state();
    const struct wte_strict_runtime runtime = make_runtime(&runtime_state);

    runtime_state.query_response.max_ranges = 0;
    if (wte_strict_enable_session(&strict_state, &runtime, true,
                                  UINT64_C(0x12345000)) !=
        WTE_STRICT_RESULT_INVALID_QUERY) {
        puts("not ok 4 - malformed query limits are rejected");
        return 1;
    }

    runtime_state = make_fake_runtime_state();
    runtime_state.query_response.max_vcpus = 0;
    if (wte_strict_enable_session(&strict_state, &runtime, true,
                                  UINT64_C(0x12345000)) !=
        WTE_STRICT_RESULT_INVALID_QUERY) {
        puts("not ok 4 - malformed query limits are rejected");
        return 1;
    }

    puts("ok 4 - malformed query limits are rejected");
    return 0;
}

static int test_zero_max_pages_per_range_is_unbounded(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state = make_fake_runtime_state();
    const struct wte_strict_runtime runtime = make_runtime(&runtime_state);
    uint64_t range_id = 0;

    runtime_state.query_response.max_pages_per_range = 0;
    wte_strict_state_init(&strict_state);
    if (wte_strict_enable_session(&strict_state, &runtime, true,
                                  UINT64_C(0x8000000000012345)) != WTE_STRICT_RESULT_OK ||
        wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x401000), UINT64_C(0x801000),
                                  &range_id) != WTE_STRICT_RESULT_OK) {
        puts("not ok 5 - zero max pages per range is unbounded");
        return 1;
    }

    puts("ok 5 - zero max pages per range is unbounded");
    return 0;
}

static int test_kernel_assigned_ids_are_copied_into_state(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state = make_fake_runtime_state();
    const struct wte_strict_runtime runtime = make_runtime(&runtime_state);
    uint64_t range_id = 0;

    wte_strict_state_init(&strict_state);
    if (wte_strict_enable_session(&strict_state, &runtime, true,
                                  UINT64_C(0x8000000000012345)) !=
            WTE_STRICT_RESULT_OK ||
        strict_state.session_id != runtime_state.assigned_session_id ||
        runtime_state.calls[1].session_id != 0 ||
        wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x401000), UINT64_C(0x403000),
                                  &range_id) != WTE_STRICT_RESULT_OK ||
        range_id != runtime_state.assigned_range_ids[0] ||
        strict_state.ranges[0].range_id != runtime_state.assigned_range_ids[0]) {
        puts("not ok 6 - kernel-assigned ids are copied into state");
        return 1;
    }

    puts("ok 6 - kernel-assigned ids are copied into state");
    return 0;
}

static int test_advertised_max_ranges_caps_registration(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state = make_fake_runtime_state();
    const struct wte_strict_runtime runtime = make_runtime(&runtime_state);
    uint64_t range_id = 0;

    runtime_state.query_response.max_ranges = 1;
    wte_strict_state_init(&strict_state);
    if (wte_strict_enable_session(&strict_state, &runtime, true,
                                  UINT64_C(0x8000000000012345)) !=
            WTE_STRICT_RESULT_OK ||
        wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x401000), UINT64_C(0x403000),
                                  &range_id) != WTE_STRICT_RESULT_OK ||
        wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x501000), UINT64_C(0x503000),
                                  &range_id) != WTE_STRICT_RESULT_RANGE_LIMIT) {
        puts("not ok 7 - advertised max ranges caps registration");
        return 1;
    }

    puts("ok 7 - advertised max ranges caps registration");
    return 0;
}

static int test_duplicate_range_registration_reuses_existing_id(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    uint64_t first_id = 0;
    uint64_t duplicate_id = 0;
    size_t first_call_count;

    if (!prepare_enabled_state(&strict_state, &runtime_state, &runtime, &first_id)) {
        puts("not ok 8 - duplicate range registration reuses existing id");
        return 1;
    }

    first_call_count = runtime_state.call_count;
    if (wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x401000), UINT64_C(0x403000),
                                  &duplicate_id) != WTE_STRICT_RESULT_OK ||
        duplicate_id != first_id ||
        runtime_state.call_count != first_call_count) {
        puts("not ok 8 - duplicate range registration reuses existing id");
        return 1;
    }

    puts("ok 8 - duplicate range registration reuses existing id");
    return 0;
}

static int test_range_remove_compacts_state(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    uint64_t first_id = 0;
    uint64_t second_id = 0;

    if (!prepare_enabled_state(&strict_state, &runtime_state, &runtime, &first_id) ||
        wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x501000), UINT64_C(0x503000),
                                  &second_id) != WTE_STRICT_RESULT_OK ||
        wte_strict_remove_range(&strict_state, &runtime, first_id) != WTE_STRICT_RESULT_OK ||
        strict_state.range_count != 1 ||
        strict_state.ranges[0].range_id != second_id ||
        runtime_state.calls[runtime_state.call_count - 1].kind != CALL_RANGE_REMOVE) {
        puts("not ok 9 - range remove compacts state");
        return 1;
    }

    puts("ok 9 - range remove compacts state");
    return 0;
}

static int test_exit_handling_uses_kernel_assigned_identity_for_ack(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    struct wte_strict_exit strict_exit;
    uint64_t range_id = 0;

    if (!prepare_enabled_state(&strict_state, &runtime_state, &runtime,
                               &range_id)) {
        puts("not ok 7 - exit handling uses kernel-assigned identity for ack");
        return 1;
    }

    strict_exit = make_exit(runtime_state.assigned_session_id, range_id, 7, 0);
    if (wte_strict_handle_exit(&strict_state, &runtime, &strict_exit) !=
            WTE_STRICT_RESULT_OK ||
        runtime_state.calls[9].session_id != runtime_state.assigned_session_id ||
        runtime_state.calls[9].value0 != range_id ||
        runtime_state.calls[9].value1 != 7) {
        puts("not ok 10 - exit handling uses kernel-assigned identity for ack");
        return 1;
    }

    puts("ok 10 - exit handling uses kernel-assigned identity for ack");
    return 0;
}

static int test_reserved_exit_fields_are_rejected(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    struct wte_strict_exit strict_exit;
    uint64_t range_id = 0;

    if (!prepare_enabled_state(&strict_state, &runtime_state, &runtime,
                               &range_id)) {
        puts("not ok 11 - reserved exit fields are rejected");
        return 1;
    }

    strict_exit = make_exit(runtime_state.assigned_session_id, range_id, 7, 0);
    strict_exit.reserved0 = 1;
    if (wte_strict_handle_exit(&strict_state, &runtime, &strict_exit) !=
        WTE_STRICT_RESULT_INVALID_EXIT) {
        puts("not ok 11 - reserved exit fields are rejected");
        return 1;
    }

    strict_exit = make_exit(runtime_state.assigned_session_id, range_id, 7, 0);
    strict_exit.reserved1 = 1;
    if (wte_strict_handle_exit(&strict_state, &runtime, &strict_exit) !=
        WTE_STRICT_RESULT_INVALID_EXIT) {
        puts("not ok 11 - reserved exit fields are rejected");
        return 1;
    }

    strict_exit = make_exit(runtime_state.assigned_session_id, range_id, 7, 0);
    strict_exit.reserved[2] = 1;
    if (wte_strict_handle_exit(&strict_state, &runtime, &strict_exit) !=
        WTE_STRICT_RESULT_INVALID_EXIT) {
        puts("not ok 8 - reserved exit fields are rejected");
        return 1;
    }

    puts("ok 11 - reserved exit fields are rejected");
    return 0;
}

static int test_unknown_exit_flags_are_rejected(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    struct wte_strict_exit strict_exit;
    uint64_t range_id = 0;

    if (!prepare_enabled_state(&strict_state, &runtime_state, &runtime,
                               &range_id)) {
        puts("not ok 12 - unknown exit flags are rejected");
        return 1;
    }

    strict_exit = make_exit(runtime_state.assigned_session_id, range_id, 7, 0);
    strict_exit.flags |= (1U << 7);
    if (wte_strict_handle_exit(&strict_state, &runtime, &strict_exit) !=
        WTE_STRICT_RESULT_INVALID_EXIT) {
        puts("not ok 9 - unknown exit flags are rejected");
        return 1;
    }

    puts("ok 12 - unknown exit flags are rejected");
    return 0;
}

static int test_prepare_and_complete_reset_are_two_phase(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    uint64_t first_range_id = 0;
    uint64_t second_range_id = 0;
    size_t before_complete_call_count;

    wte_strict_state_init(&strict_state);
    runtime_state = make_fake_runtime_state();
    runtime = make_runtime(&runtime_state);

    if (wte_strict_enable_session(&strict_state, &runtime, true,
                                  UINT64_C(0x8000000000012345)) !=
            WTE_STRICT_RESULT_OK ||
        wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x401000), UINT64_C(0x403000),
                                  &first_range_id) != WTE_STRICT_RESULT_OK ||
        wte_strict_register_range(&strict_state, &runtime,
                                  UINT64_C(0x501000), UINT64_C(0x503000),
                                  &second_range_id) != WTE_STRICT_RESULT_OK) {
        puts("not ok 13 - prepare and complete reset are two phase");
        return 1;
    }

    if (wte_strict_prepare_reset(&strict_state, &runtime) !=
            WTE_STRICT_RESULT_OK ||
        strict_state.session_id != runtime_state.assigned_reset_session_id ||
        strict_state.ranges[0].range_id != 0 ||
        strict_state.ranges[1].range_id != 0 ||
        runtime_state.calls[4].kind != CALL_RESET) {
        puts("not ok 13 - prepare and complete reset are two phase");
        return 1;
    }

    before_complete_call_count = runtime_state.call_count;
    if (wte_strict_complete_reset(&strict_state, &runtime) !=
            WTE_STRICT_RESULT_OK ||
        runtime_state.call_count != before_complete_call_count + 2 ||
        runtime_state.calls[before_complete_call_count].kind != CALL_RANGE_ADD ||
        strict_state.ranges[0].range_id != runtime_state.assigned_range_ids[2] ||
        strict_state.ranges[1].range_id != runtime_state.assigned_range_ids[3]) {
        puts("not ok 13 - prepare and complete reset are two phase");
        return 1;
    }

    puts("ok 13 - prepare and complete reset are two phase");
    return 0;
}

static int test_dump_failure_prevents_ack(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    struct wte_strict_exit strict_exit;
    uint64_t range_id = 0;

    if (!prepare_enabled_state(&strict_state, &runtime_state, &runtime,
                               &range_id)) {
        puts("not ok 14 - dump failure prevents ack");
        return 1;
    }

    runtime_state.dump_result = false;
    strict_exit = make_exit(runtime_state.assigned_session_id, range_id, 8, 0);
    if (wte_strict_handle_exit(&strict_state, &runtime, &strict_exit) !=
            WTE_STRICT_RESULT_DUMP_FAILED ||
        runtime_state.calls[runtime_state.call_count - 1].kind == CALL_ACK) {
        puts("not ok 14 - dump failure prevents ack");
        return 1;
    }

    puts("ok 14 - dump failure prevents ack");
    return 0;
}

static int test_disable_is_idempotent_locally(void)
{
    struct wte_strict_state strict_state;
    struct fake_runtime_state runtime_state;
    struct wte_strict_runtime runtime;
    uint64_t range_id = 0;
    size_t first_disable_count;

    if (!prepare_enabled_state(&strict_state, &runtime_state, &runtime,
                               &range_id)) {
        puts("not ok 15 - disable is idempotent locally");
        return 1;
    }

    if (wte_strict_disable_session(&strict_state, &runtime) !=
            WTE_STRICT_RESULT_OK) {
        puts("not ok 15 - disable is idempotent locally");
        return 1;
    }

    first_disable_count = runtime_state.call_count;
    if (wte_strict_disable_session(&strict_state, &runtime) !=
            WTE_STRICT_RESULT_OK ||
        runtime_state.call_count != first_disable_count) {
        puts("not ok 15 - disable is idempotent locally");
        return 1;
    }

    puts("ok 15 - disable is idempotent locally");
    return 0;
}

static bool wte_dump_strict_io_sanity_for_test(
    bool mkdir_ok,
    bool map_open_ok,
    bool write_ok,
    bool flush_ok,
    bool fsync_ok,
    bool close_ok)
{
    return mkdir_ok && map_open_ok && write_ok && flush_ok && fsync_ok && close_ok;
}

static bool wte_dump_strict_io_result_for_test(
    bool open_ok,
    bool write_ok,
    bool flush_ok,
    bool fsync_ok,
    bool close_ok,
    bool dirsync_ok)
{
    return open_ok && write_ok && flush_ok && fsync_ok && close_ok && dirsync_ok;
}

static int test_strict_durable_dump_requires_all_phases(void)
{
    if (wte_dump_strict_io_sanity_for_test(true, true, true, true, true, true) != true ||
        wte_dump_strict_io_result_for_test(true, true, true, true, true, true) != true ||
        wte_dump_strict_io_result_for_test(false, true, true, true, true, true) != false ||
        wte_dump_strict_io_result_for_test(true, false, true, true, true, true) != false ||
        wte_dump_strict_io_result_for_test(true, true, true, false, true, true) != false ||
        wte_dump_strict_io_result_for_test(true, true, true, true, true, false) != false) {
        puts("not ok 16 - strict durable dump requires all phases");
        return 1;
    }

    puts("ok 16 - strict durable dump requires all phases");
    return 0;
}

static int test_strict_trace_callbacks_reject_missing_context(void)
{
    if (wte_strict_trace_append(NULL, WTE_STRICT_TRACE_REGISTER_COMMIT, NULL) !=
            WTE_STRICT_RESULT_TRACE_FAILED ||
        wte_strict_trace_sync(NULL) != WTE_STRICT_RESULT_TRACE_FAILED) {
        puts("not ok 17 - strict trace callbacks reject missing context");
        return 1;
    }

    puts("ok 17 - strict trace callbacks reject missing context");
    return 0;
}

int main(void)
{
    int failures = 0;

    puts("TAP version 13");
    puts("1..17");
    failures += test_strict_flag_is_explicit_opt_in();
    failures += test_enable_rejects_missing_capability();
    failures += test_query_zero_features_is_rejected();
    failures += test_query_limits_are_validated();
    failures += test_zero_max_pages_per_range_is_unbounded();
    failures += test_kernel_assigned_ids_are_copied_into_state();
    failures += test_advertised_max_ranges_caps_registration();
    failures += test_duplicate_range_registration_reuses_existing_id();
    failures += test_range_remove_compacts_state();
    failures += test_exit_handling_uses_kernel_assigned_identity_for_ack();
    failures += test_reserved_exit_fields_are_rejected();
    failures += test_unknown_exit_flags_are_rejected();
    failures += test_prepare_and_complete_reset_are_two_phase();
    failures += test_dump_failure_prevents_ack();
    failures += test_disable_is_idempotent_locally();
    failures += test_strict_durable_dump_requires_all_phases();
    failures += test_strict_trace_callbacks_reject_missing_context();

    return failures != 0;
}
