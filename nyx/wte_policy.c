#include "wte_policy.h"

#include <string.h>

enum wte_exec_policy_action
wte_exec_policy_decide(const struct wte_exec_policy_input *input)
{
    (void)input->written;
    (void)input->diff_count;
    (void)input->rip_overlaps_diff;

    if (input->is_dynamic && input->first_exec_pending) {
        return WTE_EXEC_POLICY_ACTION_DUMP_FIRST_EXEC;
    }

    return WTE_EXEC_POLICY_ACTION_FALLTHROUGH_TO_LEGACY;
}

enum wte_dynamic_registration_policy_action
wte_dynamic_registration_policy_decide(
    const struct wte_dynamic_registration_policy_input *input)
{
    if (!input->already_dynamic || !input->baseline_valid) {
        return WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC;
    }

    if (input->first_exec_pending) {
        return input->gfn_changed ? WTE_DYNAMIC_REGISTRATION_POLICY_MAPPING_REFRESH
                                  : WTE_DYNAMIC_REGISTRATION_POLICY_KEEP_STATE;
    }

    if (input->content_changed) {
        return WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC;
    }

    return input->gfn_changed ? WTE_DYNAMIC_REGISTRATION_POLICY_MAPPING_REFRESH
                              : WTE_DYNAMIC_REGISTRATION_POLICY_KEEP_STATE;
}

static bool wte_strict_has_required_features(uint64_t features)
{
    return (features & WTE_STRICT_REQUIRED_FEATURE_MASK) ==
           WTE_STRICT_REQUIRED_FEATURE_MASK;
}

static bool wte_strict_reserved_fields_are_zero(
    const struct wte_strict_exit *strict_exit)
{
    return strict_exit->reserved0 == 0 && strict_exit->reserved1 == 0 &&
           strict_exit->reserved[0] == 0 && strict_exit->reserved[1] == 0 &&
           strict_exit->reserved[2] == 0;
}

static size_t wte_strict_range_limit(const struct wte_strict_state *state)
{
    return state->max_ranges < WTE_STRICT_MAX_RANGES
               ? state->max_ranges
               : WTE_STRICT_MAX_RANGES;
}

static struct wte_strict_range_state *wte_strict_find_range(
    struct wte_strict_state *state,
    uint64_t range_id)
{
    size_t i;

    for (i = 0; i < state->range_count; i++) {
        if (state->ranges[i].active && state->ranges[i].range_id == range_id) {
            return &state->ranges[i];
        }
    }

    return NULL;
}

static struct wte_strict_range_state *wte_strict_find_range_by_bounds(
    struct wte_strict_state *state,
    uint64_t gva_start,
    uint64_t gva_end)
{
    size_t i;

    for (i = 0; i < state->range_count; i++) {
        if (state->ranges[i].active && state->ranges[i].gva_start == gva_start &&
            state->ranges[i].gva_end == gva_end) {
            return &state->ranges[i];
        }
    }

    return NULL;
}

static void wte_strict_compact_ranges(struct wte_strict_state *state)
{
    size_t read_index;
    size_t write_index = 0;
    const size_t original_count = state->range_count;

    for (read_index = 0; read_index < state->range_count; read_index++) {
        if (!state->ranges[read_index].active) {
            continue;
        }

        if (write_index != read_index) {
            state->ranges[write_index] = state->ranges[read_index];
        }
        write_index++;
    }

    while (write_index < original_count) {
        memset(&state->ranges[write_index], 0, sizeof(state->ranges[write_index]));
        write_index++;
    }
    state->range_count = 0;
    for (read_index = 0; read_index < original_count; read_index++) {
        if (state->ranges[read_index].active) {
            state->range_count++;
        }
    }
}

static bool wte_strict_range_is_registered(
    const struct wte_strict_state *state,
    uint64_t range_id,
    uint64_t gva,
    uint32_t page_index)
{
    size_t i;

    for (i = 0; i < state->range_count; i++) {
        const struct wte_strict_range_state *range = &state->ranges[i];
        const uint64_t expected_page_index =
            (gva - range->gva_start) / UINT64_C(0x1000);

        if (!range->active || range->range_id != range_id) {
            continue;
        }

        if (gva < range->gva_start || gva >= range->gva_end) {
            return false;
        }

        return expected_page_index == page_index;
    }

    return false;
}

static enum wte_strict_result wte_strict_append_trace(
    const struct wte_strict_runtime *runtime,
    enum wte_strict_trace_event event,
    const struct wte_strict_identity *identity)
{
    if (runtime == NULL ||
        !runtime->trace_append ||
        runtime->opaque == NULL ||
        identity == NULL ||
        !runtime->trace_append(runtime->opaque, event, identity)) {
        return WTE_STRICT_RESULT_TRACE_FAILED;
    }

    return WTE_STRICT_RESULT_OK;
}

bool wte_strict_mode_requested(uint32_t setup_flags)
{
    return (setup_flags & WTE_FLAG_STRICT_PT) != 0U;
}

uint64_t wte_strict_normalize_cr3(uint64_t raw_cr3)
{
    return raw_cr3 & ~((UINT64_C(1) << 63) | UINT64_C(0xfff));
}

void wte_strict_state_init(struct wte_strict_state *state)
{
    memset(state, 0, sizeof(*state));
}

enum wte_strict_result wte_strict_enable_session(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    bool capability_available,
    uint64_t raw_cr3)
{
    struct wte_strict_query_response query_response;
    const uint64_t normalized_cr3 = wte_strict_normalize_cr3(raw_cr3);
    enum wte_strict_result result;
    uint64_t session_id = 0;

    if (!capability_available) {
        return WTE_STRICT_RESULT_UNSUPPORTED;
    }

    if (!runtime->query || !runtime->enable) {
        return WTE_STRICT_RESULT_CALLBACK_MISSING;
    }

    memset(&query_response, 0, sizeof(query_response));
    result = runtime->query(runtime->opaque, &query_response);
    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    if (query_response.features == 0) {
        return WTE_STRICT_RESULT_UNSUPPORTED;
    }

    if (query_response.abi_min_version > WTE_STRICT_ABI_VERSION_1 ||
        query_response.abi_max_version < WTE_STRICT_ABI_VERSION_1 ||
        query_response.exit_reason != WTE_STRICT_EXIT_REASON ||
        query_response.max_ranges == 0 ||
        query_response.max_vcpus < 1) {
        return WTE_STRICT_RESULT_INVALID_QUERY;
    }

    if (!wte_strict_has_required_features(query_response.features)) {
        return WTE_STRICT_RESULT_INVALID_FEATURES;
    }

    result = runtime->enable(runtime->opaque, normalized_cr3, &session_id);
    if (result != WTE_STRICT_RESULT_OK || session_id == 0) {
        return result != WTE_STRICT_RESULT_OK ? result
                                              : WTE_STRICT_RESULT_INVALID_QUERY;
    }

    state->enabled = true;
    state->reset_pending = false;
    state->normalized_cr3 = normalized_cr3;
    state->session_id = session_id;
    state->max_ranges = query_response.max_ranges;
    state->max_pages_per_range = query_response.max_pages_per_range;
    state->range_count = 0;
    state->has_last_acked = false;

    return WTE_STRICT_RESULT_OK;
}

enum wte_strict_result wte_strict_register_range(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    uint64_t gva_start,
    uint64_t gva_end,
    uint64_t *range_id)
{
    struct wte_strict_range_state *range;
    const uint64_t page_count = (gva_end - gva_start) / UINT64_C(0x1000);
    uint64_t assigned_range_id = 0;
    enum wte_strict_result result;
    const size_t range_limit = wte_strict_range_limit(state);
    struct wte_strict_range_state *existing_range;

    if (!state->enabled) {
        return WTE_STRICT_RESULT_NOT_ENABLED;
    }

    if (!runtime->range_add || range_id == NULL) {
        return WTE_STRICT_RESULT_CALLBACK_MISSING;
    }

    if (state->reset_pending) {
        return WTE_STRICT_RESULT_NOT_ENABLED;
    }

    if (gva_start >= gva_end || (gva_start & UINT64_C(0xfff)) != 0 ||
        (gva_end & UINT64_C(0xfff)) != 0 || page_count == 0 ||
        (state->max_pages_per_range != 0 &&
         page_count > state->max_pages_per_range)) {
        return WTE_STRICT_RESULT_INVALID_RANGE;
    }

    existing_range = wte_strict_find_range_by_bounds(state, gva_start, gva_end);
    if (existing_range != NULL) {
        *range_id = existing_range->range_id;
        return WTE_STRICT_RESULT_OK;
    }

    if (state->range_count >= range_limit) {
        return WTE_STRICT_RESULT_RANGE_LIMIT;
    }

    result = runtime->range_add(runtime->opaque, state->session_id, gva_start,
                                gva_end, &assigned_range_id);
    if (result != WTE_STRICT_RESULT_OK || assigned_range_id == 0) {
        return result != WTE_STRICT_RESULT_OK ? result
                                              : WTE_STRICT_RESULT_INVALID_RANGE;
    }

    range = &state->ranges[state->range_count++];
    range->active = true;
    range->gva_start = gva_start;
    range->gva_end = gva_end;
    range->range_id = assigned_range_id;
    *range_id = assigned_range_id;

    return WTE_STRICT_RESULT_OK;
}

enum wte_strict_result wte_strict_remove_range(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    uint64_t range_id)
{
    struct wte_strict_range_state *range;

    if (!state->enabled || state->reset_pending) {
        return WTE_STRICT_RESULT_NOT_ENABLED;
    }

    if (!runtime->range_remove) {
        return WTE_STRICT_RESULT_CALLBACK_MISSING;
    }

    range = wte_strict_find_range(state, range_id);
    if (range == NULL) {
        return WTE_STRICT_RESULT_INVALID_RANGE;
    }

    if (runtime->range_remove(runtime->opaque, state->session_id, range_id) !=
        WTE_STRICT_RESULT_OK) {
        return WTE_STRICT_RESULT_INVALID_RANGE;
    }

    range->active = false;
    if (state->pe_range_id == range_id) {
        state->pe_range_id = 0;
    }

    wte_strict_compact_ranges(state);
    return WTE_STRICT_RESULT_OK;
}

enum wte_strict_result wte_strict_trace_append(
    const struct wte_strict_runtime *runtime,
    enum wte_strict_trace_event event,
    const struct wte_strict_identity *identity)
{
    return wte_strict_append_trace(runtime, event, identity);
}

enum wte_strict_result wte_strict_trace_sync(
    const struct wte_strict_runtime *runtime)
{
    if (runtime == NULL || runtime->opaque == NULL || runtime->trace_sync == NULL ||
        !runtime->trace_sync(runtime->opaque)) {
        return WTE_STRICT_RESULT_TRACE_FAILED;
    }

    return WTE_STRICT_RESULT_OK;
}

enum wte_strict_result wte_strict_handle_exit(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime,
    const struct wte_strict_exit *strict_exit)
{
    const struct wte_strict_identity identity = {
        .range_id = strict_exit->range_id,
        .page_index = strict_exit->page_index,
        .generation = strict_exit->generation,
    };
    enum wte_strict_result result;

    if (!state->enabled || state->reset_pending) {
        return WTE_STRICT_RESULT_NOT_ENABLED;
    }

    if (!runtime->dump_sync || !runtime->ack || !runtime->trace_sync) {
        return WTE_STRICT_RESULT_CALLBACK_MISSING;
    }

    if (strict_exit->version != WTE_STRICT_ABI_VERSION_1 ||
        strict_exit->flags != WTE_STRICT_EXIT_KNOWN_FLAGS ||
        (strict_exit->flags & ~WTE_STRICT_EXIT_KNOWN_FLAGS) != 0 ||
        strict_exit->session_id != state->session_id ||
        strict_exit->generation == 0 ||
        wte_strict_normalize_cr3(strict_exit->cr3) != state->normalized_cr3 ||
        (strict_exit->gva & UINT64_C(0xfff)) != 0 ||
        (strict_exit->gpa & UINT64_C(0xfff)) != 0 ||
        !wte_strict_reserved_fields_are_zero(strict_exit) ||
        !wte_strict_range_is_registered(state, strict_exit->range_id,
                                        strict_exit->gva,
                                        strict_exit->page_index)) {
        return WTE_STRICT_RESULT_INVALID_EXIT;
    }

    if (state->has_last_acked &&
        state->last_acked.range_id == identity.range_id &&
        state->last_acked.page_index == identity.page_index &&
        state->last_acked.generation == identity.generation) {
        return WTE_STRICT_RESULT_ALREADY_CONSUMED;
    }

    result = wte_strict_append_trace(runtime,
                                     WTE_STRICT_TRACE_REGISTER_COMMIT,
                                     &identity);
    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    result = wte_strict_append_trace(runtime,
                                     WTE_STRICT_TRACE_STRICT_EXEC_EXIT,
                                     &identity);
    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    result = wte_strict_append_trace(runtime,
                                     WTE_STRICT_TRACE_QEMU_DUMP_BEGIN,
                                     &identity);
    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    if (!runtime->dump_sync(runtime->opaque, strict_exit)) {
        return WTE_STRICT_RESULT_DUMP_FAILED;
    }

    result = wte_strict_append_trace(runtime,
                                     WTE_STRICT_TRACE_QEMU_DUMP_END,
                                     &identity);
    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    if (runtime->opaque == NULL || !runtime->trace_sync(runtime->opaque)) {
        return WTE_STRICT_RESULT_TRACE_FAILED;
    }

    result = runtime->ack(runtime->opaque, strict_exit->session_id,
                          strict_exit->range_id, strict_exit->generation,
                          strict_exit->page_index);
    if (result != WTE_STRICT_RESULT_OK) {
        return WTE_STRICT_RESULT_ACK_FAILED;
    }

    result = wte_strict_append_trace(runtime, WTE_STRICT_TRACE_STRICT_ACK,
                                     &identity);
    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    if (runtime->opaque == NULL || !runtime->trace_sync(runtime->opaque)) {
        return WTE_STRICT_RESULT_TRACE_FAILED;
    }

    state->last_acked = identity;
    state->has_last_acked = true;
    return WTE_STRICT_RESULT_OK;
}

enum wte_strict_result wte_strict_prepare_reset(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime)
{
    enum wte_strict_result result;
    uint64_t new_session_id = 0;
    size_t i;

    if (!state->enabled) {
        return WTE_STRICT_RESULT_OK;
    }

    if (!runtime->reset) {
        return WTE_STRICT_RESULT_CALLBACK_MISSING;
    }

    result = runtime->reset(runtime->opaque, state->session_id,
                            &new_session_id);
    if (result != WTE_STRICT_RESULT_OK || new_session_id == 0) {
        return result != WTE_STRICT_RESULT_OK ? result
                                              : WTE_STRICT_RESULT_INVALID_QUERY;
    }

    state->session_id = new_session_id;
    state->reset_pending = true;
    state->has_last_acked = false;
    for (i = 0; i < state->range_count; i++) {
        state->ranges[i].range_id = 0;
    }

    return WTE_STRICT_RESULT_OK;
}

enum wte_strict_result wte_strict_complete_reset(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime)
{
    size_t i;

    if (!state->enabled) {
        return WTE_STRICT_RESULT_OK;
    }

    if (!state->reset_pending) {
        return WTE_STRICT_RESULT_OK;
    }

    if (!runtime->range_add) {
        return WTE_STRICT_RESULT_CALLBACK_MISSING;
    }

    for (i = 0; i < state->range_count; i++) {
        uint64_t range_id = 0;
        enum wte_strict_result result = runtime->range_add(
            runtime->opaque, state->session_id, state->ranges[i].gva_start,
            state->ranges[i].gva_end, &range_id);

        if (result != WTE_STRICT_RESULT_OK || range_id == 0) {
            return result != WTE_STRICT_RESULT_OK ? result
                                                  : WTE_STRICT_RESULT_INVALID_RANGE;
        }

        state->ranges[i].range_id = range_id;
    }

    state->reset_pending = false;
    return WTE_STRICT_RESULT_OK;
}

enum wte_strict_result wte_strict_reset_session(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime)
{
    enum wte_strict_result result = wte_strict_prepare_reset(state, runtime);

    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    return wte_strict_complete_reset(state, runtime);
}

enum wte_strict_result wte_strict_disable_session(
    struct wte_strict_state *state,
    const struct wte_strict_runtime *runtime)
{
    enum wte_strict_result result;

    if (!state->enabled) {
        return WTE_STRICT_RESULT_OK;
    }

    if (!runtime->disable) {
        return WTE_STRICT_RESULT_CALLBACK_MISSING;
    }

    result = runtime->disable(runtime->opaque, state->session_id);
    if (result != WTE_STRICT_RESULT_OK) {
        return result;
    }

    state->enabled = false;
    state->reset_pending = false;
    state->session_id = 0;
    state->normalized_cr3 = 0;
    state->max_ranges = 0;
    state->max_pages_per_range = 0;
    state->range_count = 0;
    state->has_last_acked = false;

    return WTE_STRICT_RESULT_OK;
}

const char *wte_strict_trace_event_name(enum wte_strict_trace_event event)
{
    switch (event) {
    case WTE_STRICT_TRACE_REGISTER_COMMIT:
        return "REGISTER_COMMIT";
    case WTE_STRICT_TRACE_STRICT_EXEC_EXIT:
        return "STRICT_EXEC_EXIT";
    case WTE_STRICT_TRACE_QEMU_DUMP_BEGIN:
        return "QEMU_DUMP_BEGIN";
    case WTE_STRICT_TRACE_QEMU_DUMP_END:
        return "QEMU_DUMP_END";
    case WTE_STRICT_TRACE_STRICT_ACK:
        return "STRICT_ACK";
    }

    return "UNKNOWN";
}
