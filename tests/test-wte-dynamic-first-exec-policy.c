#include <stdio.h>

#include "../nyx/wte_policy.h"
#include "../nyx/wte_policy.c"

static int test_pending_dynamic_page_requests_first_exec_dump(void)
{
    const struct wte_exec_policy_input input = {
        .is_dynamic = true,
        .first_exec_pending = true,
        .written = false,
        .diff_count = 0,
        .rip_overlaps_diff = false,
    };

    const enum wte_exec_policy_action action = wte_exec_policy_decide(&input);

    if (action != WTE_EXEC_POLICY_ACTION_DUMP_FIRST_EXEC) {
        puts("not ok 1 - pending dynamic page requests first-exec dump");
        return 1;
    }

    puts("ok 1 - pending dynamic page requests first-exec dump");
    return 0;
}

static int test_dynamic_page_without_pending_uses_legacy_path(void)
{
    const struct wte_exec_policy_input input = {
        .is_dynamic = true,
        .first_exec_pending = false,
        .written = false,
        .diff_count = 0,
        .rip_overlaps_diff = false,
    };

    const enum wte_exec_policy_action action = wte_exec_policy_decide(&input);

    if (action != WTE_EXEC_POLICY_ACTION_FALLTHROUGH_TO_LEGACY) {
        puts("not ok 2 - dynamic page without pending uses legacy path");
        return 1;
    }

    puts("ok 2 - dynamic page without pending uses legacy path");
    return 0;
}

static int test_first_registration_arms(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = false,
        .baseline_valid = false,
        .first_exec_pending = false,
        .content_changed = false,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC) {
        puts("not ok 3 - first registration arms");
        return 1;
    }

    puts("ok 3 - first registration arms");
    return 0;
}

static int test_missing_baseline_no_pending_arms(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = false,
        .first_exec_pending = false,
        .content_changed = false,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC) {
        puts("not ok 4 - missing baseline no pending arms");
        return 1;
    }

    puts("ok 4 - missing baseline no pending arms");
    return 0;
}

static int test_valid_baseline_no_pending_unchanged_keeps(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = false,
        .content_changed = false,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_KEEP_STATE) {
        puts("not ok 5 - valid baseline no pending unchanged keeps");
        return 1;
    }

    puts("ok 5 - valid baseline no pending unchanged keeps");
    return 0;
}

static int test_valid_baseline_no_pending_changed_arms(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = false,
        .content_changed = true,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC) {
        puts("not ok 6 - valid baseline no pending changed arms");
        return 1;
    }

    puts("ok 6 - valid baseline no pending changed arms");
    return 0;
}

static int test_valid_baseline_pending_unchanged_keeps(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = true,
        .content_changed = false,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_KEEP_STATE) {
        puts("not ok 7 - valid baseline pending unchanged keeps");
        return 1;
    }

    puts("ok 7 - valid baseline pending unchanged keeps");
    return 0;
}

static int test_valid_baseline_pending_changed_keeps(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = true,
        .content_changed = true,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_KEEP_STATE) {
        puts("not ok 8 - valid baseline pending changed keeps");
        return 1;
    }

    puts("ok 8 - valid baseline pending changed keeps");
    return 0;
}

static int test_registration_to_execution_sequence_identical(void)
{
    const struct wte_dynamic_registration_policy_input registration = {
        .already_dynamic = false,
        .baseline_valid = false,
        .first_exec_pending = false,
        .content_changed = false,
    };
    const struct wte_exec_policy_input execution = {
        .is_dynamic = true,
        .first_exec_pending = true,
        .written = false,
        .diff_count = 0,
        .rip_overlaps_diff = false,
    };
    const struct wte_dynamic_registration_policy_input repeated = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = false,
        .content_changed = false,
    };

    if (wte_dynamic_registration_policy_decide(&registration) !=
        WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC) {
        puts("not ok 9 - registration-to-execution identical sequence");
        return 1;
    }

    if (wte_exec_policy_decide(&execution) !=
        WTE_EXEC_POLICY_ACTION_DUMP_FIRST_EXEC) {
        puts("not ok 9 - registration-to-execution identical sequence");
        return 1;
    }

    if (wte_dynamic_registration_policy_decide(&repeated) !=
        WTE_DYNAMIC_REGISTRATION_POLICY_KEEP_STATE) {
        puts("not ok 9 - registration-to-execution identical sequence");
        return 1;
    }

    puts("ok 9 - registration-to-execution identical sequence");
    return 0;
}

static int test_registration_to_execution_sequence_changed_consumed(void)
{
    const struct wte_dynamic_registration_policy_input changed = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = false,
        .content_changed = true,
    };
    const struct wte_exec_policy_input execution = {
        .is_dynamic = true,
        .first_exec_pending = true,
        .written = false,
        .diff_count = 0,
        .rip_overlaps_diff = false,
    };

    if (wte_dynamic_registration_policy_decide(&changed) !=
        WTE_DYNAMIC_REGISTRATION_POLICY_ARM_FIRST_EXEC) {
        puts("not ok 10 - registration-to-execution changed consumed sequence");
        return 1;
    }

    if (wte_exec_policy_decide(&execution) !=
        WTE_EXEC_POLICY_ACTION_DUMP_FIRST_EXEC) {
        puts("not ok 10 - registration-to-execution changed consumed sequence");
        return 1;
    }

    puts("ok 10 - registration-to-execution changed consumed sequence");
    return 0;
}

static int test_consumed_unchanged_remap(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = false,
        .content_changed = false,
        .gfn_changed = true,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_MAPPING_REFRESH) {
        puts("not ok 11 - consumed unchanged remap uses mapping refresh");
        return 1;
    }

    puts("ok 11 - consumed unchanged remap uses mapping refresh");
    return 0;
}

static int test_pending_remap(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = true,
        .content_changed = false,
        .gfn_changed = true,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_MAPPING_REFRESH) {
        puts("not ok 12 - pending remap uses mapping refresh");
        return 1;
    }

    puts("ok 12 - pending remap uses mapping refresh");
    return 0;
}

static int test_pending_changed_remap(void)
{
    const struct wte_dynamic_registration_policy_input input = {
        .already_dynamic = true,
        .baseline_valid = true,
        .first_exec_pending = true,
        .content_changed = true,
        .gfn_changed = true,
    };

    const enum wte_dynamic_registration_policy_action action =
        wte_dynamic_registration_policy_decide(&input);

    if (action != WTE_DYNAMIC_REGISTRATION_POLICY_MAPPING_REFRESH) {
        puts("not ok 13 - pending changed remap preserves pending state");
        return 1;
    }

    puts("ok 13 - pending changed remap preserves pending state");
    return 0;
}

int main(void)
{
    int failures = 0;

    puts("TAP version 13");
    puts("1..13");
    failures += test_pending_dynamic_page_requests_first_exec_dump();
    failures += test_dynamic_page_without_pending_uses_legacy_path();
    failures += test_first_registration_arms();
    failures += test_missing_baseline_no_pending_arms();
    failures += test_valid_baseline_no_pending_unchanged_keeps();
    failures += test_valid_baseline_no_pending_changed_arms();
    failures += test_valid_baseline_pending_unchanged_keeps();
    failures += test_valid_baseline_pending_changed_keeps();
    failures += test_registration_to_execution_sequence_identical();
    failures += test_registration_to_execution_sequence_changed_consumed();
    failures += test_consumed_unchanged_remap();
    failures += test_pending_remap();
    failures += test_pending_changed_remap();

    return failures != 0;
}
