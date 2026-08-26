#include <stdio.h>

#include "../nyx/wte_policy.h"
#include "../nyx/wte_policy.c"

static int test_pending_dynamic_page_requests_first_exec_dump(void)
{
    /* Given: an explicitly registered dynamic page whose first execution is
     * still pending, but which has no WRITTEN bit, no content diff, and no
     * RIP overlap with any diff range.
    */
    const struct wte_exec_policy_input input = {
        .is_dynamic = true,
        .first_exec_pending = true,
        .written = false,
        .diff_count = 0,
        .rip_overlaps_diff = false,
    };

    /* When: the execution policy is evaluated before the legacy WRITTEN/diff
     * gates in wte_handle_exec_violation().
     */
    const enum wte_exec_policy_action action = wte_exec_policy_decide(&input);

    /* Then: the policy requires a first-exec dump unconditionally. */
    if (action != WTE_EXEC_POLICY_ACTION_DUMP_FIRST_EXEC) {
        puts("not ok 1 - pending dynamic page requests first-exec dump");
        return 1;
    }

    puts("ok 1 - pending dynamic page requests first-exec dump");
    return 0;
}

static int test_dynamic_page_without_pending_uses_legacy_path(void)
{
    /* Given: the same explicit dynamic registration, but no pending-first-exec
     * bit and still no WRITTEN/diff/RIP-overlap evidence.
    */
    const struct wte_exec_policy_input input = {
        .is_dynamic = true,
        .first_exec_pending = false,
        .written = false,
        .diff_count = 0,
        .rip_overlaps_diff = false,
    };

    /* When: the pure execution policy is evaluated. */
    const enum wte_exec_policy_action action = wte_exec_policy_decide(&input);

    /* Then: no pending bit selects the legacy path instead of a dump. */
    if (action != WTE_EXEC_POLICY_ACTION_FALLTHROUGH_TO_LEGACY) {
        puts("not ok 2 - dynamic page without pending uses legacy path");
        return 1;
    }

    puts("ok 2 - dynamic page without pending uses legacy path");
    return 0;
}

int main(void)
{
    int failures = 0;

    puts("TAP version 13");
    puts("1..2");
    failures += test_pending_dynamic_page_requests_first_exec_dump();
    failures += test_dynamic_page_without_pending_uses_legacy_path();

    return failures != 0;
}
