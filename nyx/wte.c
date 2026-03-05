/*
 * WtE (Written-then-Executed) Detection — Core Implementation
 *
 * Leverages KVM Dirty Ring for EPT-based write tracking and Intel PT
 * bb_callback for execution monitoring. Content diff eliminates false
 * positives from incidental dirty pages.
 */

#include "qemu/osdep.h"

#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include "exec/cpu-common.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"

#include "nyx/debug.h"
#include "nyx/helpers.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"
#include "nyx/wte.h"

#include "nyx/snapshot/memory/backend/nyx_dirty_ring.h"
#include "nyx/fast_vm_reload.h"

/* ── Dirty Ring Globals (defined in nyx_dirty_ring.c) ──────────── */

extern int                   dirty_ring_size;
extern struct kvm_dirty_gfn *kvm_dirty_gfns;
extern uint32_t              kvm_dirty_gfns_index;
extern uint32_t              kvm_dirty_gfns_index_mask;

/* ── WtE Singleton ─────────────────────────────────────────────── */

static wte_state_t wte_state;

/* ── Debug Counters (bb_callback stats) ────────────────────────────── */

static uint64_t dbg_bb_total_calls   = 0;
static uint64_t dbg_bb_translate_fail = 0;
static uint64_t dbg_bb_dirty_miss     = 0;
static uint64_t dbg_bb_exec_already   = 0;
static uint64_t dbg_bb_diff_zero      = 0;
static uint64_t dbg_bb_wte_hit        = 0;

/* ── Helpers ───────────────────────────────────────────────────── */

/*
 * Compute content diff between baseline and current page content.
 * Records changed byte ranges (contiguous changed regions).
 */
static void wte_compute_diff(wte_page_info_t *info)
{
    info->diff_count = 0;
    info->diff_done  = true;

    bool in_diff = false;
    int  start   = 0;

    for (int i = 0; i < WTE_PAGE_SIZE; i++) {
        bool differ = (info->baseline[i] != info->current[i]);

        if (differ && !in_diff) {

            in_diff = true;
            start   = i;
        } else if (!differ && in_diff) {

            in_diff = false;
            if (info->diff_count < WTE_MAX_DIFF_RANGES) {
                info->diff_offsets[info->diff_count] = (uint16_t)start;
                info->diff_lengths[info->diff_count] = (uint16_t)(i - start);
                info->diff_count++;
            }
        }
    }


    if (in_diff && info->diff_count < WTE_MAX_DIFF_RANGES) {
        info->diff_offsets[info->diff_count] = (uint16_t)start;
        info->diff_lengths[info->diff_count] = (uint16_t)(WTE_PAGE_SIZE - start);
        info->diff_count++;
    }
}

/*
 * Dump WtE detection results: page content + diff info + module map.
 */
static void wte_dump_detection(uint64_t exec_rip, uint64_t gfn,
                               wte_page_info_t *info, CPUState *cpu)
{
    char *dump_dir = NULL;
    assert(asprintf(&dump_dir, "%s/dump/wte_round%03d_gfn%lx",
                    GET_GLOBAL_STATE()->workdir_path,
                    wte_state.round, (unsigned long)gfn) != -1);
    mkdir(dump_dir, 0755);


    char *path = NULL;
    assert(asprintf(&path, "%s/baseline.bin", dump_dir) != -1);
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(info->baseline, 1, WTE_PAGE_SIZE, f);
        fclose(f);
    }
    free(path);


    assert(asprintf(&path, "%s/current.bin", dump_dir) != -1);
    f = fopen(path, "wb");
    if (f) {
        fwrite(info->current, 1, WTE_PAGE_SIZE, f);
        fclose(f);
    }
    free(path);


    assert(asprintf(&path, "%s/diff_report.txt", dump_dir) != -1);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "WtE Detection Report\n");
        fprintf(f, "====================\n");
        fprintf(f, "Round:     %d\n", wte_state.round);
        fprintf(f, "GFN:       0x%lx\n", (unsigned long)gfn);
        fprintf(f, "GPA:       0x%lx\n", (unsigned long)info->gpa);
        fprintf(f, "Exec RIP:  0x%lx\n", (unsigned long)exec_rip);
        fprintf(f, "CR3:       0x%lx\n", (unsigned long)wte_state.target_cr3);
        fprintf(f, "Diff Ranges: %d\n\n", info->diff_count);

        for (int i = 0; i < info->diff_count; i++) {
            fprintf(f, "  Range[%d]: offset=0x%04x, length=%d bytes\n",
                    i, info->diff_offsets[i], info->diff_lengths[i]);
        }
        fclose(f);
    }
    free(path);

    nyx_printf("[WtE] DETECTED round=%d GFN=0x%lx GPA=0x%lx RIP=0x%lx diffs=%d\n",
               wte_state.round, (unsigned long)gfn, (unsigned long)info->gpa,
               (unsigned long)exec_rip, info->diff_count);

    free(dump_dir);
}

/* ── Public API ────────────────────────────────────────────────── */

void wte_init(void)
{
    memset(&wte_state, 0, sizeof(wte_state_t));

    wte_state.dirty_map    = kh_init(WTE_DIRTY);
    wte_state.exec_map     = kh_init(WTE_EXEC);
    wte_state.bb_deferred  = kh_init(WTE_BB_DEFER);
    wte_state.round        = 0;
    wte_state.active       = false;
    wte_state.overflow_count = 0;

    nyx_printf("[WtE] Initialized\n");
}

void wte_destroy(void)
{
    if (wte_state.dirty_map) {
        khiter_t k;
        for (k = kh_begin(wte_state.dirty_map);
             k != kh_end(wte_state.dirty_map); ++k)
        {
            if (kh_exist(wte_state.dirty_map, k)) {
                free(kh_value(wte_state.dirty_map, k));
            }
        }
        kh_destroy(WTE_DIRTY, wte_state.dirty_map);
    }
    if (wte_state.exec_map) {
        kh_destroy(WTE_EXEC, wte_state.exec_map);
    }
    if (wte_state.bb_deferred) {
        kh_destroy(WTE_BB_DEFER, wte_state.bb_deferred);
    }

    memset(&wte_state, 0, sizeof(wte_state_t));
    nyx_printf("[WtE] Destroyed\n");
}

void wte_activate(uint64_t cr3, bool is_64bit)
{
    wte_state.active     = true;
    wte_state.target_cr3 = cr3;
    wte_state.is_64bit   = is_64bit;
    wte_state.round      = 0;
    wte_state.wte_count  = 0;
    wte_state.total_wte_count = 0;

    /* Sync to current dirty ring index so we only scan new entries */
    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;

    nyx_printf("[WtE] Activated: CR3=0x%lx, 64bit=%d\n",
               (unsigned long)cr3, is_64bit);
}

void wte_deactivate(void)
{
    nyx_printf("[WtE] Deactivated: total detections=%d across %d rounds\n",
               wte_state.total_wte_count, wte_state.round + 1);
    wte_state.active = false;
}

/*
 * Scan dirty ring entries that haven't been processed yet.
 * For each new dirty GFN: read current page content via GPA,
 * store baseline (if first time) and current content for later diff.
 *
 * MUST be called BEFORE dirty_ring_flush_and_collect() so entries
 * are still valid in the ring.
 */
void wte_scan_dirty_ring(void)
{
    if (!wte_state.active || !kvm_dirty_gfns) {
        return;
    }

    uint32_t scan_idx = wte_state.last_scanned_ring_index;
    int      new_pages = 0;
    int      updated_pages = 0;
    int      diff_at_scan = 0;  /* pages with diff_count > 0 at scan time */

    while (true) {
        uint32_t ring_idx = scan_idx & kvm_dirty_gfns_index_mask;
        struct kvm_dirty_gfn *entry = &kvm_dirty_gfns[ring_idx];

        if ((entry->flags & 0x1) == 0) {
            break;
        }

        uint64_t gfn = entry->offset;
        uint64_t gpa = gfn << 12;

        /* Skip low system pages (IVT, BDA, etc.) — not target process memory */
        if (gfn <= 0x10) {
            scan_idx++;
            continue;
        }

        khiter_t k = kh_get(WTE_DIRTY, wte_state.dirty_map, gfn);

        if (k == kh_end(wte_state.dirty_map)) {
            wte_page_info_t *info = malloc(sizeof(wte_page_info_t));
            memset(info, 0, sizeof(wte_page_info_t));
            info->gpa = gpa;

            /*
             * Read baseline content from root snapshot (shadow memory).
             * This gives us the pre-write content for accurate diff.
             */
            if (fast_reload_root_created(get_fast_reload_snapshot())) {
                if (!read_snapshot_memory(get_fast_reload_snapshot(),
                                         gpa, info->baseline, WTE_PAGE_SIZE)) {
                    /* Snapshot doesn't cover this GPA — use current as baseline */
                    cpu_physical_memory_read(gpa, info->baseline, WTE_PAGE_SIZE);
                }
            } else {
                /* No snapshot available — fallback to current content */
                cpu_physical_memory_read(gpa, info->baseline, WTE_PAGE_SIZE);
            }
            info->baseline_valid = true;

            /* Read current content (post-write) */
            cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);

            wte_compute_diff(info);
            /* DEBUG: log first 10 new dirty pages */
            if (new_pages < 10) {
                nyx_printf("[WtE][DBG] new dirty GFN=0x%lx GPA=0x%lx diff_count=%d\n",
                           (unsigned long)gfn, (unsigned long)gpa, info->diff_count);
            }
            if (info->diff_count > 0) {
                diff_at_scan++;
            }

            int ret;
            k = kh_put(WTE_DIRTY, wte_state.dirty_map, gfn, &ret);
            kh_value(wte_state.dirty_map, k) = info;

            new_pages++;
        } else {
            wte_page_info_t *info = kh_value(wte_state.dirty_map, k);
            cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);
            wte_compute_diff(info);
            updated_pages++;
            if (info->diff_count > 0) {
                diff_at_scan++;
            }
        }

        scan_idx++;
    }

    wte_state.last_scanned_ring_index = scan_idx;

    if (new_pages > 0 || updated_pages > 0) {
        nyx_printf("[WtE] Scanned ring: %d new, %d updated dirty pages ",
                   new_pages, updated_pages);
        nyx_printf("(total tracked: %lu, diff_at_scan: %d)\n",
                   (unsigned long)kh_size(wte_state.dirty_map), diff_at_scan);
    }
}

/*
 * Intel PT bb_callback — called for every basic block executed by guest.
 *
 * Checks if the execution target falls within a dirty page (GFN in dirty_map).
 * If so, verifies content diff to confirm WtE, then dumps.
 */
void wte_bb_callback(void *opaque, disassembler_mode_t mode,
                     uint64_t ip, uint64_t tsc)
{

    if (!wte_state.active) {
        return;
    }

    dbg_bb_total_calls++;

    /* Log first 5 bb_callback invocations */
    if (dbg_bb_total_calls <= 5) {
        nyx_printf("[WtE][DBG] bb_callback #%lu: ip=0x%lx mode=%d\n",
                   (unsigned long)dbg_bb_total_calls, (unsigned long)ip, mode);
    }

    /*
     * Convert virtual IP → physical GFN.
     * Use the target process CR3 for translation.
     */
    CPUState *cpu = first_cpu;
    uint64_t phys_addr = get_paging_phys_addr(cpu, wte_state.target_cr3, ip);

    if (phys_addr == (uint64_t)-1) {
        dbg_bb_translate_fail++;
        if (dbg_bb_translate_fail <= 5) {
            nyx_printf("[WtE][DBG] translate FAIL: ip=0x%lx cr3=0x%lx\n",
                       (unsigned long)ip, (unsigned long)wte_state.target_cr3);
        }
        return;
    }

    uint64_t gfn = phys_addr >> 12;

    khiter_t k = kh_get(WTE_DIRTY, wte_state.dirty_map, gfn);
    if (k == kh_end(wte_state.dirty_map)) {
        dbg_bb_dirty_miss++;
        if (dbg_bb_dirty_miss <= 5) {
            nyx_printf("[WtE][DBG] dirty_map MISS: ip=0x%lx gfn=0x%lx phys=0x%lx\n",
                       (unsigned long)ip, (unsigned long)gfn, (unsigned long)phys_addr);
        }
        /* Defer this IP for later re-check when dirty_map is complete */
        int defer_ret;
        kh_put(WTE_BB_DEFER, wte_state.bb_deferred, ip, &defer_ret);
        return;
    }

    /* HIT: ip lands on a dirty page */
    nyx_printf("[WtE][DBG] dirty_map HIT: ip=0x%lx gfn=0x%lx\n",
               (unsigned long)ip, (unsigned long)gfn);

    khiter_t ek = kh_get(WTE_EXEC, wte_state.exec_map, gfn);
    if (ek != kh_end(wte_state.exec_map)) {
        dbg_bb_exec_already++;
        return;
    }
    wte_page_info_t *info = kh_value(wte_state.dirty_map, k);

    /*
     * Re-read current content to get latest state at execution time.
     * This is crucial: the page may have been written further between
     * the dirty ring scan and this execution.
     */
    cpu_physical_memory_read(info->gpa, info->current, WTE_PAGE_SIZE);
    wte_compute_diff(info);

    nyx_printf("[WtE][DBG] dirty HIT detail: gfn=0x%lx gpa=0x%lx diff_count=%d\n",
               (unsigned long)gfn, (unsigned long)info->gpa, info->diff_count);

    if (info->diff_count == 0) {
        dbg_bb_diff_zero++;
        return;
    }

    /* Confirmed WtE */
    int ret;
    ek = kh_put(WTE_EXEC, wte_state.exec_map, gfn, &ret);
    kh_value(wte_state.exec_map, ek) = ip;

    wte_state.wte_count++;
    wte_state.total_wte_count++;
    dbg_bb_wte_hit++;

    nyx_printf("[WtE] *** WRITTEN-THEN-EXECUTED ***  round=%d  RIP=0x%lx  "
               "GFN=0x%lx  GPA=0x%lx  diffs=%d\n",
               wte_state.round, (unsigned long)ip, (unsigned long)gfn,
               (unsigned long)info->gpa, info->diff_count);

    wte_dump_detection(ip, gfn, info, cpu);
}

/* ── Debug summary — call after pt_dump completes to see bb_callback stats ─── */

void wte_print_debug_summary(void)
{
    nyx_printf("[WtE][DBG] === BB_CALLBACK SUMMARY === "
               "total=%lu tfail=%lu miss=%lu dirty_hit=%lu diff0=%lu "
               "exec_dup=%lu wte=%lu dirty_map_size=%lu "
               "deferred=%lu overflow=%lu\n",
               (unsigned long)dbg_bb_total_calls,
               (unsigned long)dbg_bb_translate_fail,
               (unsigned long)dbg_bb_dirty_miss,
               (unsigned long)(dbg_bb_diff_zero + dbg_bb_wte_hit),
               (unsigned long)dbg_bb_diff_zero,
               (unsigned long)dbg_bb_exec_already,
               (unsigned long)dbg_bb_wte_hit,
               (unsigned long)kh_size(wte_state.dirty_map),
               (unsigned long)kh_size(wte_state.bb_deferred),
               (unsigned long)wte_state.overflow_count);
}

/*
 * Reset WtE tracking for next detection round.
 * Clears dirty_map and exec_map, increments round counter.
 * After this, new writes will be tracked from zero base.
 */
void wte_reset_round(void)
{
    if (!wte_state.active) {
        return;
    }

    nyx_printf("[WtE] Round %d complete: %d WtE detections. Resetting.\n",
               wte_state.round, wte_state.wte_count);


    khiter_t k;
    for (k = kh_begin(wte_state.dirty_map);
         k != kh_end(wte_state.dirty_map); ++k)
    {
        if (kh_exist(wte_state.dirty_map, k)) {
            free(kh_value(wte_state.dirty_map, k));
        }
    }


    kh_clear(WTE_DIRTY, wte_state.dirty_map);
    kh_clear(WTE_EXEC, wte_state.exec_map);
    kh_clear(WTE_BB_DEFER, wte_state.bb_deferred);


    wte_state.round++;
    wte_state.wte_count = 0;


    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;

    nyx_printf("[WtE] Round %d started. Tracking from clean state.\n",
               wte_state.round);
}

bool wte_is_active(void)
{
    return wte_state.active;
}

/*
 * Check deferred BB IPs against the now-complete dirty_map.
 * Called at RELEASE after final dirty ring scan + pt_dump,
 * when dirty_map is fully populated.
 */
void wte_check_deferred_bbs(void)
{
    if (!wte_state.active || !wte_state.bb_deferred) {
        return;
    }

    int checked = 0, hits = 0;
    CPUState *cpu = first_cpu;

    nyx_printf("[WtE] Checking %lu deferred BBs against dirty_map (size=%lu)\n",
               (unsigned long)kh_size(wte_state.bb_deferred),
               (unsigned long)kh_size(wte_state.dirty_map));

    khiter_t ki;
    for (ki = kh_begin(wte_state.bb_deferred);
         ki != kh_end(wte_state.bb_deferred); ++ki)
    {
        if (!kh_exist(wte_state.bb_deferred, ki)) {
            continue;
        }

        uint64_t ip = kh_key(wte_state.bb_deferred, ki);
        checked++;

        /* Translate IP → physical → GFN */
        uint64_t phys_addr = get_paging_phys_addr(cpu, wte_state.target_cr3, ip);
        if (phys_addr == (uint64_t)-1) {
            continue;
        }

        uint64_t gfn = phys_addr >> 12;

        /* Check dirty_map */
        khiter_t dk = kh_get(WTE_DIRTY, wte_state.dirty_map, gfn);
        if (dk == kh_end(wte_state.dirty_map)) {
            continue;  /* Still not in dirty_map — not a write target */
        }

        /* Skip if already confirmed WtE for this GFN */
        khiter_t ek = kh_get(WTE_EXEC, wte_state.exec_map, gfn);
        if (ek != kh_end(wte_state.exec_map)) {
            continue;
        }

        /* Re-read current content and compute diff */
        wte_page_info_t *info = kh_value(wte_state.dirty_map, dk);
        cpu_physical_memory_read(info->gpa, info->current, WTE_PAGE_SIZE);
        wte_compute_diff(info);

        nyx_printf("[WtE][DBG] deferred HIT: ip=0x%lx gfn=0x%lx diff_count=%d\n",
                   (unsigned long)ip, (unsigned long)gfn, info->diff_count);

        if (info->diff_count == 0) {
            continue;
        }

        /* Confirmed WtE via deferred check */
        int ret;
        ek = kh_put(WTE_EXEC, wte_state.exec_map, gfn, &ret);
        kh_value(wte_state.exec_map, ek) = ip;

        wte_state.wte_count++;
        wte_state.total_wte_count++;
        dbg_bb_wte_hit++;
        hits++;

        nyx_printf("[WtE] *** DEFERRED WtE DETECTED ***  round=%d  RIP=0x%lx  "
                   "GFN=0x%lx  GPA=0x%lx  diffs=%d\n",
                   wte_state.round, (unsigned long)ip, (unsigned long)gfn,
                   (unsigned long)info->gpa, info->diff_count);

        wte_dump_detection(ip, gfn, info, cpu);
    }

    nyx_printf("[WtE] Deferred check done: checked=%d hits=%d\n", checked, hits);
}

wte_state_t *wte_get_state(void)
{
    return &wte_state;
}
