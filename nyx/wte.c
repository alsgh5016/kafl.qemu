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

/* ── Dirty Ring Globals (defined in nyx_dirty_ring.c) ──────────── */

extern int                   dirty_ring_size;
extern struct kvm_dirty_gfn *kvm_dirty_gfns;
extern uint32_t              kvm_dirty_gfns_index;
extern uint32_t              kvm_dirty_gfns_index_mask;

/* ── WtE Singleton ─────────────────────────────────────────────── */

static wte_state_t wte_state;

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

    wte_state.dirty_map = kh_init(WTE_DIRTY);
    wte_state.exec_map  = kh_init(WTE_EXEC);
    wte_state.round     = 0;
    wte_state.active    = false;

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

    while (true) {
        uint32_t ring_idx = scan_idx & kvm_dirty_gfns_index_mask;
        struct kvm_dirty_gfn *entry = &kvm_dirty_gfns[ring_idx];


        if ((entry->flags & 0x1) == 0) {
            break;
        }

        uint64_t gfn = entry->offset;
        uint64_t gpa = gfn << 12;


        khiter_t k = kh_get(WTE_DIRTY, wte_state.dirty_map, gfn);

        if (k == kh_end(wte_state.dirty_map)) {

            wte_page_info_t *info = malloc(sizeof(wte_page_info_t));
            memset(info, 0, sizeof(wte_page_info_t));
            info->gpa = gpa;

            /* Read baseline content (snapshot-time content via physical read) */
            cpu_physical_memory_read(gpa, info->baseline, WTE_PAGE_SIZE);
            info->baseline_valid = true;

            /* Read current content (post-write) */
            cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);


            wte_compute_diff(info);


            int ret;
            k = kh_put(WTE_DIRTY, wte_state.dirty_map, gfn, &ret);
            kh_value(wte_state.dirty_map, k) = info;

            new_pages++;
        } else {

            wte_page_info_t *info = kh_value(wte_state.dirty_map, k);
            cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);
            wte_compute_diff(info);
        }

        scan_idx++;
    }

    wte_state.last_scanned_ring_index = scan_idx;

    if (new_pages > 0) {
        nyx_printf("[WtE] Scanned ring: %d new dirty pages (total tracked: %u)\n",
                   new_pages, kh_size(wte_state.dirty_map));
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

    /*
     * Convert virtual IP → physical GFN.
     * Use the target process CR3 for translation.
     */
    CPUState *cpu = first_cpu;
    uint64_t phys_addr = get_paging_phys_addr(cpu, wte_state.target_cr3, ip);

    if (phys_addr == (uint64_t)-1) {
        /* Translation failed — page not mapped, ignore */
        return;
    }

    uint64_t gfn = phys_addr >> 12;


    khiter_t k = kh_get(WTE_DIRTY, wte_state.dirty_map, gfn);
    if (k == kh_end(wte_state.dirty_map)) {
        return;
    }

    khiter_t ek = kh_get(WTE_EXEC, wte_state.exec_map, gfn);
    if (ek != kh_end(wte_state.exec_map)) {
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


    if (info->diff_count == 0) {
        return;
    }



    int ret;
    ek = kh_put(WTE_EXEC, wte_state.exec_map, gfn, &ret);
    kh_value(wte_state.exec_map, ek) = ip;

    wte_state.wte_count++;
    wte_state.total_wte_count++;

    nyx_printf("[WtE] *** WRITTEN-THEN-EXECUTED ***  round=%d  RIP=0x%lx  "
               "GFN=0x%lx  GPA=0x%lx  diffs=%d\n",
               wte_state.round, (unsigned long)ip, (unsigned long)gfn,
               (unsigned long)info->gpa, info->diff_count);


    wte_dump_detection(ip, gfn, info, cpu);
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

wte_state_t *wte_get_state(void)
{
    return &wte_state;
}
