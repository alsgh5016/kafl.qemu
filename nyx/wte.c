/*
 * WtE (Written-then-Executed) Detection — EPT NX Implementation
 *
 * Uses KVM Dirty Ring for write tracking and EPT NX bit manipulation
 * via KVM ioctls. When a dirty page is executed, KVM intercepts the
 * EPT NX violation and exits with KVM_EXIT_KAFL_WTE. Content diff
 * eliminates false positives from incidental dirty pages.
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

#include "target/i386/cpu.h"

/* Defined in hypercall.c — declared here because hypercall.h cannot
 * reference CPUX86State (x86-specific type unknown to vl.c). */
extern void dump_full_process_memory(CPUState *cpu, CPUX86State *env,
                                     const char *label);

/* ── Dirty Ring Globals (defined in nyx_dirty_ring.c) ──────────── */

extern int                   dirty_ring_size;
extern struct kvm_dirty_gfn *kvm_dirty_gfns;
extern uint32_t              kvm_dirty_gfns_index;
extern uint32_t              kvm_dirty_gfns_index_mask;

/* ── WtE Singleton ─────────────────────────────────────────────── */

static wte_state_t wte_state;

/* ── Internal: Page Tracking (simple dynamic array) ─────────────── */

#define WTE_INITIAL_CAPACITY 256

static int wte_find_page(uint64_t gfn)
{
    for (int i = 0; i < wte_state.page_count; i++) {
        if (wte_state.gfns[i] == gfn) {
            return i;
        }
    }
    return -1;
}

static wte_page_info_t *wte_add_page(uint64_t gfn)
{
    if (wte_state.page_count >= wte_state.page_capacity) {
        int new_cap = wte_state.page_capacity * 2;
        wte_state.pages = realloc(wte_state.pages,
                                  new_cap * sizeof(wte_page_info_t *));
        wte_state.gfns  = realloc(wte_state.gfns,
                                  new_cap * sizeof(uint64_t));
        wte_state.page_capacity = new_cap;
    }

    wte_page_info_t *info = malloc(sizeof(wte_page_info_t));
    memset(info, 0, sizeof(wte_page_info_t));

    int idx = wte_state.page_count;
    wte_state.pages[idx] = info;
    wte_state.gfns[idx]  = gfn;
    wte_state.page_count++;

    return info;
}

static void wte_free_all_pages(void)
{
    for (int i = 0; i < wte_state.page_count; i++) {
        free(wte_state.pages[i]);
    }
    wte_state.page_count = 0;
}

/* ── Content Diff ──────────────────────────────────────────────── */

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

/* ── Dump ──────────────────────────────────────────────────────── */

static void wte_dump_detection(uint64_t exec_rip, uint64_t gfn,
                               wte_page_info_t *info)
{
    char *dump_dir = NULL;
    assert(asprintf(&dump_dir, "%s/dump/wte_round%03d_gfn%lx",
                    GET_GLOBAL_STATE()->workdir_path,
                    wte_state.round, (unsigned long)gfn) != -1);
    mkdir(dump_dir, 0755);

    /* baseline.bin */
    char *path = NULL;
    assert(asprintf(&path, "%s/baseline.bin", dump_dir) != -1);
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(info->baseline, 1, WTE_PAGE_SIZE, f);
        fclose(f);
    }
    free(path);

    /* current.bin */
    assert(asprintf(&path, "%s/current.bin", dump_dir) != -1);
    f = fopen(path, "wb");
    if (f) {
        fwrite(info->current, 1, WTE_PAGE_SIZE, f);
        fclose(f);
    }
    free(path);

    /* diff_report.txt */
    assert(asprintf(&path, "%s/diff_report.txt", dump_dir) != -1);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "WtE Detection Report (EPT NX)\n");
        fprintf(f, "=============================\n");
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

/* ── KVM ioctl Wrappers ───────────────────────────────────────── */

int wte_kvm_enable(void)
{
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_WTE_ENABLE, 0);
    if (ret < 0) {
        nyx_printf("[WtE] ERROR: KVM_NYX_WTE_ENABLE failed: %d\n", ret);
    } else {
        nyx_printf("[WtE] KVM WtE enabled\n");
        wte_state.kvm_wte_enabled = true;
    }
    return ret;
}

int wte_kvm_disable(void)
{
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_WTE_DISABLE, 0);
    if (ret < 0) {
        nyx_printf("[WtE] ERROR: KVM_NYX_WTE_DISABLE failed: %d\n", ret);
    } else {
        nyx_printf("[WtE] KVM WtE disabled\n");
        wte_state.kvm_wte_enabled = false;
    }
    return ret;
}

int wte_kvm_set_nx(uint64_t *gfns, uint32_t count)
{
    if (count == 0) {
        return 0;
    }

    /*
     * Allocate kvm_nyx_wte_gfns with flexible array member.
     * struct kvm_nyx_wte_gfns { __u32 count; __u32 flags; __u64 gfns[]; };
     */
    size_t size = sizeof(struct kvm_nyx_wte_gfns) + count * sizeof(uint64_t);
    struct kvm_nyx_wte_gfns *req = malloc(size);
    req->count = count;
    req->flags = 0;
    memcpy(req->gfns, gfns, count * sizeof(uint64_t));

    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_WTE_SET_NX, req);
    if (ret < 0) {
        nyx_printf("[WtE] ERROR: KVM_NYX_WTE_SET_NX failed: %d (count=%u)\n",
                   ret, count);
    }

    free(req);
    return ret;
}

int wte_kvm_clear_nx(uint64_t *gfns, uint32_t count)
{
    if (count == 0) {
        return 0;
    }

    size_t size = sizeof(struct kvm_nyx_wte_gfns) + count * sizeof(uint64_t);
    struct kvm_nyx_wte_gfns *req = malloc(size);
    req->count = count;
    req->flags = 0;
    memcpy(req->gfns, gfns, count * sizeof(uint64_t));

    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_WTE_CLEAR_NX, req);
    if (ret < 0) {
        nyx_printf("[WtE] ERROR: KVM_NYX_WTE_CLEAR_NX failed: %d (count=%u)\n",
                   ret, count);
    }

    free(req);
    return ret;
}

/* ── Public API ────────────────────────────────────────────────── */

void wte_init(void)
{
    memset(&wte_state, 0, sizeof(wte_state_t));

    wte_state.pages = malloc(WTE_INITIAL_CAPACITY * sizeof(wte_page_info_t *));
    wte_state.gfns  = malloc(WTE_INITIAL_CAPACITY * sizeof(uint64_t));
    wte_state.page_capacity = WTE_INITIAL_CAPACITY;
    wte_state.page_count    = 0;

    wte_state.round  = 0;
    wte_state.active = false;
    wte_state.kvm_wte_enabled = false;

    nyx_printf("[WtE] Initialized (EPT NX mode)\n");
}

void wte_destroy(void)
{
    if (wte_state.kvm_wte_enabled) {
        wte_kvm_disable();
    }

    wte_free_all_pages();
    free(wte_state.pages);
    free(wte_state.gfns);

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
    wte_state.nx_pages_set    = 0;

    /* Enable KVM WtE tracking */
    if (!wte_state.kvm_wte_enabled) {
        wte_kvm_enable();
    }

    /* Sync to current dirty ring index so we only scan new entries */
    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;

    nyx_printf("[WtE] Activated: CR3=0x%lx, 64bit=%d\n",
               (unsigned long)cr3, is_64bit);
}

void wte_deactivate(void)
{
    nyx_printf("[WtE] Deactivated: total detections=%d across %d rounds\n",
               wte_state.total_wte_count, wte_state.round + 1);

    if (wte_state.kvm_wte_enabled) {
        wte_kvm_disable();
    }

    wte_state.active = false;
}

/*
 * Scan dirty ring entries that haven't been processed yet.
 * For each new dirty GFN: read baseline + current content,
 * then mark the page NX in EPT via ioctl so execution will
 * trigger KVM_EXIT_KAFL_WTE.
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

    /* Collect GFNs that need NX set (new dirty pages not yet NX-protected) */
    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int      nx_batch_count = 0;

    while (true) {
        uint32_t ring_idx = scan_idx & kvm_dirty_gfns_index_mask;
        struct kvm_dirty_gfn *entry = &kvm_dirty_gfns[ring_idx];

        if ((entry->flags & 0x1) == 0) {
            break;
        }

        uint64_t gfn = entry->offset;
        uint64_t gpa = gfn << 12;

        /* Skip low system pages (IVT, BDA, etc.) */
        if (gfn <= 0x10) {
            scan_idx++;
            continue;
        }

        int idx = wte_find_page(gfn);

        if (idx < 0) {
            /* New dirty page — create tracking entry */
            wte_page_info_t *info = wte_add_page(gfn);
            info->gpa = gpa;

            /* Read baseline from root snapshot (shadow memory) */
            if (fast_reload_root_created(get_fast_reload_snapshot())) {
                if (!read_snapshot_memory(get_fast_reload_snapshot(),
                                         gpa, info->baseline, WTE_PAGE_SIZE)) {
                    cpu_physical_memory_read(gpa, info->baseline, WTE_PAGE_SIZE);
                }
            } else {
                cpu_physical_memory_read(gpa, info->baseline, WTE_PAGE_SIZE);
            }
            info->baseline_valid = true;

            /* Read current content (post-write) */
            cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);
            wte_compute_diff(info);

            /* Mark NX in EPT — batch for efficiency */
            if (!info->nx_set && nx_batch_count < WTE_MAX_BATCH_GFNS) {
                nx_batch[nx_batch_count++] = gfn;
                info->nx_set = true;
            }

            if (new_pages < 3) {
                nyx_printf("[WtE][DBG] new dirty GFN=0x%lx GPA=0x%lx diff_count=%d\n",
                           (unsigned long)gfn, (unsigned long)gpa, info->diff_count);
            }

            new_pages++;
        } else {
            /* Existing dirty page — re-written, update content */
            wte_page_info_t *info = wte_state.pages[idx];
            cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);
            wte_compute_diff(info);

            /* Re-set NX if it was cleared after a previous WtE detection */
            if (!info->nx_set && nx_batch_count < WTE_MAX_BATCH_GFNS) {
                nx_batch[nx_batch_count++] = gfn;
                info->nx_set = true;
            }

            updated_pages++;
        }

        scan_idx++;
    }

    wte_state.last_scanned_ring_index = scan_idx;

    /* Batch ioctl: set NX on all newly dirty pages */
    if (nx_batch_count > 0) {
        wte_kvm_set_nx(nx_batch, nx_batch_count);
        wte_state.nx_pages_set += nx_batch_count;

        nyx_printf("[WtE] Set NX on %d pages (total NX: %d)\n",
                   nx_batch_count, wte_state.nx_pages_set);
    }

    if (new_pages > 0 || updated_pages > 0) {
        nyx_printf("[WtE] Scanned ring: %d new, %d updated dirty pages "
                   "(total tracked: %d)\n",
                   new_pages, updated_pages, wte_state.page_count);
    }
}

/*
 * Handle EPT NX violation — called when KVM exits with KVM_EXIT_KAFL_WTE.
 *
 * The guest attempted to execute code on a page we marked NX because
 * it was written to (dirty). We perform a content diff to confirm
 * the write actually changed code, then dump if confirmed.
 *
 * After handling, clear the NX bit so the guest can re-execute.
 * KVM_RUN will automatically retry the faulting instruction.
 */
void wte_handle_nx_violation(uint64_t gfn, uint64_t gpa, uint64_t rip, CPUState *cpu)
{
    if (!wte_state.active) {
        /* Not active — just clear NX and let guest continue */
        wte_kvm_clear_nx(&gfn, 1);
        return;
    }

    nyx_printf("[WtE] NX violation: GFN=0x%lx GPA=0x%lx RIP=0x%lx\n",
               (unsigned long)gfn, (unsigned long)gpa, (unsigned long)rip);

    int idx = wte_find_page(gfn);

    if (idx < 0) {
        /*
         * Page not in our tracking — might have been marked NX before
         * we started tracking, or from a stale state. Clear NX and go.
         */
        nyx_printf("[WtE] WARN: NX violation for untracked GFN=0x%lx, clearing\n",
                   (unsigned long)gfn);
        wte_kvm_clear_nx(&gfn, 1);
        return;
    }

    wte_page_info_t *info = wte_state.pages[idx];

    /* Re-read current content at execution time for accurate diff */
    cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);
    wte_compute_diff(info);

    if (info->diff_count == 0) {
        /* No actual code change — false positive (incidental dirty page).
         * Clear NX so guest can execute without further exits. */
        nyx_printf("[WtE] False positive (no diff): GFN=0x%lx, clearing NX\n",
                   (unsigned long)gfn);
        info->nx_set = false;
        wte_state.nx_pages_set--;
        wte_kvm_clear_nx(&gfn, 1);
        return;
    }

    /* Confirmed WtE — dump detection results */
    wte_state.wte_count++;
    wte_state.total_wte_count++;

    nyx_printf("[WtE] *** WRITTEN-THEN-EXECUTED ***  round=%d  RIP=0x%lx  "
               "GFN=0x%lx  GPA=0x%lx  diffs=%d\n",
               wte_state.round, (unsigned long)rip, (unsigned long)gfn,
               (unsigned long)gpa, info->diff_count);

    wte_dump_detection(rip, gfn, info);

    /* Full process memory dump at WtE detection */
    {
        X86CPU *cpux86 = X86_CPU(cpu);
        CPUX86State *env = &cpux86->env;
        char wte_label[128];
        snprintf(wte_label, sizeof(wte_label), "wte_round%d_rip0x%lx_gfn0x%lx",
                 wte_state.round, (unsigned long)rip, (unsigned long)gfn);
        dump_full_process_memory(cpu, env, wte_label);
    }

    /* Clear NX so the faulting instruction can re-execute.
     * If this page is written again, dirty ring will re-trigger NX set. */
    info->nx_set = false;
    wte_state.nx_pages_set--;
    wte_kvm_clear_nx(&gfn, 1);
}

/*
 * Reset WtE tracking for next detection round.
 * Clears all NX bits, frees page tracking, increments round counter.
 * After this, new writes will be tracked from zero base.
 */
void wte_reset_round(void)
{
    if (!wte_state.active) {
        return;
    }

    nyx_printf("[WtE] Round %d complete: %d WtE detections. Resetting.\n",
               wte_state.round, wte_state.wte_count);

    /* Collect all GFNs that still have NX set and clear them */
    uint64_t clear_batch[WTE_MAX_BATCH_GFNS];
    int      clear_count = 0;

    for (int i = 0; i < wte_state.page_count; i++) {
        if (wte_state.pages[i]->nx_set) {
            if (clear_count < WTE_MAX_BATCH_GFNS) {
                clear_batch[clear_count++] = wte_state.gfns[i];
            }
        }
    }

    if (clear_count > 0) {
        wte_kvm_clear_nx(clear_batch, clear_count);
        nyx_printf("[WtE] Cleared NX on %d pages\n", clear_count);
    }

    /* Free all page tracking */
    wte_free_all_pages();

    /* Reset counters */
    wte_state.round++;
    wte_state.wte_count    = 0;
    wte_state.nx_pages_set = 0;

    /* Sync to current dirty ring index */
    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;

    nyx_printf("[WtE] Round %d started. Tracking from clean state.\n",
               wte_state.round);
}

void wte_print_debug_summary(void)
{
    nyx_printf("[WtE][DBG] === SUMMARY === "
               "round=%d wte_count=%d total=%d "
               "tracked_pages=%d nx_pages=%d\n",
               wte_state.round,
               wte_state.wte_count,
               wte_state.total_wte_count,
               wte_state.page_count,
               wte_state.nx_pages_set);
}

bool wte_is_active(void)
{
    return wte_state.active;
}

wte_state_t *wte_get_state(void)
{
    return &wte_state;
}
