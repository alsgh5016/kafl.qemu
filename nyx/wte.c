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

int wte_kvm_set_cr3(uint64_t cr3)
{
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_WTE_SET_CR3, &cr3);
    if (ret < 0) {
        nyx_printf("[WtE] ERROR: KVM_NYX_WTE_SET_CR3 failed: %d\n", ret);
    } else {
        nyx_printf("[WtE] KVM target CR3 set to 0x%lx\n", (unsigned long)cr3);
    }
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

    /* Re-NX queue for kernel RIP skip recovery */
    wte_state.renx_queue    = malloc(WTE_MAX_BATCH_GFNS * sizeof(uint64_t));
    wte_state.renx_count    = 0;
    wte_state.renx_capacity = WTE_MAX_BATCH_GFNS;

    /* Cross-dump byte diff snapshot */
    wte_crossdump_init();
}

void wte_destroy(void)
{
    if (wte_state.kvm_wte_enabled) {
        wte_kvm_disable();
    }

    wte_free_all_pages();
    free(wte_state.pages);
    free(wte_state.gfns);
    free(wte_state.renx_queue);

    /* Cross-dump byte diff cleanup */
    wte_crossdump_destroy();

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
    wte_state.renx_count      = 0;

    /* DLL noise filter — skip dump for system DLL VA range */
    wte_state.dll_filter_enabled  = true;
    wte_state.dll_va_threshold    = is_64bit ? WTE_DLL_VA_THRESHOLD_64
                                             : WTE_DLL_VA_THRESHOLD_32;
    wte_state.dll_filtered_count  = 0;
    wte_state.dll_filtered_total  = 0;

    /* Enable KVM WtE tracking */
    if (!wte_state.kvm_wte_enabled) {
        wte_kvm_enable();
    }
    /* Set target CR3 in KVM for kernel-side filtering */
    wte_kvm_set_cr3(cr3);

    /* Sync to current dirty ring index so we only scan new entries */
    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;

    nyx_printf("[WtE] Activated: CR3=0x%lx, 64bit=%d, DLL filter threshold=0x%lx\n",
               (unsigned long)cr3, is_64bit,
               (unsigned long)wte_state.dll_va_threshold);
}

void wte_deactivate(void)
{
    nyx_printf("[WtE] Deactivated: total detections=%d (%d dumped, %d DLL-filtered) across %d rounds\n",
               wte_state.total_wte_count,
               wte_state.total_wte_count - wte_state.dll_filtered_total,
               wte_state.dll_filtered_total,
               wte_state.round + 1);

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

    /* Process re-NX queue: pages that had NX cleared for kernel RIP skip.
     * Re-set NX on these pages so user-mode WtE can still be detected. */
    if (wte_state.renx_count > 0) {
        int re_nx = 0;
        uint64_t renx_batch[WTE_MAX_BATCH_GFNS];
        int renx_batch_count = 0;

        for (int i = 0; i < wte_state.renx_count; i++) {
            uint64_t gfn = wte_state.renx_queue[i];
            int idx = wte_find_page(gfn);
            if (idx >= 0 && !wte_state.pages[idx]->nx_set) {
                renx_batch[renx_batch_count++] = gfn;
                wte_state.pages[idx]->nx_set = true;
                re_nx++;

                /* Flush batch when full */
                if (renx_batch_count >= WTE_MAX_BATCH_GFNS) {
                    wte_kvm_set_nx(renx_batch, renx_batch_count);
                    wte_state.nx_pages_set += renx_batch_count;
                    renx_batch_count = 0;
                }
            }
        }
        if (renx_batch_count > 0) {
            wte_kvm_set_nx(renx_batch, renx_batch_count);
            wte_state.nx_pages_set += renx_batch_count;
        }
        if (re_nx > 0) {
            nyx_printf("[WtE] Re-NX applied to %d pages (kernel RIP recovery)\n", re_nx);
        }
        wte_state.renx_count = 0;
    }

    uint32_t scan_idx = wte_state.last_scanned_ring_index;
    int      new_pages = 0;
    int      updated_pages = 0;
    int      total_nx_set_this_scan = 0;

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
            if (!info->nx_set) {
                nx_batch[nx_batch_count++] = gfn;
                info->nx_set = true;

                /* Flush batch when full (kernel ioctl limit = 4096) */
                if (nx_batch_count >= WTE_MAX_BATCH_GFNS) {
                    wte_kvm_set_nx(nx_batch, nx_batch_count);
                    total_nx_set_this_scan += nx_batch_count;
                    nx_batch_count = 0;
                }
            }

            if (new_pages < 3) {
                nyx_printf("[WtE][DBG] new dirty GFN=0x%lx GPA=0x%lx diff_count=%d\n",
                           (unsigned long)gfn, (unsigned long)gpa, info->diff_count);
            }

            /* Diagnostic: check if this new dirty GFN is in target PE range */
            if (wte_is_target_pe_gfn(gfn)) {
                nyx_printf("[WtE][DIAG] *** TARGET PE GFN 0x%lx IS DIRTY! ***\n",
                           (unsigned long)gfn);
                nyx_printf("[WtE][DIAG]   diff_count=%d, baseline_valid=%d\n",
                           info->diff_count, info->baseline_valid);
                /* Print first 16 bytes of baseline and current for comparison */
                nyx_printf("[WtE][DIAG]   baseline[0..15]: %02x %02x %02x %02x  %02x %02x %02x %02x"
                           "  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
                           info->baseline[0],  info->baseline[1],
                           info->baseline[2],  info->baseline[3],
                           info->baseline[4],  info->baseline[5],
                           info->baseline[6],  info->baseline[7],
                           info->baseline[8],  info->baseline[9],
                           info->baseline[10], info->baseline[11],
                           info->baseline[12], info->baseline[13],
                           info->baseline[14], info->baseline[15]);
                nyx_printf("[WtE][DIAG]   current[0..15]:  %02x %02x %02x %02x  %02x %02x %02x %02x"
                           "  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
                           info->current[0],  info->current[1],
                           info->current[2],  info->current[3],
                           info->current[4],  info->current[5],
                           info->current[6],  info->current[7],
                           info->current[8],  info->current[9],
                           info->current[10], info->current[11],
                           info->current[12], info->current[13],
                           info->current[14], info->current[15]);
            }

            new_pages++;
        } else {
            /* Existing dirty page — re-written, update content */
            wte_page_info_t *info = wte_state.pages[idx];
            cpu_physical_memory_read(gpa, info->current, WTE_PAGE_SIZE);
            wte_compute_diff(info);

            /* Re-set NX if it was cleared after a previous WtE detection */
            if (!info->nx_set) {
                nx_batch[nx_batch_count++] = gfn;
                info->nx_set = true;

                /* Flush batch when full */
                if (nx_batch_count >= WTE_MAX_BATCH_GFNS) {
                    wte_kvm_set_nx(nx_batch, nx_batch_count);
                    total_nx_set_this_scan += nx_batch_count;
                    nx_batch_count = 0;
                }
            }


            /* Diagnostic: check if re-dirtied GFN is in target PE */
            if (wte_is_target_pe_gfn(gfn)) {
                nyx_printf("[WtE][DIAG] *** TARGET PE GFN 0x%lx RE-DIRTIED! diff=%d ***\n",
                           (unsigned long)gfn, info->diff_count);
            }
            updated_pages++;
        }

        scan_idx++;
    }

    wte_state.last_scanned_ring_index = scan_idx;

    /* Flush remaining NX batch */
    if (nx_batch_count > 0) {
        wte_kvm_set_nx(nx_batch, nx_batch_count);
        total_nx_set_this_scan += nx_batch_count;
    }

    if (total_nx_set_this_scan > 0) {
        wte_state.nx_pages_set += total_nx_set_this_scan;
        nyx_printf("[WtE] Set NX on %d pages (total NX: %d)\n",
                   total_nx_set_this_scan, wte_state.nx_pages_set);
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

    /* Layer 2 safety net: skip kernel-mode RIP (should be filtered by KVM CR3,
     * but catch any that slip through — e.g., CR3 not yet set) */
    if (rip >= 0xFFFF800000000000ULL) {
        nyx_printf("[WtE] Skipping kernel RIP=0x%lx GFN=0x%lx — queued for re-NX\n",
                   (unsigned long)rip, (unsigned long)gfn);
        /* Clear NX so guest can continue executing this page,
         * but queue the GFN for re-NX on next dirty ring scan.
         * This prevents permanent NX loss: if user-mode code later
         * executes this page, the re-applied NX will catch it. */
        wte_kvm_clear_nx(&gfn, 1);
        if (wte_state.renx_count < wte_state.renx_capacity) {
            wte_state.renx_queue[wte_state.renx_count++] = gfn;
        }
        /* Also mark page tracking as nx_set=false so re-NX logic
         * in scan knows to re-set it */
        int idx = wte_find_page(gfn);
        if (idx >= 0) {
            wte_state.pages[idx]->nx_set = false;
            wte_state.nx_pages_set--;
        }
        return;
    }

    nyx_printf("[WtE] NX violation: GFN=0x%lx GPA=0x%lx RIP=0x%lx\n",
               (unsigned long)gfn, (unsigned long)gpa, (unsigned long)rip);

    /* Diagnostic: check if NX violation is in target PE */
    if (wte_is_target_pe_gfn(gfn)) {
        nyx_printf("[WtE][DIAG] *** TARGET PE NX VIOLATION! *** GFN=0x%lx RIP=0x%lx\n",
                   (unsigned long)gfn, (unsigned long)rip);
    }

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

    /* Confirmed WtE — check DLL noise filter before dumping */
    wte_state.wte_count++;
    wte_state.total_wte_count++;

    /* DLL noise filter: if RIP is in system DLL VA range, log but skip dump.
     * NX is still cleared so guest can continue. The WtE is counted but
     * no expensive file I/O or process memory dump is performed. */
    if (wte_state.dll_filter_enabled && rip >= wte_state.dll_va_threshold) {
        wte_state.dll_filtered_count++;
        wte_state.dll_filtered_total++;
        nyx_printf("[WtE] DLL-FILTERED: RIP=0x%lx >= 0x%lx  GFN=0x%lx  diffs=%d  "
                   "(filtered %d this round, %d total)\n",
                   (unsigned long)rip, (unsigned long)wte_state.dll_va_threshold,
                   (unsigned long)gfn, info->diff_count,
                   wte_state.dll_filtered_count, wte_state.dll_filtered_total);
        /* Update baseline even for DLL-filtered pages, so repeated
         * dirty ring re-entries don't re-trigger DLL filter logging
         * for the same unchanged content. */
        memcpy(info->baseline, info->current, WTE_PAGE_SIZE);

        info->nx_set = false;
        wte_state.nx_pages_set--;
        wte_kvm_clear_nx(&gfn, 1);
        return;
    }

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

    /* Update baseline to current content so that future NX violations
     * on this page only trigger WtE if NEW writes occur after this point.
     * Without this, the same diff (vs root snapshot) triggers repeated
     * false positive WtE detections on already-unpacked pages. */
    memcpy(info->baseline, info->current, WTE_PAGE_SIZE);

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

    nyx_printf("[WtE] Round %d complete: %d WtE detections (%d filtered by DLL). Resetting.\n",
               wte_state.round, wte_state.wte_count, wte_state.dll_filtered_count);

    /* Collect all GFNs that still have NX set and clear them */
    uint64_t clear_batch[WTE_MAX_BATCH_GFNS];
    int      clear_count = 0;
    int      total_cleared = 0;

    for (int i = 0; i < wte_state.page_count; i++) {
        if (wte_state.pages[i]->nx_set) {
            clear_batch[clear_count++] = wte_state.gfns[i];

            /* Flush batch when full */
            if (clear_count >= WTE_MAX_BATCH_GFNS) {
                wte_kvm_clear_nx(clear_batch, clear_count);
                total_cleared += clear_count;
                clear_count = 0;
            }
        }
    }

    if (clear_count > 0) {
        wte_kvm_clear_nx(clear_batch, clear_count);
        total_cleared += clear_count;
    }

    if (total_cleared > 0) {
        nyx_printf("[WtE] Cleared NX on %d pages\n", total_cleared);
    }

    /* Free all page tracking */
    wte_free_all_pages();

    /* Reset counters */
    wte_state.round++;
    wte_state.wte_count    = 0;
    wte_state.nx_pages_set = 0;
    wte_state.renx_count   = 0;  /* Clear re-NX queue */
    wte_state.dll_filtered_count = 0; /* Reset per-round DLL filter count */

    /* Sync to current dirty ring index */
    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;

    nyx_printf("[WtE] Round %d started. Tracking from clean state.\n",
               wte_state.round);
}

void wte_print_debug_summary(void)
{
    nyx_printf("[WtE][DBG] === SUMMARY === "
               "round=%d wte_count=%d total=%d "
               "tracked_pages=%d nx_pages=%d "
               "dll_filtered=%d dll_filtered_total=%d\n",
               wte_state.round,
               wte_state.wte_count,
               wte_state.total_wte_count,
               wte_state.page_count,
               wte_state.nx_pages_set,
               wte_state.dll_filtered_count,
               wte_state.dll_filtered_total);
}

bool wte_is_active(void)
{
    return wte_state.active;
}

wte_state_t *wte_get_state(void)
{
    return &wte_state;
}


/* ── EPROCESS Walking: Find CR3 by PID ────────────────────────── */

/* Windows 10 x64 EPROCESS layout offsets.
 * These are stable across Windows 10 21H2 (19044) / 22H2 (19045).
 * EPROCESS starts with KPROCESS (Pcb), so DirectoryTableBase is
 * at KPROCESS+0x28 = EPROCESS+0x28. */
#define EPROCESS_OFF_DTB           0x28   /* DirectoryTableBase (CR3) */
#define EPROCESS_OFF_PID           0x440  /* UniqueProcessId          */
#define EPROCESS_OFF_LINKS         0x448  /* ActiveProcessLinks        */
#define EPROCESS_OFF_IMAGENAME     0x5A8  /* ImageFileName[15]         */

/* Maximum iterations to prevent infinite loop on corrupted list */
#define EPROCESS_WALK_MAX          4096

/*
 * Walk the Windows EPROCESS linked list to find a process's CR3 given its PID.
 *
 * Strategy:
 *   1. Use the harness CR3 (current vCPU CR3) to access kernel VA space.
 *      In Windows x64, all processes share the kernel page tables (upper
 *      half of PML4), so ANY process CR3 can read kernel-mode addresses.
 *   2. Start from the System process (PID=4) by scanning known locations,
 *      or start from the current process and walk the circular list.
 *   3. Walk ActiveProcessLinks (doubly-linked circular list) until we
 *      find the target PID.
 *
 * @param cpu       vCPU state for memory access
 * @param harness_cr3  CR3 of the harness process (for kernel VA access)
 * @param target_pid   PID of the process whose CR3 we want
 * @return CR3 value (page-aligned), or 0 on failure
 */
uint64_t wte_find_cr3_by_pid(CPUState *cpu, uint64_t harness_cr3, uint64_t target_pid)
{
    /*
     * Step 1: Find the current process (harness) EPROCESS.
     * We read GS:[0x188] → KTHREAD, then KTHREAD.ApcState.Process → EPROCESS.
     * But this requires reading GS base which is MSR-dependent.
     *
     * Simpler approach: Use KPCR → KdVersionBlock → PsActiveProcessHead.
     * But finding PsActiveProcessHead without symbols is unreliable.
     *
     * Most reliable approach for our use case:
     *   Walk ALL physical memory pages looking for EPROCESS with PID=4 (System),
     *   or use the fact that PID=4 (System) always exists and its EPROCESS
     *   is usually at a well-known position.
     *
     * BEST approach: Since the harness already knows its own PID,
     * and we have the harness CR3, we can:
     *   a) Scan GS base (IA32_GS_BASE MSR) → KPCR
     *   b) KPCR+0x180 → KPRCB → KPRCB+0x008 → CurrentThread (KTHREAD)
     *   c) KTHREAD+0x220 → KTHREAD.Process → EPROCESS of current process
     *   d) Walk ActiveProcessLinks from there until we find target_pid
     *
     * We use approach (a-d) since we have full register access.
     */

    /* Read IA32_GS_BASE to get KPCR (kernel GS base for x64) */
    kvm_arch_get_registers(cpu);
    CPUX86State *env = &(X86_CPU(cpu)->env);
    uint64_t gs_base = env->segs[R_GS].base;

    nyx_printf("[WtE][CR3] Looking up CR3 for PID %lu via EPROCESS walk\n",
               (unsigned long)target_pid);
    nyx_printf("[WtE][CR3] Harness CR3=0x%lx, GS base=0x%lx\n",
               (unsigned long)harness_cr3, (unsigned long)gs_base);

    /* KPCR+0x180 → KPRCB, KPRCB+0x008 → CurrentThread (KTHREAD*) */
    uint64_t kthread_ptr = 0;
    if (!read_virtual_memory_cr3(gs_base + 0x188, (uint8_t *)&kthread_ptr,
                                 sizeof(kthread_ptr), cpu, harness_cr3)) {
        nyx_printf("[WtE][CR3] ERROR: Failed to read KPCR.CurrentThread at 0x%lx\n",
                   (unsigned long)(gs_base + 0x188));
        return 0;
    }
    nyx_printf("[WtE][CR3] CurrentThread (KTHREAD): 0x%lx\n",
               (unsigned long)kthread_ptr);

    /* KTHREAD+0x220 → KTHREAD.Process (EPROCESS*) — Win10 x64 offset */
    uint64_t eprocess_ptr = 0;
    if (!read_virtual_memory_cr3(kthread_ptr + 0x220, (uint8_t *)&eprocess_ptr,
                                 sizeof(eprocess_ptr), cpu, harness_cr3)) {
        nyx_printf("[WtE][CR3] ERROR: Failed to read KTHREAD.Process at 0x%lx\n",
                   (unsigned long)(kthread_ptr + 0x220));
        return 0;
    }
    nyx_printf("[WtE][CR3] Current EPROCESS: 0x%lx\n",
               (unsigned long)eprocess_ptr);

    /* Walk ActiveProcessLinks circular list starting from current EPROCESS */
    uint64_t start_eprocess = eprocess_ptr;
    int iter = 0;

    do {
        /* Read PID at EPROCESS+0x440 */
        uint64_t pid = 0;
        if (!read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_PID,
                                     (uint8_t *)&pid, sizeof(pid),
                                     cpu, harness_cr3)) {
            nyx_printf("[WtE][CR3] ERROR: Failed to read PID at EPROCESS 0x%lx\n",
                       (unsigned long)eprocess_ptr);
            return 0;
        }

        /* Read ImageFileName for logging */
        char image_name[16] = {0};
        read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_IMAGENAME,
                                (uint8_t *)image_name, 15, cpu, harness_cr3);
        image_name[15] = '\0';

        if (iter < 10 || pid == target_pid) {
            nyx_printf("[WtE][CR3]   EPROCESS=0x%lx PID=%lu Name=%s\n",
                       (unsigned long)eprocess_ptr, (unsigned long)pid, image_name);
        }

        if (pid == target_pid) {
            /* Found! Read DirectoryTableBase (CR3) */
            uint64_t cr3 = 0;
            if (!read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_DTB,
                                         (uint8_t *)&cr3, sizeof(cr3),
                                         cpu, harness_cr3)) {
                nyx_printf("[WtE][CR3] ERROR: Failed to read CR3 at EPROCESS 0x%lx\n",
                           (unsigned long)eprocess_ptr);
                return 0;
            }
            cr3 &= 0xFFFFFFFFFFFFF000ULL;  /* Page-align */
            nyx_printf("[WtE][CR3] Found target PID %lu: CR3=0x%lx Name=%s\n",
                       (unsigned long)target_pid, (unsigned long)cr3, image_name);
            return cr3;
        }

        /* Follow ActiveProcessLinks.Flink to next EPROCESS.
         * LIST_ENTRY.Flink at EPROCESS+0x448 points to the NEXT
         * EPROCESS's ActiveProcessLinks field, so subtract 0x448
         * to get the base of the next EPROCESS. */
        uint64_t next_link = 0;
        if (!read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_LINKS,
                                     (uint8_t *)&next_link, sizeof(next_link),
                                     cpu, harness_cr3)) {
            nyx_printf("[WtE][CR3] ERROR: Failed to read ActiveProcessLinks at 0x%lx\n",
                       (unsigned long)(eprocess_ptr + EPROCESS_OFF_LINKS));
            return 0;
        }

        /* next_link points to ActiveProcessLinks of next EPROCESS,
         * subtract offset to get EPROCESS base */
        eprocess_ptr = next_link - EPROCESS_OFF_LINKS;

        iter++;
    } while (eprocess_ptr != start_eprocess && iter < EPROCESS_WALK_MAX);

    nyx_printf("[WtE][CR3] ERROR: PID %lu not found after %d iterations\n",
               (unsigned long)target_pid, iter);
    return 0;
}

/* ── Eager NX: Set NX on target PE pages at setup time ────────── */

/*
 * Set EPT NX bit on all pages backing the target PE image.
 * Called during WTE_SETUP, BEFORE the target process executes any code.
 * This ensures the very first execution of any PE page triggers an NX
 * violation, catching the initial unpacking write+exec.
 *
 * Unlike the lazy approach (NX set only when dirty ring reports writes),
 * this eagerly protects all PE pages so even the first instruction
 * execution after a write is caught.
 *
 * @param cpu         vCPU state for page table walks
 * @param image_base  Target PE image base VA
 * @param image_size  Target PE SizeOfImage
 * @param cr3         Target process CR3 (for page table walk)
 */
void wte_eager_set_nx_on_pe(CPUState *cpu, uint64_t image_base,
                            uint64_t image_size, uint64_t cr3)
{
    nyx_printf("[WtE][EAGER] Setting NX on target PE pages: VA 0x%lx - 0x%lx (size=0x%lx)\n",
               (unsigned long)image_base, (unsigned long)(image_base + image_size),
               (unsigned long)image_size);

    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int nx_batch_count = 0;
    int total_nx = 0;
    int mapped = 0;
    int unmapped = 0;

    uint64_t va;
    for (va = image_base; va < image_base + image_size; va += WTE_PAGE_SIZE) {
        uint64_t pa = get_paging_phys_addr(cpu, cr3, va);

        if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
            unmapped++;
            continue;
        }

        uint64_t gfn = pa >> 12;
        uint64_t gpa = pa & 0xFFFFFFFFFFFFF000ULL;
        mapped++;

        /* Add page to WtE tracking with baseline content */
        int idx = wte_find_page(gfn);
        wte_page_info_t *info;

        if (idx < 0) {
            info = wte_add_page(gfn);
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

            /* Current content = baseline at setup time (no writes yet) */
            memcpy(info->current, info->baseline, WTE_PAGE_SIZE);
            info->diff_done = true;
            info->diff_count = 0;
        } else {
            info = wte_state.pages[idx];
        }

        /* Set NX via batch */
        if (!info->nx_set) {
            nx_batch[nx_batch_count++] = gfn;
            info->nx_set = true;

            if (nx_batch_count >= WTE_MAX_BATCH_GFNS) {
                wte_kvm_set_nx(nx_batch, nx_batch_count);
                total_nx += nx_batch_count;
                nx_batch_count = 0;
            }
        }
    }

    /* Flush remaining batch */
    if (nx_batch_count > 0) {
        wte_kvm_set_nx(nx_batch, nx_batch_count);
        total_nx += nx_batch_count;
    }

    wte_state.nx_pages_set += total_nx;

    nyx_printf("[WtE][EAGER] NX set on %d pages (%d mapped, %d unmapped) "
               "total NX now: %d\n",
               total_nx, mapped, unmapped, wte_state.nx_pages_set);
}
/* ── Diagnostic: Target PE GFN Mapping ────────────────────────── */

bool wte_is_target_pe_gfn(uint64_t gfn)
{
    for (int i = 0; i < wte_state.target_pe_gfn_count; i++) {
        if (wte_state.target_pe_gfns[i] == gfn) {
            return true;
        }
    }
    return false;
}

/*
 * Walk target process page tables to map target PE VA range to GFNs.
 * This reveals which physical pages back the target PE image and
 * allows us to track them specifically in dirty ring scans.
 *
 * Must be called after wte_activate() with valid CPU state.
 */
void wte_diagnose_target_pe(CPUState *cpu, uint64_t image_base, uint64_t image_size)
{
    if (!wte_state.active) {
        nyx_printf("[WtE][DIAG] Cannot diagnose — WtE not active\n");
        return;
    }

    wte_state.target_image_base = image_base;
    wte_state.target_image_end  = image_base + image_size;
    wte_state.target_pe_gfn_count = 0;

    uint64_t cr3 = wte_state.target_cr3;

    nyx_printf("[WtE][DIAG] ============================================\n");
    nyx_printf("[WtE][DIAG] Target PE diagnostic: VA 0x%lx - 0x%lx (size=0x%lx)\n",
               (unsigned long)image_base, (unsigned long)(image_base + image_size),
               (unsigned long)image_size);
    nyx_printf("[WtE][DIAG] Target CR3: 0x%lx\n", (unsigned long)cr3);

    int mapped = 0, unmapped = 0;
    uint64_t va;
    for (va = image_base; va < image_base + image_size; va += WTE_PAGE_SIZE) {
        uint64_t pa = get_paging_phys_addr(cpu, cr3, va);

        if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
            if (unmapped < 5) {
                nyx_printf("[WtE][DIAG]   VA 0x%08lx → UNMAPPED\n",
                           (unsigned long)va);
            }
            unmapped++;
            continue;
        }

        uint64_t gfn = pa >> 12;
        mapped++;

        /* Store in target PE GFN list */
        if (wte_state.target_pe_gfn_count < WTE_MAX_TARGET_PE_PAGES) {
            wte_state.target_pe_gfns[wte_state.target_pe_gfn_count] = gfn;
            wte_state.target_pe_vas[wte_state.target_pe_gfn_count] = va;
            wte_state.target_pe_gfn_count++;
        }

        /* Log each mapping */
        if (mapped <= 20 || (mapped % 16 == 0)) {
            nyx_printf("[WtE][DIAG]   VA 0x%08lx → PA 0x%lx (GFN=0x%lx)\n",
                       (unsigned long)va, (unsigned long)pa, (unsigned long)gfn);
        }

        /* Also check: is this GFN already in dirty ring tracking? */
        int idx = wte_find_page(gfn);
        if (idx >= 0) {
            nyx_printf("[WtE][DIAG]   ** GFN 0x%lx ALREADY TRACKED (diff=%d, nx=%d) **\n",
                       (unsigned long)gfn,
                       wte_state.pages[idx]->diff_count,
                       wte_state.pages[idx]->nx_set);
        }

        /* Read current content vs snapshot baseline */
        uint8_t current_page[WTE_PAGE_SIZE];
        uint8_t baseline_page[WTE_PAGE_SIZE];
        cpu_physical_memory_read(pa & 0xFFFFFFFFFFFFF000ULL, current_page, WTE_PAGE_SIZE);

        bool baseline_read = false;
        if (fast_reload_root_created(get_fast_reload_snapshot())) {
            baseline_read = read_snapshot_memory(get_fast_reload_snapshot(),
                                                  pa & 0xFFFFFFFFFFFFF000ULL,
                                                  baseline_page, WTE_PAGE_SIZE);
        }
        if (!baseline_read) {
            memcpy(baseline_page, current_page, WTE_PAGE_SIZE);
        }

        /* Compute diff between baseline and current */
        int diff_bytes = 0;
        for (int i = 0; i < WTE_PAGE_SIZE; i++) {
            if (baseline_page[i] != current_page[i]) {
                diff_bytes++;
            }
        }

        if (diff_bytes > 0) {
            nyx_printf("[WtE][DIAG]   ** VA 0x%08lx (GFN=0x%lx): %d bytes DIFFER from baseline! **\n",
                       (unsigned long)va, (unsigned long)gfn, diff_bytes);
        }
    }

    nyx_printf("[WtE][DIAG] Target PE: %d pages mapped, %d unmapped, %d stored for tracking\n",
               mapped, unmapped, wte_state.target_pe_gfn_count);
    if (unmapped > 5) {
        nyx_printf("[WtE][DIAG]   (suppressed %d unmapped page logs)\n", unmapped - 5);
    }
    nyx_printf("[WtE][DIAG] ============================================\n");
}
