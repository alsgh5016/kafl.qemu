/*
 * WtE (Written-then-Executed) Detection — Dual-Watch Implementation
 *
 * Primary path (PE pages):
 *   EPT W=0 for write detection → EPT X=0 for execute detection
 *   Zero timing gap: both write and execute cause immediate VM exits.
 *
 * Supplementary path (non-PE pages):
 *   Dirty ring for write detection → EPT NX for execute detection
 *   Has timing gaps but catches dynamic allocation WtE.
 *
 * Safety net (all pages):
 *   Intel PT trace decoded incrementally at each VM exit.
 *   Catches CoW-induced misses where GFN changes break EPT tracking.
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
#include "nyx/api_hook.h"

#include "nyx/snapshot/memory/backend/nyx_dirty_ring.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/pt.h"
#include "nyx/hypercall/hypercall.h"

#include "target/i386/cpu.h"

/* Defined in hypercall.c */
extern void dump_full_process_memory(CPUState *cpu, CPUX86State *env,
                                     const char *label,
                                     const wte_dump_event_t *event,
                                     uint64_t cr3_override);

/* ── Dirty Ring Globals (defined in nyx_dirty_ring.c) ──────────── */

extern int                   dirty_ring_size;
extern struct kvm_dirty_gfn *kvm_dirty_gfns;
extern uint32_t              kvm_dirty_gfns_index;
extern uint32_t              kvm_dirty_gfns_index_mask;

/* ── WtE Singleton ─────────────────────────────────────────────── */

static wte_state_t wte_state;

/* ── VA-based Page Table Helpers ───────────────────────────────── */

static wte_page_entry_t *wte_lookup_va(uint64_t page_va)
{
    if (!wte_state.page_table) return NULL;
    return g_hash_table_lookup(wte_state.page_table, &page_va);
}

static wte_page_entry_t *wte_lookup_or_create_va(uint64_t page_va,
                                                  uint64_t gfn)
{
    wte_page_entry_t *entry = wte_lookup_va(page_va);
    if (entry) return entry;

    entry = g_new0(wte_page_entry_t, 1);
    entry->va  = page_va;
    entry->gfn = gfn;
    entry->gpa = gfn << 12;
    uint64_t *key = g_new(uint64_t, 1);
    *key = page_va;
    g_hash_table_insert(wte_state.page_table, key, entry);
    return entry;
}

/* Find page entry by GFN (for dirty ring / NX violation on non-PE pages) */
static wte_page_entry_t *wte_lookup_gfn(uint64_t gfn)
{
    GHashTableIter iter;
    gpointer key, value;

    if (!wte_state.page_table) return NULL;

    g_hash_table_iter_init(&iter, wte_state.page_table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        wte_page_entry_t *entry = value;
        if (entry->gfn == gfn) return entry;
    }
    return NULL;
}

static bool wte_gfn_has_other_reference(uint64_t gfn, uint64_t current_va)
{
    GHashTableIter iter;
    gpointer key, value;

    if (!wte_state.page_table) return false;

    for (int i = 0; i < wte_state.pe_page_count; i++) {
        if (wte_state.pe_gfns[i] == gfn && wte_state.pe_vas[i] != current_va)
            return true;
    }

    g_hash_table_iter_init(&iter, wte_state.page_table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        wte_page_entry_t *entry = value;
        if (entry->gfn == gfn && entry->va != current_va)
            return true;
    }
    return false;
}

/* ── Content Diff ──────────────────────────────────────────────── */

static void wte_compute_diff(wte_page_entry_t *entry)
{
    entry->diff_count = 0;

    bool in_diff = false;
    int  start   = 0;

    for (int i = 0; i < WTE_PAGE_SIZE; i++) {
        bool differ = (entry->baseline[i] != entry->current[i]);

        if (differ && !in_diff) {
            in_diff = true;
            start   = i;
        } else if (!differ && in_diff) {
            in_diff = false;
            if (entry->diff_count < WTE_MAX_DIFF_RANGES) {
                entry->diff_offsets[entry->diff_count] = (uint16_t)start;
                entry->diff_lengths[entry->diff_count] = (uint16_t)(i - start);
                entry->diff_count++;
            }
        }
    }

    if (in_diff && entry->diff_count < WTE_MAX_DIFF_RANGES) {
        entry->diff_offsets[entry->diff_count] = (uint16_t)start;
        entry->diff_lengths[entry->diff_count] = (uint16_t)(WTE_PAGE_SIZE - start);
        entry->diff_count++;
    }
}

/* ── Dump ──────────────────────────────────────────────────────── */

static void wte_dump_detection(uint64_t exec_rip, wte_page_entry_t *entry,
                               const char *source)
{
    char *dump_dir = NULL;
    assert(asprintf(&dump_dir, "%s/dump/wte_r%03d_evt%03d_va0x%lx",
                    GET_GLOBAL_STATE()->workdir_path,
                    wte_state.round, wte_state.wte_count,
                    (unsigned long)entry->va) != -1);
    mkdir(dump_dir, 0755);

    /* baseline.bin */
    char *path = NULL;
    assert(asprintf(&path, "%s/baseline.bin", dump_dir) != -1);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(entry->baseline, 1, WTE_PAGE_SIZE, f); fclose(f); }
    free(path);

    /* current.bin */
    assert(asprintf(&path, "%s/current.bin", dump_dir) != -1);
    f = fopen(path, "wb");
    if (f) { fwrite(entry->current, 1, WTE_PAGE_SIZE, f); fclose(f); }
    free(path);

    /* diff_report.txt */
    assert(asprintf(&path, "%s/diff_report.txt", dump_dir) != -1);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "WtE Detection Report (Dual-Watch)\n");
        fprintf(f, "==================================\n");
        fprintf(f, "Source:    %s\n", source);
        fprintf(f, "Round:     %d\n", wte_state.round);
        fprintf(f, "Event:     %d\n", wte_state.wte_count);
        fprintf(f, "VA:        0x%lx\n", (unsigned long)entry->va);
        fprintf(f, "GFN:       0x%lx\n", (unsigned long)entry->gfn);
        fprintf(f, "GPA:       0x%lx\n", (unsigned long)entry->gpa);
        fprintf(f, "Exec RIP:  0x%lx\n", (unsigned long)exec_rip);
        fprintf(f, "CR3:       0x%lx\n", (unsigned long)wte_state.target_cr3);
        fprintf(f, "Diff Ranges: %d\n\n", entry->diff_count);

        for (int i = 0; i < entry->diff_count; i++) {
            fprintf(f, "  Range[%d]: offset=0x%04x, length=%d bytes\n",
                    i, entry->diff_offsets[i], entry->diff_lengths[i]);
        }
        fclose(f);
    }
    free(path);

    nyx_printf("[WtE][DETECT] *** WRITTEN-THEN-EXECUTED ***  source=%s round=%d "
               "VA=0x%lx RIP=0x%lx GFN=0x%lx diffs=%d\n",
               source, wte_state.round,
               (unsigned long)entry->va, (unsigned long)exec_rip,
               (unsigned long)entry->gfn, entry->diff_count);

    free(dump_dir);
}

/* ── KVM ioctl Wrappers ───────────────────────────────────────── */

int wte_kvm_enable(void)
{
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_WTE_ENABLE, 0);
    if (ret < 0) {
        nyx_printf("[WtE] ERROR: KVM_NYX_WTE_ENABLE failed: %d\n", ret);
    } else {
        nyx_printf("[WtE] KVM WtE enabled (Dual-Watch mode)\n");
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

static int wte_kvm_batch_ioctl(int ioctl_nr, uint64_t *gfns, uint32_t count)
{
    if (count == 0) return 0;

    size_t size = sizeof(struct kvm_nyx_wte_gfns) + count * sizeof(uint64_t);
    struct kvm_nyx_wte_gfns *req = malloc(size);
    req->count = count;
    req->flags = 0;
    memcpy(req->gfns, gfns, count * sizeof(uint64_t));

    int ret = kvm_vm_ioctl(kvm_state, ioctl_nr, req);
    free(req);
    return ret;
}

int wte_kvm_set_nx(uint64_t *gfns, uint32_t count)
{
    int ret = wte_kvm_batch_ioctl(KVM_NYX_WTE_SET_NX, gfns, count);
    if (ret < 0)
        nyx_printf("[WtE] ERROR: SET_NX failed: %d (count=%u)\n", ret, count);
    return ret;
}

int wte_kvm_clear_nx(uint64_t *gfns, uint32_t count)
{
    int ret = wte_kvm_batch_ioctl(KVM_NYX_WTE_CLEAR_NX, gfns, count);
    if (ret < 0)
        nyx_printf("[WtE] ERROR: CLEAR_NX failed: %d (count=%u)\n", ret, count);
    return ret;
}

int wte_kvm_set_wp(uint64_t *gfns, uint32_t count)
{
    int ret = wte_kvm_batch_ioctl(KVM_NYX_WTE_SET_WP, gfns, count);
    if (ret < 0)
        nyx_printf("[WtE] ERROR: SET_WP failed: %d (count=%u)\n", ret, count);
    return ret;
}

int wte_kvm_clear_wp(uint64_t *gfns, uint32_t count)
{
    int ret = wte_kvm_batch_ioctl(KVM_NYX_WTE_CLEAR_WP, gfns, count);
    if (ret < 0)
        nyx_printf("[WtE] ERROR: CLEAR_WP failed: %d (count=%u)\n", ret, count);
    return ret;
}

int wte_kvm_set_cr3(uint64_t cr3)
{
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_WTE_SET_CR3, &cr3);
    if (ret < 0) {
        nyx_printf("[WtE] ERROR: SET_CR3 failed: %d\n", ret);
    } else {
        nyx_printf("[WtE] KVM target CR3 set to 0x%lx\n", (unsigned long)cr3);
    }
    return ret;
}

/* ── Public API: Lifecycle ─────────────────────────────────────── */

void wte_init(void)
{
    memset(&wte_state, 0, sizeof(wte_state_t));

    wte_state.page_table = g_hash_table_new_full(
        g_int64_hash, g_int64_equal, g_free, g_free);

    wte_state.renx_queue    = malloc(WTE_MAX_BATCH_GFNS * sizeof(uint64_t));
    wte_state.renx_count    = 0;
    wte_state.renx_capacity = WTE_MAX_BATCH_GFNS;

    wte_crossdump_init();

    nyx_printf("[WtE] Initialized (Dual-Watch mode)\n");
}

void wte_destroy(void)
{
    if (wte_state.kvm_wte_enabled) {
        wte_kvm_disable();
    }

    if (wte_state.page_table) {
        g_hash_table_destroy(wte_state.page_table);
        wte_state.page_table = NULL;
    }

    free(wte_state.renx_queue);

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
    wte_state.renx_count = 0;

    wte_state.dll_filter_enabled  = true;
    wte_state.dll_module_count    = 0;
    wte_state.dll_filtered_count  = 0;
    wte_state.dll_filtered_total  = 0;

    wte_state.mtf_active     = false;
    wte_state.mtf_reason     = WTE_MTF_REASON_WRITE;
    wte_state.mtf_target_va  = 0;
    wte_state.mtf_target_gfn = 0;

    /* Close any open JIT-IL dump before resetting state so num_records
     * gets patched correctly (wte_activate may be called multiple rounds). */
    if (wte_state.jit_tap.dump_file)
        wte_jit_il_close();

    /* Reset JIT tap state (keep dump_seq for monotone file naming) */
    wte_state.jit_tap.enabled                 = false;
    wte_state.jit_tap.clrjit_base             = 0;
    wte_state.jit_tap.clrjit_end              = 0;
    wte_state.jit_tap.g_jit_va                = 0;
    wte_state.jit_tap.getjit_va               = 0;
    wte_state.jit_tap.compile_method_va       = 0;
    wte_state.jit_tap.getjit_nx_armed         = false;
    wte_state.jit_tap.getjit_gfn              = 0;
    wte_state.jit_tap.compile_method_nx_armed = false;
    wte_state.jit_tap.compile_method_gfn      = 0;
    wte_state.jit_tap.rearm_pending              = false;
    wte_state.jit_tap.getjit_returned_pending    = false;
    wte_state.jit_tap.mtf_rearm_gfn              = 0;
    wte_state.jit_tap.dump_file               = NULL;
    wte_state.jit_tap.records_written         = 0;
    wte_state.jit_tap.count_file_offset       = 0;

    wte_state.jit_tap.getehinfo_va          = 0;
    wte_state.jit_tap.getehinfo_nx_armed    = false;
    wte_state.jit_tap.getehinfo_gfn         = 0;
    wte_state.jit_tap.pending_write         = false;
    wte_state.jit_tap.pending_ftn           = 0;
    wte_state.jit_tap.pending_scope         = 0;
    if (wte_state.jit_tap.pending_il_bytes) {
        free(wte_state.jit_tap.pending_il_bytes);
        wte_state.jit_tap.pending_il_bytes  = NULL;
    }
    wte_state.jit_tap.pending_il_size       = 0;
    wte_state.jit_tap.pending_eh_count      = 0;
    wte_state.jit_tap.eh_expected           = 0;
    wte_state.jit_tap.eh_captured           = 0;
    wte_state.jit_tap.eh_clause_ptr         = 0;
    wte_state.jit_tap.eh_return_pending     = false;
    wte_state.jit_tap.eh_return_gfn         = 0;
    wte_state.jit_tap.eh_rearm_pending      = false;

    /* Force-JIT sweep trigger (JIT-idle).  Phase 1: self-enable with a
     * default idle threshold for log-only validation; phase 2 will drive
     * enable/threshold from WTE_SETUP (harness opt-in). */
    wte_state.sweep_trigger.enabled           = true;
    wte_state.sweep_trigger.flag_gva          = 0;
    wte_state.sweep_trigger.harness_cr3       = 0;
    wte_state.sweep_trigger.idle_threshold_us = 500000;  /* 500 ms */
    wte_state.sweep_trigger.last_jit_us       = 0;
    wte_state.sweep_trigger.idle_active       = false;
    wte_state.sweep_trigger.idle_windows      = 0;

    if (!wte_state.kvm_wte_enabled) {
        wte_kvm_enable();
    }
    wte_kvm_set_cr3(cr3);

    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;
    wte_state.pt_decode_cursor = 0;

    nyx_printf("[WtE] Activated: CR3=0x%lx, 64bit=%d, DLL filter=module-list\n",
               (unsigned long)cr3, is_64bit);
}

void wte_deactivate(void)
{
    /* Finalize JIT-IL dump if open */
    if (wte_state.jit_tap.dump_file)
        wte_jit_il_close();

    /* Disarm any remaining JIT tap NX */
    if (wte_state.jit_tap.getjit_nx_armed &&
        wte_state.jit_tap.getjit_gfn != 0) {
        uint64_t gfn = wte_state.jit_tap.getjit_gfn;
        wte_kvm_clear_nx(&gfn, 1);
        wte_state.jit_tap.getjit_nx_armed = false;
    }
    if (wte_state.jit_tap.compile_method_nx_armed &&
        wte_state.jit_tap.compile_method_gfn != 0) {
        uint64_t gfn = wte_state.jit_tap.compile_method_gfn;
        wte_kvm_clear_nx(&gfn, 1);
        wte_state.jit_tap.compile_method_nx_armed = false;
    }
    if (wte_state.jit_tap.getehinfo_nx_armed &&
        wte_state.jit_tap.getehinfo_gfn != 0) {
        uint64_t gfn = wte_state.jit_tap.getehinfo_gfn;
        wte_kvm_clear_nx(&gfn, 1);
        wte_state.jit_tap.getehinfo_nx_armed = false;
    }
    if (wte_state.jit_tap.eh_return_pending &&
        wte_state.jit_tap.eh_return_gfn != 0) {
        uint64_t gfn = wte_state.jit_tap.eh_return_gfn;
        wte_kvm_clear_nx(&gfn, 1);
        wte_state.jit_tap.eh_return_pending = false;
    }
    if (wte_state.jit_tap.pending_il_bytes) {
        free(wte_state.jit_tap.pending_il_bytes);
        wte_state.jit_tap.pending_il_bytes = NULL;
    }
    wte_state.jit_tap.pending_write = false;

    nyx_printf("[WtE] Deactivated: total=%d (dumped=%d, DLL-filtered=%d, "
               "CoW-recovered=%lu) across %d rounds\n",
               wte_state.total_wte_count,
               wte_state.total_wte_count - wte_state.dll_filtered_total,
               wte_state.dll_filtered_total,
               (unsigned long)wte_state.total_cow_recoveries,
               wte_state.round + 1);

    if (wte_state.kvm_wte_enabled) {
        wte_kvm_disable();
    }
    wte_state.active = false;
}

/* ── PE Range Protection: W=0 + X=0 ──────────────────────────── */

void wte_protect_pe_range(CPUState *cpu, uint64_t image_base,
                          uint64_t image_size, uint64_t cr3)
{
    nyx_printf("[WtE][PROTECT] Setting W=0 + X=0 on PE: VA 0x%lx - 0x%lx\n",
               (unsigned long)image_base,
               (unsigned long)(image_base + image_size));

    wte_state.pe_base_va = image_base;
    wte_state.pe_end_va  = image_base + image_size;
    wte_state.pe_size    = image_size;
    wte_state.pe_page_count = 0;

    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    uint64_t wp_batch[WTE_MAX_BATCH_GFNS];
    int nx_count = 0, wp_count = 0;
    int mapped = 0, unmapped = 0;

    for (uint64_t va = image_base; va < image_base + image_size;
         va += WTE_PAGE_SIZE) {
        uint64_t pa = get_paging_phys_addr(cpu, cr3, va);

        if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
            unmapped++;
            continue;
        }

        uint64_t gfn = pa >> 12;
        uint64_t page_va = va & ~0xFFFULL;
        mapped++;

        /* Store VA→GFN mapping for CoW detection */
        if (wte_state.pe_page_count < WTE_MAX_TARGET_PE_PAGES) {
            wte_state.pe_vas[wte_state.pe_page_count] = page_va;
            wte_state.pe_gfns[wte_state.pe_page_count] = gfn;
            wte_state.pe_page_count++;
        }

        /* Create VA-based page entry */
        wte_page_entry_t *entry = wte_lookup_or_create_va(page_va, gfn);
        entry->flags = WTE_PAGE_IS_PE | WTE_PAGE_W_PROTECTED | WTE_PAGE_X_BLOCKED;

        /* Read baseline from root snapshot */
        uint64_t gpa = pa & 0xFFFFFFFFFFFFF000ULL;
        entry->gpa = gpa;
        if (fast_reload_root_created(get_fast_reload_snapshot())) {
            if (!read_snapshot_memory(get_fast_reload_snapshot(),
                                     gpa, entry->baseline, WTE_PAGE_SIZE)) {
                cpu_physical_memory_read(gpa, entry->baseline, WTE_PAGE_SIZE);
            }
        } else {
            cpu_physical_memory_read(gpa, entry->baseline, WTE_PAGE_SIZE);
        }
        entry->baseline_valid = true;
        memcpy(entry->current, entry->baseline, WTE_PAGE_SIZE);

        /* Batch NX + WP */
        nx_batch[nx_count++] = gfn;
        wp_batch[wp_count++] = gfn;

        if (nx_count >= WTE_MAX_BATCH_GFNS) {
            wte_kvm_set_nx(nx_batch, nx_count);
            nx_count = 0;
        }
        if (wp_count >= WTE_MAX_BATCH_GFNS) {
            wte_kvm_set_wp(wp_batch, wp_count);
            wp_count = 0;
        }
    }

    /* Flush remaining batches */
    if (nx_count > 0) wte_kvm_set_nx(nx_batch, nx_count);
    if (wp_count > 0) wte_kvm_set_wp(wp_batch, wp_count);

    nyx_printf("[WtE][PROTECT] PE protected: %d pages (W=0+X=0), "
               "%d unmapped, %d VA→GFN entries stored\n",
               mapped, unmapped, wte_state.pe_page_count);
}

/* ── Event-driven dynamic-region registration ───────────────────
 *
 * Called from the api_hook RETURN callbacks when the packer
 * allocates or promotes memory to executable (NtAllocateVirtualMemory
 * with PAGE_EXECUTE_*, NtProtectVirtualMemory promoting to EXECUTE).
 *
 * For each page in [base, base+size):
 *   1. Resolve guest VA → PA via target_cr3 page-table walk
 *   2. Create a DYNAMIC entry with baseline=0 (any non-zero byte is
 *      treated as packer-written)
 *   3. Set EPT NX so the next instruction fetch triggers WtE
 *
 * Replaces the timing-sensitive periodic rescan: install is bounded
 * to exactly the range the packer just allocated, deterministically.
 */
void wte_register_dynamic_exec_region(CPUState *cpu,
                                      uint64_t base, uint64_t size)
{
    if (!wte_state.active) return;
    uint64_t cr3 = wte_state.target_cr3;
    if (cr3 == 0 || size == 0) return;

    uint64_t va_start = base & ~(WTE_PAGE_SIZE - 1ULL);
    uint64_t va_end   = (base + size + WTE_PAGE_SIZE - 1) &
                        ~(WTE_PAGE_SIZE - 1ULL);

    /* Always record the range so wte_handle_exec_violation can late-bind
     * pages that are unmapped now but get committed later (lazy COMMIT
     * is common — e.g., amber's RWX VirtualAlloc(0x427000) returns before
     * any of the 1063 pages are actually backed). */
    if (wte_state.dyn_range_count <
        (int)(sizeof(wte_state.dyn_ranges) / sizeof(wte_state.dyn_ranges[0]))) {
        bool dup = false;
        for (int i = 0; i < wte_state.dyn_range_count; i++) {
            if (wte_state.dyn_ranges[i].base == va_start &&
                wte_state.dyn_ranges[i].end  == va_end) { dup = true; break; }
        }
        if (!dup) {
            int idx = wte_state.dyn_range_count++;
            wte_state.dyn_ranges[idx].base = va_start;
            wte_state.dyn_ranges[idx].end  = va_end;

            /* Also register with KVM so the EPT-violation handler can
             * pre-NX the SPTE on lazy-COMMIT fault — eliminates the
             * polling race that left amber's OEP at OEP+0x84. */
            struct kvm_nyx_dyn_range req = {
                .base = va_start,
                .end  = va_end,
            };
            int rc = kvm_vm_ioctl(kvm_state,
                                  KVM_NYX_DYN_RANGE_ADD, &req);
            if (rc < 0)
                nyx_printf("[WtE][DYN-REG] KVM ioctl failed: %d\n", rc);
        }
    }

    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int      nx_count   = 0;
    int      registered = 0, skipped_pe = 0, unmapped = 0;

    for (uint64_t va = va_start; va < va_end; va += WTE_PAGE_SIZE) {
        if (va >= wte_state.pe_base_va && va < wte_state.pe_end_va) {
            skipped_pe++;
            continue;
        }
        uint64_t pa = get_paging_phys_addr(cpu, cr3, va);
        if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
            unmapped++;
            continue;
        }
        uint64_t gfn = pa >> 12;
        uint64_t gpa = gfn << 12;

        wte_page_entry_t *entry = wte_lookup_or_create_va(va, gfn);
        if (!entry) continue;

        if (!(entry->flags & (WTE_PAGE_X_BLOCKED | WTE_PAGE_X_ALLOWED))) {
            entry->gpa = gpa;
            entry->flags |= WTE_PAGE_IS_DYNAMIC | WTE_PAGE_WRITTEN;
            memset(entry->baseline, 0, WTE_PAGE_SIZE);
            entry->baseline_valid = true;
            cpu_physical_memory_read(gpa, entry->current, WTE_PAGE_SIZE);
        }
        entry->flags |= WTE_PAGE_X_BLOCKED;

        nx_batch[nx_count++] = gfn;
        registered++;
        if (nx_count >= WTE_MAX_BATCH_GFNS) {
            wte_kvm_set_nx(nx_batch, nx_count);
            nx_count = 0;
        }
    }
    if (nx_count > 0) wte_kvm_set_nx(nx_batch, nx_count);

    nyx_printf("[WtE][DYN-REG] base=0x%lx size=0x%lx → %d NX'd, "
               "%d PE-skip, %d unmapped\n",
               (unsigned long)base, (unsigned long)size,
               registered, skipped_pe, unmapped);
}

/* ── JIT-IL Tap (Phase 2) ───────────────────────────────────────── */

/*
 * Binary dump format (little-endian, x86 32-bit pointers):
 *
 *   File header  (10 bytes):
 *       magic[6]      b"JITIL\x01"
 *       num_records   uint32   (patched at close time)
 *
 *   Per record:
 *       wte_seq       uint32
 *       ftn           uint32   (MethodDesc*)
 *       scope         uint32   (CORINFO_MODULE_HANDLE*)
 *       il_size       uint32
 *       eh_count      uint16
 *       _reserved     uint16   = 0
 *       il_bytes[il_size]
 *       pad[]                  zero-pad to next 4-byte boundary
 */

static const uint8_t k_jitil_magic[6] = {'J','I','T','I','L','\x02'};

static void wte_jit_il_open(void)
{
    wte_state.jit_tap.records_written = 0;
    wte_state.jit_tap.count_file_offset = 0;
    wte_state.jit_tap.dump_file = NULL;

    char *path = NULL;
    assert(asprintf(&path, "%s/dump/jit_il_dump_%d",
                    GET_GLOBAL_STATE()->workdir_path,
                    wte_state.jit_tap.dump_seq++) != -1);

    /* Ensure dump directory exists */
    char *ddir = NULL;
    assert(asprintf(&ddir, "%s/dump", GET_GLOBAL_STATE()->workdir_path) != -1);
    mkdir(ddir, 0755);
    free(ddir);

    FILE *f = fopen(path, "wb");
    free(path);
    if (!f) {
        nyx_printf("[JIT-TAP] ERROR: cannot open jit_il dump file\n");
        return;
    }
    fwrite(k_jitil_magic, 1, 6, f);
    uint32_t zero = 0;
    wte_state.jit_tap.count_file_offset = ftell(f);
    fwrite(&zero, 4, 1, f);
    fflush(f);
    wte_state.jit_tap.dump_file = f;
    nyx_printf("[JIT-TAP] Opened jit_il_dump_%d\n",
               wte_state.jit_tap.dump_seq - 1);
}

static void wte_jit_il_write(uint32_t wte_seq, uint32_t ftn, uint32_t scope,
                              const uint8_t *il_bytes, uint32_t il_size,
                              uint16_t eh_count,
                              const wte_eh_clause_t *eh_clauses)
{
    FILE *f = wte_state.jit_tap.dump_file;
    if (!f) return;

    /* Fixed record header: wte_seq(4) ftn(4) scope(4) il_size(4)
     *                       eh_count(2) _reserved(2) */
    uint8_t hdr[20];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr + 0,  &wte_seq,   4);
    memcpy(hdr + 4,  &ftn,       4);
    memcpy(hdr + 8,  &scope,     4);
    memcpy(hdr + 12, &il_size,   4);
    memcpy(hdr + 16, &eh_count,  2);
    fwrite(hdr, 1, sizeof(hdr), f);
    fwrite(il_bytes, 1, il_size, f);

    /* Pad to next absolute 4-byte boundary */
    long cur = ftell(f);
    int pad = (int)((-cur) & 3);
    if (pad > 0) {
        uint8_t zeros[3] = {0, 0, 0};
        fwrite(zeros, 1, pad, f);
    }

    /* Write EH clauses (24 bytes each, already 4-byte aligned) */
    if (eh_count > 0 && eh_clauses != NULL) {
        fwrite(eh_clauses, sizeof(wte_eh_clause_t), eh_count, f);
    }

    wte_state.jit_tap.records_written++;

    /* Patch num_records in-place after every write so the file is valid
     * even if the process is killed by timeout before wte_jit_il_close(). */
    long end_pos = ftell(f);
    uint32_t count = (uint32_t)wte_state.jit_tap.records_written;
    fseek(f, wte_state.jit_tap.count_file_offset, SEEK_SET);
    fwrite(&count, 4, 1, f);
    fseek(f, end_pos, SEEK_SET);
    fflush(f);

    nyx_printf("[JIT-TAP] Record #%d: ftn=0x%x scope=0x%x il_size=%u eh=%u\n",
               wte_state.jit_tap.records_written, ftn, scope, il_size, eh_count);
}

static void wte_jit_flush_pending(void)
{
    if (!wte_state.jit_tap.pending_write) return;

    /* Write only the clauses we actually captured.  Using pending_eh_count
     * (the expected EHcount) here would emit stale eh_clauses[] entries from
     * a previous method plus uninitialised slots when capture was cut short
     * (e.g. MTF-busy fallback), corrupting the record. */
    uint16_t captured = wte_state.jit_tap.eh_captured;
    uint16_t expected = wte_state.jit_tap.pending_eh_count;
    if (captured < expected) {
        nyx_printf("[JIT-TAP] WARNING: ftn=0x%x partial EH capture %u/%u — "
                   "writing %u clause(s)\n",
                   wte_state.jit_tap.pending_ftn, captured, expected, captured);
    }

    wte_jit_il_write(wte_state.jit_tap.pending_wte_seq,
                     wte_state.jit_tap.pending_ftn,
                     wte_state.jit_tap.pending_scope,
                     wte_state.jit_tap.pending_il_bytes,
                     wte_state.jit_tap.pending_il_size,
                     captured,
                     wte_state.jit_tap.eh_clauses);
    free(wte_state.jit_tap.pending_il_bytes);
    wte_state.jit_tap.pending_il_bytes   = NULL;
    wte_state.jit_tap.pending_write      = false;
    wte_state.jit_tap.getehinfo_nx_armed = false;
    wte_state.jit_tap.eh_return_pending  = false;
    wte_state.jit_tap.eh_rearm_pending   = false;
}

void wte_jit_il_close(void)
{
    FILE *f = wte_state.jit_tap.dump_file;
    if (!f) return;

    /* Flush any pending buffered write before closing */
    if (wte_state.jit_tap.pending_write) {
        wte_jit_flush_pending();
    }

    /* Patch num_records in the file header */
    uint32_t count = (uint32_t)wte_state.jit_tap.records_written;
    fseek(f, wte_state.jit_tap.count_file_offset, SEEK_SET);
    fwrite(&count, 4, 1, f);
    fclose(f);
    wte_state.jit_tap.dump_file = NULL;

    nyx_printf("[JIT-TAP] Closed jit_il dump (%d records)\n", count);
}

/* ── Force-JIT sweep trigger (JIT-idle detection) ───────────────────
 * Passive: reuses the compileMethod tap to watch how long the JIT has
 * been quiet.  No EPT-NX on hot pages, no guest thread held — so no
 * deadlock risk and no anti-debug/anti-tamper surface. */

void wte_sweep_trigger_setup(uint64_t flag_gva, uint64_t harness_cr3,
                             uint64_t idle_threshold_us)
{
    wte_state.sweep_trigger.enabled           = true;
    wte_state.sweep_trigger.flag_gva          = flag_gva;
    wte_state.sweep_trigger.harness_cr3       = harness_cr3;
    wte_state.sweep_trigger.idle_threshold_us = idle_threshold_us;
    wte_state.sweep_trigger.last_jit_us       = 0;
    wte_state.sweep_trigger.idle_active       = false;
    wte_state.sweep_trigger.idle_windows      = 0;
    nyx_printf("[SWEEP-TRIG] enabled: flag_gva=0x%lx cr3=0x%lx idle=%lu us\n",
               (unsigned long)flag_gva, (unsigned long)harness_cr3,
               (unsigned long)idle_threshold_us);
}

void wte_sweep_trigger_note_jit(void)
{
    if (!wte_state.sweep_trigger.enabled) return;
    wte_state.sweep_trigger.last_jit_us = (uint64_t)g_get_monotonic_time();
    /* JIT resumed — close any open idle window so the NEXT gap re-arms.
     * This is what makes us catch the last (pre-exit) gap instead of the
     * first CLR-init gap. */
    wte_state.sweep_trigger.idle_active = false;
}

void wte_sweep_trigger_check(CPUState *cpu)
{
    if (!wte_state.sweep_trigger.enabled)         return;
    if (wte_state.sweep_trigger.idle_active)      return;  /* window logged */
    if (wte_state.sweep_trigger.last_jit_us == 0) return;  /* no JIT yet   */

    uint64_t now  = (uint64_t)g_get_monotonic_time();
    uint64_t idle = now - wte_state.sweep_trigger.last_jit_us;
    if (idle < wte_state.sweep_trigger.idle_threshold_us) return;

    wte_state.sweep_trigger.idle_active = true;
    wte_state.sweep_trigger.idle_windows++;

    /* Signal the harness: write the idle-window counter into its flag.  The
     * harness polling loop sees the change and runs the force-JIT sweep on
     * the live process.  Every window (re)writes — the last one before exit
     * is the one that yields full coverage; earlier ones are harmless
     * (PrepareMethod is idempotent). */
    bool wrote = false;
    if (wte_state.sweep_trigger.flag_gva != 0) {
        uint64_t pa = get_paging_phys_addr(cpu,
                          wte_state.sweep_trigger.harness_cr3,
                          wte_state.sweep_trigger.flag_gva);
        if (pa != 0 && pa != 0xFFFFFFFFFFFFFFFFULL) {
            uint32_t val = wte_state.sweep_trigger.idle_windows;
            wrote = write_physical_memory(pa, (uint8_t *)&val, 4, cpu);
        } else {
            nyx_printf("[SWEEP-TRIG] phys walk FAILED: harness_cr3=0x%lx "
                       "flag_gva=0x%lx -> pa=0x%lx (cur cr3=0x%lx)\n",
                       (unsigned long)wte_state.sweep_trigger.harness_cr3,
                       (unsigned long)wte_state.sweep_trigger.flag_gva,
                       (unsigned long)pa,
                       (unsigned long)(X86_CPU(cpu)->env.cr[3] &
                                       0xFFFFFFFFFFFFF000ULL));
        }
    }

    nyx_printf("[SWEEP-TRIG] idle window #%u: JIT quiet %lu us (threshold %lu) "
               "— harness flag %s\n",
               wte_state.sweep_trigger.idle_windows,
               (unsigned long)idle,
               (unsigned long)wte_state.sweep_trigger.idle_threshold_us,
               wte_state.sweep_trigger.flag_gva == 0 ? "disabled"
                   : (wrote ? "written" : "WRITE FAILED (paged out?)"));
}

/* Parse PE export directory to find the VA of a named export.
 * Returns 0 on failure.
 * Reads from guest virtual memory under current CR3. */
static uint64_t wte_jit_find_export(CPUState *cpu, uint64_t dll_base,
                                     const char *target_name)
{
    /* DOS header */
    uint8_t dos[0x40];
    if (!read_virtual_memory(dll_base, dos, sizeof(dos), cpu)) return 0;
    if (dos[0] != 'M' || dos[1] != 'Z') return 0;
    uint32_t pe_off = *(uint32_t *)(dos + 0x3C);

    /* PE signature + COFF + optional header */
    uint8_t pe[0x108];
    if (!read_virtual_memory(dll_base + pe_off, pe, sizeof(pe), cpu)) return 0;
    if (memcmp(pe, "PE\0\0", 4) != 0) return 0;

    uint16_t magic = *(uint16_t *)(pe + 24);  /* Optional header magic */
    uint32_t exp_rva;
    if (magic == 0x10B)       /* PE32  (x86) */
        exp_rva = *(uint32_t *)(pe + 24 + 96);
    else if (magic == 0x20B)  /* PE32+ (x64) */
        exp_rva = *(uint32_t *)(pe + 24 + 112);
    else return 0;
    if (exp_rva == 0) return 0;

    /* IMAGE_EXPORT_DIRECTORY (40 bytes) */
    uint8_t exp[40];
    if (!read_virtual_memory(dll_base + exp_rva, exp, sizeof(exp), cpu)) return 0;

    uint32_t num_names = *(uint32_t *)(exp + 24);
    uint32_t addr_rva  = *(uint32_t *)(exp + 28);
    uint32_t name_rva  = *(uint32_t *)(exp + 32);
    uint32_t ord_rva   = *(uint32_t *)(exp + 36);

    size_t tlen = strlen(target_name);

    for (uint32_t i = 0; i < num_names && i < 8192; i++) {
        uint32_t nrva = 0;
        if (!read_virtual_memory(dll_base + name_rva + (uint64_t)i * 4,
                                 (uint8_t *)&nrva, 4, cpu)) break;

        uint8_t name[32] = {0};
        read_virtual_memory(dll_base + nrva, name,
                            tlen + 1 < sizeof(name) ? tlen + 1 : sizeof(name) - 1,
                            cpu);
        if (memcmp(name, target_name, tlen) != 0 || name[tlen] != 0)
            continue;

        uint16_t ordinal = 0;
        if (!read_virtual_memory(dll_base + ord_rva + (uint64_t)i * 2,
                                 (uint8_t *)&ordinal, 2, cpu)) return 0;
        uint32_t func_rva = 0;
        if (!read_virtual_memory(dll_base + addr_rva + (uint64_t)ordinal * 4,
                                 (uint8_t *)&func_rva, 4, cpu)) return 0;
        return dll_base + func_rva;
    }
    return 0;
}

/* Scan the first bytes of getJit() for MOV EAX, [moffs32] (0xA1 <addr32>).
 * Returns the absolute VA of the g_jit global, or 0 if not found. */
static uint64_t wte_jit_find_g_jit(CPUState *cpu, uint64_t getjit_va)
{
    uint8_t code[8];
    if (!read_virtual_memory(getjit_va, code, sizeof(code), cpu)) return 0;
    /* 0xA1 = MOV EAX, moffs32 (x86 32-bit, 5 bytes: opcode + abs addr) */
    if (code[0] == 0xA1) {
        uint32_t addr = *(uint32_t *)(code + 1);
        return (uint64_t)addr;
    }
    return 0;
}

/* Dereference g_jit → ICorJitCompiler* → vtable → vtable[0] = compileMethod.
 * Returns 0 if g_jit has not been initialized (null instance). */
static uint64_t wte_jit_resolve_compile_method(CPUState *cpu, uint64_t g_jit_va)
{
    uint32_t instance = 0;
    if (!read_virtual_memory(g_jit_va, (uint8_t *)&instance, 4, cpu) ||
        instance == 0)
        return 0;

    uint32_t vtable = 0;
    if (!read_virtual_memory((uint64_t)instance, (uint8_t *)&vtable, 4, cpu) ||
        vtable == 0)
        return 0;

    uint32_t compile_method = 0;
    if (!read_virtual_memory((uint64_t)vtable, (uint8_t *)&compile_method, 4,
                              cpu) || compile_method == 0)
        return 0;

    return (uint64_t)compile_method;
}

/* Arm EPT NX on a single page (helper used by JIT tap). */
static void wte_jit_tap_arm_nx(CPUState *cpu, uint64_t va, uint64_t *out_gfn)
{
    (void)cpu;
    uint64_t pa = get_paging_phys_addr(cpu, wte_state.target_cr3, va);
    if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
        nyx_printf("[JIT-TAP] arm_nx: VA=0x%lx not mapped\n", (unsigned long)va);
        *out_gfn = 0;
        return;
    }
    uint64_t gfn = pa >> 12;
    wte_kvm_set_nx(&gfn, 1);
    *out_gfn = gfn;
    nyx_printf("[JIT-TAP] NX armed: VA=0x%lx GFN=0x%lx\n",
               (unsigned long)va, (unsigned long)gfn);
}

void wte_jit_tap_on_dll_load(CPUState *cpu, uint64_t module_base,
                              uint64_t module_end, const char *name)
{
    if (!wte_state.active) return;

    /* Case-insensitive check for "clrjit.dll" */
    const char *bn = name;
    /* Strip path if present */
    const char *slash = strrchr(name, '\\');
    if (!slash) slash = strrchr(name, '/');
    if (slash) bn = slash + 1;

    bool is_clrjit = (strncasecmp(bn, "clrjit.dll", 10) == 0 ||
                      strncasecmp(bn, "mscorjit.dll", 12) == 0);
    if (!is_clrjit) return;

    nyx_printf("[JIT-TAP] Detected CLR JIT: %s base=0x%lx end=0x%lx\n",
               name, (unsigned long)module_base, (unsigned long)module_end);

    wte_state.jit_tap.enabled    = true;
    wte_state.jit_tap.clrjit_base = module_base;
    wte_state.jit_tap.clrjit_end  = module_end;

    /* Step 1: find getJit() export */
    uint64_t getjit_va = wte_jit_find_export(cpu, module_base, "getJit");
    if (getjit_va == 0) {
        nyx_printf("[JIT-TAP] getJit export not found\n");
        return;
    }
    wte_state.jit_tap.getjit_va = getjit_va;
    nyx_printf("[JIT-TAP] getJit VA=0x%lx\n", (unsigned long)getjit_va);

    /* Step 2: extract g_jit global VA from first instruction */
    uint64_t g_jit_va = wte_jit_find_g_jit(cpu, getjit_va);
    if (g_jit_va == 0) {
        nyx_printf("[JIT-TAP] g_jit global not found in getJit prologue\n");
        return;
    }
    wte_state.jit_tap.g_jit_va = g_jit_va;
    nyx_printf("[JIT-TAP] g_jit VA=0x%lx\n", (unsigned long)g_jit_va);

    /* Step 3: try to resolve compileMethod now (g_jit may already be set
     * if CLR was initialized before we detected the DLL) */
    uint64_t cm_va = wte_jit_resolve_compile_method(cpu, g_jit_va);
    if (cm_va != 0) {
        wte_state.jit_tap.compile_method_va = cm_va;
        nyx_printf("[JIT-TAP] compileMethod VA=0x%lx (immediate)\n",
                   (unsigned long)cm_va);
        wte_jit_tap_arm_nx(cpu, cm_va, &wte_state.jit_tap.compile_method_gfn);
        wte_state.jit_tap.compile_method_nx_armed = (wte_state.jit_tap.compile_method_gfn != 0);
        if (!wte_state.jit_tap.dump_file)
            wte_jit_il_open();
    } else {
        /* g_jit not initialized yet: arm trap on getJit page so we'll
         * retry resolution after the JIT singleton is created. */
        nyx_printf("[JIT-TAP] g_jit not initialized yet — arming getJit trap\n");
        wte_jit_tap_arm_nx(cpu, getjit_va, &wte_state.jit_tap.getjit_gfn);
        wte_state.jit_tap.getjit_nx_armed = (wte_state.jit_tap.getjit_gfn != 0);
    }
}

/* Handle exec violation on a JIT tap page (getJit or compileMethod).
 *
 * Returns true if the violation was consumed — caller must return immediately.
 * Returns false if the GFN/RIP is unrelated to the JIT tap.
 *
 * Execution flow:
 *   getJit page trap:
 *     → try to resolve compileMethod (g_jit may now be set)
 *     → if resolved: disarm getJit NX, arm compileMethod NX
 *     → either way: allow exec via MTF re-arm on getJit page
 *
 *   compileMethod page trap:
 *     → if RIP == compile_method_va: capture CORINFO_METHOD_INFO args
 *     → allow exec via MTF re-arm on compileMethod page
 */
bool wte_jit_tap_handle_exec(CPUState *cpu, uint64_t gfn, uint64_t gpa,
                              uint64_t rip)
{
    if (!wte_state.jit_tap.enabled) return false;

    /* getEHinfo return trap: getEHinfo has returned; clause_ptr is now filled. */
    if (wte_state.jit_tap.eh_return_pending &&
        gfn == wte_state.jit_tap.eh_return_gfn) {
        wte_state.jit_tap.eh_return_pending = false;
        uint64_t ret_gfn = wte_state.jit_tap.eh_return_gfn;
        wte_kvm_clear_nx(&ret_gfn, 1);

        uint16_t captured = wte_state.jit_tap.eh_captured;
        if (captured < WTE_JIT_MAX_EH_CLAUSES) {
            wte_eh_clause_t *clause = &wte_state.jit_tap.eh_clauses[captured];
            if (read_virtual_memory(wte_state.jit_tap.eh_clause_ptr,
                                    (uint8_t *)clause,
                                    sizeof(wte_eh_clause_t), cpu)) {
                wte_state.jit_tap.eh_captured++;
                nyx_printf("[JIT-TAP] EH[%u]: flags=0x%x try=[0x%x,+0x%x) "
                           "handler=[0x%x,+0x%x)\n",
                           captured, clause->flags,
                           clause->try_offset, clause->try_length,
                           clause->handler_offset, clause->handler_length);
            }
        }

        if (wte_state.jit_tap.eh_captured < wte_state.jit_tap.eh_expected) {
            /* More clauses — re-arm getEHinfo NX for next call */
            wte_kvm_set_nx(&wte_state.jit_tap.getehinfo_gfn, 1);
            wte_state.jit_tap.getehinfo_nx_armed = true;
        } else {
            /* All clauses captured — flush IL + EH record */
            nyx_printf("[JIT-TAP] EH capture complete (%u clauses) — flushing record\n",
                       wte_state.jit_tap.eh_captured);
            wte_jit_flush_pending();
        }
        return true;
    }

    /* Deferred re-arm: if the previous compileMethod trap cleared NX to allow
     * execution, re-arm NX now that we're back on a different page (the
     * compileMethod function has returned to its caller). */
    if (wte_state.jit_tap.rearm_pending &&
        gfn != wte_state.jit_tap.compile_method_gfn &&
        !wte_state.jit_tap.pending_write) {
        uint64_t cm_gfn = wte_state.jit_tap.compile_method_gfn;
        wte_kvm_set_nx(&cm_gfn, 1);
        wte_state.jit_tap.rearm_pending            = false;
        wte_state.jit_tap.compile_method_nx_armed  = true;
        nyx_printf("[JIT-TAP] Deferred re-arm: NX restored on compileMethod "
                   "GFN=0x%lx\n", (unsigned long)cm_gfn);
        /* Do NOT return — continue to process this exec violation normally */
    }

    /* Deferred getEHinfo re-arm: a false (non-getEHinfo) entry on the
     * getEHinfo page cleared NX while MTF was busy with an API hook step.
     * Now that we're back on a different page (the false function returned),
     * re-arm the getEHinfo NX so the genuine call is still intercepted. */
    if (wte_state.jit_tap.eh_rearm_pending &&
        wte_state.jit_tap.pending_write &&
        gfn != wte_state.jit_tap.getehinfo_gfn) {
        uint64_t gehi_gfn = wte_state.jit_tap.getehinfo_gfn;
        wte_kvm_set_nx(&gehi_gfn, 1);
        wte_state.jit_tap.eh_rearm_pending   = false;
        wte_state.jit_tap.getehinfo_nx_armed = true;
        nyx_printf("[JIT-TAP] Deferred re-arm: NX restored on getEHinfo "
                   "GFN=0x%lx\n", (unsigned long)gehi_gfn);
        /* Do NOT return — continue to process this exec violation normally */
    }

    /* Deferred getJit resolve: getJit initializes the g_jit singleton itself,
     * so g_jit is null at getJit entry.  After clearing NX (allowing getJit
     * to run), we set getjit_returned_pending=true.  On the next exec
     * violation from a different GFN (after getJit has returned), retry. */
    if (wte_state.jit_tap.getjit_returned_pending &&
        gfn != wte_state.jit_tap.getjit_gfn) {
        wte_state.jit_tap.getjit_returned_pending = false;
        uint64_t cm_va = wte_jit_resolve_compile_method(
            cpu, wte_state.jit_tap.g_jit_va);
        if (cm_va != 0) {
            wte_state.jit_tap.compile_method_va = cm_va;
            nyx_printf("[JIT-TAP] compileMethod VA=0x%lx (deferred getJit resolve)\n",
                       (unsigned long)cm_va);
            wte_jit_tap_arm_nx(cpu, cm_va,
                               &wte_state.jit_tap.compile_method_gfn);
            wte_state.jit_tap.compile_method_nx_armed =
                (wte_state.jit_tap.compile_method_gfn != 0);
            if (!wte_state.jit_tap.dump_file)
                wte_jit_il_open();
        } else {
            /* Still null — re-arm getJit trap for another try */
            nyx_printf("[JIT-TAP] deferred resolve: g_jit still null, "
                       "re-arming getJit trap\n");
            wte_jit_tap_arm_nx(cpu, wte_state.jit_tap.getjit_va,
                               &wte_state.jit_tap.getjit_gfn);
            wte_state.jit_tap.getjit_nx_armed =
                (wte_state.jit_tap.getjit_gfn != 0);
        }
        /* Do NOT return — continue to process this exec violation normally */
    }

    bool is_getjit_page = (wte_state.jit_tap.getjit_nx_armed &&
                           gfn == wte_state.jit_tap.getjit_gfn);
    bool is_cm_page     = (wte_state.jit_tap.compile_method_nx_armed &&
                           gfn == wte_state.jit_tap.compile_method_gfn);

    /* Late-bind: arm_nx failed (compileMethod page was demand-paged at
     * resolve time), but we now see the actual execution.  The current
     * EPT violation proves the GFN is live — record it and handle as a
     * normal compileMethod trap (deferred re-arm will install NX later). */
    if (!is_cm_page &&
        !wte_state.jit_tap.compile_method_nx_armed &&
        wte_state.jit_tap.compile_method_va != 0 &&
        rip == wte_state.jit_tap.compile_method_va) {
        wte_state.jit_tap.compile_method_gfn = gfn;
        nyx_printf("[JIT-TAP] Late-bind: compileMethod GFN=0x%lx\n",
                   (unsigned long)gfn);
        is_cm_page = true;
    }

    /* getEHinfo entry trap: intercept to install return-address NX. */
    if (wte_state.jit_tap.pending_write &&
        wte_state.jit_tap.getehinfo_nx_armed &&
        gfn == wte_state.jit_tap.getehinfo_gfn) {

        X86CPU      *cpux86_eh = X86_CPU(cpu);
        CPUX86State *env_eh    = &cpux86_eh->env;
        uint32_t esp_eh = (uint32_t)env_eh->regs[R_ESP];

        /* getEHinfo is a C++ virtual member of ICorJitInfo (thiscall, this
         * in ECX), so the explicit args sit at:
         *   [ESP+0x00] = return address
         *   [ESP+0x04] = ftn (CORINFO_METHOD_HANDLE)
         *   [ESP+0x08] = EHnumber (unsigned)
         *   [ESP+0x0C] = clause (CORINFO_EH_CLAUSE* output buffer) */
        uint32_t ret_addr = 0, ftn_arg = 0, eh_num = 0, clause_ptr = 0;
        read_virtual_memory((uint64_t)(esp_eh + 0x00), (uint8_t *)&ret_addr,   4, cpu);
        read_virtual_memory((uint64_t)(esp_eh + 0x04), (uint8_t *)&ftn_arg,    4, cpu);
        read_virtual_memory((uint64_t)(esp_eh + 0x08), (uint8_t *)&eh_num,     4, cpu);
        read_virtual_memory((uint64_t)(esp_eh + 0x0C), (uint8_t *)&clause_ptr, 4, cpu);

        /* Verify expected ftn and sequential clause index */
        if (ftn_arg  == wte_state.jit_tap.pending_ftn &&
            eh_num   == wte_state.jit_tap.eh_captured &&
            clause_ptr != 0 && ret_addr != 0) {

            uint64_t ret_pa = get_paging_phys_addr(cpu, wte_state.target_cr3,
                                                   (uint64_t)ret_addr);
            if (ret_pa != 0 && ret_pa != 0xFFFFFFFFFFFFFFFFULL) {
                uint64_t ret_gfn = ret_pa >> 12;
                wte_kvm_set_nx(&ret_gfn, 1);
                wte_state.jit_tap.eh_return_gfn     = ret_gfn;
                wte_state.jit_tap.eh_return_pending = true;
                wte_state.jit_tap.eh_clause_ptr     = (uint64_t)clause_ptr;

                /* Clear NX to let getEHinfo execute */
                wte_kvm_clear_nx(&wte_state.jit_tap.getehinfo_gfn, 1);
                wte_state.jit_tap.getehinfo_nx_armed = false;

                nyx_printf("[JIT-TAP] getEHinfo[%u]: ftn=0x%x clause_ptr=0x%x "
                           "ret_gfn=0x%lx\n",
                           eh_num, ftn_arg, clause_ptr,
                           (unsigned long)ret_gfn);
                return true;
            }
        }

        /* Not the real getEHinfo entry: getEHinfo shares its 4K page with
         * other JIT helpers, so any of them can fault first (NX is
         * page-granular).  Don't give up on the pending EH capture — step
         * over this instruction with MTF and re-arm the getEHinfo NX so the
         * genuine call (ftn == pending_ftn) is still intercepted. */
        wte_kvm_clear_nx(&wte_state.jit_tap.getehinfo_gfn, 1);
        /* MTF is free unless an API hook is mid single-step.  Note: a bare
         * "api_hook_step_idx < 0" test is wrong — the field is zero-initialised
         * and only ever set under api_hook_mode, so it stays 0 (>= 0) when no
         * API hooks exist, which would wrongly block MTF forever. */
        if (!GET_GLOBAL_STATE()->api_hook_mode ||
            GET_GLOBAL_STATE()->api_hook_step_idx < 0) {
            /* Precise: single-step the false entry, re-arm on MTF. */
            wte_state.mtf_active            = true;
            wte_state.mtf_reason            = WTE_MTF_REASON_JIT_REARM;
            wte_state.jit_tap.mtf_rearm_gfn = wte_state.jit_tap.getehinfo_gfn;
            kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_MTF);
            /* getehinfo_nx_armed stays true — MTF handler re-arms the NX. */
            nyx_printf("[JIT-TAP] getEHinfo page: non-getEHinfo entry "
                       "(ftn=0x%x), MTF step-over to re-arm\n", ftn_arg);
        } else {
            /* MTF busy with an API hook step — fall back to deferred re-arm:
             * NX stays cleared for now, and the next exec violation on a
             * different GFN re-arms the getEHinfo NX (see handle_exec top).
             * Keeps the pending EH capture alive instead of dropping it. */
            wte_state.jit_tap.eh_rearm_pending = true;
            /* getehinfo_nx_armed stays true — deferred path re-arms the NX. */
            nyx_printf("[JIT-TAP] getEHinfo page: non-getEHinfo entry "
                       "(ftn=0x%x), MTF busy — deferred re-arm\n", ftn_arg);
        }
        return true;
    }

    if (!is_getjit_page && !is_cm_page) return false;

    (void)gpa;

    if (is_getjit_page) {
        /* One-shot getJit trap: disarm NX first to avoid loop (the trap
         * fires at entry before any instruction runs; re-arm would
         * immediately trap every instruction on the same page). */
        uint64_t gjgfn = wte_state.jit_tap.getjit_gfn;
        wte_kvm_clear_nx(&gjgfn, 1);
        wte_state.jit_tap.getjit_nx_armed = false;

        /* Try to resolve compileMethod */
        uint64_t cm_va = wte_jit_resolve_compile_method(
            cpu, wte_state.jit_tap.g_jit_va);
        if (cm_va != 0) {
            wte_state.jit_tap.compile_method_va = cm_va;
            nyx_printf("[JIT-TAP] compileMethod VA=0x%lx (from getJit trap)\n",
                       (unsigned long)cm_va);
            wte_jit_tap_arm_nx(cpu, cm_va,
                               &wte_state.jit_tap.compile_method_gfn);
            wte_state.jit_tap.compile_method_nx_armed =
                (wte_state.jit_tap.compile_method_gfn != 0);
            if (!wte_state.jit_tap.dump_file)
                wte_jit_il_open();
        } else {
            /* g_jit null at getJit entry: getJit() itself creates the
             * singleton, so it's always null before getJit runs.
             * Set deferred flag; the resolve will be retried on the next
             * exec violation from a different GFN (after getJit returns). */
            wte_state.jit_tap.getjit_returned_pending = true;
            nyx_printf("[JIT-TAP] getJit entry: g_jit null, "
                       "deferring resolve to return\n");
        }
        return true;
    }

    /* compileMethod page trap */
    if (rip == wte_state.jit_tap.compile_method_va) {
        /* Capture CORINFO_METHOD_INFO arguments.
         *
         * ConfuserEx2 (and similar .NET JIT hooks) replaces vtable[0] with
         * a stdcall wrapper that passes 'this' as an explicit first arg:
         *
         *   [ESP + 0x00] = return address
         *   [ESP + 0x04] = pThis (ICorJitCompiler*, lives inside clrjit.dll)
         *   [ESP + 0x08] = comp  (ICorJitInfo*)
         *   [ESP + 0x0C] = info  (CORINFO_METHOD_INFO*)  ← read here
         *   [ESP + 0x10] = flags
         *
         * Standard thiscall would put info at [ESP+8]; diagnostic confirmed
         * il_size == [ESP+8] value, so the actual offset is +0x0C.
         *
         * CORINFO_METHOD_INFO layout (x86, .NET Framework 4.x):
         *   +0x00 ftn        (CORINFO_METHOD_HANDLE)
         *   +0x04 scope      (CORINFO_MODULE_HANDLE)
         *   +0x08 ILCode     (BYTE*)
         *   +0x0C ILCodeSize (unsigned int)
         *   +0x10 maxStack   (unsigned short)
         *   +0x12 EHcount    (unsigned short)
         */
        X86CPU      *cpux86 = X86_CPU(cpu);
        CPUX86State *env    = &cpux86->env;
        uint32_t esp = (uint32_t)env->regs[R_ESP];

        uint32_t info_ptr = 0;
        if (!read_virtual_memory((uint64_t)(esp + 0xC),
                                 (uint8_t *)&info_ptr, 4, cpu) ||
            info_ptr == 0) {
            nyx_printf("[JIT-TAP] compileMethod: failed to read info ptr\n");
            goto allow_cm;
        }

        uint8_t info_buf[24];
        if (!read_virtual_memory((uint64_t)info_ptr, info_buf, sizeof(info_buf),
                                 cpu)) {
            nyx_printf("[JIT-TAP] compileMethod: failed to read CORINFO_METHOD_INFO\n");
            goto allow_cm;
        }

        /* CORINFO_METHOD_INFO (x86 .NET 4.x):
         *   +0x00 ftn, +0x04 scope, +0x08 ILCode, +0x0C ILCodeSize,
         *   +0x10 maxStack (unsigned, 4B), +0x14 EHcount (unsigned, 4B),
         *   +0x18 options.  maxStack/EHcount are 4-byte unsigned, NOT u16. */
        uint32_t ftn       = *(uint32_t *)(info_buf + 0x00);
        uint32_t scope     = *(uint32_t *)(info_buf + 0x04);
        uint32_t ilcode    = *(uint32_t *)(info_buf + 0x08);
        uint32_t il_size   = *(uint32_t *)(info_buf + 0x0C);
        uint32_t eh_count  = *(uint32_t *)(info_buf + 0x14);

        /* Clamp EH count to our capture buffer; a pathological value here
         * almost certainly means a struct/ABI mismatch, so skip EH capture. */
        if (eh_count > WTE_JIT_MAX_EH_CLAUSES) {
            nyx_printf("[JIT-TAP] compileMethod: eh_count=%u exceeds max %d, "
                       "skipping EH capture\n", eh_count, WTE_JIT_MAX_EH_CLAUSES);
            eh_count = 0;
        }


        if (il_size == 0 || il_size > 0x10000) {
            nyx_printf("[JIT-TAP] compileMethod: skip il_size=%u\n", il_size);
            goto allow_cm;
        }

        /* A real method is being JIT-compiled — reset the sweep idle timer. */
        wte_sweep_trigger_note_jit();

        /* Flush any still-pending write from a previous method */
        if (wte_state.jit_tap.pending_write) {
            nyx_printf("[JIT-TAP] compileMethod: flushing stale pending write\n");
            if (wte_state.jit_tap.getehinfo_nx_armed) {
                wte_kvm_clear_nx(&wte_state.jit_tap.getehinfo_gfn, 1);
                wte_state.jit_tap.getehinfo_nx_armed = false;
            }
            if (wte_state.jit_tap.eh_return_pending) {
                wte_kvm_clear_nx(&wte_state.jit_tap.eh_return_gfn, 1);
                wte_state.jit_tap.eh_return_pending = false;
            }
            wte_jit_flush_pending();
        }

        uint8_t *il_bytes = malloc(il_size);
        if (!il_bytes) goto allow_cm;

        bool ok = read_virtual_memory((uint64_t)ilcode, il_bytes, il_size, cpu);
        if (!ok) {
            nyx_printf("[JIT-TAP] compileMethod: failed to read IL bytes "
                       "(ILCode=0x%x size=%u)\n", ilcode, il_size);
            free(il_bytes);
            goto allow_cm;
        }

        if (eh_count > 0 && wte_state.jit_tap.getehinfo_va == 0) {
            /* Resolve getEHinfo VA from comp vtable (one-time per run) */
            uint32_t comp_va = 0;
            read_virtual_memory((uint64_t)(esp + 0x08), (uint8_t *)&comp_va, 4, cpu);
            if (comp_va != 0) {
                uint32_t vtable = 0;
                if (read_virtual_memory((uint64_t)comp_va, (uint8_t *)&vtable,
                                        4, cpu) && vtable != 0) {
                    uint32_t gehinfo_fn = 0;
                    uint32_t slot_off = WTE_GETEHINFO_VTABLE_SLOT * 4;
                    if (read_virtual_memory((uint64_t)(vtable + slot_off),
                                            (uint8_t *)&gehinfo_fn, 4, cpu) &&
                        gehinfo_fn != 0) {
                        wte_state.jit_tap.getehinfo_va = (uint64_t)gehinfo_fn;
                        nyx_printf("[JIT-TAP] getEHinfo VA=0x%x (vtable[%d])\n",
                                   gehinfo_fn, WTE_GETEHINFO_VTABLE_SLOT);
                    }
                }
            }
        }

        if (eh_count > 0 && wte_state.jit_tap.getehinfo_va != 0) {
            /* Arm getEHinfo NX and buffer the write */
            uint64_t gehi_gfn = 0;
            wte_jit_tap_arm_nx(cpu, wte_state.jit_tap.getehinfo_va, &gehi_gfn);
            if (gehi_gfn != 0) {
                wte_state.jit_tap.getehinfo_gfn      = gehi_gfn;
                wte_state.jit_tap.getehinfo_nx_armed = true;

                wte_state.jit_tap.pending_il_bytes  = il_bytes;  /* transfer ownership */
                wte_state.jit_tap.pending_il_size   = il_size;
                wte_state.jit_tap.pending_ftn        = ftn;
                wte_state.jit_tap.pending_scope      = scope;
                wte_state.jit_tap.pending_wte_seq    = (uint32_t)wte_state.wte_count;
                wte_state.jit_tap.pending_eh_count   = eh_count;
                wte_state.jit_tap.eh_expected        = eh_count;
                wte_state.jit_tap.eh_captured        = 0;
                wte_state.jit_tap.eh_return_pending  = false;
                wte_state.jit_tap.eh_rearm_pending   = false;
                wte_state.jit_tap.pending_write      = true;
                il_bytes = NULL;  /* owned by pending state now */
                nyx_printf("[JIT-TAP] compileMethod: buffered ftn=0x%x eh_count=%u "
                           "pending EH capture\n", ftn, eh_count);
            } else {
                /* NX arm failed — write without EH */
                wte_jit_il_write((uint32_t)wte_state.wte_count, ftn, scope,
                                  il_bytes, il_size, eh_count, NULL);
            }
        } else {
            /* No EH or getEHinfo not resolved — write immediately */
            wte_jit_il_write((uint32_t)wte_state.wte_count, ftn, scope,
                              il_bytes, il_size, eh_count, NULL);
        }
        free(il_bytes);  /* NULL-safe if ownership was transferred */
    }

allow_cm:
    /* Allow compileMethod to execute by clearing NX.  Re-arm is deferred:
     * the next exec violation from a different GFN triggers re-arm
     * (see the rearm_pending check at the top of this function). */
    wte_kvm_clear_nx(&wte_state.jit_tap.compile_method_gfn, 1);
    wte_state.jit_tap.compile_method_nx_armed = false;
    wte_state.jit_tap.rearm_pending           = true;
    return true;
}

/* Re-arm NX on the JIT tap page after MTF single-step.
 * Returns true if the MTF was consumed by the JIT tap. */
bool wte_jit_tap_handle_mtf(CPUState *cpu)
{
    (void)cpu;
    if (!wte_state.jit_tap.enabled) return false;
    if (wte_state.mtf_reason != WTE_MTF_REASON_JIT_REARM) return false;

    uint64_t gfn = wte_state.jit_tap.mtf_rearm_gfn;
    if (gfn != 0) {
        wte_kvm_set_nx(&gfn, 1);
        nyx_printf("[JIT-TAP] MTF: NX re-armed on GFN=0x%lx\n",
                   (unsigned long)gfn);
    }
    wte_state.mtf_active = false;
    wte_state.mtf_reason = WTE_MTF_REASON_WRITE;
    return true;
}

/* ── Event-driven DLL registration ──────────────────────────────
 *
 * Called from api_hook RETURN callbacks when LdrLoadDll succeeds
 * (or NtMapViewOfSection with SEC_IMAGE).  Refreshes the dll_modules
 * list via PEB→Ldr (so new DLLs are visible to the noise filter)
 * and untracks any DYNAMIC entries that were mistakenly created on
 * the freshly loaded DLL's address range — those came from the legacy
 * rescan path and would otherwise produce spurious WtE dumps when
 * the DLL's normal code executes.
 */
void wte_register_loaded_dll(CPUState *cpu, uint64_t module_base)
{
    if (!wte_state.active || module_base == 0) return;

    /* Refresh dll_modules so subsequent wte_is_dll_rip / dump filtering
     * sees the new DLL.  Cheap PEB→Ldr walk. */
    wte_enumerate_dlls(cpu);

    /* JIT tap: check if this is clrjit.dll and arm compileMethod trap */
    for (int i = 0; i < wte_state.dll_module_count; i++) {
        if (wte_state.dll_modules[i].base == module_base) {
            wte_jit_tap_on_dll_load(cpu,
                                    wte_state.dll_modules[i].base,
                                    wte_state.dll_modules[i].end,
                                    wte_state.dll_modules[i].name);
            break;
        }
    }

    /* Find the freshly-loaded DLL's range. */
    uint64_t dll_end = 0;
    for (int i = 0; i < wte_state.dll_module_count; i++) {
        if (wte_state.dll_modules[i].base == module_base) {
            dll_end = wte_state.dll_modules[i].end;
            break;
        }
    }
    if (dll_end == 0) {
        /* DLL not yet visible in PEB→Ldr (race during loader init).
         * Caller will retry on the next LdrLoadDll RETURN. */
        return;
    }

    /* Sweep page_table for DYNAMIC entries that fall in this DLL's range
     * and untrack them. */
    GHashTableIter iter;
    gpointer       key, value;
    uint64_t       clear_batch[WTE_MAX_BATCH_GFNS];
    int            clear_count = 0;
    int            untracked = 0;

    g_hash_table_iter_init(&iter, wte_state.page_table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        wte_page_entry_t *entry = (wte_page_entry_t *)value;
        if (entry->va < module_base || entry->va >= dll_end) continue;
        if (!(entry->flags & WTE_PAGE_IS_DYNAMIC)) continue;

        if (entry->flags & WTE_PAGE_X_BLOCKED) {
            if (clear_count < WTE_MAX_BATCH_GFNS)
                clear_batch[clear_count++] = entry->gfn;
        }
        entry->flags &= ~(WTE_PAGE_IS_DYNAMIC | WTE_PAGE_WRITTEN |
                          WTE_PAGE_X_BLOCKED);
        entry->flags |= WTE_PAGE_X_ALLOWED;
        untracked++;
    }
    if (clear_count > 0) wte_kvm_clear_nx(clear_batch, clear_count);

    nyx_printf("[WtE][DLL-REG] base=0x%lx end=0x%lx %d entries cleaned\n",
               (unsigned long)module_base, (unsigned long)dll_end,
               untracked);
}

/* ── Lightweight dyn_range re-check ─────────────────────────────
 *
 * Walks ONLY the registered dynamic ranges (api_hook NtAllocate /
 * NtProtect callbacks recorded these into wte_state.dyn_ranges[]).
 * Any page that is now mapped but not yet in our tracking table
 * gets NX'd and a DYNAMIC entry created.
 *
 * Cheap: typical dyn_range size is a few hundred to a few thousand
 * pages, so each call is O(N) PT lookups against target_cr3 — well
 * under a millisecond.  Called every ~200 VM exits, frequent enough
 * that a freshly-mapped page is captured before the packer has a
 * chance to execute it.
 *
 * This catches the case where:
 *  - api_hook ran at NtAllocate RETURN: PTE not present yet (lazy
 *    COMMIT), set_nx_gfn no-op
 *  - packer later faults the page in: SPTE created but auto-NX hook
 *    in tdp_mmu_map_handle_target_level missed it (cr3 race or fault
 *    type quirk)
 *  - packer fetches code from the page: no NX on SPTE → fetch
 *    succeeds, WtE detection bypassed
 */
void wte_recheck_dyn_ranges(CPUState *cpu)
{
    if (!wte_state.active || wte_state.dyn_range_count == 0) return;
    uint64_t cr3 = wte_state.target_cr3;
    if (cr3 == 0) return;

    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int      nx_count    = 0;
    int      newly_nxd   = 0;

    for (int r = 0; r < wte_state.dyn_range_count; r++) {
        uint64_t base = wte_state.dyn_ranges[r].base;
        uint64_t end  = wte_state.dyn_ranges[r].end;
        for (uint64_t va = base; va < end; va += WTE_PAGE_SIZE) {
            if (va >= wte_state.pe_base_va && va < wte_state.pe_end_va)
                continue;

            uint64_t pa = get_paging_phys_addr(cpu, cr3, va);
            if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) continue;

            uint64_t gfn = pa >> 12;
            uint64_t gpa = gfn << 12;

            wte_page_entry_t *entry = wte_lookup_gfn(gfn);
            if (entry && (entry->flags & (WTE_PAGE_X_BLOCKED |
                                          WTE_PAGE_X_ALLOWED))) {
                continue; /* already tracked */
            }

            entry = wte_lookup_or_create_va(va, gfn);
            entry->gpa = gpa;
            entry->flags |= WTE_PAGE_IS_DYNAMIC | WTE_PAGE_WRITTEN |
                            WTE_PAGE_X_BLOCKED;
            memset(entry->baseline, 0, WTE_PAGE_SIZE);
            entry->baseline_valid = true;
            cpu_physical_memory_read(gpa, entry->current, WTE_PAGE_SIZE);

            nx_batch[nx_count++] = gfn;
            newly_nxd++;
            if (nx_count >= WTE_MAX_BATCH_GFNS) {
                wte_kvm_set_nx(nx_batch, nx_count);
                nx_count = 0;
            }
        }
    }
    if (nx_count > 0) wte_kvm_set_nx(nx_batch, nx_count);

    if (newly_nxd > 0)
        nyx_printf("[WtE][DYN-RECHECK] %d newly mapped page(s) NX'd "
                   "(across %d range(s))\n",
                   newly_nxd, wte_state.dyn_range_count);
}

/* ── Global NX: set X=0 on ALL mapped user pages (non-PE) ────────
 *
 * Walk target CR3 page tables and set NX on every user-space page
 * that is NOT already PE-protected.  This catches dynamically
 * allocated regions (e.g., amber packer's VirtualAlloc'd buffer)
 * without relying on dirty ring timing.
 *
 * When exec violation fires on these pages:
 *   - DLL pages → allowed by DLL filter (wte_is_dll_rip)
 *   - Dynamic unpack regions → DYN-EXEC path → WtE detection
 */
/* Per-mapped-page callback used by wte_walk_user_pages. */
typedef void (*wte_page_action_fn)(uint64_t va, uint64_t gfn, uint64_t gpa,
                                   void *ctx);

/* User-space VA bounds.
 *
 *   32-bit (WOW64): walk PML4[0] → PDPT[0..1] (covers 0..2 GiB).
 *     Skip [0..0x10000) and [0x7FFF0000..) — NULL guard / Windows top-of-user.
 *
 *   64-bit native: walk PML4[0..255] (canonical lower half, 0..128 TiB) →
 *     full PDPT[0..511] per entry. Skip [0..0x10000) and the top 128 KiB of
 *     canonical user space as a guard against kernel-shared pages.
 */
#define WTE_VA_LOW_GUARD          0x0000000000010000ULL
#define WTE_VA_HIGH_GUARD_32      0x000000007FFF0000ULL
#define WTE_VA_HIGH_GUARD_64      0x00007FFFFFFE0000ULL

/* Walk every mapped 4 KiB user-space page under `cr3` and invoke `fn` on it.
 *
 * 2 MiB huge pages are expanded into 512 × 4 KiB invocations so callers see
 * a uniform 4 KiB granularity. 1 GiB huge pages are skipped (rare in user
 * space; would expand to 256 K invocations).
 */
static void wte_walk_user_pages(CPUState *cpu, uint64_t cr3, bool is_64bit,
                                wte_page_action_fn fn, void *ctx)
{
    (void)cpu;

    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    int pml4_max = is_64bit ? 256 : 1;
    int pdpt_max = is_64bit ? 512 : 2;

    uint64_t high_guard = is_64bit ? WTE_VA_HIGH_GUARD_64
                                   : WTE_VA_HIGH_GUARD_32;

    for (int pml4_idx = 0; pml4_idx < pml4_max; pml4_idx++) {
        uint64_t pml4e = pml4_table[pml4_idx];
        if (!(pml4e & 1)) continue;

        uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
        uint64_t pdpt_table[512];
        cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

        for (int pdpte_idx = 0; pdpte_idx < pdpt_max; pdpte_idx++) {
            uint64_t pdpte = pdpt_table[pdpte_idx];
            if (!(pdpte & 1)) continue;
            if (pdpte & (1ULL << 7)) continue; /* 1 GiB huge page */

            uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
            uint64_t pd_table[512];
            cpu_physical_memory_read(pd_base, pd_table, 4096);

            uint64_t base_va_lvl3 = ((uint64_t)pml4_idx  << 39) |
                                    ((uint64_t)pdpte_idx << 30);

            for (int pde_idx = 0; pde_idx < 512; pde_idx++) {
                uint64_t pde = pd_table[pde_idx];
                if (!(pde & 1)) continue;

                uint64_t base_va = base_va_lvl3 |
                                   ((uint64_t)pde_idx << 21);

                if (pde & (1ULL << 7)) {
                    /* 2 MiB huge page → emit 512 × 4 KiB */
                    uint64_t page_phys = pde & 0x000FFFFFFFE00000ULL;
                    for (int k = 0; k < 512; k++) {
                        uint64_t va = base_va | ((uint64_t)k << 12);
                        if (va < WTE_VA_LOW_GUARD) continue;
                        if (va >= high_guard) continue;
                        uint64_t gfn = (page_phys + ((uint64_t)k << 12)) >> 12;
                        fn(va, gfn, gfn << 12, ctx);
                    }
                } else {
                    uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
                    uint64_t pt_table[512];
                    cpu_physical_memory_read(pt_base, pt_table, 4096);

                    for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                        uint64_t pte = pt_table[pte_idx];
                        if (!(pte & 1)) continue;

                        uint64_t va = base_va | ((uint64_t)pte_idx << 12);
                        if (va < WTE_VA_LOW_GUARD) continue;
                        if (va >= high_guard) continue;

                        uint64_t gfn = (pte & 0x000FFFFFFFFFF000ULL) >> 12;
                        fn(va, gfn, gfn << 12, ctx);
                    }
                }
            }
        }
    }
}

typedef struct {
    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int      nx_count;
    int      total_nx;
    int      skipped_pe;
} wte_protect_ctx_t;

static void wte_protect_visit(uint64_t va, uint64_t gfn, uint64_t gpa,
                              void *ctx_)
{
    (void)gpa;
    wte_protect_ctx_t *ctx = ctx_;

    if (va >= wte_state.pe_base_va && va < wte_state.pe_end_va) {
        ctx->skipped_pe++;
        return;
    }

    ctx->nx_batch[ctx->nx_count++] = gfn;
    ctx->total_nx++;
    if (ctx->nx_count >= WTE_MAX_BATCH_GFNS) {
        wte_kvm_set_nx(ctx->nx_batch, ctx->nx_count);
        ctx->nx_count = 0;
    }
}

void wte_protect_all_user_pages(CPUState *cpu, uint64_t cr3)
{
    wte_protect_ctx_t pctx = { 0 };

    wte_walk_user_pages(cpu, cr3, wte_state.is_64bit,
                        wte_protect_visit, &pctx);

    if (pctx.nx_count > 0)
        wte_kvm_set_nx(pctx.nx_batch, pctx.nx_count);

    nyx_printf("[WtE][GLOBAL-NX] (%s) Set X=0 on %d non-PE user pages "
               "(%d PE pages skipped)\n",
               wte_state.is_64bit ? "64-bit" : "32-bit",
               pctx.total_nx, pctx.skipped_pe);
}

/* ── Periodic re-scan: NX newly allocated user pages ─────────────
 *
 * Called every N VM exits from kvm-all.c.  Re-walks the target CR3
 * page table and sets NX on any user page that wasn't present at
 * the initial WTE_SETUP scan.
 */
typedef struct {
    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int      nx_count;
    int      new_nx;
    int      rescan_call_count;
} wte_rescan_ctx_t;

static void wte_rescan_visit(uint64_t va, uint64_t gfn, uint64_t gpa,
                             void *ctx_)
{
    (void)gpa;
    wte_rescan_ctx_t *ctx = ctx_;

    if (va >= wte_state.pe_base_va && va < wte_state.pe_end_va) return;

    /* Skip if already NX-blocked or execution already allowed */
    wte_page_entry_t *entry = wte_lookup_gfn(gfn);
    if (entry && (entry->flags & (WTE_PAGE_X_BLOCKED |
                                  WTE_PAGE_X_ALLOWED))) return;

    /* Apply NX only.  Do NOT create tracking entries or set IS_DYNAMIC here.
     *
     * IS_DYNAMIC is set exclusively by wte_register_dynamic_exec_region
     * (called from NtAllocate/NtProtect api_hooks) and by the late-bind
     * path in wte_handle_exec_violation for pages in registered dyn_ranges.
     *
     * Creating IS_DYNAMIC entries during rescan is unreliable: the DLL list
     * may be stale or the enumeration context incorrect (rescan fires from
     * arbitrary VM exits, not necessarily the target-process context).
     * This caused DLL pages loaded after the initial enumeration to receive
     * IS_DYNAMIC and then generate spurious WtE events.
     *
     * Pages NX'd here without a tracking entry hit the "untracked GFN →
     * allow execution" fast path in wte_handle_exec_violation. */
    if (entry)
        entry->flags |= WTE_PAGE_X_BLOCKED;

    ctx->nx_batch[ctx->nx_count++] = gfn;
    ctx->new_nx++;
    if (ctx->nx_count >= WTE_MAX_BATCH_GFNS) {
        wte_kvm_set_nx(ctx->nx_batch, ctx->nx_count);
        ctx->nx_count = 0;
    }
}

void wte_rescan_user_pages(CPUState *cpu)
{
    if (!wte_state.active) return;

    /* Only rescan when running in a context where target CR3 is valid */
    uint64_t cr3 = wte_state.target_cr3;
    if (cr3 == 0) return;

    /* Ensure DLL list is populated before the walk so wte_rescan_visit can
     * skip DLL pages.  Without this, the per-page DLL check loops zero times
     * and every page (including DLL pages) gets marked IS_DYNAMIC. */
    if (wte_state.dll_filter_enabled && wte_state.dll_module_count == 0)
        wte_enumerate_dlls(cpu);

    static int rescan_call_count = 0;
    static int total_user_pages_seen = 0;
    rescan_call_count++;

    wte_rescan_ctx_t rctx = {
        .nx_count          = 0,
        .new_nx            = 0,
        .rescan_call_count = rescan_call_count,
    };

    wte_walk_user_pages(cpu, cr3, wte_state.is_64bit,
                        wte_rescan_visit, &rctx);

    if (rctx.nx_count > 0) wte_kvm_set_nx(rctx.nx_batch, rctx.nx_count);

    total_user_pages_seen += rctx.new_nx;

    if (rctx.new_nx > 0) {
        nyx_printf("[WtE][RESCAN] (%s) #%d: NX applied to %d new user pages "
                   "(total tracked: %d)\n",
                   wte_state.is_64bit ? "64-bit" : "32-bit",
                   rescan_call_count, rctx.new_nx, total_user_pages_seen);
    }

    /* Diagnostic: count all dynamic (non-PE) tracked pages */
    if ((rescan_call_count % 100) == 1) {
        int dyn_total = 0, dyn_blocked = 0, dyn_allowed = 0;
        GHashTableIter diag_iter;
        gpointer dkey, dval;
        g_hash_table_iter_init(&diag_iter, wte_state.page_table);
        while (g_hash_table_iter_next(&diag_iter, &dkey, &dval)) {
            wte_page_entry_t *e = dval;
            if (!(e->flags & WTE_PAGE_IS_DYNAMIC)) continue;
            dyn_total++;
            if (e->flags & WTE_PAGE_X_BLOCKED) dyn_blocked++;
            if (e->flags & WTE_PAGE_X_ALLOWED) dyn_allowed++;
        }
        if (dyn_total > 0) {
            nyx_printf("[WtE][RESCAN-DIAG] #%d: dynamic pages: "
                       "%d total, %d NX-blocked, %d allowed\n",
                       rescan_call_count, dyn_total, dyn_blocked, dyn_allowed);
        }
    }
}

/* ── Write Violation Handler (EPT W=0) ────────────────────────── */

void wte_handle_write_violation(uint64_t gfn, uint64_t gpa,
                                uint64_t rip, CPUState *cpu)
{
    if (!wte_state.active) {
        wte_kvm_clear_wp(&gfn, 1);
        return;
    }

    wte_state.total_w_violations++;

    /* Find the VA for this GFN by checking PE mappings */
    uint64_t fault_va = 0;
    for (int i = 0; i < wte_state.pe_page_count; i++) {
        if (wte_state.pe_gfns[i] == gfn) {
            fault_va = wte_state.pe_vas[i];
            break;
        }
    }

    /* If not found in PE mappings, try reverse lookup from page table */
    if (fault_va == 0) {
        wte_page_entry_t *by_gfn = wte_lookup_gfn(gfn);
        if (by_gfn) {
            fault_va = by_gfn->va;
        }
    }

    if (fault_va == 0) {
        /* Unknown GFN — just clear WP and continue */
        nyx_printf("[WtE][WRITE] Unknown GFN=0x%lx RIP=0x%lx, clearing WP\n",
                   (unsigned long)gfn, (unsigned long)rip);
        wte_kvm_clear_wp(&gfn, 1);
        return;
    }

    wte_page_entry_t *entry = wte_lookup_or_create_va(fault_va, gfn);

    /* Mark as written */
    entry->flags |= WTE_PAGE_WRITTEN;
    entry->write_count++;
    entry->gfn = gfn;
    entry->gpa = gpa & ~0xFFFULL;

    /* Read pre-write content (write hasn't happened yet — EPT trapped
     * BEFORE the instruction completed) */
    cpu_physical_memory_read(entry->gpa, entry->current, WTE_PAGE_SIZE);

    uint64_t rip_page = rip & ~0xFFFULL;
    bool same_page = (rip_page == fault_va);

    nyx_printf("[WtE][WRITE] VA=0x%lx GFN=0x%lx RIP=0x%lx (write #%d%s)\n",
               (unsigned long)fault_va, (unsigned long)gfn,
               (unsigned long)rip, entry->write_count,
               same_page ? " SAME-PAGE" : "");

    /* Allow write: W=1 */
    wte_kvm_clear_wp(&gfn, 1);
    entry->flags &= ~WTE_PAGE_W_PROTECTED;

    if (same_page) {
        /* Same-page self-modifying code: the writing instruction is on
         * the same page it's writing to. Setting X=0 would prevent the
         * instruction from executing, so the write never completes.
         *
         * Solution: W=1+X=1 temporarily, arm MTF to confirm write
         * completion, then re-arm W=0. X=0 is NOT set — allows
         * multiple writes before execute. DEFERRED flag enables
         * diff-based WtE detection at the next VM exit. */
        if (entry->flags & WTE_PAGE_X_BLOCKED) {
            wte_kvm_clear_nx(&gfn, 1);
            entry->flags &= ~WTE_PAGE_X_BLOCKED;
        }
        entry->flags |= WTE_PAGE_DEFERRED;
        entry->last_write_rip = rip;

        /* Arm MTF to confirm write and re-arm W=0 after completion.
         * Skip only if an API hook is mid single-step (api_hook_step_idx is
         * zero-initialised and only set under api_hook_mode, so test the mode
         * too — a bare "< 0" check would block MTF whenever no API hooks
         * exist). */
        if (!GET_GLOBAL_STATE()->api_hook_mode ||
            GET_GLOBAL_STATE()->api_hook_step_idx < 0) {
            wte_state.mtf_active     = true;
            wte_state.mtf_target_va  = fault_va;
            wte_state.mtf_target_gfn = gfn;
            kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_MTF);
        }
    } else {
        /* Different page: standard path. Set X=0 to catch subsequent
         * execution on the written page. */
        if (!(entry->flags & WTE_PAGE_X_BLOCKED)) {
            wte_kvm_set_nx(&gfn, 1);
            entry->flags |= WTE_PAGE_X_BLOCKED;
        }
    }
}

/* ── MTF Handler (same-page write confirmation) ─────────────── */

void wte_handle_mtf(CPUState *cpu)
{
    if (!wte_state.active || !wte_state.mtf_active) return;

    /* JIT tap re-arm takes priority — check reason field */
    if (wte_state.mtf_reason == WTE_MTF_REASON_JIT_REARM) {
        wte_jit_tap_handle_mtf(cpu);
        return;
    }

    uint64_t gfn = wte_state.mtf_target_gfn;
    uint64_t va  = wte_state.mtf_target_va;

    wte_state.mtf_active  = false;
    wte_state.mtf_reason  = WTE_MTF_REASON_WRITE;

    wte_page_entry_t *entry = wte_lookup_va(va);
    if (!entry) return;

    /* Write instruction completed. Re-arm W=0 so the next write to
     * this page causes another W violation (enabling multi-write
     * tracking). Do NOT set X=0 — execution must continue on this
     * page for subsequent write instructions. */
    wte_kvm_set_wp(&gfn, 1);
    entry->flags |= WTE_PAGE_W_PROTECTED;

    nyx_printf("[WtE][MTF] Write confirmed VA=0x%lx, W=0 re-armed\n",
               (unsigned long)va);
}

/* ── Thread ID helper ────────────────────────────────────────── */

/*
 * Read the Windows Thread ID from the current thread's TEB.
 *   64-bit: GS.base = TEB, ClientId.UniqueThread at TEB+0x48
 *   32-bit: FS.base = TEB, ClientId.UniqueThread at TEB+0x24
 * Returns 0 on read failure (never returns garbage).
 */
static uint32_t wte_get_thread_id(CPUState *cpu)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;

    if (wte_state.is_64bit) {
        uint64_t teb = env->segs[R_GS].base;
        uint64_t tid64 = 0;
        if (!read_virtual_memory(teb + 0x48, (uint8_t *)&tid64, 8, cpu))
            return 0;
        return (uint32_t)tid64;
    } else {
        uint32_t teb = (uint32_t)env->segs[R_FS].base;
        uint32_t tid = 0;
        if (!read_virtual_memory((uint64_t)(teb + 0x24), (uint8_t *)&tid, 4, cpu))
            return 0;
        return tid;
    }
}

/* ── Deferred Verification (same-page self-modifying code) ────── */

void wte_check_deferred_pages(CPUState *cpu)
{
    if (!wte_state.active || !wte_state.page_table) return;

    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, wte_state.page_table);

    while (g_hash_table_iter_next(&iter, &key, &value)) {
        wte_page_entry_t *entry = value;

        if (!(entry->flags & WTE_PAGE_DEFERRED)) continue;

        /* Page was left open (W=1+X=1) for same-page self-modifying code.
         * Now re-read content and check if anything actually changed. */
        entry->flags &= ~WTE_PAGE_DEFERRED;

        cpu_physical_memory_read(entry->gpa, entry->current, WTE_PAGE_SIZE);
        wte_compute_diff(entry);

        if (entry->diff_count > 0) {
            /* Real change detected — WtE on same-page self-modifying code */
            wte_state.wte_count++;
            wte_state.total_wte_count++;

            nyx_printf("[WtE][DEFERRED-DETECT] VA=0x%lx GFN=0x%lx diffs=%d "
                       "write_rip=0x%lx\n",
                       (unsigned long)entry->va, (unsigned long)entry->gfn,
                       entry->diff_count,
                       (unsigned long)entry->last_write_rip);

            /* Full process memory dump (incremental — only changed pages) */
            {
                X86CPU *cpux86 = X86_CPU(cpu);
                CPUX86State *env = &cpux86->env;
                char wte_label[128];
                uint32_t _tid = wte_get_thread_id(cpu);
                snprintf(wte_label, sizeof(wte_label),
                         "wte_rip0x%lx_va0x%lx_tid0x%08x",
                         (unsigned long)entry->last_write_rip,
                         (unsigned long)entry->va, _tid);
                uint64_t _teb = wte_state.is_64bit
                    ? env->segs[R_GS].base
                    : (uint64_t)(uint32_t)env->segs[R_FS].base;
                wte_dump_event_t evt = {
                    .type            = "DEFERRED",
                    .rip             = entry->last_write_rip,
                    .va              = entry->va,
                    .gfn             = entry->gfn,
                    .fs_base         = _teb,
                    .diff_count      = entry->diff_count,
                    .wte_count       = wte_state.wte_count,
                    .total_wte_count = wte_state.total_wte_count,
                };
                dump_full_process_memory(cpu, env, wte_label, &evt, 0);
            }

            /* Rescan after deferred WtE dump too */
            wte_rescan_user_pages(cpu);

            /* Update baseline for next change detection */
            memcpy(entry->baseline, entry->current, WTE_PAGE_SIZE);
        }

        /* Re-protect: W=0 + X=0 for next cycle */
        entry->flags &= ~WTE_PAGE_WRITTEN;
        entry->write_count = 0;

        uint64_t gfn = entry->gfn;
        wte_kvm_set_wp(&gfn, 1);
        entry->flags |= WTE_PAGE_W_PROTECTED;
        wte_kvm_set_nx(&gfn, 1);
        entry->flags |= WTE_PAGE_X_BLOCKED;
        entry->flags &= ~WTE_PAGE_X_ALLOWED;
    }
}

/* ── DLL Module Enumeration (PEB→Ldr walk) ─────────────────────── */

static void wte_read_name(CPUState *cpu, uint64_t buf, uint16_t len,
                          char *out, int out_max)
{
    memset(out, 0, out_max);
    if (len == 0 || buf == 0) return;
    int nchars = (len / 2 < out_max - 1) ? len / 2 : out_max - 1;
    uint16_t wbuf[WTE_DLL_NAME_LEN];
    memset(wbuf, 0, sizeof(wbuf));
    read_virtual_memory(buf, (uint8_t *)wbuf, nchars * 2, cpu);
    for (int c = 0; c < nchars; c++)
        out[c] = (char)(wbuf[c] & 0xFF);
}

/*
 * Bitness-aware PEB→Ldr→InMemoryOrderModuleList walk.
 *
 * 64-bit offsets (cur = &LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks):
 *   cur+0x20 = DllBase (8B), cur+0x30 = SizeOfImage (4B),
 *   cur+0x48 = BaseDllName.Length (2B), cur+0x50 = BaseDllName.Buffer (8B)
 *
 * 32-bit offsets (cur = &LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks):
 *   cur+0x10 = DllBase (4B), cur+0x18 = SizeOfImage (4B),
 *   cur+0x24 = BaseDllName.Length (2B), cur+0x28 = BaseDllName.Buffer (4B)
 */

int wte_walk_module_list(CPUState *cpu, wte_dll_entry_t *out, int max)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;
    int count = 0;

    if (wte_state.is_64bit) {
        uint64_t teb = env->segs[R_GS].base;
        uint64_t peb = 0, ldr = 0;
        if (!read_virtual_memory(teb + 0x60, (uint8_t *)&peb, 8, cpu) || peb == 0) {
            nyx_printf("[WtE][DLL] Failed to read PEB64 (GS=0x%lx)\n",
                       (unsigned long)teb);
            return 0;
        }
        if (!read_virtual_memory(peb + 0x18, (uint8_t *)&ldr, 8, cpu) || ldr == 0) {
            nyx_printf("[WtE][DLL] Failed to read PEB64->Ldr\n");
            return 0;
        }
        uint64_t list_head = ldr + 0x20;
        uint64_t cur = 0;
        read_virtual_memory(list_head, (uint8_t *)&cur, 8, cpu);

        while (cur != 0 && cur != list_head && count < max) {
            uint64_t dll_base = 0; uint32_t dll_size = 0;
            uint16_t name_len = 0; uint64_t name_buf = 0;
            read_virtual_memory(cur + 0x20, (uint8_t *)&dll_base, 8, cpu);
            read_virtual_memory(cur + 0x30, (uint8_t *)&dll_size, 4, cpu);
            read_virtual_memory(cur + 0x48, (uint8_t *)&name_len, 2, cpu);
            read_virtual_memory(cur + 0x50, (uint8_t *)&name_buf, 8, cpu);
            if (dll_base != 0 && dll_size != 0) {
                wte_read_name(cpu, name_buf, name_len,
                              out[count].name, WTE_DLL_NAME_LEN);
                out[count].base = dll_base;
                out[count].end  = dll_base + dll_size;
                count++;
            }
            uint64_t next = 0;
            if (!read_virtual_memory(cur, (uint8_t *)&next, 8, cpu)) break;
            if (next == cur) break;
            cur = next;
        }
    } else {
        uint32_t teb = (uint32_t)(env->segs[R_FS].base);
        uint32_t peb = 0, ldr = 0;
        if (!read_virtual_memory((uint64_t)(teb + 0x30),
                                  (uint8_t *)&peb, 4, cpu) || peb == 0) {
            nyx_printf("[WtE][DLL] Failed to read PEB32 (FS=0x%x)\n", teb);
            return 0;
        }
        if (!read_virtual_memory((uint64_t)(peb + 0x0C),
                                  (uint8_t *)&ldr, 4, cpu) || ldr == 0) {
            nyx_printf("[WtE][DLL] Failed to read PEB32->Ldr\n");
            return 0;
        }
        uint32_t list_head = ldr + 0x14;
        uint32_t cur = 0;
        read_virtual_memory((uint64_t)list_head, (uint8_t *)&cur, 4, cpu);

        while (cur != 0 && cur != list_head && count < max) {
            uint32_t dll_base = 0, dll_size = 0;
            uint16_t name_len = 0; uint32_t name_buf = 0;
            read_virtual_memory((uint64_t)(cur + 0x10), (uint8_t *)&dll_base, 4, cpu);
            read_virtual_memory((uint64_t)(cur + 0x18), (uint8_t *)&dll_size, 4, cpu);
            read_virtual_memory((uint64_t)(cur + 0x24), (uint8_t *)&name_len, 2, cpu);
            read_virtual_memory((uint64_t)(cur + 0x28), (uint8_t *)&name_buf, 4, cpu);
            if (dll_base != 0 && dll_size != 0) {
                wte_read_name(cpu, (uint64_t)name_buf, name_len,
                              out[count].name, WTE_DLL_NAME_LEN);
                out[count].base = dll_base;
                out[count].end  = dll_base + dll_size;
                count++;
            }
            uint32_t next = 0;
            if (!read_virtual_memory((uint64_t)cur, (uint8_t *)&next, 4, cpu)) break;
            if (next == cur) break;
            cur = next;
        }
    }

    return count;
}

void wte_enumerate_dlls(CPUState *cpu)
{
    wte_dll_entry_t raw[WTE_MAX_DLL_MODULES];
    int total = wte_walk_module_list(cpu, raw, WTE_MAX_DLL_MODULES);

    wte_state.dll_module_count = 0;
    for (int i = 0; i < total; i++) {
        bool is_target = (raw[i].base >= wte_state.pe_base_va &&
                          raw[i].base < wte_state.pe_end_va);
        if (!is_target)
            wte_state.dll_modules[wte_state.dll_module_count++] = raw[i];
    }

    nyx_printf("[WtE][DLL] Enumerated %d modules (excluding target PE)\n",
               wte_state.dll_module_count);
    for (int i = 0; i < wte_state.dll_module_count; i++) {
        nyx_printf("[WtE][DLL]   %-30s 0x%016lx - 0x%016lx\n",
                   wte_state.dll_modules[i].name,
                   (unsigned long)wte_state.dll_modules[i].base,
                   (unsigned long)wte_state.dll_modules[i].end);
    }

    /* JIT tap: if not yet armed, scan newly enumerated list for clrjit.dll.
     * Catches the case where clrjit.dll was already loaded before the first
     * api_hook LdrLoadDll callback fires (e.g. early DLL injection). */
    if (!wte_state.jit_tap.enabled) {
        for (int i = 0; i < wte_state.dll_module_count; i++) {
            wte_jit_tap_on_dll_load(cpu,
                                    wte_state.dll_modules[i].base,
                                    wte_state.dll_modules[i].end,
                                    wte_state.dll_modules[i].name);
            if (wte_state.jit_tap.enabled) break;
        }
    }
}

/*
 * Check if RIP falls within a known DLL module.
 * On first call (empty list) or when RIP is in an unknown region,
 * re-scans PEB→Ldr to pick up dynamically loaded DLLs.
 */
bool wte_is_dll_rip(uint64_t rip, CPUState *cpu)
{
    /* Quick check against current module list */
    for (int i = 0; i < wte_state.dll_module_count; i++) {
        if (rip >= wte_state.dll_modules[i].base &&
            rip < wte_state.dll_modules[i].end) {
            return true;
        }
    }

    /* RIP not in any known DLL. If it's in the target PE, it's not a DLL. */
    if (rip >= wte_state.pe_base_va && rip < wte_state.pe_end_va) {
        return false;
    }

    /* Unknown region — re-scan PEB→Ldr to catch newly loaded DLLs.
     * Rate-limit: skip re-scan if we already re-scanned recently
     * (within last 100 wte_is_dll_rip calls with unknown RIP). */
    static int unknown_rip_since_rescan = 0;
    unknown_rip_since_rescan++;
    if (unknown_rip_since_rescan > 1 && unknown_rip_since_rescan < 100) {
        return false;
    }
    unknown_rip_since_rescan = 0;

    int old_count = wte_state.dll_module_count;
    wte_enumerate_dlls(cpu);

    if (wte_state.dll_module_count != old_count) {
        nyx_printf("[WtE][DLL] Re-scan: module count %d → %d\n",
                   old_count, wte_state.dll_module_count);

        /* wte_enumerate_dlls rebuilds the full list from scratch,
         * so re-check the entire list (not just new entries). */
        for (int i = 0; i < wte_state.dll_module_count; i++) {
            if (rip >= wte_state.dll_modules[i].base &&
                rip < wte_state.dll_modules[i].end) {
                return true;
            }
        }
    }

    /* Still not in any DLL — dynamic allocation, not a DLL */
    return false;
}

/* ── Execute Violation Handler (EPT X=0) ──────────────────────── */

void wte_handle_exec_violation(uint64_t gfn, uint64_t gpa,
                               uint64_t rip, CPUState *cpu)
{
    if (!wte_state.active) {
        wte_kvm_clear_nx(&gfn, 1);
        return;
    }

    /* JIT tap: check before WTE path so tap pages aren't cleared as
     * "untracked GFN" (clrjit pages are not in the PE/dyn tracking). */
    if (wte_jit_tap_handle_exec(cpu, gfn, gpa, rip))
        return;

    wte_state.total_x_violations++;

    /* Skip kernel-mode RIP — do NOT re-NX kernel pages (infinite loop) */
    if (rip >= 0xFFFF800000000000ULL) {
        wte_kvm_clear_nx(&gfn, 1);
        return;
    }

    nyx_printf("[WtE][EXEC] GFN=0x%lx GPA=0x%lx RIP=0x%lx\n",
               (unsigned long)gfn, (unsigned long)gpa, (unsigned long)rip);

    /* Lazy install API hooks: WTE_SETUP runs in harness (64-bit) context
     * where PEB→Ldr walk fails to enumerate the target's 32-bit modules.
     * On the first exec violation the target packer is on-CPU, so the
     * 32-bit PEB is reachable and ntdll can be discovered for install. */
    nyx_api_hook_try_install_lazy(cpu);

    /* Try to find page entry by GFN → VA lookup */
    uint64_t page_va = 0;
    wte_page_entry_t *entry = NULL;

    /* Check PE mappings first */
    for (int i = 0; i < wte_state.pe_page_count; i++) {
        if (wte_state.pe_gfns[i] == gfn) {
            page_va = wte_state.pe_vas[i];
            break;
        }
    }

    if (page_va != 0) {
        entry = wte_lookup_va(page_va);
    }

    /* Fallback: search by GFN in all tracked pages */
    if (!entry) {
        entry = wte_lookup_gfn(gfn);
        if (entry) page_va = entry->va;
    }

    /* VA-based detection: RIP in PE range but GFN not tracked (CoW) */
    if (!entry && wte_state.pe_base_va != 0 &&
        rip >= wte_state.pe_base_va && rip < wte_state.pe_end_va) {
        page_va = rip & ~0xFFFULL;
        entry = wte_lookup_or_create_va(page_va, gfn);
        entry->flags |= WTE_PAGE_IS_PE | WTE_PAGE_WRITTEN;
        entry->gpa = gpa & ~0xFFFULL;

        cpu_physical_memory_read(entry->gpa, entry->baseline, WTE_PAGE_SIZE);
        entry->baseline_valid = true;
        cpu_physical_memory_read(entry->gpa, entry->current, WTE_PAGE_SIZE);
        wte_compute_diff(entry);

        nyx_printf("[WtE][VA-DETECT] Untracked GFN=0x%lx but RIP=0x%lx "
                   "in PE range — CoW suspected\n",
                   (unsigned long)gfn, (unsigned long)rip);
    }

    if (!entry) {
        /* Late-bind for dynamic ranges that were unmapped at api_hook
         * register time (lazy MEM_COMMIT — pages backed only on first
         * access).  If RIP falls into a recorded NtAllocate/NtProtect
         * range, create the entry now and continue with WtE detection. */
        bool in_dyn_range = false;
        for (int r = 0; r < wte_state.dyn_range_count; r++) {
            if (rip >= wte_state.dyn_ranges[r].base &&
                rip <  wte_state.dyn_ranges[r].end) {
                in_dyn_range = true;
                break;
            }
        }
        if (in_dyn_range) {
            page_va = rip & ~0xFFFULL;
            entry = wte_lookup_or_create_va(page_va, gfn);
            entry->gpa = gpa & ~0xFFFULL;
            entry->flags |= WTE_PAGE_IS_DYNAMIC | WTE_PAGE_WRITTEN;
            memset(entry->baseline, 0, WTE_PAGE_SIZE);
            entry->baseline_valid = true;
            cpu_physical_memory_read(entry->gpa, entry->current,
                                     WTE_PAGE_SIZE);
            nyx_printf("[WtE][LATE-BIND] dyn-range hit: VA=0x%lx GFN=0x%lx "
                       "RIP=0x%lx — tracking now\n",
                       (unsigned long)page_va, (unsigned long)gfn,
                       (unsigned long)rip);
            /* fall through to WRITTEN branch below */
        } else {
            /* Completely unknown page — just allow execution */
            nyx_printf("[WtE][EXEC] Untracked GFN=0x%lx RIP=0x%lx, allowing\n",
                       (unsigned long)gfn, (unsigned long)rip);
            wte_kvm_clear_nx(&gfn, 1);
            return;
        }
    }

    /* Check if this page was written */
    if (entry->flags & WTE_PAGE_WRITTEN) {
        /* Re-read current content for accurate diff */
        cpu_physical_memory_read(entry->gpa, entry->current, WTE_PAGE_SIZE);
        wte_compute_diff(entry);

        if (entry->diff_count == 0) {
            /* No actual content change — false positive (EPT trapped
             * the write BEFORE it completed, or same value written).
             * For PE pages, re-protect W=0 so subsequent real writes
             * (e.g., packer decryption after CoW copy) are still caught. */
            nyx_printf("[WtE][EXEC] False positive (no diff): VA=0x%lx\n",
                       (unsigned long)entry->va);
            entry->flags &= ~WTE_PAGE_WRITTEN;
            wte_kvm_clear_nx(&gfn, 1);
            entry->flags &= ~WTE_PAGE_X_BLOCKED;
            entry->flags |= WTE_PAGE_X_ALLOWED;

            if (entry->flags & WTE_PAGE_IS_PE) {
                wte_kvm_set_wp(&gfn, 1);
                entry->flags |= WTE_PAGE_W_PROTECTED;
            }
            return;
        }

        /* Architectural guard: only report WtE on target PE pages or
         * explicitly registered dynamic alloc regions.  Pages tracked via
         * dirty ring alone (IS_PE / IS_DYNAMIC both clear) are DLL / system
         * pages — allow execution silently without triggering a dump. */
        if (!(entry->flags & (WTE_PAGE_IS_PE | WTE_PAGE_IS_DYNAMIC))) {
            nyx_printf("[WtE][EXEC] Non-target page VA=0x%lx skipped "
                       "(not IS_PE/IS_DYNAMIC)\n",
                       (unsigned long)entry->va);
            memcpy(entry->baseline, entry->current, WTE_PAGE_SIZE);
            entry->flags &= ~WTE_PAGE_WRITTEN;
            wte_kvm_clear_nx(&gfn, 1);
            entry->flags &= ~WTE_PAGE_X_BLOCKED;
            entry->flags |= WTE_PAGE_X_ALLOWED;
            return;
        }

        /* Check if the EXECUTED address was actually modified.
         * A page may have diffs (e.g., Themida VM writes data at offset A)
         * but execute at a different offset B that was NOT modified.
         * Only flag WtE when the instruction being executed is in a
         * modified range — this is the true "Written-then-Executed". */
        {
            uint16_t rip_offset = (uint16_t)(rip & 0xFFF);
            /* Check if RIP falls within any diff range.
             * Use a window of 15 bytes (max x86 instruction length). */
            bool rip_in_diff = false;
            for (int d = 0; d < entry->diff_count; d++) {
                uint16_t diff_start = entry->diff_offsets[d];
                uint16_t diff_end   = diff_start + entry->diff_lengths[d];
                /* RIP overlaps diff if instruction window intersects */
                if (rip_offset < diff_end && rip_offset + 15 > diff_start) {
                    rip_in_diff = true;
                    break;
                }
            }

            if (!rip_in_diff) {
                /* Page was modified but NOT at the executed address.
                 * This is NOT WtE — e.g., VM dispatcher writes data
                 * on the same page as code.
                 *
                 * Release this page from tracking: update baseline,
                 * clear WRITTEN, leave W=1 + X=1.  This avoids
                 * repeated VM exits on mixed data+code pages (Themida).
                 * If actual code bytes on this page are modified later,
                 * a future write violation will re-arm tracking. */
                nyx_printf("[WtE][EXEC] Diff exists but RIP=0x%lx (offset 0x%x) "
                           "not in modified range: VA=0x%lx diffs=%d — releasing page\n",
                           (unsigned long)rip, rip_offset,
                           (unsigned long)entry->va, entry->diff_count);
                memcpy(entry->baseline, entry->current, WTE_PAGE_SIZE);
                entry->flags &= ~WTE_PAGE_WRITTEN;

                wte_kvm_clear_nx(&gfn, 1);
                entry->flags &= ~WTE_PAGE_X_BLOCKED;
                entry->flags |= WTE_PAGE_X_ALLOWED;
                /* W=0 is NOT re-set — page stays W=1, X=1 (released) */
                return;
            }
        }

        /* DLL noise filter (module-list based) */
        if (wte_state.dll_filter_enabled && wte_is_dll_rip(rip, cpu)) {
            wte_state.dll_filtered_count++;
            wte_state.dll_filtered_total++;
            wte_state.wte_count++;
            wte_state.total_wte_count++;
            nyx_printf("[WtE][DLL-FILTERED] RIP=0x%lx VA=0x%lx diffs=%d\n",
                       (unsigned long)rip, (unsigned long)entry->va,
                       entry->diff_count);
            memcpy(entry->baseline, entry->current, WTE_PAGE_SIZE);
            entry->flags &= ~WTE_PAGE_WRITTEN;
            wte_kvm_clear_nx(&gfn, 1);
            entry->flags &= ~WTE_PAGE_X_BLOCKED;
            entry->flags |= WTE_PAGE_X_ALLOWED;
            return;
        }

        /* ★ WtE DETECTED — executed address IS in a modified range */
        wte_state.wte_count++;
        wte_state.total_wte_count++;

        /* Full process memory dump (incremental — only changed pages) */
        {
            X86CPU *cpux86 = X86_CPU(cpu);
            CPUX86State *env = &cpux86->env;
            char wte_label[128];
            uint32_t _tid = wte_get_thread_id(cpu);
            snprintf(wte_label, sizeof(wte_label),
                     "wte_rip0x%lx_va0x%lx_tid0x%08x",
                     (unsigned long)rip,
                     (unsigned long)entry->va, _tid);
            uint64_t _teb = wte_state.is_64bit
                ? env->segs[R_GS].base
                : (uint64_t)(uint32_t)env->segs[R_FS].base;
            wte_dump_event_t evt = {
                .type            = "EXEC",
                .rip             = rip,
                .va              = entry->va,
                .gfn             = entry->gfn,
                .fs_base         = _teb,
                .diff_count      = entry->diff_count,
                .wte_count       = wte_state.wte_count,
                .total_wte_count = wte_state.total_wte_count,
            };
            dump_full_process_memory(cpu, env, wte_label, &evt, 0);
        }

        /* Phase 4: post-WtE rescan removed.  api_hook NtAllocate/NtProtect
         * callbacks register dynamic regions deterministically when the
         * packer allocates/promotes them, so the rescan-as-catchup pattern
         * is no longer needed. */

        /* Post-detection: update baseline, re-protect for next layer.
         * RIP-in-diff check above prevents tight loops on VM dispatchers,
         * so immediate W=0 re-protect is safe here. */
        memcpy(entry->baseline, entry->current, WTE_PAGE_SIZE);
        entry->flags &= ~WTE_PAGE_WRITTEN;
        entry->write_count = 0;

        /* Allow execution (X=1), re-protect write (W=0) */
        wte_kvm_clear_nx(&gfn, 1);
        entry->flags &= ~WTE_PAGE_X_BLOCKED;
        entry->flags |= WTE_PAGE_X_ALLOWED;

        if (entry->flags & WTE_PAGE_IS_PE) {
            wte_kvm_set_wp(&gfn, 1);
            entry->flags |= WTE_PAGE_W_PROTECTED;
        }
    } else {
        /* Not written — first-time execution (DLL, system code, etc.) */
        entry->flags |= WTE_PAGE_X_ALLOWED;
        entry->flags &= ~WTE_PAGE_X_BLOCKED;
        wte_kvm_clear_nx(&gfn, 1);

        /* If this is an unknown dynamic region, start write tracking */
        bool is_known = (entry->flags & WTE_PAGE_IS_PE) ||
                        (entry->flags & WTE_PAGE_IS_DYNAMIC);

        /* VA-range check first (no rate-limit); fall back to RIP-based
         * check (wte_is_dll_rip includes lazy re-enumerate for new DLLs). */
        bool in_dll = false;
        if (wte_state.dll_filter_enabled) {
            for (int d = 0; d < wte_state.dll_module_count; d++) {
                if (entry->va >= wte_state.dll_modules[d].base &&
                    entry->va <  wte_state.dll_modules[d].end) {
                    in_dll = true;
                    break;
                }
            }
            if (!in_dll)
                in_dll = wte_is_dll_rip(rip, cpu);
        }

        if (!is_known && !in_dll) {
            nyx_printf("[WtE][DYN-EXEC] New execution region: VA=0x%lx "
                       "GFN=0x%lx RIP=0x%lx\n",
                       (unsigned long)entry->va, (unsigned long)gfn,
                       (unsigned long)rip);
            entry->flags |= WTE_PAGE_IS_DYNAMIC;

            /* Set W=0 on this page to catch future writes */
            wte_kvm_set_wp(&gfn, 1);
            entry->flags |= WTE_PAGE_W_PROTECTED;
        }
    }
}

/* ── Dirty Ring Scan (supplementary, non-PE pages) ─────────────── */

void wte_scan_dirty_ring(void)
{
    if (!wte_state.active || !kvm_dirty_gfns) {
        return;
    }

    /* Process re-NX queue first */
    if (wte_state.renx_count > 0) {
        uint64_t renx_batch[WTE_MAX_BATCH_GFNS];
        int renx_batch_count = 0;

        for (int i = 0; i < wte_state.renx_count; i++) {
            renx_batch[renx_batch_count++] = wte_state.renx_queue[i];
            if (renx_batch_count >= WTE_MAX_BATCH_GFNS) {
                wte_kvm_set_nx(renx_batch, renx_batch_count);
                renx_batch_count = 0;
            }
        }
        if (renx_batch_count > 0) {
            wte_kvm_set_nx(renx_batch, renx_batch_count);
        }
        wte_state.renx_count = 0;
    }

    /* Scan dirty ring for non-PE dirty pages.
     * PE pages are handled by EPT W=0 (primary path), so we only
     * need to track non-PE pages via dirty ring for supplementary
     * WtE detection on dynamically allocated memory. */
    uint32_t scan_idx = wte_state.last_scanned_ring_index;
    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int      nx_batch_count = 0;

    while (true) {
        uint32_t ring_idx = scan_idx & kvm_dirty_gfns_index_mask;
        struct kvm_dirty_gfn *ring_entry = &kvm_dirty_gfns[ring_idx];

        if ((ring_entry->flags & 0x1) == 0) {
            break;
        }

        uint64_t gfn = ring_entry->offset;

        /* Skip low system pages */
        if (gfn <= 0x10) {
            scan_idx++;
            continue;
        }

        /* Skip GFNs that belong to PE (already handled by EPT W=0) */
        bool is_pe_gfn = false;
        for (int i = 0; i < wte_state.pe_page_count; i++) {
            if (wte_state.pe_gfns[i] == gfn) {
                is_pe_gfn = true;
                break;
            }
        }

        if (!is_pe_gfn) {
            /* Non-PE dirty page — track it with NX for supplementary WtE.
             * Skip known DLL GFN ranges to avoid massive VM exit overhead
             * from NX on system DLL pages (the reason this was disabled). */
            uint64_t gpa_check = gfn << 12;

            /* Heuristic: DLL pages are typically mapped at high GPA ranges
             * corresponding to system DLL VAs (0x70000000+).  We skip these
             * to avoid the VM exit storm that caused the original disable.
             * Dynamic alloc by packers (VirtualAlloc) uses lower GPAs.
             * Note: GPA != GVA, but for user-mode with identity-ish mapping
             * in early boot, the GFN range is a reasonable heuristic.
             * Exec violations on these pages will still be caught by the
             * DLL filter in wte_handle_exec_violation. */
            bool skip_as_likely_dll = false;
            if (wte_state.dll_filter_enabled && wte_state.dll_module_count > 0) {
                /* Check if this GFN's pseudo-VA falls in any known DLL range */
                for (int d = 0; d < wte_state.dll_module_count; d++) {
                    if (gpa_check >= wte_state.dll_modules[d].base &&
                        gpa_check <  wte_state.dll_modules[d].end) {
                        skip_as_likely_dll = true;
                        break;
                    }
                }
            }
            if (skip_as_likely_dll) {
                scan_idx++;
                continue;
            }

            wte_page_entry_t *entry = wte_lookup_gfn(gfn);
            if (!entry) {
                /* New non-PE dirty page — we don't know the VA,
                 * so create a temporary entry keyed by GPA.
                 * The VA will be determined at execute violation time. */
                uint64_t pseudo_va = gfn << 12;  /* use GPA as pseudo-VA */
                entry = wte_lookup_or_create_va(pseudo_va, gfn);
                entry->gpa = gfn << 12;
                entry->flags |= WTE_PAGE_WRITTEN;

                /* Read baseline and current */
                if (fast_reload_root_created(get_fast_reload_snapshot())) {
                    if (!read_snapshot_memory(get_fast_reload_snapshot(),
                                             entry->gpa, entry->baseline,
                                             WTE_PAGE_SIZE)) {
                        cpu_physical_memory_read(entry->gpa, entry->baseline,
                                                WTE_PAGE_SIZE);
                    }
                } else {
                    cpu_physical_memory_read(entry->gpa, entry->baseline,
                                            WTE_PAGE_SIZE);
                }
                entry->baseline_valid = true;
                cpu_physical_memory_read(entry->gpa, entry->current,
                                        WTE_PAGE_SIZE);
                wte_compute_diff(entry);
            } else {
                /* Existing page — update content */
                entry->flags |= WTE_PAGE_WRITTEN;
                cpu_physical_memory_read(entry->gpa, entry->current,
                                        WTE_PAGE_SIZE);
                wte_compute_diff(entry);
            }

            /* Set NX on this dirty non-PE page */
            if (!(entry->flags & WTE_PAGE_X_BLOCKED) &&
                !(entry->flags & WTE_PAGE_X_ALLOWED)) {
                nx_batch[nx_batch_count++] = gfn;
                entry->flags |= WTE_PAGE_X_BLOCKED;

                if (nx_batch_count >= WTE_MAX_BATCH_GFNS) {
                    wte_kvm_set_nx(nx_batch, nx_batch_count);
                    nx_batch_count = 0;
                }
            }
        }

        scan_idx++;
    }

    int total_scanned = scan_idx - wte_state.last_scanned_ring_index;
    wte_state.last_scanned_ring_index = scan_idx;

    if (nx_batch_count > 0) {
        wte_kvm_set_nx(nx_batch, nx_batch_count);
    }

    /* Periodic diagnostic: log every 1000th scan with entries */
    static int scan_call_count = 0;
    scan_call_count++;
    if (total_scanned > 0 && (scan_call_count % 1000 == 1)) {
        nyx_printf("[WtE][DIRTY-DIAG] scan #%d: %d entries, %d NX applied, "
                   "dll_filter=%d dll_modules=%d\n",
                   scan_call_count, total_scanned, nx_batch_count,
                   wte_state.dll_filter_enabled,
                   wte_state.dll_module_count);
    }
}

/* ── Round Management ──────────────────────────────────────────── */

void wte_reset_round(void)
{
    if (!wte_state.active) return;

    nyx_printf("[WtE] Round %d complete: %d WtE (%d DLL-filtered, "
               "%d CoW-recovered)\n",
               wte_state.round, wte_state.wte_count,
               wte_state.dll_filtered_count,
               wte_state.pt_cow_recoveries);

    /* Clear all NX and WP bits */
    GHashTableIter iter;
    gpointer key, value;
    uint64_t clear_nx_batch[WTE_MAX_BATCH_GFNS];
    uint64_t clear_wp_batch[WTE_MAX_BATCH_GFNS];
    int nx_count = 0, wp_count = 0;

    g_hash_table_iter_init(&iter, wte_state.page_table);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        wte_page_entry_t *entry = value;

        if (entry->flags & WTE_PAGE_X_BLOCKED) {
            clear_nx_batch[nx_count++] = entry->gfn;
            if (nx_count >= WTE_MAX_BATCH_GFNS) {
                wte_kvm_clear_nx(clear_nx_batch, nx_count);
                nx_count = 0;
            }
        }
        if (entry->flags & WTE_PAGE_W_PROTECTED) {
            clear_wp_batch[wp_count++] = entry->gfn;
            if (wp_count >= WTE_MAX_BATCH_GFNS) {
                wte_kvm_clear_wp(clear_wp_batch, wp_count);
                wp_count = 0;
            }
        }
    }

    if (nx_count > 0) wte_kvm_clear_nx(clear_nx_batch, nx_count);
    if (wp_count > 0) wte_kvm_clear_wp(clear_wp_batch, wp_count);

    /* Clear page table */
    g_hash_table_remove_all(wte_state.page_table);

    /* Clear in-flight MTF state */
    wte_state.mtf_active     = false;
    wte_state.mtf_reason     = WTE_MTF_REASON_WRITE;
    wte_state.mtf_target_va  = 0;
    wte_state.mtf_target_gfn = 0;

    /* Clear JIT tap EH/pending state */
    if (wte_state.jit_tap.getehinfo_nx_armed) {
        wte_kvm_clear_nx(&wte_state.jit_tap.getehinfo_gfn, 1);
    }
    if (wte_state.jit_tap.eh_return_pending) {
        wte_kvm_clear_nx(&wte_state.jit_tap.eh_return_gfn, 1);
    }
    if (wte_state.jit_tap.pending_il_bytes) {
        free(wte_state.jit_tap.pending_il_bytes);
        wte_state.jit_tap.pending_il_bytes = NULL;
    }
    wte_state.jit_tap.pending_write         = false;
    wte_state.jit_tap.getehinfo_nx_armed    = false;
    wte_state.jit_tap.eh_return_pending     = false;
    wte_state.jit_tap.eh_rearm_pending      = false;
    wte_state.jit_tap.eh_captured           = 0;
    wte_state.jit_tap.eh_expected           = 0;

    /* Reset counters */
    wte_state.round++;
    wte_state.wte_count          = 0;
    wte_state.renx_count         = 0;
    wte_state.dll_filtered_count = 0;
    wte_state.pt_cow_recoveries  = 0;
    wte_state.pt_decode_cursor   = 0;

    wte_state.last_scanned_ring_index = kvm_dirty_gfns_index;

    nyx_printf("[WtE] Round %d started.\n", wte_state.round);
}

/* ── Status / Debug ────────────────────────────────────────────── */

bool wte_is_active(void) { return wte_state.active; }
wte_state_t *wte_get_state(void) { return &wte_state; }

void wte_print_debug_summary(void)
{
    nyx_printf("[WtE][DBG] round=%d wte=%d total=%d "
               "w_violations=%lu x_violations=%lu cow_recoveries=%lu "
               "pages_tracked=%u\n",
               wte_state.round, wte_state.wte_count,
               wte_state.total_wte_count,
               (unsigned long)wte_state.total_w_violations,
               (unsigned long)wte_state.total_x_violations,
               (unsigned long)wte_state.total_cow_recoveries,
               wte_state.page_table ?
                   g_hash_table_size(wte_state.page_table) : 0);
}

/* ── EPROCESS Walking: Find CR3 by PID ────────────────────────── */

#define EPROCESS_OFF_DTB           0x28
#define EPROCESS_OFF_PID           0x440
#define EPROCESS_OFF_LINKS         0x448
#define EPROCESS_OFF_IMAGENAME     0x5A8
#define EPROCESS_WALK_MAX          4096

uint64_t wte_find_cr3_by_pid(CPUState *cpu, uint64_t harness_cr3,
                             uint64_t target_pid)
{
    kvm_arch_get_registers(cpu);
    CPUX86State *env = &(X86_CPU(cpu)->env);

    uint64_t gs_base;
    if ((env->segs[R_CS].selector & 3) == 3) {
        gs_base = env->kernelgsbase;
        nyx_printf("[WtE][CR3] User-mode, using kernelgsbase for KPCR\n");
    } else {
        gs_base = env->segs[R_GS].base;
        nyx_printf("[WtE][CR3] Kernel-mode, using GS base for KPCR\n");
    }

    nyx_printf("[WtE][CR3] Looking up CR3 for PID %lu\n",
               (unsigned long)target_pid);

    uint64_t kthread_ptr = 0;
    if (!read_virtual_memory_cr3(gs_base + 0x188, (uint8_t *)&kthread_ptr,
                                 sizeof(kthread_ptr), cpu, harness_cr3)) {
        nyx_printf("[WtE][CR3] ERROR: Failed to read KPCR.CurrentThread\n");
        return 0;
    }

    uint64_t eprocess_ptr = 0;
    if (!read_virtual_memory_cr3(kthread_ptr + 0x220, (uint8_t *)&eprocess_ptr,
                                 sizeof(eprocess_ptr), cpu, harness_cr3)) {
        nyx_printf("[WtE][CR3] ERROR: Failed to read KTHREAD.Process\n");
        return 0;
    }

    uint64_t start_eprocess = eprocess_ptr;
    int iter_count = 0;

    do {
        uint64_t pid = 0;
        if (!read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_PID,
                                     (uint8_t *)&pid, sizeof(pid),
                                     cpu, harness_cr3)) {
            nyx_printf("[WtE][CR3] ERROR: Failed to read PID at EPROCESS 0x%lx\n",
                       (unsigned long)eprocess_ptr);
            return 0;
        }

        char image_name[16] = {0};
        read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_IMAGENAME,
                                (uint8_t *)image_name, 15, cpu, harness_cr3);
        image_name[15] = '\0';

        if (iter_count < 10 || pid == target_pid) {
            nyx_printf("[WtE][CR3]   EPROCESS=0x%lx PID=%lu Name=%s\n",
                       (unsigned long)eprocess_ptr, (unsigned long)pid,
                       image_name);
        }

        if (pid == target_pid) {
            uint64_t cr3 = 0;
            if (!read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_DTB,
                                         (uint8_t *)&cr3, sizeof(cr3),
                                         cpu, harness_cr3)) {
                nyx_printf("[WtE][CR3] ERROR: Failed to read CR3\n");
                return 0;
            }
            cr3 &= 0xFFFFFFFFFFFFF000ULL;
            nyx_printf("[WtE][CR3] Found PID %lu: CR3=0x%lx Name=%s\n",
                       (unsigned long)target_pid, (unsigned long)cr3,
                       image_name);
            return cr3;
        }

        uint64_t next_link = 0;
        if (!read_virtual_memory_cr3(eprocess_ptr + EPROCESS_OFF_LINKS,
                                     (uint8_t *)&next_link, sizeof(next_link),
                                     cpu, harness_cr3)) {
            nyx_printf("[WtE][CR3] ERROR: Failed to read ActiveProcessLinks\n");
            return 0;
        }

        eprocess_ptr = next_link - EPROCESS_OFF_LINKS;
        iter_count++;
    } while (eprocess_ptr != start_eprocess && iter_count < EPROCESS_WALK_MAX);

    nyx_printf("[WtE][CR3] ERROR: PID %lu not found after %d iterations\n",
               (unsigned long)target_pid, iter_count);
    return 0;
}

/* ── Diagnostic: Target PE GFN Mapping ────────────────────────── */

bool wte_is_target_pe_gfn(uint64_t gfn)
{
    for (int i = 0; i < wte_state.pe_page_count; i++) {
        if (wte_state.pe_gfns[i] == gfn) return true;
    }
    return false;
}

void wte_diagnose_target_pe(CPUState *cpu, uint64_t image_base,
                            uint64_t image_size)
{
    if (!wte_state.active) {
        nyx_printf("[WtE][DIAG] Cannot diagnose — WtE not active\n");
        return;
    }

    wte_state.pe_base_va = image_base;
    wte_state.pe_end_va  = image_base + image_size;

    uint64_t cr3 = wte_state.target_cr3;

    nyx_printf("[WtE][DIAG] ============================================\n");
    nyx_printf("[WtE][DIAG] Target PE: VA 0x%lx - 0x%lx (size=0x%lx)\n",
               (unsigned long)image_base,
               (unsigned long)(image_base + image_size),
               (unsigned long)image_size);

    int mapped = 0, unmapped = 0;
    for (uint64_t va = image_base; va < image_base + image_size;
         va += WTE_PAGE_SIZE) {
        uint64_t pa = get_paging_phys_addr(cpu, cr3, va);

        if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
            unmapped++;
            continue;
        }

        uint64_t gfn = pa >> 12;
        mapped++;

        if (mapped <= 20 || (mapped % 16 == 0)) {
            nyx_printf("[WtE][DIAG]   VA 0x%08lx → PA 0x%lx (GFN=0x%lx)\n",
                       (unsigned long)va, (unsigned long)pa,
                       (unsigned long)gfn);
        }
    }

    nyx_printf("[WtE][DIAG] %d mapped, %d unmapped\n", mapped, unmapped);
    nyx_printf("[WtE][DIAG] ============================================\n");
}

/* ── Intel PT Safety Net ──────────────────────────────────────── */

/*
 * Check Intel PT trace for WtE events that EPT missed (CoW cases).
 * Called at every VM exit. Performs incremental decode of new PT data.
 *
 * This is a stub — the actual PT decode integration depends on the
 * libxdc decoder API and PT buffer layout. The logic is:
 *   1. Get new PT packets since last decode
 *   2. Extract TIP (Target IP) packets → executed VAs
 *   3. Check if any executed VA is in a "written" PE page
 *   4. If found and EPT didn't catch it → WtE detected → dump
 *   5. Re-protect the new GFN so EPT catches it next time
 */
void wte_pt_check(CPUState *cpu)
{
    if (!wte_state.active || wte_state.pe_page_count == 0) {
        return;
    }

    /* Passive force-JIT sweep trigger: detect JIT quiescence. */
    wte_sweep_trigger_check(cpu);

    /*
     * CoW detection via VA→GFN rescan:
     * Since full PT decode is expensive, we use a lighter approach:
     * periodically rescan PE VA→GFN mappings. If a GFN changed (CoW),
     * apply EPT protections to the new GFN immediately.
     *
     * This is checked at every VM exit and is fast (just page table walks
     * for PE pages, typically < 100 pages).
     */
    uint64_t cr3 = wte_state.target_cr3;
    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    uint64_t wp_batch[WTE_MAX_BATCH_GFNS];
    int nx_count = 0, wp_count = 0;

    for (int i = 0; i < wte_state.pe_page_count; i++) {
        uint64_t va = wte_state.pe_vas[i];
        uint64_t old_gfn = wte_state.pe_gfns[i];

        uint64_t pa = get_paging_phys_addr(cpu, cr3, va);
        if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) continue;

        uint64_t new_gfn = pa >> 12;
        if (new_gfn == old_gfn) continue;

        /* CoW detected! GFN changed for this VA */
        wte_state.pe_gfns[i] = new_gfn;

        nyx_printf("[WtE][COW-DETECT] VA 0x%lx: GFN 0x%lx → 0x%lx\n",
                   (unsigned long)va, (unsigned long)old_gfn,
                   (unsigned long)new_gfn);

        if (!wte_gfn_has_other_reference(old_gfn, va)) {
            wte_kvm_clear_nx(&old_gfn, 1);
            wte_kvm_clear_wp(&old_gfn, 1);
        }

        /* Update or create page entry for this VA */
        wte_page_entry_t *entry = wte_lookup_va(va);
        if (entry) {
            entry->gfn = new_gfn;
            entry->gpa = new_gfn << 12;

            /* Re-read content from new GFN */
            cpu_physical_memory_read(entry->gpa, entry->current, WTE_PAGE_SIZE);
            wte_compute_diff(entry);

            /* Only mark WRITTEN if content actually differs from baseline.
             * CoW often just copies the same content to a new physical page,
             * which would cause a false positive exec violation. */
            if (entry->diff_count > 0) {
                entry->flags |= WTE_PAGE_WRITTEN;
            }
        } else {
            entry = wte_lookup_or_create_va(va, new_gfn);
            entry->flags = WTE_PAGE_IS_PE;
            entry->gpa = new_gfn << 12;
            cpu_physical_memory_read(entry->gpa, entry->baseline, WTE_PAGE_SIZE);
            entry->baseline_valid = true;
            cpu_physical_memory_read(entry->gpa, entry->current, WTE_PAGE_SIZE);
            wte_compute_diff(entry);
            if (entry->diff_count > 0) {
                entry->flags |= WTE_PAGE_WRITTEN;
            }
        }

        /* Set EPT protections on new GFN */
        nx_batch[nx_count++] = new_gfn;
        wp_batch[wp_count++] = new_gfn;
        entry->flags |= WTE_PAGE_X_BLOCKED | WTE_PAGE_W_PROTECTED;
        entry->flags &= ~WTE_PAGE_X_ALLOWED;

        if (nx_count >= WTE_MAX_BATCH_GFNS) {
            wte_kvm_set_nx(nx_batch, nx_count);
            nx_count = 0;
        }
        if (wp_count >= WTE_MAX_BATCH_GFNS) {
            wte_kvm_set_wp(wp_batch, wp_count);
            wp_count = 0;
        }

        wte_state.pt_cow_recoveries++;
        wte_state.total_cow_recoveries++;
    }

    if (nx_count > 0) wte_kvm_set_nx(nx_batch, nx_count);
    if (wp_count > 0) wte_kvm_set_wp(wp_batch, wp_count);
}
