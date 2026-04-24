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

#include "nyx/snapshot/memory/backend/nyx_dirty_ring.h"
#include "nyx/fast_vm_reload.h"

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
    return g_hash_table_lookup(wte_state.page_table,
                               GUINT_TO_POINTER(page_va));
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
    g_hash_table_insert(wte_state.page_table,
                        GUINT_TO_POINTER(page_va), entry);
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
        g_direct_hash, g_direct_equal, NULL, g_free);

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
    wte_state.mtf_target_va  = 0;
    wte_state.mtf_target_gfn = 0;

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
void wte_protect_all_user_pages(CPUState *cpu, uint64_t cr3)
{
    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int nx_count = 0;
    int total_nx = 0, skipped_pe = 0;

    /* PML4[0] covers user-space VA 0x000000000000 - 0x007FFFFFFFFFFF */
    uint64_t pml4e = pml4_table[0];
    if (!(pml4e & 1)) {
        nyx_printf("[WtE][GLOBAL-NX] PML4[0] not present, skip\n");
        return;
    }

    uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    uint64_t pdpt_table[512];
    cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

    /* PDPT[0..1] covers VA 0x00000000 - 0x7FFFFFFF (32-bit user space) */
    for (int pdpte_idx = 0; pdpte_idx < 2; pdpte_idx++) {
        uint64_t pdpte = pdpt_table[pdpte_idx];
        if (!(pdpte & 1)) continue;
        if (pdpte & (1ULL << 7)) continue; /* 1GB huge page */

        uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
        uint64_t pd_table[512];
        cpu_physical_memory_read(pd_base, pd_table, 4096);

        for (int pde_idx = 0; pde_idx < 512; pde_idx++) {
            uint64_t pde = pd_table[pde_idx];
            if (!(pde & 1)) continue;

            if (pde & (1ULL << 7)) {
                /* 2MB huge page → split into 512 × 4KB for NX */
                uint64_t page_phys = pde & 0x000FFFFFFFE00000ULL;
                uint32_t base_va = ((uint32_t)pdpte_idx << 30) |
                                   ((uint32_t)pde_idx << 21);
                for (int k = 0; k < 512; k++) {
                    uint32_t va = base_va + ((uint32_t)k << 12);
                    if (va < 0x10000 || va >= 0x7FFF0000) continue;
                    uint64_t gfn = (page_phys + ((uint64_t)k << 12)) >> 12;

                    /* Skip PE pages (already W=0+X=0) */
                    bool is_pe = (va >= wte_state.pe_base_va &&
                                  va < wte_state.pe_end_va);
                    if (is_pe) { skipped_pe++; continue; }

                    nx_batch[nx_count++] = gfn;
                    total_nx++;
                    if (nx_count >= WTE_MAX_BATCH_GFNS) {
                        wte_kvm_set_nx(nx_batch, nx_count);
                        nx_count = 0;
                    }
                }
            } else {
                /* 4KB page table */
                uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
                uint64_t pt_table[512];
                cpu_physical_memory_read(pt_base, pt_table, 4096);

                for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                    uint64_t pte = pt_table[pte_idx];
                    if (!(pte & 1)) continue;

                    uint32_t va = ((uint32_t)pdpte_idx << 30) |
                                  ((uint32_t)pde_idx << 21) |
                                  ((uint32_t)pte_idx << 12);
                    if (va < 0x10000 || va >= 0x7FFF0000) continue;

                    uint64_t gfn = (pte & 0x000FFFFFFFFFF000ULL) >> 12;

                    bool is_pe = (va >= wte_state.pe_base_va &&
                                  va < wte_state.pe_end_va);
                    if (is_pe) { skipped_pe++; continue; }

                    nx_batch[nx_count++] = gfn;
                    total_nx++;
                    if (nx_count >= WTE_MAX_BATCH_GFNS) {
                        wte_kvm_set_nx(nx_batch, nx_count);
                        nx_count = 0;
                    }
                }
            }
        }
    }

    if (nx_count > 0) wte_kvm_set_nx(nx_batch, nx_count);

    nyx_printf("[WtE][GLOBAL-NX] Set X=0 on %d non-PE user pages "
               "(%d PE pages skipped)\n", total_nx, skipped_pe);
}

/* ── Periodic re-scan: NX newly allocated user pages ─────────────
 *
 * Called every N VM exits from kvm-all.c.  Re-walks the target CR3
 * page table and sets NX on any user page that wasn't present at
 * the initial WTE_SETUP scan.
 */
void wte_rescan_user_pages(CPUState *cpu)
{
    if (!wte_state.active) return;

    X86CPU *cpux86 = X86_CPU(cpu);
    CPUX86State *env = &cpux86->env;

    /* Only rescan when running in a context where target CR3 is valid */
    uint64_t cr3 = wte_state.target_cr3;
    if (cr3 == 0) return;

    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    uint64_t pml4e = pml4_table[0];
    if (!(pml4e & 1)) return;

    uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    uint64_t pdpt_table[512];
    cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

    uint64_t nx_batch[WTE_MAX_BATCH_GFNS];
    int nx_count = 0;
    int new_nx = 0;

    for (int pdpte_idx = 0; pdpte_idx < 2; pdpte_idx++) {
        uint64_t pdpte = pdpt_table[pdpte_idx];
        if (!(pdpte & 1)) continue;
        if (pdpte & (1ULL << 7)) continue;

        uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
        uint64_t pd_table[512];
        cpu_physical_memory_read(pd_base, pd_table, 4096);

        for (int pde_idx = 0; pde_idx < 512; pde_idx++) {
            uint64_t pde = pd_table[pde_idx];
            if (!(pde & 1)) continue;

            if (pde & (1ULL << 7)) {
                /* 2MB huge page */
                uint64_t page_phys = pde & 0x000FFFFFFFE00000ULL;
                uint32_t base_va = ((uint32_t)pdpte_idx << 30) |
                                   ((uint32_t)pde_idx << 21);
                for (int k = 0; k < 512; k++) {
                    uint32_t va = base_va + ((uint32_t)k << 12);
                    if (va < 0x10000 || va >= 0x7FFF0000) continue;
                    if (va >= wte_state.pe_base_va &&
                        va < wte_state.pe_end_va) continue;
                    uint64_t gfn = (page_phys + ((uint64_t)k << 12)) >> 12;
                    uint64_t gpa = gfn << 12;

                    /* Skip if already tracked */
                    wte_page_entry_t *entry = wte_lookup_gfn(gfn);
                    if (entry && (entry->flags & (WTE_PAGE_X_BLOCKED |
                                                  WTE_PAGE_X_ALLOWED)))
                        continue;

                    /* Create tracking entry so exec handler finds it */
                    if (!entry) {
                        entry = wte_lookup_or_create_va((uint64_t)va, gfn);
                        entry->gpa = gpa;
                        entry->flags |= WTE_PAGE_IS_DYNAMIC | WTE_PAGE_WRITTEN;
                        cpu_physical_memory_read(gpa, entry->baseline, WTE_PAGE_SIZE);
                        entry->baseline_valid = true;
                        memcpy(entry->current, entry->baseline, WTE_PAGE_SIZE);
                    }
                    entry->flags |= WTE_PAGE_X_BLOCKED;

                    nx_batch[nx_count++] = gfn;
                    new_nx++;
                    if (nx_count >= WTE_MAX_BATCH_GFNS) {
                        wte_kvm_set_nx(nx_batch, nx_count);
                        nx_count = 0;
                    }
                }
            } else {
                uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
                uint64_t pt_table[512];
                cpu_physical_memory_read(pt_base, pt_table, 4096);

                for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                    uint64_t pte = pt_table[pte_idx];
                    if (!(pte & 1)) continue;

                    uint32_t va = ((uint32_t)pdpte_idx << 30) |
                                  ((uint32_t)pde_idx << 21) |
                                  ((uint32_t)pte_idx << 12);
                    if (va < 0x10000 || va >= 0x7FFF0000) continue;
                    if (va >= wte_state.pe_base_va &&
                        va < wte_state.pe_end_va) continue;
                    uint64_t gfn = (pte & 0x000FFFFFFFFFF000ULL) >> 12;
                    uint64_t gpa = gfn << 12;

                    wte_page_entry_t *entry = wte_lookup_gfn(gfn);
                    if (entry && (entry->flags & (WTE_PAGE_X_BLOCKED |
                                                  WTE_PAGE_X_ALLOWED)))
                        continue;

                    /* Create tracking entry so exec handler finds it */
                    if (!entry) {
                        entry = wte_lookup_or_create_va((uint64_t)va, gfn);
                        entry->gpa = gpa;
                        entry->flags |= WTE_PAGE_IS_DYNAMIC | WTE_PAGE_WRITTEN;
                        cpu_physical_memory_read(gpa, entry->baseline, WTE_PAGE_SIZE);
                        entry->baseline_valid = true;
                        memcpy(entry->current, entry->baseline, WTE_PAGE_SIZE);
                    }
                    entry->flags |= WTE_PAGE_X_BLOCKED;

                    nx_batch[nx_count++] = gfn;
                    new_nx++;
                    if (nx_count >= WTE_MAX_BATCH_GFNS) {
                        wte_kvm_set_nx(nx_batch, nx_count);
                        nx_count = 0;
                    }
                }
            }
        }
    }

    if (nx_count > 0) wte_kvm_set_nx(nx_batch, nx_count);

    if (new_nx > 0) {
        nyx_printf("[WtE][RESCAN] NX applied to %d new user pages\n", new_nx);
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
         * Skip if API hook is already using MTF. */
        if (GET_GLOBAL_STATE()->api_hook_step_idx < 0) {
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

    uint64_t gfn = wte_state.mtf_target_gfn;
    uint64_t va  = wte_state.mtf_target_va;

    wte_state.mtf_active = false;

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
                uint32_t _fs = (uint32_t)env->segs[R_FS].base;
                snprintf(wte_label, sizeof(wte_label),
                         "wte_rip0x%lx_va0x%lx_tid0x%08x",
                         (unsigned long)entry->last_write_rip,
                         (unsigned long)entry->va, _fs);
                wte_dump_event_t evt = {
                    .type            = "DEFERRED",
                    .rip             = entry->last_write_rip,
                    .va              = entry->va,
                    .gfn             = entry->gfn,
                    .fs_base         = (uint64_t)env->segs[R_FS].base,
                    .diff_count      = entry->diff_count,
                    .wte_count       = wte_state.wte_count,
                    .total_wte_count = wte_state.total_wte_count,
                };
                dump_full_process_memory(cpu, env, wte_label, &evt, 0);
            }

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

void wte_enumerate_dlls(CPUState *cpu)
{
    X86CPU *cpux86 = X86_CPU(cpu);
    CPUX86State *env = &cpux86->env;

    wte_state.dll_module_count = 0;

    /* 32-bit WOW64: TEB at FS base, PEB at TEB+0x30 */
    uint32_t fs_base = (uint32_t)(env->segs[R_FS].base);
    uint32_t peb_ptr = 0;
    if (!read_virtual_memory((uint64_t)(fs_base + 0x30),
                             (uint8_t *)&peb_ptr, 4, cpu) || peb_ptr == 0) {
        nyx_printf("[WtE][DLL] Failed to read PEB (FS=0x%x)\n", fs_base);
        return;
    }

    /* PEB+0x0C → Ldr (PEB_LDR_DATA) */
    uint32_t ldr_ptr = 0;
    if (!read_virtual_memory((uint64_t)(peb_ptr + 0x0C),
                             (uint8_t *)&ldr_ptr, 4, cpu) || ldr_ptr == 0) {
        nyx_printf("[WtE][DLL] Failed to read PEB->Ldr\n");
        return;
    }

    /* InLoadOrderModuleList at Ldr+0x14 */
    uint32_t list_head = ldr_ptr + 0x14;
    uint32_t flink = 0;
    read_virtual_memory((uint64_t)list_head, (uint8_t *)&flink, 4, cpu);

    uint32_t cur = flink;
    int count = 0;
    while (cur != 0 && cur != list_head &&
           count < WTE_MAX_DLL_MODULES) {
        uint32_t dll_base = 0, dll_size = 0;
        read_virtual_memory((uint64_t)(cur + 0x10), (uint8_t *)&dll_base, 4, cpu);
        read_virtual_memory((uint64_t)(cur + 0x18), (uint8_t *)&dll_size, 4, cpu);

        /* Read module name (UNICODE_STRING at cur+0x24) */
        uint16_t name_len = 0;
        uint32_t name_buf = 0;
        read_virtual_memory((uint64_t)(cur + 0x24), (uint8_t *)&name_len, 2, cpu);
        read_virtual_memory((uint64_t)(cur + 0x24 + 4), (uint8_t *)&name_buf, 4, cpu);

        char name[WTE_DLL_NAME_LEN];
        memset(name, 0, sizeof(name));
        if (name_len > 0 && name_buf != 0) {
            uint16_t wbuf[WTE_DLL_NAME_LEN];
            memset(wbuf, 0, sizeof(wbuf));
            int nchars = (name_len / 2 < WTE_DLL_NAME_LEN - 1)
                             ? name_len / 2 : WTE_DLL_NAME_LEN - 1;
            read_virtual_memory((uint64_t)name_buf,
                                (uint8_t *)wbuf, nchars * 2, cpu);
            for (int c = 0; c < nchars; c++)
                name[c] = (char)(wbuf[c] & 0xFF);
        }

        /* Skip the target PE itself — never filter it */
        bool is_target = (dll_base >= wte_state.pe_base_va &&
                          dll_base < wte_state.pe_end_va);

        if (dll_base != 0 && dll_size != 0 && !is_target) {
            wte_dll_entry_t *entry =
                &wte_state.dll_modules[wte_state.dll_module_count];
            entry->base = dll_base;
            entry->end  = (uint64_t)dll_base + dll_size;
            memcpy(entry->name, name, WTE_DLL_NAME_LEN);
            wte_state.dll_module_count++;
        }

        count++;
        uint32_t next = 0;
        if (!read_virtual_memory((uint64_t)cur, (uint8_t *)&next, 4, cpu))
            break;
        if (next == cur) break;
        cur = next;
    }

    nyx_printf("[WtE][DLL] Enumerated %d modules (excluding target PE)\n",
               wte_state.dll_module_count);
    for (int i = 0; i < wte_state.dll_module_count; i++) {
        nyx_printf("[WtE][DLL]   %-30s 0x%08lx - 0x%08lx\n",
                   wte_state.dll_modules[i].name,
                   (unsigned long)wte_state.dll_modules[i].base,
                   (unsigned long)wte_state.dll_modules[i].end);
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

    wte_state.total_x_violations++;

    /* Skip kernel-mode RIP — do NOT re-NX kernel pages (infinite loop) */
    if (rip >= 0xFFFF800000000000ULL) {
        wte_kvm_clear_nx(&gfn, 1);
        return;
    }

    nyx_printf("[WtE][EXEC] GFN=0x%lx GPA=0x%lx RIP=0x%lx\n",
               (unsigned long)gfn, (unsigned long)gpa, (unsigned long)rip);

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
        /* Completely unknown page — just allow execution */
        nyx_printf("[WtE][EXEC] Untracked GFN=0x%lx RIP=0x%lx, allowing\n",
                   (unsigned long)gfn, (unsigned long)rip);
        wte_kvm_clear_nx(&gfn, 1);
        return;
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
            uint32_t _fs = (uint32_t)env->segs[R_FS].base;
            snprintf(wte_label, sizeof(wte_label),
                     "wte_rip0x%lx_va0x%lx_tid0x%08x",
                     (unsigned long)rip,
                     (unsigned long)entry->va, _fs);
            wte_dump_event_t evt = {
                .type            = "EXEC",
                .rip             = rip,
                .va              = entry->va,
                .gfn             = entry->gfn,
                .fs_base         = (uint64_t)env->segs[R_FS].base,
                .diff_count      = entry->diff_count,
                .wte_count       = wte_state.wte_count,
                .total_wte_count = wte_state.total_wte_count,
            };
            dump_full_process_memory(cpu, env, wte_label, &evt, 0);
        }

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
        bool in_dll = wte_state.dll_filter_enabled &&
                      wte_is_dll_rip(rip, cpu);

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
    wte_state.mtf_target_va  = 0;
    wte_state.mtf_target_gfn = 0;

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

