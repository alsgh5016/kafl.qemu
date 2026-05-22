/*
 * WtE (Written-then-Executed) Detection — Dual-Watch Architecture
 *
 * Uses EPT Write Protection (W=0) for real-time write detection and
 * EPT NX (X=0) for real-time execution interception on target PE pages.
 * Non-PE pages use dirty ring + NX for write/execute tracking.
 * Intel PT serves as a safety net to catch CoW-induced misses.
 *
 * Detection cycle:
 *   1. WTE_SETUP: Set EPT W=0 + X=0 on target PE pages
 *   2. Guest writes to PE page → EPT write violation → VM exit
 *      → mark page as "written" (VA-based), W=1, keep X=0
 *   3. Guest executes PE page → EPT execute violation → VM exit
 *      → written? → WtE detected → memory dump → W=0 re-protect, X=1
 *      → not written? → allow exec (X=1)
 *   4. Intel PT safety net: decode trace at each VM exit, catch CoW misses
 *   5. Non-PE pages: dirty ring + NX (legacy path, supplementary)
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "qemu/osdep.h"

/* ── Constants ─────────────────────────────────────────────────── */

#define WTE_PAGE_SIZE       4096
#define WTE_MAX_DIFF_RANGES 256
#define WTE_MAX_BATCH_GFNS  4096
#define WTE_MAX_TARGET_PE_PAGES 512

/* DLL noise filter: module-list based */
#define WTE_MAX_DLL_MODULES  128
#define WTE_DLL_NAME_LEN      64

/* Cross-dump max pages */
#define WTE_CROSSDUMP_MAX_PAGES  8192

/* EPT violation types (matches KVM kafl_wte.type) */
#define WTE_VIOLATION_EXEC   0
#define WTE_VIOLATION_WRITE  1

/* ── Page flags ────────────────────────────────────────────────── */

#define WTE_PAGE_WRITTEN       (1 << 0)  /* page was written to          */
#define WTE_PAGE_W_PROTECTED   (1 << 1)  /* EPT W=0 is set              */
#define WTE_PAGE_X_BLOCKED     (1 << 2)  /* EPT X=0 is set              */
#define WTE_PAGE_X_ALLOWED     (1 << 3)  /* execution explicitly allowed */
#define WTE_PAGE_IS_PE         (1 << 4)  /* belongs to target PE image   */
#define WTE_PAGE_IS_DYNAMIC    (1 << 5)  /* dynamically detected region  */
#define WTE_PAGE_DEFERRED      (1 << 6)  /* same-page write: W=1+X=1,
                                          * pending verification at next
                                          * EPT violation on other page  */

/* ── DLL module entry (for noise filtering) ───────────────────── */

typedef struct {
    uint64_t base;                           /* module base VA            */
    uint64_t end;                            /* base + size               */
    char     name[WTE_DLL_NAME_LEN];         /* module name (ASCII)       */
} wte_dll_entry_t;

/* ── Per-page tracking entry ───────────────────────────────────── */

typedef struct {
    uint64_t va;                             /* page VA (4KB aligned)     */
    uint64_t gfn;                            /* current GFN mapping       */
    uint64_t gpa;                            /* GFN << 12                 */
    uint32_t flags;                          /* WTE_PAGE_* flags          */
    uint32_t write_count;                    /* writes this round         */
    uint64_t last_write_rip;                 /* RIP of first SAME-PAGE write
                                              * (saved at DEFERRED setup)  */

    /* Content tracking for diff */
    uint8_t  baseline[WTE_PAGE_SIZE];        /* content at snapshot/setup */
    uint8_t  current[WTE_PAGE_SIZE];         /* content at detection time */
    bool     baseline_valid;
    int      diff_count;
    uint16_t diff_offsets[WTE_MAX_DIFF_RANGES];
    uint16_t diff_lengths[WTE_MAX_DIFF_RANGES];
} wte_page_entry_t;

/* ── Main state ────────────────────────────────────────────────── */

typedef struct {
    bool     active;
    bool     kvm_wte_enabled;

    /* Target process */
    uint64_t target_cr3;
    uint64_t target_pid;
    bool     is_64bit;

    /* Target PE range */
    uint64_t pe_base_va;
    uint64_t pe_end_va;
    uint64_t pe_size;

    /* VA-based page tracking (GHashTable: VA → wte_page_entry_t*) */
    GHashTable *page_table;

    /* PE VA→GFN initial mappings (for CoW detection by PT safety net) */
    uint64_t pe_vas[WTE_MAX_TARGET_PE_PAGES];
    uint64_t pe_gfns[WTE_MAX_TARGET_PE_PAGES];
    int      pe_page_count;

    /* Round management */
    int      round;
    int      wte_count;            /* WtE detections this round        */
    int      total_wte_count;      /* WtE detections across all rounds */

    /* DLL noise filter (module-list based) */
    bool            dll_filter_enabled;
    wte_dll_entry_t dll_modules[WTE_MAX_DLL_MODULES];
    int             dll_module_count;
    int             dll_filtered_count;
    int             dll_filtered_total;

    /* MTF state for same-page write confirmation */
    bool     mtf_active;           /* MTF armed for a same-page write    */
    uint64_t mtf_target_va;        /* VA of the page being written       */
    uint64_t mtf_target_gfn;       /* GFN of the page being written      */

    /* Dirty ring for non-PE pages (legacy supplementary path) */
    uint32_t last_scanned_ring_index;

    /* PT safety net state */
    uint64_t pt_decode_cursor;     /* last decoded offset in PT buffer  */
    int      pt_cow_recoveries;    /* CoW recoveries via PT this round  */

    /* Statistics */
    uint64_t overflow_count;
    uint64_t total_w_violations;
    uint64_t total_x_violations;
    uint64_t total_cow_recoveries;

    /* Re-NX queue for non-PE pages (legacy path) */
    uint64_t *renx_queue;
    int       renx_count;
    int       renx_capacity;

    /* Dynamic alloc ranges from api_hook NtAllocate/NtProtect callbacks.
     * Used by wte_handle_exec_violation late-bind path: when an
     * exec violation arrives on a GFN we never registered (because the
     * page was lazy-committed and unmapped at register time), but the
     * RIP falls within a recorded range, we create the tracking entry
     * on the spot instead of allowing exec through. */
    struct {
        uint64_t base;
        uint64_t end;
    } dyn_ranges[64];
    int dyn_range_count;

} wte_state_t;

/* ── Public API ────────────────────────────────────────────────── */

/* Lifecycle */
void wte_init(void);
void wte_destroy(void);
void wte_activate(uint64_t cr3, bool is_64bit);
void wte_deactivate(void);

/* KVM ioctl wrappers */
int  wte_kvm_enable(void);
int  wte_kvm_disable(void);
int  wte_kvm_set_nx(uint64_t *gfns, uint32_t count);
int  wte_kvm_clear_nx(uint64_t *gfns, uint32_t count);
int  wte_kvm_set_wp(uint64_t *gfns, uint32_t count);
int  wte_kvm_clear_wp(uint64_t *gfns, uint32_t count);
int  wte_kvm_set_cr3(uint64_t cr3);

/* EPT violation handlers (called from hypercall.c) */
void wte_handle_write_violation(uint64_t gfn, uint64_t gpa,
                                uint64_t rip, CPUState *cpu);
void wte_handle_exec_violation(uint64_t gfn, uint64_t gpa,
                               uint64_t rip, CPUState *cpu);

/* Deferred verification: check same-page writes that were left open
 * (W=1+X=1). Called at every VM exit to ensure timely detection. */
void wte_check_deferred_pages(CPUState *cpu);


/* MTF handler: confirm same-page write completed, re-arm W=0.
 * Called from handle_hypercall_kafl_mtf when mtf_active is set. */
void wte_handle_mtf(CPUState *cpu);

/* PE range protection: W=0 + X=0 on target PE pages.
 * Called during WTE_SETUP, BEFORE target process executes. */
void wte_protect_pe_range(CPUState *cpu, uint64_t image_base,
                          uint64_t image_size, uint64_t cr3);

/* Global NX: set X=0 on all mapped user pages (non-PE) for
 * dynamic region detection (amber-style packers) */
void wte_protect_all_user_pages(CPUState *cpu, uint64_t cr3);

/* Periodic re-scan: NX newly allocated pages since last scan.
 * NOTE: superseded by event-driven api_hook in Phase 4 — kept only for
 * legacy callsites; not called from kvm-all.c / wte_handle_exec_violation
 * any more. */
void wte_rescan_user_pages(CPUState *cpu);

/* Event-driven dynamic-region registration — called from the api_hook
 * RETURN callbacks for NtAllocateVirtualMemory/NtProtectVirtualMemory
 * when the new protection includes PAGE_EXECUTE_*.  Walks the [base,
 * base+size) page table mapping in target_cr3, applies EPT NX, and
 * creates DYNAMIC entries with baseline=0 so the next exec triggers
 * WtE detection. */
void wte_register_dynamic_exec_region(CPUState *cpu,
                                      uint64_t base, uint64_t size);

/* Event-driven DLL registration — called from the api_hook RETURN
 * callback for LdrLoadDll/NtMapViewOfSection (SEC_IMAGE).  Refreshes
 * wte_state.dll_modules via PEB→Ldr walk (so the new DLL is now
 * included in the noise filter) AND removes any DYNAMIC entries that
 * were mistakenly created on those pages by the legacy rescan path
 * before the DLL was identified. */
void wte_register_loaded_dll(CPUState *cpu, uint64_t module_base);

/* Lightweight re-check of all registered dyn_ranges:
 * walks only the recorded ranges (typically a few hundred pages, very
 * cheap) and applies NX to any page that has become mapped since
 * register-time but isn't yet in our tracking table.  Catches lazy
 * MEM_COMMIT pages whose SPTE was created without auto-NX firing
 * (target_cr3 race etc.). */
void wte_recheck_dyn_ranges(CPUState *cpu);

/* Dirty ring scan for non-PE pages (supplementary legacy path) */
void wte_scan_dirty_ring(void);

/* Round management */
void wte_reset_round(void);

/* Status */
bool         wte_is_active(void);
wte_state_t *wte_get_state(void);

/* Debug */
void wte_print_debug_summary(void);

/* EPROCESS walking: find target process CR3 by PID */
uint64_t wte_find_cr3_by_pid(CPUState *cpu, uint64_t harness_cr3,
                             uint64_t target_pid);

/* Diagnostic: map target PE VA range to GFNs */
void wte_diagnose_target_pe(CPUState *cpu, uint64_t image_base,
                            uint64_t image_size);

/* Check if a GFN belongs to target PE */
bool wte_is_target_pe_gfn(uint64_t gfn);

/* Intel PT safety net: check PT trace for CoW-missed WtE.
 * Call at every VM exit after dirty ring scan. */
void wte_pt_check(CPUState *cpu);

/* DLL module enumeration (PEB→Ldr walk) and RIP filtering */
int  wte_walk_module_list(CPUState *cpu, wte_dll_entry_t *out, int max);
void wte_enumerate_dlls(CPUState *cpu);
bool wte_is_dll_rip(uint64_t rip, CPUState *cpu);

/* Cross-dump byte diff */
void wte_crossdump_init(void);
void wte_crossdump_destroy(void);

/* ── WtE dump event metadata ──────────────────────────────────── */

typedef struct {
    const char *type;              /* "DEFERRED" or "EXEC"           */
    uint64_t    rip;               /* trigger RIP (0 if unknown)     */
    uint64_t    va;                /* target page VA                 */
    uint64_t    gfn;               /* target page GFN                */
    uint64_t    fs_base;           /* guest FS_BASE (= TEB ptr,
                                    * unique per thread on Win32)    */
    int         diff_count;        /* byte diffs in target page      */
    int         wte_count;         /* WtE count (this detection #)   */
    int         total_wte_count;   /* total WtE count cumulative     */
} wte_dump_event_t;
