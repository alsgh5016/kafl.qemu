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

/* DLL noise filter VA thresholds */
#define WTE_DLL_VA_THRESHOLD_32  0x70000000ULL
#define WTE_DLL_VA_THRESHOLD_64  0x00007FF000000000ULL

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

    /* DLL noise filter */
    bool     dll_filter_enabled;
    uint64_t dll_va_threshold;
    int      dll_filtered_count;
    int      dll_filtered_total;

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
 * (W=1+X=1). Called at the start of each EPT violation handler. */
void wte_check_deferred_pages(CPUState *cpu);

/* PE range protection: W=0 + X=0 on target PE pages.
 * Called during WTE_SETUP, BEFORE target process executes. */
void wte_protect_pe_range(CPUState *cpu, uint64_t image_base,
                          uint64_t image_size, uint64_t cr3);

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

/* Cross-dump byte diff */
void wte_crossdump_init(void);
void wte_crossdump_destroy(void);

/* ── WtE dump event metadata ──────────────────────────────────── */

typedef struct {
    const char *type;              /* "DEFERRED" or "EXEC"           */
    uint64_t    rip;               /* trigger RIP (0 if unknown)     */
    uint64_t    va;                /* target page VA                 */
    uint64_t    gfn;               /* target page GFN                */
    int         diff_count;        /* byte diffs in target page      */
    int         wte_count;         /* WtE count (this detection #)   */
    int         total_wte_count;   /* total WtE count cumulative     */
} wte_dump_event_t;
