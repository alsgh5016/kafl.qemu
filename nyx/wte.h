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
#include <stdio.h>
#include <stdint.h>

#include "qemu/osdep.h"
#include "nyx/wte_policy.h"

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
#define WTE_PAGE_DYN_FIRST_EXEC_PENDING (1 << 7)

/* JIT tap vtable slot for ICorStaticInfo::getEHinfo (.NET 4.x x86 ABI).
 * Slot 8 = 8th pure virtual after the base-class vtable starts. */
#define WTE_GETEHINFO_VTABLE_SLOT  8

/* Maximum EH clauses buffered per method. */
#define WTE_JIT_MAX_EH_CLAUSES     64

/* ── DLL module entry (for noise filtering) ───────────────────── */

typedef struct {
    uint64_t base;                           /* module base VA            */
    uint64_t end;                            /* base + size               */
    char     name[WTE_DLL_NAME_LEN];         /* module name (ASCII)       */
} wte_dll_entry_t;

/* EH clause — mirrors CORINFO_EH_CLAUSE (CLR 4.x, 24 bytes). */
typedef struct {
    uint32_t flags;          /* 0=catch 1=filter 2=finally 4=fault */
    uint32_t try_offset;
    uint32_t try_length;
    uint32_t handler_offset;
    uint32_t handler_length;
    uint32_t class_token;    /* catch type token or filter offset */
} wte_eh_clause_t;

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
    bool     strict_mode;
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

    /* MTF reason codes */
#define WTE_MTF_REASON_WRITE     0   /* same-page write confirmation     */
#define WTE_MTF_REASON_JIT_REARM 1   /* re-arm JIT tap page NX           */

    /* MTF state for same-page write confirmation and JIT tap re-arm */
    bool     mtf_active;           /* MTF is armed                       */
    uint8_t  mtf_reason;           /* WTE_MTF_REASON_* discriminator     */
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

    /* JIT-IL tap state (Phase 2) — hypervisor-side compileMethod capture */
    struct {
        bool     enabled;

        /* clrjit.dll address range (filled at DLL load time) */
        uint64_t clrjit_base;
        uint64_t clrjit_end;

        /* Resolved VAs (0 until resolved) */
        uint64_t g_jit_va;           /* VA of the g_jit global (ICorJitCompiler**) */
        uint64_t getjit_va;          /* VA of getJit() export */
        uint64_t compile_method_va;  /* VA of ICorJitCompiler::compileMethod */

        /* EPT NX trap state */
        bool     getjit_nx_armed;
        uint64_t getjit_gfn;
        bool     compile_method_nx_armed;
        uint64_t compile_method_gfn;

        /* Deferred re-arm: when compileMethod NX is cleared to allow exec,
         * rearm_pending is set.  The JIT tap exec handler re-arms NX on
         * the NEXT violation from a different GFN (i.e., after compileMethod
         * has returned to its caller), avoiding the single-page MTF loop. */
        bool     rearm_pending;

        /* Deferred getJit resolve: set when getJit trap fires at entry but
         * g_jit is still null (getJit itself initializes the singleton).
         * On the next exec violation from a different GFN (after getJit has
         * returned), retry wte_jit_resolve_compile_method(). */
        bool     getjit_returned_pending;

        /* MTF re-arm: used only for the one-shot getJit trap path */
        uint64_t mtf_rearm_gfn;

        /* getEHinfo tap: return-address NX approach */
        uint64_t getehinfo_va;
        bool     getehinfo_nx_armed;
        uint64_t getehinfo_gfn;

        /* Pending IL write — buffered until all EH clauses captured */
        bool     pending_write;
        uint32_t pending_wte_seq;
        uint32_t pending_ftn;
        uint32_t pending_scope;
        uint8_t *pending_il_bytes;   /* malloc'd; freed after flush */
        uint32_t pending_il_size;
        uint16_t pending_eh_count;

        /* In-flight EH accumulation */
        uint16_t eh_expected;        /* EHcount from compileMethod           */
        uint16_t eh_captured;        /* clauses received so far              */
        uint64_t eh_clause_ptr;      /* guest VA of current clause output    */
        bool     eh_return_pending;  /* waiting for getEHinfo return-NX trap */
        uint64_t eh_return_gfn;      /* GFN of getEHinfo return address      */
        bool     eh_rearm_pending;   /* deferred getEHinfo NX re-arm (MTF busy
                                      * fallback): re-arm on next exec on a
                                      * different GFN                        */
        wte_eh_clause_t eh_clauses[WTE_JIT_MAX_EH_CLAUSES];

        /* jit_il_dump_N output file */
        int      dump_seq;           /* incremented each wte_activate */
        FILE    *dump_file;          /* NULL when closed                */
        int      records_written;
        long     count_file_offset;  /* fseek position of num_records field */
    } jit_tap;

    /* ── Force-JIT sweep trigger (JIT-idle detection) ───────────────
     * Instead of trapping process exit (which would need EPT-NX on a hot
     * ntdll page, or a hardware BP), we watch the compileMethod trap rate.
     * Once no method has been JIT-compiled for `idle_threshold_us`, the JIT
     * has quiesced — loading is stable and every executed method is already
     * captured — which is the right moment to run the force-JIT sweep that
     * picks up never-called methods (e.g. an uninvoked .ctor).
     *
     * Detection is purely passive (it reuses the existing compileMethod
     * trap), so it adds no anti-debug / anti-tamper surface, needs no KVM
     * change, and never holds a guest thread (no deadlock risk).
     *
     * Signalling: when idle is detected we write `1` to a flag in harness
     * memory (GVA provided at WTE_SETUP).  The harness polls it, runs the
     * sweep, and the timer trigger remains as a fallback. */
    struct {
        bool     enabled;            /* harness provided a flag GVA       */
        uint64_t flag_gva;           /* harness sweep-signal flag GVA     */
        uint64_t harness_cr3;        /* CR3 to write the flag             */
        uint64_t last_jit_us;        /* g_get_monotonic_time() of last
                                      * compileMethod trap; 0 = none yet  */
        uint64_t idle_threshold_us;  /* idle span that triggers the sweep */
        bool     idle_active;        /* inside an idle window already
                                      * logged; cleared when JIT resumes.
                                      * NOT one-shot — re-arms each gap so
                                      * the last (pre-exit) gap is caught,
                                      * not the first CLR-init gap.        */
        uint32_t idle_windows;       /* count of idle windows seen so far  */
    } sweep_trigger;

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

    struct wte_strict_state strict_state;
    FILE *strict_trace_file;

} wte_state_t;

/* ── Public API ────────────────────────────────────────────────── */

/* Lifecycle */
void wte_init(void);
void wte_destroy(void);
void wte_activate(uint64_t cr3, bool is_64bit);
bool wte_activate_strict(CPUState *cpu, uint64_t cr3, bool is_64bit,
                         uint64_t image_base, uint64_t image_size);
void wte_deactivate(void);
bool wte_is_strict_mode(void);
void wte_handle_strict_exit(CPUState *cpu,
                            const struct kvm_nyx_strict_pt_exit *strict_exit);
void wte_handle_strict_pre_restore_reset(CPUState *cpu);
void wte_handle_strict_post_restore_reset(CPUState *cpu);

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

/* JIT-IL tap: called from wte_register_loaded_dll when a DLL is mapped.
 * If the DLL is clrjit.dll, resolves compileMethod and arms EPT NX. */
void wte_jit_tap_on_dll_load(CPUState *cpu, uint64_t module_base,
                              uint64_t module_end, const char *name);

/* JIT-IL tap: exec-violation handler for tap pages.
 * Returns true if the violation was consumed (caller must not process it). */
bool wte_jit_tap_handle_exec(CPUState *cpu, uint64_t gfn, uint64_t gpa,
                              uint64_t rip);

/* JIT-IL tap: MTF handler — re-arms NX on the tap page.
 * Returns true if the MTF was consumed (caller must not process it). */
bool wte_jit_tap_handle_mtf(CPUState *cpu);

/* JIT-IL tap: finalize and close the current dump file (called at deactivate). */
void wte_jit_il_close(void);

/* Force-JIT sweep trigger: enable JIT-idle detection (called from WTE_SETUP
 * when the harness provides a sweep-signal flag GVA). */
void wte_sweep_trigger_setup(uint64_t flag_gva, uint64_t harness_cr3,
                             uint64_t idle_threshold_us);

/* Force-JIT sweep trigger: note that a method was just JIT-compiled
 * (called from the compileMethod tap to reset the idle timer). */
void wte_sweep_trigger_note_jit(void);

/* Force-JIT sweep trigger: check for JIT-idle and, on first detection, write
 * the sweep-request flag into harness memory.  Called every VM exit from
 * wte_pt_check.  No-op unless enabled and not yet signaled. */
void wte_sweep_trigger_check(CPUState *cpu);

/* DLL module enumeration (PEB→Ldr walk) and RIP filtering */
int  wte_walk_module_list(CPUState *cpu, wte_dll_entry_t *out, int max,
                          uint64_t cr3);
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
