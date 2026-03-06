/*
 * WtE (Written-then-Executed) Detection — EPT NX Architecture
 *
 * Uses KVM Dirty Ring for write tracking and EPT NX bit for
 * execution interception. When a dirty page is executed, the
 * EPT NX violation causes a VM exit (KVM_EXIT_KAFL_WTE).
 * Content diff confirms actual code modification to avoid
 * false positives.
 *
 * Detection cycle:
 *   1. Guest writes to page → KVM Dirty Ring entry
 *   2. wte_scan_dirty_ring() → reads dirty GFNs → ioctl SET_NX
 *   3. Guest executes dirty page → EPT NX violation → VM exit
 *   4. wte_handle_nx_violation() → content diff → dump if confirmed
 *   5. ioctl CLEAR_NX on confirmed page → guest resumes
 *   6. Round reset: clear all NX bits → detect next unpacking layer
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "qemu/osdep.h"

/* ── Page Info ─────────────────────────────────────────────────── */

#define WTE_PAGE_SIZE       4096
#define WTE_MAX_DIFF_RANGES 256

/* Maximum GFNs per batch ioctl call */
#define WTE_MAX_BATCH_GFNS  512

typedef struct {
    uint64_t gpa;                            /* Guest Physical Address (GFN << 12) */
    uint8_t  baseline[WTE_PAGE_SIZE];        /* Content at snapshot time            */
    uint8_t  current[WTE_PAGE_SIZE];         /* Content when dirty detected         */
    bool     baseline_valid;
    bool     diff_done;
    int      diff_count;                     /* Number of changed byte ranges       */
    uint16_t diff_offsets[WTE_MAX_DIFF_RANGES]; /* Changed byte range start offsets */
    uint16_t diff_lengths[WTE_MAX_DIFF_RANGES]; /* Changed byte range lengths       */
    bool     nx_set;                         /* EPT NX bit currently set for page   */
} wte_page_info_t;

/* ── WtE Global State ─────────────────────────────────────────── */

typedef struct {
    /* GFN → page_info tracking (simple dynamic array) */
    wte_page_info_t **pages;                 /* Array of page info pointers         */
    uint64_t         *gfns;                  /* Parallel array of GFN keys          */
    int               page_count;            /* Number of tracked pages             */
    int               page_capacity;         /* Allocated capacity                  */

    int      round;                          /* Current detection round             */
    bool     active;                         /* WtE detection enabled               */
    bool     kvm_wte_enabled;                /* KVM WtE ioctl enabled               */

    uint64_t target_cr3;                     /* Target process CR3                  */
    bool     is_64bit;                       /* 64-bit PE target mode               */

    uint32_t last_scanned_ring_index;        /* Last dirty ring index we scanned    */
    int      wte_count;                      /* Total WtE detections this round     */
    int      total_wte_count;                /* Total WtE detections across rounds  */
    int      nx_pages_set;                   /* Number of pages with NX bit set     */
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

/* Dirty ring scan — call before dirty ring flush.
 * Reads new dirty GFNs and marks them NX in EPT via ioctl. */
void wte_scan_dirty_ring(void);

/* EPT NX violation handler — called on KVM_EXIT_KAFL_WTE.
 * Performs content diff, dumps if confirmed WtE, clears NX. */
void wte_handle_nx_violation(uint64_t gfn, uint64_t gpa, uint64_t rip, CPUState *cpu);

/* Round management */
void wte_reset_round(void);

/* Status */
bool         wte_is_active(void);
wte_state_t *wte_get_state(void);

/* Debug */
void wte_print_debug_summary(void);
