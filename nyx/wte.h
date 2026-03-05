/*
 * WtE (Written-then-Executed) Detection for Malware Unpacking Analysis
 *
 * Uses KVM Dirty Ring for write tracking and Intel PT bb_callback for
 * execution tracking. Content diff confirms actual code modification
 * to avoid false positives.
 *
 * Detection cycle:
 *   1. Guest writes to page → EPT dirty ring entry
 *   2. WtE scan: read dirty ring → store baseline + current content
 *   3. Intel PT bb_callback: execution on dirty page detected
 *   4. Content diff confirms WtE → memory dump
 *   5. Round reset: clear all tracking → detect next unpacking layer
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "qemu/osdep.h"
#include "nyx/khash.h"
#include <libxdc.h>

/* ── Page Info ─────────────────────────────────────────────────── */

#define WTE_PAGE_SIZE       4096
#define WTE_MAX_DIFF_RANGES 256

typedef struct {
    uint64_t gpa;                            /* Guest Physical Address (GFN << 12) */
    uint8_t  baseline[WTE_PAGE_SIZE];        /* Content at snapshot time            */
    uint8_t  current[WTE_PAGE_SIZE];         /* Content when dirty detected         */
    bool     baseline_valid;
    bool     diff_done;
    int      diff_count;                     /* Number of changed byte ranges       */
    uint16_t diff_offsets[WTE_MAX_DIFF_RANGES]; /* Changed byte range start offsets */
    uint16_t diff_lengths[WTE_MAX_DIFF_RANGES]; /* Changed byte range lengths       */
} wte_page_info_t;

/* ── Khash Types ───────────────────────────────────────────────── */

/* key = GFN (uint64_t), value = wte_page_info_t* */
KHASH_MAP_INIT_INT64(WTE_DIRTY, wte_page_info_t *)

/* key = GFN (uint64_t), value = first execution RIP */
KHASH_MAP_INIT_INT64(WTE_EXEC, uint64_t)

/* key = IP (uint64_t) — set of deferred BB IPs that missed dirty_map during overflow */
KHASH_SET_INIT_INT64(WTE_BB_DEFER)

/* ── WtE Global State ─────────────────────────────────────────── */

typedef struct {
    khash_t(WTE_DIRTY)    *dirty_map;       /* GFN → page info (write tracking)   */
    khash_t(WTE_EXEC)     *exec_map;        /* GFN → RIP (execution tracking)     */
    khash_t(WTE_BB_DEFER) *bb_deferred;     /* IPs that missed dirty_map (deferred)*/

    int      round;                          /* Current detection round            */
    bool     active;                         /* WtE detection enabled              */
    bool     snapshot_taken;                 /* Snapshot baseline captured          */

    uint64_t target_cr3;                     /* Target process CR3                 */
    bool     is_64bit;                       /* 64-bit PE target mode              */

    uint32_t last_scanned_ring_index;        /* Last dirty ring index we scanned   */
    int      wte_count;                      /* Total WtE detections this round    */
    int      total_wte_count;                /* Total WtE detections across rounds */
    uint64_t overflow_count;                 /* Number of PT overflows handled     */
} wte_state_t;

/* ── Public API ────────────────────────────────────────────────── */

/* Lifecycle */
void wte_init(void);
void wte_destroy(void);
void wte_activate(uint64_t cr3, bool is_64bit);
void wte_deactivate(void);

/* Dirty ring scan — call before dirty ring flush */
void wte_scan_dirty_ring(void);

/* bb_callback — registered with libxdc */
void wte_bb_callback(void *opaque, disassembler_mode_t mode,
                     uint64_t ip, uint64_t tsc);

/* Deferred BB check — call at RELEASE after final dirty ring scan + pt_dump */
void wte_check_deferred_bbs(void);

/* Round management */
void wte_reset_round(void);

/* Status */
bool        wte_is_active(void);
wte_state_t *wte_get_state(void);

/* Debug */
void wte_print_debug_summary(void);


