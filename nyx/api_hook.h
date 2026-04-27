/*
 * Nyx API Hook Module — stealth ntdll instrumentation via KVM EPT-RIP filter.
 *
 * Hooks 4 ntdll exports at the Nt* boundary so DLL loads and dynamic-code
 * allocations are observed deterministically (event-driven, no rescan):
 *
 *   LdrLoadDll              → DLL exclusion list update
 *   NtAllocateVirtualMemory → dynamic exec-region NX
 *   NtProtectVirtualMemory  → RW→RWX promotion NX
 *   NtMapViewOfSection      → DLL/image-mapping detection (SEC_IMAGE)
 *
 * Hooks live in the kernel hook table (KVM_NYX_HOOK_*).  EPT exec
 * violations on hook pages are filtered by RIP: only matching RIPs exit
 * to userspace as KVM_EXIT_KAFL_NYX_HOOK; non-matching instructions are
 * stepped over in-kernel via MTF.  No guest memory modification, no DR.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "qemu/osdep.h"

/* ── Hook identification ──────────────────────────────────────── */

typedef enum {
    NYX_HOOK_NONE = 0,
    NYX_HOOK_LDR_LOAD_DLL_ENTRY,
    NYX_HOOK_NT_ALLOCATE_VM_ENTRY,
    NYX_HOOK_NT_PROTECT_VM_ENTRY,
    NYX_HOOK_NT_MAP_VIEW_ENTRY,
    /* Return-side hooks share IDs in the same enum, dynamically packed
     * with a stack frame index to disambiguate concurrent calls. */
    NYX_HOOK_RETURN_BASE = 0x10000,
} nyx_hook_kind_t;

/* Build hook_id for return one-shot: (RETURN_BASE + slot_index) packed
 * with a 32-bit nonce so we can detect mismatches.  Layout:
 *   bits  0..15 = slot_index (0..63)
 *   bits 16..31 = entry_kind (NYX_HOOK_*_ENTRY)
 *   bits 32..63 = nonce
 */
static inline uint64_t nyx_hook_id_make_return(uint16_t slot_idx,
                                               uint16_t entry_kind,
                                               uint32_t nonce)
{
    return (uint64_t)NYX_HOOK_RETURN_BASE
         | ((uint64_t)slot_idx & 0xFFFFULL)
         | (((uint64_t)entry_kind & 0xFFFFULL) << 16)
         | ((uint64_t)nonce << 32);
}

static inline bool nyx_hook_id_is_return(uint64_t hook_id)
{
    return (hook_id & ~0xFFFFFFFFFFFFULL) ==
           ((uint64_t)NYX_HOOK_RETURN_BASE & ~0xFFFFFFFFFFFFULL)
        || (hook_id & NYX_HOOK_RETURN_BASE) == NYX_HOOK_RETURN_BASE;
}

/* ── Pending call tracking (LIFO by RSP) ──────────────────────── */

#define NYX_PENDING_MAX 32

typedef struct {
    bool      in_use;
    uint16_t  slot_idx;
    uint32_t  nonce;
    nyx_hook_kind_t entry_kind;

    uint64_t  entry_rip;
    uint64_t  entry_rsp;       /* guest RSP at function entry */
    uint64_t  return_addr;     /* [RSP] at entry — RIP after RET */
    uint64_t  return_hook_id;  /* what we registered with KVM     */

    /* Snapshot of stdcall args (32-bit) or fastcall regs (64-bit).
     * Variant per function — populated by the entry handler. */
    union {
        struct { uint64_t module_handle_out; uint64_t flags;
                 uint64_t name_unicode_str;  uint64_t handle_ptr; } ldr;
        struct { uint64_t process_handle;   uint64_t base_ptr;
                 uint64_t zero_bits;         uint64_t size_ptr;
                 uint64_t alloc_type;        uint64_t protect; } alloc;
        struct { uint64_t process_handle;   uint64_t base_ptr;
                 uint64_t size_ptr;          uint64_t new_protect;
                 uint64_t old_protect_ptr; }                     protect;
        struct { uint64_t section_handle;   uint64_t process_handle;
                 uint64_t base_ptr;          uint64_t alloc_attrs; } map;
    } args;
} nyx_pending_call_t;

/* ── Module state ─────────────────────────────────────────────── */

typedef struct {
    bool     active;
    bool     initialized;
    uint64_t ntdll_base;
    uint64_t ntdll_size;
    bool     is_64bit;          /* mirror of wte_state.is_64bit */

    /* Resolved entry RIPs — 0 if export not found */
    uint64_t rip_ldr_load_dll;
    uint64_t rip_nt_allocate_vm;
    uint64_t rip_nt_protect_vm;
    uint64_t rip_nt_map_view;

    /* Pending call stack (LIFO by entry_rsp) */
    nyx_pending_call_t pending[NYX_PENDING_MAX];
    int                pending_count;
    uint32_t           next_nonce;
} nyx_api_hook_state_t;

/* ── Public API ───────────────────────────────────────────────── */

/* Lifecycle */
void nyx_api_hook_init(void);
void nyx_api_hook_destroy(void);

/* Discovery + registration — call AFTER wte_activate().
 * Walks ntdll exports via guest memory reads, then registers ENTRY
 * hooks via KVM_NYX_HOOK_ADD.  Also batch-NX's the pages containing
 * the resolved RIPs so the EPT violation path actually fires. */
int  nyx_api_hook_install(CPUState *cpu, uint64_t ntdll_base, bool is_64bit);

/* Lazy-install retry: WTE_SETUP runs in harness (64-bit) context
 * where FS:[0x30] doesn't yield a valid 32-bit PEB, so PEB→Ldr
 * walk fails to find ntdll.  This helper is called from the WtE
 * exec-violation handler (target packer is on-CPU at that point)
 * and re-attempts enumeration + install if not yet active. */
void nyx_api_hook_try_install_lazy(CPUState *cpu);

/* Dispatched from the KVM_EXIT_KAFL_NYX_HOOK handler in hypercall.c. */
void nyx_api_hook_dispatch(CPUState *cpu, uint64_t hook_id,
                           uint64_t rip, uint64_t cr3);

/* Status accessors */
bool nyx_api_hook_is_active(void);
nyx_api_hook_state_t *nyx_api_hook_get_state(void);

/* KVM ioctl wrappers (single-entry add/remove) */
int  nyx_api_hook_kvm_add(uint64_t rip, uint64_t gfn, uint64_t hook_id);
int  nyx_api_hook_kvm_remove(uint64_t rip);
int  nyx_api_hook_kvm_clear(void);
