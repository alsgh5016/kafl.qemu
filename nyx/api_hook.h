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
    NYX_HOOK_LDR_LOAD_DLL_ENTRY      = 1,
    NYX_HOOK_NT_ALLOCATE_VM_ENTRY    = 2,
    NYX_HOOK_NT_PROTECT_VM_ENTRY     = 3,
    NYX_HOOK_NT_MAP_VIEW_ENTRY       = 4,
    /* Generic anti-analysis observation hook. One kind serves every entry in the
     * generated NYX_ANTI_APIS[] table; the specific API is carried as an index in
     * the entry hook_id (see nyx_hook_id_make_anti_entry) and in the pending slot. */
    NYX_HOOK_ANTI_OBSERVE            = 5,
} nyx_hook_kind_t;

/* hook_id layout
 *   bit 63       : RETURN flag (1 = return one-shot, 0 = entry)
 *   bits 32..62  : nonce (re-use detection across snapshot)
 *   bits 24..31  : (reserved)
 *   bits 16..23  : entry_kind (1..4)
 *   bits  0..15  : pending-stack slot index
 *
 * ENTRY hook_id is just nyx_hook_kind_t value (1..4) — bit 63 = 0.
 */
#define NYX_HOOK_ID_RETURN_FLAG  (1ULL << 63)
/* ENTRY hook_id for a generic anti-observe hook: bit 62 set, catalog index in low
 * 16 bits. Distinguishes it from the 4 bespoke WtE entry kinds (plain 1..4). */
#define NYX_HOOK_ID_ANTI_FLAG    (1ULL << 62)

static inline uint64_t nyx_hook_id_make_anti_entry(uint16_t api_idx)
{
    return NYX_HOOK_ID_ANTI_FLAG | ((uint64_t)api_idx & 0xFFFFULL);
}
static inline bool nyx_hook_id_is_anti_entry(uint64_t id)
{
    return (id & NYX_HOOK_ID_RETURN_FLAG) == 0 && (id & NYX_HOOK_ID_ANTI_FLAG) != 0;
}
static inline uint16_t nyx_hook_id_anti_index(uint64_t id)
{
    return (uint16_t)(id & 0xFFFFULL);
}

static inline uint64_t nyx_hook_id_make_return(uint16_t slot_idx,
                                               uint16_t entry_kind,
                                               uint32_t nonce)
{
    /* nonce restricted to 31 bits so it doesn't collide with the
     * RETURN_FLAG bit at position 63 once shifted into bits 32..63. */
    return NYX_HOOK_ID_RETURN_FLAG
         | ((uint64_t)slot_idx   & 0xFFFFULL)
         | (((uint64_t)entry_kind & 0xFFULL) << 16)
         | (((uint64_t)nonce     & 0x7FFFFFFFULL) << 32);
}

static inline bool     nyx_hook_id_is_return    (uint64_t id) { return (id & NYX_HOOK_ID_RETURN_FLAG) != 0; }
static inline uint16_t nyx_hook_id_return_slot  (uint64_t id) { return (uint16_t)(id & 0xFFFFULL); }
static inline uint16_t nyx_hook_id_return_kind  (uint64_t id) { return (uint16_t)((id >> 16) & 0xFFULL); }
/* mask out RETURN_FLAG that collapsed into bit 31 after the right-shift. */
static inline uint32_t nyx_hook_id_return_nonce (uint64_t id) { return (uint32_t)((id >> 32) & 0x7FFFFFFFU); }

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
        /* Generic anti-observe capture: which catalog API, its discriminator arg
         * value, and the output-buffer pointer to read back on return (0 if none). */
        struct { uint16_t api_idx;          uint32_t disc_value;
                 uint32_t out_ptr; }                                 anti;
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
