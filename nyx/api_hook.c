/*
 * Nyx API Hook Module — implementation.
 *
 * Discovers ntdll Nt* function entry RIPs and registers them with
 * the in-kernel hook table.  EPT exec violations on those pages are
 * filtered by RIP server-side; only matching RIPs cause a userspace
 * exit (KVM_EXIT_KAFL_NYX_HOOK), dispatched here.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "sysemu/kvm.h"

#include <linux/kvm.h>

#include "target/i386/cpu.h"

#include "nyx/api_hook.h"
#include "nyx/wte.h"
#include "nyx/memory_access.h"
#include "nyx/debug.h"

/* ── Module state ─────────────────────────────────────────────── */

static nyx_api_hook_state_t g_state = {0};

bool nyx_api_hook_is_active(void) { return g_state.active; }
nyx_api_hook_state_t *nyx_api_hook_get_state(void) { return &g_state; }

void nyx_api_hook_init(void)
{
    memset(&g_state, 0, sizeof(g_state));
    g_state.next_nonce  = 1;
    g_state.initialized = true;
    nyx_printf("[NYX-HOOK] init\n");
}

void nyx_api_hook_destroy(void)
{
    if (!g_state.initialized) return;
    nyx_api_hook_kvm_clear();
    memset(&g_state, 0, sizeof(g_state));
    nyx_printf("[NYX-HOOK] destroy\n");
}

/* ── KVM ioctl wrappers ───────────────────────────────────────── */

int nyx_api_hook_kvm_add(uint64_t rip, uint64_t gfn, uint64_t hook_id)
{
    struct kvm_nyx_hook_entry req = {
        .rip = rip, .hook_id = hook_id, .gfn = gfn, .flags = 0, .pad = 0,
    };
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_HOOK_ADD, &req);
    if (ret < 0)
        nyx_printf("[NYX-HOOK] ERROR: HOOK_ADD rip=0x%lx ret=%d\n",
                   (unsigned long)rip, ret);
    return ret;
}

int nyx_api_hook_kvm_remove(uint64_t rip)
{
    struct kvm_nyx_hook_entry req = {
        .rip = rip, .hook_id = 0, .gfn = 0, .flags = 0, .pad = 0,
    };
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_HOOK_REMOVE, &req);
    if (ret < 0 && ret != -ENOENT)
        nyx_printf("[NYX-HOOK] ERROR: HOOK_REMOVE rip=0x%lx ret=%d\n",
                   (unsigned long)rip, ret);
    return ret;
}

int nyx_api_hook_kvm_clear(void)
{
    int ret = kvm_vm_ioctl(kvm_state, KVM_NYX_HOOK_CLEAR, 0);
    if (ret < 0)
        nyx_printf("[NYX-HOOK] ERROR: HOOK_CLEAR ret=%d\n", ret);
    return ret;
}

/* ── PE export directory walk ─────────────────────────────────── */

/* Minimal PE structures — we read field-by-field via read_virtual_memory
 * to avoid alignment/packing assumptions and to skip fields we don't use. */

#define IMAGE_DOS_SIGNATURE  0x5A4D       /* "MZ" */
#define IMAGE_NT_SIGNATURE   0x00004550   /* "PE\0\0" */

#define DOS_E_LFANEW_OFFSET   0x3C
#define NT_FILEHEADER_OFFSET  0x4
#define FILEHEADER_SIZE       0x14
/* OptionalHeader.DataDirectory[Export] is at:
 *   PE32:  NT_HEADERS + 0x18 (FileHeader) + 0x60 (OptionalHeader[Export RVA])
 *   PE32+: NT_HEADERS + 0x18 (FileHeader) + 0x70 (OptionalHeader[Export RVA])
 * We compute via Magic field in OptionalHeader. */

typedef struct {
    uint32_t export_flags;        /* 0x00 */
    uint32_t timestamp;           /* 0x04 */
    uint16_t major_version;       /* 0x08 */
    uint16_t minor_version;       /* 0x0A */
    uint32_t name_rva;            /* 0x0C */
    uint32_t ordinal_base;        /* 0x10 */
    uint32_t addr_table_count;    /* 0x14 — # of EAT entries */
    uint32_t name_ptr_count;      /* 0x18 — # of name entries */
    uint32_t addr_table_rva;      /* 0x1C — EAT (function RVAs) */
    uint32_t name_ptr_rva;        /* 0x20 — ENT (name RVAs) */
    uint32_t ordinal_table_rva;   /* 0x24 — EOT (ordinals)   */
} pe_export_dir_t;

static bool read_u8 (CPUState *cpu, uint64_t va, uint8_t  *out)
{ return read_virtual_memory(va, (uint8_t*)out, 1, cpu); }
static bool read_u16(CPUState *cpu, uint64_t va, uint16_t *out)
{ return read_virtual_memory(va, (uint8_t*)out, 2, cpu); }
static bool read_u32(CPUState *cpu, uint64_t va, uint32_t *out)
{ return read_virtual_memory(va, (uint8_t*)out, 4, cpu); }

/* Resolve a single export name → RVA. Returns 0 if not found. */
static uint32_t pe_resolve_export_rva(CPUState *cpu, uint64_t img_base,
                                      const char *target_name)
{
    uint16_t dos_sig = 0;
    if (!read_u16(cpu, img_base, &dos_sig) || dos_sig != IMAGE_DOS_SIGNATURE) {
        nyx_printf("[NYX-HOOK] PE parse: bad DOS sig at 0x%lx\n",
                   (unsigned long)img_base);
        return 0;
    }
    uint32_t e_lfanew = 0;
    if (!read_u32(cpu, img_base + DOS_E_LFANEW_OFFSET, &e_lfanew)) return 0;

    uint64_t nt_hdr = img_base + e_lfanew;
    uint32_t nt_sig = 0;
    if (!read_u32(cpu, nt_hdr, &nt_sig) || nt_sig != IMAGE_NT_SIGNATURE) {
        nyx_printf("[NYX-HOOK] PE parse: bad NT sig\n");
        return 0;
    }

    /* OptionalHeader starts after FileHeader (size 0x14) at NT+0x18 */
    uint64_t opt_hdr = nt_hdr + 0x18;
    uint16_t magic = 0;
    if (!read_u16(cpu, opt_hdr, &magic)) return 0;

    /* Export Data Directory offset within OptionalHeader:
     *   PE32  (magic=0x10b): 0x60
     *   PE32+ (magic=0x20b): 0x70
     */
    uint64_t export_dir_rva_off;
    if (magic == 0x10b)      export_dir_rva_off = 0x60;
    else if (magic == 0x20b) export_dir_rva_off = 0x70;
    else {
        nyx_printf("[NYX-HOOK] PE parse: unknown magic 0x%x\n", magic);
        return 0;
    }
    uint32_t export_dir_rva = 0, export_dir_size = 0;
    if (!read_u32(cpu, opt_hdr + export_dir_rva_off,     &export_dir_rva))  return 0;
    if (!read_u32(cpu, opt_hdr + export_dir_rva_off + 4, &export_dir_size)) return 0;
    if (export_dir_rva == 0 || export_dir_size == 0) return 0;

    pe_export_dir_t edir;
    if (!read_virtual_memory(img_base + export_dir_rva,
                             (uint8_t*)&edir, sizeof(edir), cpu)) {
        return 0;
    }

    size_t target_len = strlen(target_name);
    /* Walk name pointer table */
    for (uint32_t i = 0; i < edir.name_ptr_count; i++) {
        uint32_t name_rva = 0;
        if (!read_u32(cpu, img_base + edir.name_ptr_rva + i * 4, &name_rva))
            continue;
        if (name_rva == 0) continue;

        /* Read name (cap at 96 bytes) and compare */
        char buf[96];
        memset(buf, 0, sizeof(buf));
        for (size_t b = 0; b < sizeof(buf) - 1; b++) {
            uint8_t ch;
            if (!read_u8(cpu, img_base + name_rva + b, &ch)) { buf[b] = 0; break; }
            buf[b] = (char)ch;
            if (ch == 0) break;
        }
        if (strncmp(buf, target_name, target_len) != 0 ||
            buf[target_len] != 0) continue;

        /* Found — look up corresponding ordinal then EAT entry */
        uint16_t ord = 0;
        if (!read_u16(cpu, img_base + edir.ordinal_table_rva + i * 2, &ord))
            return 0;
        if (ord >= edir.addr_table_count) return 0;

        uint32_t fn_rva = 0;
        if (!read_u32(cpu, img_base + edir.addr_table_rva + ord * 4, &fn_rva))
            return 0;
        return fn_rva;
    }
    return 0;
}

/* ── Hook installation ────────────────────────────────────────── */

/* Compose ENTRY hook_id from the function kind. */
static uint64_t entry_hook_id(nyx_hook_kind_t kind) { return (uint64_t)kind; }

static int register_entry_hook(CPUState *cpu, const char *label,
                               uint64_t rip, nyx_hook_kind_t kind)
{
    if (rip == 0) {
        nyx_printf("[NYX-HOOK] %s: RVA not found, skip\n", label);
        return -1;
    }

    /* NX the page so EPT exec violation actually fires.  KVM-side
     * filter checks RIP and decides exit vs in-kernel step-over. */
    uint64_t pa  = get_paging_phys_addr(cpu, wte_get_state()->target_cr3, rip);
    if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
        nyx_printf("[NYX-HOOK] %s: rip=0x%lx not mapped\n", label,
                   (unsigned long)rip);
        return -1;
    }
    uint64_t gfn = pa >> 12;

    int rc = wte_kvm_set_nx(&gfn, 1);
    if (rc < 0) {
        nyx_printf("[NYX-HOOK] %s: NX failed gfn=0x%lx ret=%d\n", label,
                   (unsigned long)gfn, rc);
        return rc;
    }

    rc = nyx_api_hook_kvm_add(rip, gfn, entry_hook_id(kind));
    if (rc < 0) return rc;

    nyx_printf("[NYX-HOOK] %s ENTRY @ rip=0x%lx gfn=0x%lx hook_id=%d\n",
               label, (unsigned long)rip, (unsigned long)gfn, (int)kind);
    return 0;
}

int nyx_api_hook_install(CPUState *cpu, uint64_t ntdll_base, bool is_64bit)
{
    if (!g_state.initialized) nyx_api_hook_init();

    g_state.ntdll_base = ntdll_base;
    g_state.is_64bit   = is_64bit;
    g_state.pending_count = 0;

    nyx_printf("[NYX-HOOK] install: ntdll_base=0x%lx is_64bit=%d\n",
               (unsigned long)ntdll_base, is_64bit);

    /* Resolve export RVAs */
    uint32_t rva_ldr_load   = pe_resolve_export_rva(cpu, ntdll_base, "LdrLoadDll");
    uint32_t rva_nt_alloc   = pe_resolve_export_rva(cpu, ntdll_base, "NtAllocateVirtualMemory");
    uint32_t rva_nt_protect = pe_resolve_export_rva(cpu, ntdll_base, "NtProtectVirtualMemory");
    uint32_t rva_nt_map     = pe_resolve_export_rva(cpu, ntdll_base, "NtMapViewOfSection");

    g_state.rip_ldr_load_dll  = rva_ldr_load   ? ntdll_base + rva_ldr_load   : 0;
    g_state.rip_nt_allocate_vm = rva_nt_alloc   ? ntdll_base + rva_nt_alloc   : 0;
    g_state.rip_nt_protect_vm  = rva_nt_protect ? ntdll_base + rva_nt_protect : 0;
    g_state.rip_nt_map_view    = rva_nt_map     ? ntdll_base + rva_nt_map     : 0;

    nyx_printf("[NYX-HOOK]   LdrLoadDll              RVA=0x%x  RIP=0x%lx\n",
               rva_ldr_load,   (unsigned long)g_state.rip_ldr_load_dll);
    nyx_printf("[NYX-HOOK]   NtAllocateVirtualMemory RVA=0x%x  RIP=0x%lx\n",
               rva_nt_alloc,   (unsigned long)g_state.rip_nt_allocate_vm);
    nyx_printf("[NYX-HOOK]   NtProtectVirtualMemory  RVA=0x%x  RIP=0x%lx\n",
               rva_nt_protect, (unsigned long)g_state.rip_nt_protect_vm);
    nyx_printf("[NYX-HOOK]   NtMapViewOfSection      RVA=0x%x  RIP=0x%lx\n",
               rva_nt_map,     (unsigned long)g_state.rip_nt_map_view);

    /* Register ENTRY hooks (KVM-side + NX) */
    int total = 0;
    if (register_entry_hook(cpu, "LdrLoadDll",
            g_state.rip_ldr_load_dll, NYX_HOOK_LDR_LOAD_DLL_ENTRY) == 0) total++;
    if (register_entry_hook(cpu, "NtAllocateVirtualMemory",
            g_state.rip_nt_allocate_vm, NYX_HOOK_NT_ALLOCATE_VM_ENTRY) == 0) total++;
    if (register_entry_hook(cpu, "NtProtectVirtualMemory",
            g_state.rip_nt_protect_vm, NYX_HOOK_NT_PROTECT_VM_ENTRY) == 0) total++;
    if (register_entry_hook(cpu, "NtMapViewOfSection",
            g_state.rip_nt_map_view, NYX_HOOK_NT_MAP_VIEW_ENTRY) == 0) total++;

    g_state.active = (total > 0);
    nyx_printf("[NYX-HOOK] install complete: %d/%d hooks active\n", total, 4);
    return total;
}

/* ── Stack/arg helpers (32-bit guest, stdcall) ────────────────── */

static bool read_guest_u32(CPUState *cpu, uint64_t va, uint32_t *out)
{
    return read_virtual_memory(va, (uint8_t *)out, 4, cpu);
}

/* stdcall: [ESP+0]=RetAddr, [ESP+4]=arg1, [ESP+8]=arg2, ...
 * idx is 0-based for the first argument. */
static bool read_stack_arg32(CPUState *cpu, uint64_t esp, int idx, uint32_t *out)
{
    return read_guest_u32(cpu, esp + 4ULL * (idx + 1), out);
}

/* ── Pending stack ────────────────────────────────────────────── */

static int pending_alloc_slot(void)
{
    /* Find a free slot first (holes from out-of-order returns). */
    for (int i = 0; i < NYX_PENDING_MAX; i++) {
        if (!g_state.pending[i].in_use) {
            if (i + 1 > g_state.pending_count)
                g_state.pending_count = i + 1;
            return i;
        }
    }
    return -1;
}

static void pending_free_slot(int slot)
{
    if (slot < 0 || slot >= NYX_PENDING_MAX) return;
    g_state.pending[slot].in_use = false;
    /* Compact pending_count from the top. */
    while (g_state.pending_count > 0 &&
           !g_state.pending[g_state.pending_count - 1].in_use) {
        g_state.pending_count--;
    }
}

/* ── Return-hook registration ─────────────────────────────────── */

static int register_return_hook(CPUState *cpu, uint64_t return_addr,
                                uint64_t hook_id)
{
    uint64_t cr3 = wte_get_state()->target_cr3;
    uint64_t pa  = get_paging_phys_addr(cpu, cr3, return_addr);
    if (pa == 0xFFFFFFFFFFFFFFFFULL || pa == 0) {
        nyx_printf("[NYX-HOOK] return_addr=0x%lx not mapped (skip)\n",
                   (unsigned long)return_addr);
        return -1;
    }
    uint64_t gfn = pa >> 12;

    int rc = wte_kvm_set_nx(&gfn, 1);
    if (rc < 0) {
        nyx_printf("[NYX-HOOK] return: NX fail gfn=0x%lx ret=%d\n",
                   (unsigned long)gfn, rc);
        return rc;
    }
    return nyx_api_hook_kvm_add(return_addr, gfn, hook_id);
}

/* ── ENTRY: capture args, push pending, arm return hook ───────── */

static void on_entry_hit(CPUState *cpu, nyx_hook_kind_t kind, uint64_t rip)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;
    uint64_t     esp    = env->regs[R_ESP] & 0xFFFFFFFFULL;

    uint32_t ret_addr_32 = 0;
    if (!read_guest_u32(cpu, esp, &ret_addr_32)) {
        nyx_printf("[NYX-HOOK] ENTRY kind=%d: cannot read return addr (ESP=0x%lx)\n",
                   (int)kind, (unsigned long)esp);
        return;
    }

    int slot = pending_alloc_slot();
    if (slot < 0) {
        nyx_printf("[NYX-HOOK] ENTRY kind=%d: pending stack full (%d slots)\n",
                   (int)kind, NYX_PENDING_MAX);
        return;
    }
    nyx_pending_call_t *p = &g_state.pending[slot];
    memset(p, 0, sizeof(*p));
    p->in_use      = true;
    p->slot_idx    = (uint16_t)slot;
    p->nonce       = g_state.next_nonce++;
    p->entry_kind  = kind;
    p->entry_rip   = rip;
    p->entry_rsp   = esp;
    p->return_addr = (uint64_t)ret_addr_32;

    /* Capture per-function args from stdcall stack. */
    uint32_t a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
    switch (kind) {
    case NYX_HOOK_LDR_LOAD_DLL_ENTRY:
        /* (PWSTR Path, PULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE Module) */
        read_stack_arg32(cpu, esp, 0, &a0);
        read_stack_arg32(cpu, esp, 1, &a1);
        read_stack_arg32(cpu, esp, 2, &a2);
        read_stack_arg32(cpu, esp, 3, &a3);
        p->args.ldr.module_handle_out = a3;
        p->args.ldr.flags             = a1;
        p->args.ldr.name_unicode_str  = a2;
        p->args.ldr.handle_ptr        = a3;
        break;
    case NYX_HOOK_NT_ALLOCATE_VM_ENTRY:
        /* (HANDLE, PVOID *Base, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocType, ULONG Protect) */
        read_stack_arg32(cpu, esp, 0, &a0);
        read_stack_arg32(cpu, esp, 1, &a1);
        read_stack_arg32(cpu, esp, 2, &a2);
        read_stack_arg32(cpu, esp, 3, &a3);
        read_stack_arg32(cpu, esp, 4, &a4);
        read_stack_arg32(cpu, esp, 5, &a5);
        p->args.alloc.process_handle = a0;
        p->args.alloc.base_ptr       = a1;
        p->args.alloc.zero_bits      = a2;
        p->args.alloc.size_ptr       = a3;
        p->args.alloc.alloc_type     = a4;
        p->args.alloc.protect        = a5;
        break;
    case NYX_HOOK_NT_PROTECT_VM_ENTRY:
        /* (HANDLE, PVOID *Base, PSIZE_T NumberOfBytes, ULONG NewProtect, PULONG OldProtect) */
        read_stack_arg32(cpu, esp, 0, &a0);
        read_stack_arg32(cpu, esp, 1, &a1);
        read_stack_arg32(cpu, esp, 2, &a2);
        read_stack_arg32(cpu, esp, 3, &a3);
        read_stack_arg32(cpu, esp, 4, &a4);
        p->args.protect.process_handle    = a0;
        p->args.protect.base_ptr          = a1;
        p->args.protect.size_ptr          = a2;
        p->args.protect.new_protect       = a3;
        p->args.protect.old_protect_ptr   = a4;
        break;
    case NYX_HOOK_NT_MAP_VIEW_ENTRY:
        /* (HANDLE Section, HANDLE Process, PVOID *Base, ULONG_PTR ZeroBits, SIZE_T Commit,
         *  PLARGE_INTEGER Offset, PSIZE_T ViewSize, SECTION_INHERIT Inherit, ULONG AllocType,
         *  ULONG Win32Protect)
         * We capture the first 3 args + the AllocType (slot 8) for SEC_IMAGE detection. */
        read_stack_arg32(cpu, esp, 0, &a0);
        read_stack_arg32(cpu, esp, 1, &a1);
        read_stack_arg32(cpu, esp, 2, &a2);
        read_stack_arg32(cpu, esp, 8, &a3);
        p->args.map.section_handle = a0;
        p->args.map.process_handle = a1;
        p->args.map.base_ptr       = a2;
        p->args.map.alloc_attrs    = a3;
        break;
    default:
        nyx_printf("[NYX-HOOK] ENTRY: unknown kind=%d\n", (int)kind);
        pending_free_slot(slot);
        return;
    }

    uint64_t rhid = nyx_hook_id_make_return((uint16_t)slot,
                                            (uint16_t)kind,
                                            p->nonce);
    p->return_hook_id = rhid;

    if (register_return_hook(cpu, p->return_addr, rhid) < 0) {
        /* Could not register — drop pending; outer will run unhooked. */
        pending_free_slot(slot);
        return;
    }

    nyx_printf("[NYX-HOOK] ENTRY kind=%d slot=%d esp=0x%08x ret=0x%08x "
               "args=[0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x]\n",
               (int)kind, slot, (uint32_t)esp, (uint32_t)p->return_addr,
               a0, a1, a2, a3, a4, a5);
}

/* ── RETURN: read result, run per-function callback ───────────── */

static void on_ldr_load_dll_return(CPUState *cpu, nyx_pending_call_t *p,
                                   uint32_t status)
{
    if ((int32_t)status < 0) {
        nyx_printf("[NYX-HOOK] LdrLoadDll FAIL status=0x%08x\n", status);
        return;
    }
    /* Module is a PHANDLE → read the HMODULE (= base address). */
    uint32_t module_base = 0;
    if (p->args.ldr.handle_ptr)
        read_guest_u32(cpu, p->args.ldr.handle_ptr, &module_base);
    nyx_printf("[NYX-HOOK] LdrLoadDll OK status=0x%x base=0x%08x\n",
               status, module_base);

    /* Phase 3 minimal: rely on wte_enumerate_dlls to refresh module list
     * lazily.  Phase 4 will plug into wte_state.dll_modules directly +
     * remove any incorrectly-tracked dynamic entries on this DLL range. */
}

static void on_nt_allocate_return(CPUState *cpu, nyx_pending_call_t *p,
                                  uint32_t status)
{
    if ((int32_t)status < 0) {
        nyx_printf("[NYX-HOOK] NtAllocate FAIL status=0x%08x\n", status);
        return;
    }
    /* PAGE_EXECUTE_* family: 0x10 (X), 0x20 (RX), 0x40 (RWX), 0x80 (WCX) */
    bool has_exec = (p->args.alloc.protect & 0xF0) != 0;

    uint32_t base = 0, size = 0;
    if (p->args.alloc.base_ptr)
        read_guest_u32(cpu, p->args.alloc.base_ptr, &base);
    if (p->args.alloc.size_ptr)
        read_guest_u32(cpu, p->args.alloc.size_ptr, &size);

    nyx_printf("[NYX-HOOK] NtAllocate OK base=0x%08x size=0x%08x "
               "alloc_type=0x%x protect=0x%x %s\n",
               base, size, p->args.alloc.alloc_type, p->args.alloc.protect,
               has_exec ? "[EXEC]" : "");

    /* Phase 4 will: if has_exec, batch-NX [base, base+size) and create
     * DYNAMIC entries with baseline=0 so the next exec triggers WtE. */
}

static void on_nt_protect_return(CPUState *cpu, nyx_pending_call_t *p,
                                 uint32_t status)
{
    if ((int32_t)status < 0) return;

    bool has_exec = (p->args.protect.new_protect & 0xF0) != 0;
    if (!has_exec) return;  /* downgrades / non-exec — ignore */

    uint32_t base = 0, size = 0;
    if (p->args.protect.base_ptr)
        read_guest_u32(cpu, p->args.protect.base_ptr, &base);
    if (p->args.protect.size_ptr)
        read_guest_u32(cpu, p->args.protect.size_ptr, &size);

    nyx_printf("[NYX-HOOK] NtProtect+EXEC base=0x%08x size=0x%08x "
               "new_protect=0x%x\n",
               base, size, p->args.protect.new_protect);

    /* Phase 4 will NX [base, base+size) so the next exec triggers WtE. */
}

static void on_nt_map_view_return(CPUState *cpu, nyx_pending_call_t *p,
                                  uint32_t status)
{
    if ((int32_t)status < 0) return;

    /* alloc_attrs SEC_IMAGE = 0x01000000 — DLL/EXE image mapping */
    bool is_image = (p->args.map.alloc_attrs & 0x01000000U) != 0;
    uint32_t base = 0;
    if (p->args.map.base_ptr)
        read_guest_u32(cpu, p->args.map.base_ptr, &base);

    nyx_printf("[NYX-HOOK] NtMapView OK base=0x%08x alloc_attrs=0x%x %s\n",
               base, p->args.map.alloc_attrs,
               is_image ? "[SEC_IMAGE]" : "");
    (void)cpu;
}

static void on_return_hit(CPUState *cpu, uint64_t hook_id, uint64_t rip)
{
    uint16_t slot   = nyx_hook_id_return_slot(hook_id);
    uint16_t kind   = nyx_hook_id_return_kind(hook_id);
    uint32_t nonce  = nyx_hook_id_return_nonce(hook_id);

    if (slot >= NYX_PENDING_MAX) {
        nyx_printf("[NYX-HOOK] RETURN: bad slot=%u\n", slot);
        return;
    }
    nyx_pending_call_t *p = &g_state.pending[slot];
    if (!p->in_use) {
        nyx_printf("[NYX-HOOK] RETURN: slot=%u not in use\n", slot);
        goto remove_kvm_hook;
    }
    if (p->nonce != nonce) {
        nyx_printf("[NYX-HOOK] RETURN: stale nonce slot=%u expected=%u got=%u\n",
                   slot, p->nonce, nonce);
        goto remove_kvm_hook;
    }
    if ((unsigned)p->entry_kind != kind) {
        nyx_printf("[NYX-HOOK] RETURN: kind mismatch slot=%u expected=%u got=%u\n",
                   slot, p->entry_kind, kind);
        goto remove_kvm_hook;
    }

    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;
    uint32_t eax        = env->regs[R_EAX] & 0xFFFFFFFFULL;

    switch (p->entry_kind) {
    case NYX_HOOK_LDR_LOAD_DLL_ENTRY:    on_ldr_load_dll_return (cpu, p, eax); break;
    case NYX_HOOK_NT_ALLOCATE_VM_ENTRY:  on_nt_allocate_return  (cpu, p, eax); break;
    case NYX_HOOK_NT_PROTECT_VM_ENTRY:   on_nt_protect_return   (cpu, p, eax); break;
    case NYX_HOOK_NT_MAP_VIEW_ENTRY:     on_nt_map_view_return  (cpu, p, eax); break;
    default: break;
    }

remove_kvm_hook:
    /* Remove the one-shot return hook from KVM table.
     * The page stays NX'd in wte_nx_bitmap so any other registered
     * hook on the same page still works; KVM's nyx_hook_page_has_any
     * will return false for unrelated RIPs and step them over. */
    nyx_api_hook_kvm_remove(rip);
    pending_free_slot(slot);
}

/* ── Dispatch entry point ─────────────────────────────────────── */

void nyx_api_hook_dispatch(CPUState *cpu, uint64_t hook_id,
                           uint64_t rip, uint64_t cr3)
{
    (void)cr3;
    if (nyx_hook_id_is_return(hook_id)) {
        on_return_hit(cpu, hook_id, rip);
    } else {
        on_entry_hit(cpu, (nyx_hook_kind_t)hook_id, rip);
    }
}

/* ── Lazy install (retry from on-CPU target packer context) ───── */

void nyx_api_hook_try_install_lazy(CPUState *cpu)
{
    /* Auto-init on first call: WTE_SETUP cannot reach this code path
     * because the harness context lacks a valid 32-bit PEB, so init
     * must happen lazily here when the target packer is on-CPU. */
    if (!g_state.initialized) nyx_api_hook_init();
    if (g_state.active) return;

    /* Re-enumerate using current vCPU context — when invoked from the
     * WtE exec-violation handler, the target packer (32-bit) is on-CPU
     * so FS:[0x30] yields the correct 32-bit PEB. */
    wte_enumerate_dlls(cpu);

    wte_state_t *ws = wte_get_state();
    uint64_t ntdll_base = 0;
    for (int i = 0; i < ws->dll_module_count; i++) {
        const char *n = ws->dll_modules[i].name;
        if (strncasecmp(n, "ntdll.dll", 9) == 0 && n[9] == '\0') {
            ntdll_base = ws->dll_modules[i].base;
            break;
        }
    }
    if (ntdll_base == 0) return;  /* still not visible — retry later */

    int n = nyx_api_hook_install(cpu, ntdll_base, ws->is_64bit);
    nyx_printf("[NYX-HOOK] lazy install: ntdll=0x%lx hooks=%d\n",
               (unsigned long)ntdll_base, n);
}
