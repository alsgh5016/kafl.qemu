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
#include "nyx/nyx_anti_catalog.h"   /* generated: NYX_ANTI_APIS[] + decode table */
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

/* Locate the export directory of a loaded PE. Fills edir + the directory's own
 * RVA/size (needed for forwarder detection). Returns false if not a PE / no exports. */
static bool pe_get_export_dir(CPUState *cpu, uint64_t img_base,
                              pe_export_dir_t *edir,
                              uint32_t *dir_rva, uint32_t *dir_size)
{
    uint16_t dos_sig = 0;
    if (!read_u16(cpu, img_base, &dos_sig) || dos_sig != IMAGE_DOS_SIGNATURE)
        return false;
    uint32_t e_lfanew = 0;
    if (!read_u32(cpu, img_base + DOS_E_LFANEW_OFFSET, &e_lfanew)) return false;

    uint64_t nt_hdr = img_base + e_lfanew;
    uint32_t nt_sig = 0;
    if (!read_u32(cpu, nt_hdr, &nt_sig) || nt_sig != IMAGE_NT_SIGNATURE) return false;

    /* OptionalHeader starts after FileHeader (size 0x14) at NT+0x18 */
    uint64_t opt_hdr = nt_hdr + 0x18;
    uint16_t magic = 0;
    if (!read_u16(cpu, opt_hdr, &magic)) return false;

    /* Export Data Directory offset within OptionalHeader:
     *   PE32 (magic=0x10b): 0x60   PE32+ (magic=0x20b): 0x70 */
    uint64_t off;
    if (magic == 0x10b)      off = 0x60;
    else if (magic == 0x20b) off = 0x70;
    else return false;

    if (!read_u32(cpu, opt_hdr + off,     dir_rva))  return false;
    if (!read_u32(cpu, opt_hdr + off + 4, dir_size)) return false;
    if (*dir_rva == 0 || *dir_size == 0) return false;

    return read_virtual_memory(img_base + *dir_rva, (uint8_t *)edir,
                               sizeof(*edir), cpu);
}

/* Read the export name at name-table index i (capped). Returns false on read fail. */
static bool pe_read_export_name(CPUState *cpu, uint64_t img_base,
                                const pe_export_dir_t *edir, uint32_t i,
                                char *buf, size_t buf_sz)
{
    uint32_t name_rva = 0;
    if (!read_u32(cpu, img_base + edir->name_ptr_rva + i * 4, &name_rva) ||
        name_rva == 0)
        return false;
    for (size_t b = 0; b < buf_sz - 1; b++) {
        uint8_t ch;
        if (!read_u8(cpu, img_base + name_rva + b, &ch)) { buf[b] = 0; return false; }
        buf[b] = (char)ch;
        if (ch == 0) return true;
    }
    buf[buf_sz - 1] = 0;
    return true;
}

/* Function RVA for name-table index i, or 0 (also 0 for a forwarder — its EAT entry
 * points inside the export directory, a "DLL.Func" string, not code). */
static uint32_t pe_export_fn_rva(CPUState *cpu, uint64_t img_base,
                                 const pe_export_dir_t *edir, uint32_t i,
                                 uint32_t dir_rva, uint32_t dir_size)
{
    uint16_t ord = 0;
    if (!read_u16(cpu, img_base + edir->ordinal_table_rva + i * 2, &ord)) return 0;
    if (ord >= edir->addr_table_count) return 0;
    uint32_t fn_rva = 0;
    if (!read_u32(cpu, img_base + edir->addr_table_rva + ord * 4, &fn_rva)) return 0;
    if (fn_rva >= dir_rva && fn_rva < dir_rva + dir_size) return 0;  /* forwarder */
    return fn_rva;
}

/* Resolve a single export name → RVA. Returns 0 if not found or forwarded. */
static uint32_t pe_resolve_export_rva(CPUState *cpu, uint64_t img_base,
                                      const char *target_name)
{
    pe_export_dir_t edir;
    uint32_t dir_rva = 0, dir_size = 0;
    if (!pe_get_export_dir(cpu, img_base, &edir, &dir_rva, &dir_size)) return 0;

    size_t target_len = strlen(target_name);
    for (uint32_t i = 0; i < edir.name_ptr_count; i++) {
        char buf[96];
        if (!pe_read_export_name(cpu, img_base, &edir, i, buf, sizeof(buf))) continue;
        if (strncmp(buf, target_name, target_len) != 0 || buf[target_len] != 0)
            continue;
        return pe_export_fn_rva(cpu, img_base, &edir, i, dir_rva, dir_size);
    }
    return 0;
}

/* ── Hook installation ────────────────────────────────────────── */

/* Compose ENTRY hook_id from the function kind. */
static uint64_t entry_hook_id(nyx_hook_kind_t kind) { return (uint64_t)kind; }

/* Core registration: NX the RIP's page and add it to the KVM hook table with an
 * arbitrary entry hook_id.  Shared by the bespoke WtE hooks and the generic
 * anti-observe hooks so both take the same NX/exit path. */
static int register_entry_hook_id(CPUState *cpu, const char *label,
                                  uint64_t rip, uint64_t hook_id)
{
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

    rc = nyx_api_hook_kvm_add(rip, gfn, hook_id);
    if (rc < 0) return rc;
    return 0;
}

static int register_entry_hook(CPUState *cpu, const char *label,
                               uint64_t rip, nyx_hook_kind_t kind)
{
    if (rip == 0) {
        nyx_printf("[NYX-HOOK] %s: RVA not found, skip\n", label);
        return -1;
    }
    int rc = register_entry_hook_id(cpu, label, rip, entry_hook_id(kind));
    if (rc == 0)
        nyx_printf("[NYX-HOOK] %s ENTRY @ rip=0x%lx hook_id=%d\n",
                   label, (unsigned long)rip, (int)kind);
    return rc;
}

/* ── Anti-analysis hook resolution + install ──────────────────── */

/* Module preference for resolving a catalog export: real implementers first so a
 * forwarder (kernel32→kernelbase) is skipped in favour of the module that owns the
 * code.  Anything not listed is tried afterwards in load order. */
static const char *const ANTI_MOD_PREF[] = {
    "ntdll.dll", "kernelbase.dll", "kernel32.dll", "advapi32.dll",
    "user32.dll", "shell32.dll", "shlwapi.dll", "psapi.dll",
    "iphlpapi.dll", "setupapi.dll", "wtsapi32.dll", "ole32.dll", "gdi32.dll",
};

static uint64_t find_module_base_ci(wte_state_t *ws, const char *name)
{
    for (int i = 0; i < ws->dll_module_count; i++) {
        if (strcasecmp(ws->dll_modules[i].name, name) == 0)
            return ws->dll_modules[i].base;
    }
    return 0;
}

/* Index of a catalog API by exact export name, or -1. */
static int anti_index_by_name(const char *name)
{
    for (int i = 0; i < NYX_ANTI_APIS_COUNT; i++)
        if (strcmp(NYX_ANTI_APIS[i].export_name, name) == 0)
            return i;
    return -1;
}

static bool is_pref_module(const char *name)
{
    for (size_t k = 0; k < ARRAY_SIZE(ANTI_MOD_PREF); k++)
        if (strcasecmp(name, ANTI_MOD_PREF[k]) == 0)
            return true;
    return false;
}

static bool anti_string_has_vm_artifact(const char *s)
{
    static const char *const tokens[] = {
        "vbox", "virtualbox", "vmware", "vmci", "hgfs", "vmhgfs",
        "vmmouse", "vmtool", "qemu", "xen", "parallels", "prl_",
        "sbiedll", "sandboxie", "vmusbmouse", "vboxguest", "vboxminirt",
        "vboxtray", "vmwaretools",
    };

    if (!s || !*s) return false;

    char *lower = g_ascii_strdown(s, -1);
    bool matched = false;
    for (size_t i = 0; i < ARRAY_SIZE(tokens); i++) {
        if (g_strrstr(lower, tokens[i])) {
            matched = true;
            break;
        }
    }
    g_free(lower);
    return matched;
}

static const char *anti_category_tag(uint8_t category)
{
    switch (category) {
    case NYX_ANTI_DEBUG:  return "[ANTI-DEBUG]";
    case NYX_ANTI_VM:     return "[ANTI-VM]";
    case NYX_ANTI_TIMING: return "[ANTI-TIMING]";
    case NYX_ANTI_INJECT: return "[ANTI-INJECT]";
    default:              return "[ANTI]";
    }
}

/* Walk ONE module's export table exactly once, hooking every catalog API it exports
 * (module-major: 154 catalog names × N modules would be far too many full-table walks).
 * Skips forwarders, RIPs already hooked, and the RIPs owned by the 4 WtE hooks. */
static void install_anti_in_module(CPUState *cpu, uint64_t img_base,
                                   bool *api_done, uint64_t *seen, int *seen_n,
                                   int *installed)
{
    pe_export_dir_t edir;
    uint32_t dir_rva = 0, dir_size = 0;
    if (!pe_get_export_dir(cpu, img_base, &edir, &dir_rva, &dir_size)) return;

    for (uint32_t i = 0; i < edir.name_ptr_count; i++) {
        char buf[96];
        if (!pe_read_export_name(cpu, img_base, &edir, i, buf, sizeof(buf))) continue;
        int idx = anti_index_by_name(buf);
        if (idx < 0 || api_done[idx]) continue;

        uint32_t fn_rva = pe_export_fn_rva(cpu, img_base, &edir, i, dir_rva, dir_size);
        if (!fn_rva) continue;  /* forwarder / unreadable */
        uint64_t rip = img_base + fn_rva;

        if (rip == g_state.rip_ldr_load_dll  || rip == g_state.rip_nt_allocate_vm ||
            rip == g_state.rip_nt_protect_vm || rip == g_state.rip_nt_map_view) {
            api_done[idx] = true;
            continue;
        }
        bool dup = false;
        for (int s = 0; s < *seen_n; s++)
            if (seen[s] == rip) { dup = true; break; }
        api_done[idx] = true;
        if (dup) continue;
        seen[(*seen_n)++] = rip;

        if (register_entry_hook_id(cpu, NYX_ANTI_APIS[idx].export_name, rip,
                                   nyx_hook_id_make_anti_entry((uint16_t)idx)) == 0) {
            (*installed)++;
            nyx_printf("[NYX-HOOK] anti %-28s @ rip=0x%lx idx=%d cat=%u\n",
                       NYX_ANTI_APIS[idx].export_name, (unsigned long)rip, idx,
                       NYX_ANTI_APIS[idx].category);
        }
    }
}

/* Register every resolvable NYX_ANTI_APIS[] entry as a generic anti-observe hook.
 * Preference-ordered modules first so a forwarded export resolves to its real
 * implementer.  Returns the number installed. */
static int install_anti_hooks(CPUState *cpu, wte_state_t *ws)
{
    static bool api_done[NYX_ANTI_APIS_COUNT];   /* install runs once per session */
    memset(api_done, 0, sizeof(api_done));
    uint64_t seen[NYX_ANTI_APIS_COUNT];
    int      seen_n = 0;
    int      installed = 0;

    for (size_t k = 0; k < ARRAY_SIZE(ANTI_MOD_PREF); k++) {
        uint64_t base = find_module_base_ci(ws, ANTI_MOD_PREF[k]);
        if (base)
            install_anti_in_module(cpu, base, api_done, seen, &seen_n, &installed);
    }
    for (int i = 0; i < ws->dll_module_count; i++) {
        if (is_pref_module(ws->dll_modules[i].name)) continue;  /* already walked */
        install_anti_in_module(cpu, ws->dll_modules[i].base,
                               api_done, seen, &seen_n, &installed);
    }
    nyx_printf("[NYX-HOOK] anti-observe install: %d hooks (of %d catalog entries)\n",
               installed, NYX_ANTI_APIS_COUNT);
    return installed;
}

/* Decode a captured (stem, value) to its catalog meaning + artifact class. */
static const nyx_anti_meaning_t *anti_lookup_meaning(const char *stem, uint32_t value)
{
    for (int i = 0; i < NYX_ANTI_MEANINGS_COUNT; i++) {
        if (NYX_ANTI_MEANINGS[i].value == value &&
            strcmp(NYX_ANTI_MEANINGS[i].stem, stem) == 0)
            return &NYX_ANTI_MEANINGS[i];
    }
    return NULL;
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

    /* Generic anti-analysis observation hooks (full catalog). */
    int anti = install_anti_hooks(cpu, wte_get_state());

    g_state.active = (total > 0);
    nyx_printf("[NYX-HOOK] install complete: %d/%d WtE hooks + %d anti hooks active\n",
               total, 4, anti);
    return total;
}

/* ── Stack/arg helpers (32-bit guest, stdcall) ────────────────── */

static bool read_guest_u32(CPUState *cpu, uint64_t va, uint32_t *out)
{
    return read_virtual_memory(va, (uint8_t *)out, 4, cpu);
}

static bool read_guest_ptr(CPUState *cpu, uint64_t va, uint64_t *out)
{
    if (g_state.is_64bit) {
        return read_virtual_memory(va, (uint8_t *)out, 8, cpu);
    }

    uint32_t value = 0;
    if (!read_guest_u32(cpu, va, &value))
        return false;
    *out = value;
    return true;
}

/* stdcall: [ESP+0]=RetAddr, [ESP+4]=arg1, [ESP+8]=arg2, ...
 * idx is 0-based for the first argument. */
static bool read_stack_arg32(CPUState *cpu, uint64_t esp, int idx, uint32_t *out)
{
    return read_guest_u32(cpu, esp + 4ULL * (idx + 1), out);
}

static bool read_stack_arg64(CPUState *cpu, uint64_t rsp, int idx, uint64_t *out)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;

    switch (idx) {
    case 0: *out = env->regs[R_ECX]; return true;
    case 1: *out = env->regs[R_EDX]; return true;
    case 2: *out = env->regs[8];     return true;
    case 3: *out = env->regs[9];     return true;
    default:
        return read_guest_ptr(cpu, rsp + 8ULL * (idx + 1), out);
    }
}

static bool read_call_arg(CPUState *cpu, uint64_t sp, int idx, uint64_t *out)
{
    if (g_state.is_64bit)
        return read_stack_arg64(cpu, sp, idx, out);

    uint32_t value = 0;
    if (!read_stack_arg32(cpu, sp, idx, &value))
        return false;
    *out = value;
    return true;
}

static bool read_return_addr(CPUState *cpu, uint64_t sp, uint64_t *out)
{
    return read_guest_ptr(cpu, sp, out);
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
    uint64_t     sp     = g_state.is_64bit
        ? env->regs[R_ESP]
        : (env->regs[R_ESP] & 0xFFFFFFFFULL);

    uint64_t ret_addr = 0;
    if (!read_return_addr(cpu, sp, &ret_addr)) {
        nyx_printf("[NYX-HOOK] ENTRY kind=%d: cannot read return addr (SP=0x%lx)\n",
                   (int)kind, (unsigned long)sp);
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
    p->entry_rsp   = sp;
    p->return_addr = ret_addr;

    uint64_t a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0;
    switch (kind) {
    case NYX_HOOK_LDR_LOAD_DLL_ENTRY:
        /* (PWSTR Path, PULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE Module) */
        read_call_arg(cpu, sp, 0, &a0);
        read_call_arg(cpu, sp, 1, &a1);
        read_call_arg(cpu, sp, 2, &a2);
        read_call_arg(cpu, sp, 3, &a3);
        p->args.ldr.module_handle_out = a3;
        p->args.ldr.flags             = a1;
        p->args.ldr.name_unicode_str  = a2;
        p->args.ldr.handle_ptr        = a3;
        break;
    case NYX_HOOK_NT_ALLOCATE_VM_ENTRY:
        /* (HANDLE, PVOID *Base, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocType, ULONG Protect) */
        read_call_arg(cpu, sp, 0, &a0);
        read_call_arg(cpu, sp, 1, &a1);
        read_call_arg(cpu, sp, 2, &a2);
        read_call_arg(cpu, sp, 3, &a3);
        read_call_arg(cpu, sp, 4, &a4);
        read_call_arg(cpu, sp, 5, &a5);
        p->args.alloc.process_handle = a0;
        p->args.alloc.base_ptr       = a1;
        p->args.alloc.zero_bits      = a2;
        p->args.alloc.size_ptr       = a3;
        p->args.alloc.alloc_type     = a4;
        p->args.alloc.protect        = a5;
        break;
    case NYX_HOOK_NT_PROTECT_VM_ENTRY:
        /* (HANDLE, PVOID *Base, PSIZE_T NumberOfBytes, ULONG NewProtect, PULONG OldProtect) */
        read_call_arg(cpu, sp, 0, &a0);
        read_call_arg(cpu, sp, 1, &a1);
        read_call_arg(cpu, sp, 2, &a2);
        read_call_arg(cpu, sp, 3, &a3);
        read_call_arg(cpu, sp, 4, &a4);
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
        read_call_arg(cpu, sp, 0, &a0);
        read_call_arg(cpu, sp, 1, &a1);
        read_call_arg(cpu, sp, 2, &a2);
        read_call_arg(cpu, sp, 8, &a3);
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

    nyx_printf("[NYX-HOOK] ENTRY kind=%d slot=%d sp=0x%lx ret=0x%lx "
               "args=[0x%lx 0x%lx 0x%lx 0x%lx 0x%lx 0x%lx]\n",
               (int)kind, slot, (unsigned long)sp, (unsigned long)p->return_addr,
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
    uint64_t module_base = 0;
    if (p->args.ldr.handle_ptr)
        read_guest_ptr(cpu, p->args.ldr.handle_ptr, &module_base);
    nyx_printf("[NYX-HOOK] LdrLoadDll OK status=0x%x base=0x%lx\n",
               status, module_base);

    if (module_base != 0)
        wte_register_loaded_dll(cpu, module_base);
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

    uint64_t base = 0, size = 0;
    if (p->args.alloc.base_ptr)
        read_guest_ptr(cpu, p->args.alloc.base_ptr, &base);
    if (p->args.alloc.size_ptr)
        read_guest_ptr(cpu, p->args.alloc.size_ptr, &size);

    nyx_printf("[NYX-HOOK] NtAllocate OK base=0x%lx size=0x%lx "
               "alloc_type=0x%lx protect=0x%lx %s\n",
               base, size, p->args.alloc.alloc_type, p->args.alloc.protect,
               has_exec ? "[EXEC]" : "");

    if (has_exec && base != 0 && size != 0)
        wte_register_dynamic_exec_region(cpu, base, size);
}

static void on_nt_protect_return(CPUState *cpu, nyx_pending_call_t *p,
                                 uint32_t status)
{
    if ((int32_t)status < 0) return;

    bool has_exec = (p->args.protect.new_protect & 0xF0) != 0;
    if (!has_exec) return;  /* downgrades / non-exec — ignore */

    uint64_t base = 0, size = 0;
    if (p->args.protect.base_ptr)
        read_guest_ptr(cpu, p->args.protect.base_ptr, &base);
    if (p->args.protect.size_ptr)
        read_guest_ptr(cpu, p->args.protect.size_ptr, &size);

    nyx_printf("[NYX-HOOK] NtProtect+EXEC base=0x%lx size=0x%lx "
               "new_protect=0x%lx\n",
               base, size, p->args.protect.new_protect);

    if (base != 0 && size != 0)
        wte_register_dynamic_exec_region(cpu, base, size);
}

static void on_nt_map_view_return(CPUState *cpu, nyx_pending_call_t *p,
                                  uint32_t status)
{
    if ((int32_t)status < 0) return;

    /* alloc_attrs SEC_IMAGE = 0x01000000 — DLL/EXE image mapping */
    bool is_image = (p->args.map.alloc_attrs & 0x01000000U) != 0;
    uint64_t base = 0;
    if (p->args.map.base_ptr)
        read_guest_ptr(cpu, p->args.map.base_ptr, &base);

    nyx_printf("[NYX-HOOK] NtMapView OK base=0x%lx alloc_attrs=0x%lx %s\n",
               base, p->args.map.alloc_attrs,
               is_image ? "[SEC_IMAGE]" : "");

    if (is_image && base != 0)
        wte_register_loaded_dll(cpu, base);
}

/* ── Anti-observe entry/return ────────────────────────────────── */

/* Read a guest string for logging: printable-only, truncated. wide=UTF-16LE. */
static void anti_read_guest_str(CPUState *cpu, uint64_t ptr, bool wide,
                                char *out, size_t out_sz)
{
    memset(out, 0, out_sz);
    if (!ptr || out_sz == 0) return;
    size_t o = 0;
    for (size_t b = 0; o + 1 < out_sz && b < 260; b++) {
        if (wide) {
            uint16_t wc = 0;
            if (!read_virtual_memory(ptr + b * 2, (uint8_t *)&wc, 2, cpu)) break;
            if (wc == 0) break;
            out[o++] = (wc >= 0x20 && wc < 0x7f) ? (char)wc : '?';
        } else {
            uint8_t c = 0;
            if (!read_virtual_memory(ptr + b, &c, 1, cpu)) break;
            if (c == 0) break;
            out[o++] = (c >= 0x20 && c < 0x7f) ? (char)c : '?';
        }
    }
    out[o] = 0;
}

static void on_anti_entry_hit(CPUState *cpu, uint16_t api_idx, uint64_t rip)
{
    if (api_idx >= NYX_ANTI_APIS_COUNT) return;
    const nyx_anti_api_t *api = &NYX_ANTI_APIS[api_idx];
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;
    uint64_t     sp     = g_state.is_64bit
        ? env->regs[R_ESP]
        : (env->regs[R_ESP] & 0xFFFFFFFFULL);

    uint64_t disc_arg = 0, outp = 0;
    if (api->disc_arg_idx >= 0) read_call_arg(cpu, sp, api->disc_arg_idx, &disc_arg);
    if (api->out_arg_idx  >= 0) read_call_arg(cpu, sp, api->out_arg_idx,  &outp);
    uint32_t disc = (uint32_t)disc_arg;

    /* Entry-time log: decode integer discriminators, dump string args, else note call. */
    if (api->disc_arg_idx >= 0) {
        const nyx_anti_meaning_t *m = anti_lookup_meaning(api->stem, disc);
        if (m) {
            const char *tag = (m->artifact == NYX_ANTI_ART_DEBUG) ? "[ANTI-DEBUG]"
                            : (m->artifact == NYX_ANTI_ART_VM)    ? "[ANTI-VM]"
                            : "[OBSERVE]";
            nyx_printf("%s %s(%s=0x%x)\n", tag, api->export_name, m->meaning, disc);
        } else {
            nyx_printf("[OBSERVE] %s(arg%d=0x%x) cat=%u\n",
                       api->export_name, api->disc_arg_idx, disc, api->category);
        }
    } else if (api->str_arg_idx >= 0) {
        uint64_t str_ptr = 0;
        read_call_arg(cpu, sp, api->str_arg_idx, &str_ptr);
        size_t nlen = strlen(api->export_name);
        bool wide = (nlen > 0 && api->export_name[nlen - 1] == 'W');
        char sbuf[160];
        anti_read_guest_str(cpu, str_ptr, wide, sbuf, sizeof(sbuf));
        const char *tag = (api->category == NYX_ANTI_VM && anti_string_has_vm_artifact(sbuf))
            ? "[ANTI-VM]" : "[OBSERVE]";
        nyx_printf("%s %s(\"%s\")\n", tag, api->export_name, sbuf);
    } else {
        nyx_printf("%s %s() called\n", anti_category_tag(api->category), api->export_name);
    }

    /* Arm a return hook only when the result carries the signal: an output buffer
     * (NtQueryInformationProcess writes the DebugObject there), or a no-arg
     * anti-debug boolean returned in EAX (IsDebuggerPresent-style). */
    bool want_return = api->read_return ||
        (api->category == NYX_ANTI_DEBUG &&
         api->disc_arg_idx < 0 && api->str_arg_idx < 0);
    if (!want_return) return;

    uint64_t ret_addr = 0;
    if (!read_return_addr(cpu, sp, &ret_addr)) return;
    int slot = pending_alloc_slot();
    if (slot < 0) return;

    nyx_pending_call_t *p = &g_state.pending[slot];
    memset(p, 0, sizeof(*p));
    p->in_use      = true;
    p->slot_idx    = (uint16_t)slot;
    p->nonce       = g_state.next_nonce++;
    p->entry_kind  = NYX_HOOK_ANTI_OBSERVE;
    p->entry_rip   = rip;
    p->entry_rsp   = sp;
    p->return_addr = ret_addr;
    p->args.anti.api_idx    = api_idx;
    p->args.anti.disc_value = disc;
    p->args.anti.out_ptr    = outp;

    uint64_t rhid = nyx_hook_id_make_return((uint16_t)slot,
                                            (uint16_t)NYX_HOOK_ANTI_OBSERVE,
                                            p->nonce);
    p->return_hook_id = rhid;
    if (register_return_hook(cpu, p->return_addr, rhid) < 0)
        pending_free_slot(slot);
}

static void on_anti_return(CPUState *cpu, nyx_pending_call_t *p, uint32_t eax)
{
    const nyx_anti_api_t *api = &NYX_ANTI_APIS[p->args.anti.api_idx];
    uint32_t disc = p->args.anti.disc_value;
    uint64_t outval = 0;
    if (p->args.anti.out_ptr) {
        if (strcmp(api->stem, "ntqueryinformationprocess") == 0 &&
            (disc == 0x07 || disc == 0x1e)) {
            read_guest_ptr(cpu, p->args.anti.out_ptr, &outval);
        } else {
            uint32_t out32 = 0;
            if (read_guest_u32(cpu, p->args.anti.out_ptr, &out32))
                outval = out32;
        }
    }

    const nyx_anti_meaning_t *m =
        (api->disc_arg_idx >= 0) ? anti_lookup_meaning(api->stem, disc) : NULL;
    uint8_t artifact = m ? m->artifact : NYX_ANTI_ART_NONE;
    bool category_defined_anti = (api->disc_arg_idx < 0 && api->str_arg_idx < 0);

    /* Verdict for the well-known anti-debug output semantics. */
    bool detected = false;
    if (artifact == NYX_ANTI_ART_DEBUG) {
        if (strcmp(api->stem, "ntqueryinformationprocess") == 0) {
            if (disc == 0x1e || disc == 0x07) detected = (outval != 0);
            else if (disc == 0x1f)            detected = (outval == 0);
        } else if (strcmp(api->stem, "ntquerysysteminformation") == 0 && disc == 0x23) {
            uint8_t debugger_enabled = outval & 0xFF;
            uint8_t debugger_not_present = (outval >> 8) & 0xFF;
            detected = (debugger_enabled != 0 && debugger_not_present == 0);
        }
    }
    if (strcmp(api->stem, "checkremotedebuggerpresent") == 0)
        detected = (outval != 0);
    /* IsDebuggerPresent-style: no discriminator/output, EAX is the boolean. */
    if (api->disc_arg_idx < 0 && api->out_arg_idx < 0 &&
        api->category == NYX_ANTI_DEBUG)
        detected = (eax != 0);

    const char *verdict = detected ? "  ** DEBUGGER DETECTED **" : "";
    const char *tag = (artifact == NYX_ANTI_ART_DEBUG) ? "[ANTI-DEBUG]"
                    : (artifact == NYX_ANTI_ART_VM)    ? "[ANTI-VM]"
                    : category_defined_anti             ? anti_category_tag(api->category)
                    : "[OBSERVE]";
    if (m) {
        nyx_printf("%s %s(%s) -> out=0x%lx eax=0x%x%s\n",
                   tag, api->export_name, m->meaning, outval, eax, verdict);
    } else {
        nyx_printf("[OBSERVE] %s -> out=0x%lx eax=0x%x%s\n",
                   api->export_name, outval, eax, verdict);
    }
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
    case NYX_HOOK_ANTI_OBSERVE:          on_anti_return         (cpu, p, eax); break;
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
    } else if (nyx_hook_id_is_anti_entry(hook_id)) {
        on_anti_entry_hit(cpu, nyx_hook_id_anti_index(hook_id), rip);
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
