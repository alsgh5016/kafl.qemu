/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "qemu/osdep.h"

#include "exec/memory.h"
#include "qemu/main-loop.h"
#include "qemu-common.h"
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "sysemu/cpus.h"
#include "sysemu/hw_accel.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "sysemu/runstate.h"


#include "sysemu/runstate.h"
#include "nyx/debug.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/fast_vm_reload_sync.h"
#include "nyx/helpers.h"
#include "nyx/hypercall/configuration.h"
#include "nyx/hypercall/debug.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/interface.h"
#include "nyx/kvm_nested.h"
#include "nyx/memory_access.h"
#include "nyx/nested_hypercalls.h"
#include "nyx/pt.h"
#include "nyx/redqueen.h"
#include "nyx/state/state.h"
#include "nyx/page_cache.h"
#include "nyx/trace_dump.h"
#include "nyx/synchronization.h"

#include <pthread.h>
#include <libxdc.h>
#include <sys/stat.h>

/* =====================================================================
 * Async dump worker - offloads disk I/O from VCPU thread
 * ===================================================================== */

typedef struct {
    uint32_t va_start;
    uint32_t size;
    uint8_t  perm;
    uint8_t *data;
    int      num_pages;
} captured_region_t;

typedef struct { uint32_t base; uint32_t size; char name[128]; } mod_info_t;
typedef struct { uint32_t va; uint64_t phys; uint8_t perm; } mapped_page_t;
#define MAX_MODS 256

typedef struct dump_job {
    int                seq;
    char               label[128];
    mod_info_t         modules[MAX_MODS];
    int                num_modules;
    captured_region_t *regions;
    int                num_regions;
    uint64_t           total_bytes;
    char              *dump_dir;
    char              *map_content;
    struct dump_job   *next;
} dump_job_t;

static pthread_t       dump_worker_thread;
static pthread_mutex_t dump_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  dump_queue_cond  = PTHREAD_COND_INITIALIZER;
static dump_job_t     *dump_queue_head  = NULL;
static dump_job_t     *dump_queue_tail  = NULL;
static int             dump_queue_len   = 0;
static bool            dump_worker_running = false;
static bool            dump_worker_stop    = false;
#define DUMP_QUEUE_MAX  3

static int dump_seq_counter = 0;

/* Forward declarations */
static void dump_worker_init(void);
static void dump_worker_drain(void);
static void dump_worker_enqueue(dump_job_t *job);
static void wox_final_wox_check(CPUState *cpu);
static void wox_offline_pt_decode(CPUState *cpu);

bool hypercall_enabled = false;
static bool init_state = true;

void skip_init(void)
{
    init_state = false;
}

bool pt_hypercalls_enabled(void)
{
    return hypercall_enabled;
}

void pt_setup_enable_hypercalls(void)
{
    hypercall_enabled = true;
}

void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end)
{
    nyx_trace();
    if (filter_id < INTEL_PT_MAX_RANGES) {
        GET_GLOBAL_STATE()->pt_ip_filter_configured[filter_id] = true;
        GET_GLOBAL_STATE()->pt_ip_filter_a[filter_id]          = start;
        GET_GLOBAL_STATE()->pt_ip_filter_b[filter_id]          = end;
    }
}

void hypercall_commit_filter(void)
{
}

bool setup_snapshot_once = false;


bool handle_hypercall_kafl_next_payload(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg)
{
    nyx_trace();

    if (hypercall_enabled) {
        if (init_state) {
            set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 2);
            synchronization_lock();

        } else {
            if (GET_GLOBAL_STATE()->set_agent_config_done == false) {
                nyx_abort("KVM_EXIT_KAFL_SET_AGENT_CONFIG was not called.");
                return false;
            }

            if (!setup_snapshot_once) {
                coverage_bitmap_reset();
                request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                       REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP);
                setup_snapshot_once = true;

                /* At this point we need to check if PT mode is enabled
                 * and configured. Otherwise, libxdc_init() will fail.
                 */
                if(GET_GLOBAL_STATE()->nyx_pt && GET_GLOBAL_STATE()->cap_compile_time_tracing == false) {
                    for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
                        if (GET_GLOBAL_STATE()->pt_ip_filter_configured[i]) {
                            pt_enable_ip_filtering(cpu, i, true, false);
                        }
                    }
                    pt_init_decoder(cpu);
                }
                request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                       REQUEST_LOAD_SNAPSHOT_ROOT);

                GET_GLOBAL_STATE()->in_fuzzing_mode = true;
                set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                                  3);
            } else {
                synchronization_lock();
                reset_timeout_detector(&GET_GLOBAL_STATE()->timeout_detector);
                GET_GLOBAL_STATE()->in_fuzzing_mode = true;

                return true;
            }
        }
    }
    return false;
}

bool acquire_print_once_bool = true;
bool release_print_once_bool = true;

static void acquire_print_once(CPUState *cpu)
{
    if (acquire_print_once_bool) {
        acquire_print_once_bool = false;
        kvm_arch_get_registers(cpu);
        nyx_debug("handle_hypercall_kafl_acquire at IP: %lx\n", get_rip(cpu));
    }
}

void handle_hypercall_kafl_acquire(struct kvm_run *run,
                                   CPUState       *cpu,
                                   uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        if (!init_state) {
            /*
             * If NEXT_PAYLOAD was never called (single-shot mode),
             * initialize PT hardware here: push IP filters to KVM,
             * init decoder, and set in_fuzzing_mode so pt_dump()
             * actually writes trace data.
             */
            if (!setup_snapshot_once) {

                /* Force-enable PT trace dump for offline decode.
                 * If dump_pt_trace was not set in QEMU config, the trace
                 * dump file is never created and pt_write_pt_dump_file()
                 * silently drops data.  We need this data for offline
                 * bulk decode at RELEASE time (Plan A: lazy decoder). */
                {
                    char *trace_path = NULL;
                    assert(asprintf(&trace_path, "%s/pt_trace_dump_0",
                                    GET_GLOBAL_STATE()->workdir_path) != -1);
                    pt_trace_dump_init(trace_path);
                    free(trace_path);
                    nyx_printf("[WOX] PT trace dump force-enabled for offline decode\n");
                }
                for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
                    if (GET_GLOBAL_STATE()->pt_ip_filter_configured[i]) {
                        pt_enable_ip_filtering(cpu, i, true, false);
                    }
                }

                /* Initialize PT decoder for real-time trace decoding.
                 * In normal kAFL mode this happens in NEXT_PAYLOAD, but
                 * single-shot mode never calls NEXT_PAYLOAD.  The decoder
                 * is required so libxdc_decode() can populate page_cache
                 * with executed-page addresses for W⊕X detection.
                 */
                // [LAZY] if (GET_GLOBAL_STATE()->nyx_pt &&
                //     GET_GLOBAL_STATE()->cap_compile_time_tracing == false) {
                //     pt_init_decoder(cpu);
                //     nyx_printf("[WOX] PT decoder initialized (single-shot mode)\n");
                // }
                GET_GLOBAL_STATE()->in_fuzzing_mode = true;
                setup_snapshot_once = true;

                /* Take W⊕X dirty-bit baseline snapshot at tracing start */
                wox_take_snapshot(cpu);
                dump_worker_init();
            }
            acquire_print_once(cpu);
            synchronization_enter_fuzzing_loop(cpu);
        }
    }
}

static void handle_hypercall_get_payload(struct kvm_run *run,
                                         CPUState       *cpu,
                                         uint64_t        hypercall_arg)
{
    nyx_trace();

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_GET_PAYLOAD")) {
        return;
    }

    if (GET_GLOBAL_STATE()->get_host_config_done == false) {
        nyx_abort("KVM_EXIT_KAFL_GET_HOST_CONFIG was not called...");
        return;
    }

    if (hypercall_enabled && !setup_snapshot_once) {
        nyx_debug_p(CORE_PREFIX, "Payload Address: 0x%lx\n", hypercall_arg);
        kvm_arch_get_registers(cpu);
        CPUX86State *env               = &(X86_CPU(cpu))->env;
        GET_GLOBAL_STATE()->parent_cr3 = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;
        nyx_debug_p(CORE_PREFIX, "Payload CR3: 0x%lx\n",
                    (uint64_t)GET_GLOBAL_STATE()->parent_cr3);
        // print_48_pagetables(GET_GLOBAL_STATE()->parent_cr3);

        if (hypercall_arg & 0xFFF) {
            nyx_abort("Payload buffer at 0x%lx is not page-aligned!", hypercall_arg);
        }

        remap_payload_buffer(hypercall_arg, cpu);
        set_payload_buffer(hypercall_arg);
    }
}

static void set_return_value(CPUState *cpu, uint64_t return_value)
{
    kvm_arch_get_registers(cpu);
    CPUX86State *env = &(X86_CPU(cpu))->env;
    env->regs[R_EAX] = return_value;
    kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
}

static void handle_hypercall_kafl_req_stream_data(struct kvm_run *run,
                                                  CPUState       *cpu,
                                                  uint64_t        hypercall_arg)
{
    static uint8_t req_stream_buffer[0x1000];
    if (is_called_in_fuzzing_mode("HYPERCALL_KAFL_REQ_STREAM_DATA")) {
        return;
    }

    kvm_arch_get_registers(cpu);
    /* address has to be page aligned */
    if ((hypercall_arg & 0xFFF) != 0) {
        nyx_error("REQ_STREAM_DATA: Provided address is not page aligned!\n");
        set_return_value(cpu, 0xFFFFFFFFFFFFFFFFULL);
    } else {
        read_virtual_memory(hypercall_arg, (uint8_t *)req_stream_buffer, 0x100, cpu);
        uint64_t bytes = sharedir_request_file(GET_GLOBAL_STATE()->sharedir,
                                               (const char *)req_stream_buffer,
                                               req_stream_buffer);
        if (bytes != 0xFFFFFFFFFFFFFFFFULL) {
            write_virtual_memory(hypercall_arg, (uint8_t *)req_stream_buffer, bytes,
                                 cpu);
        }
        set_return_value(cpu, bytes);
    }
}

static void handle_hypercall_kafl_req_stream_data_bulk(struct kvm_run *run,
                                                       CPUState       *cpu,
                                                       uint64_t        hypercall_arg)
{
    static uint8_t req_stream_buffer[0x1000];
    req_data_bulk_t req_data_bulk_data;

    if (is_called_in_fuzzing_mode("HYPERCALL_KAFL_REQ_STREAM_DATA_BULK")) {
        return;
    }

    kvm_arch_get_registers(cpu);
    /* address has to be page aligned */
    if ((hypercall_arg & 0xFFF) != 0) {
        nyx_error("REQ_STREAM_DATA_BULK: Provided address is not page aligned!\n");
        set_return_value(cpu, 0xFFFFFFFFFFFFFFFFUL);
        return;
    }

    uint64_t bytes = 0;
    read_virtual_memory(hypercall_arg, (uint8_t *)&req_data_bulk_data, 0x1000, cpu);

    assert(req_data_bulk_data.num_addresses <= 479);
    for (int i = 0; i < req_data_bulk_data.num_addresses; i++) {
        uint64_t ret_val =
            sharedir_request_file(GET_GLOBAL_STATE()->sharedir,
                                  (const char *)req_data_bulk_data.file_name,
                                  req_stream_buffer);
        if (ret_val == 0xFFFFFFFFFFFFFFFFUL) {
            bytes = ret_val;
            break;
        }
        if (ret_val == 0) {
            break;
        }
        bytes += ret_val;
        write_virtual_memory((uint64_t)req_data_bulk_data.addresses[i],
                             (uint8_t *)req_stream_buffer, ret_val, cpu);
    }
    set_return_value(cpu, bytes);
}

static void handle_hypercall_kafl_range_submit(struct kvm_run *run,
                                               CPUState       *cpu,
                                               uint64_t        hypercall_arg)
{
    uint64_t buffer[3];

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_RANGE_SUBMIT")) {
        return;
    }

    read_virtual_memory(hypercall_arg, (uint8_t *)&buffer, sizeof(buffer), cpu);

    if (buffer[2] >= 2) {
        nyx_warn("ignoring invalid range register %ld\n", buffer[2]);
        return;
    }

    if (GET_GLOBAL_STATE()->pt_ip_filter_configured[buffer[2]]) {
        nyx_warn("ignoring already configured range reg %ld\n", buffer[2]);
        return;
    }

    if (buffer[0] != 0 && buffer[1] != 0) {
        GET_GLOBAL_STATE()->pt_ip_filter_a[buffer[2]]          = buffer[0];
        GET_GLOBAL_STATE()->pt_ip_filter_b[buffer[2]]          = buffer[1];
        GET_GLOBAL_STATE()->pt_ip_filter_configured[buffer[2]] = true;
        nyx_debug_p(CORE_PREFIX, "Configured range register IP%ld: 0x%08lx-0x%08lx\n",
                    buffer[2], buffer[0], buffer[1]);
    } else {
        nyx_warn("ignoring invalid range register %ld (NULL page)\n", buffer[2]);
    }
}

static void release_print_once(CPUState *cpu)
{
    if (release_print_once_bool) {
        release_print_once_bool = false;
        kvm_arch_get_registers(cpu);
        nyx_debug("handle_hypercall_kafl_release at IP: %lx\n", get_rip(cpu));
    }
}

void handle_hypercall_kafl_release(struct kvm_run *run,
                                   CPUState       *cpu,
                                   uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        if (init_state) {
            nyx_debug_p(CORE_PREFIX, "[RELEASE] init_state=false\n");
            init_state = false;
        } else {
            if (hypercall_arg > 0) {
                GET_GLOBAL_STATE()->starved = 1;
            } else {
                GET_GLOBAL_STATE()->starved = 0;
            }




            /* 1. Stop PT tracing and flush last raw data to dump file */
            synchronization_disable_pt(cpu);

            /* 2. Offline bulk decode: init decoder + read dump file + decode */
            wox_offline_pt_decode(cpu);

            /* 3. Final W+X cross-check (uses page_cache from offline decode) */
            wox_final_wox_check(cpu);

            /* 4. Final dirty-page report + content diff */
            wox_final_dirty_report(cpu);

            /* 5. Wait for all pending async dumps to complete */
            dump_worker_drain();

            release_print_once(cpu);
        }
    }
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    int                    err;
};

void handle_hypercall_kafl_mtf(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    kvm_arch_get_registers_fast(cpu);
    nyx_debug_p(CORE_PREFIX, "%s --> %lx\n", __func__, get_rip(cpu));
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_MTF);
    /* Check if this MTF is for API hook single-step resume */
    if (GET_GLOBAL_STATE()->api_hook_mode &&
        GET_GLOBAL_STATE()->api_hook_step_idx >= 0) {
        int idx = GET_GLOBAL_STATE()->api_hook_step_idx;
        uint64_t hook_addr = GET_GLOBAL_STATE()->api_hook_saved_rip;
        nyx_debug_p(CORE_PREFIX, "  MTF: re-inserting API hook[%d] at 0x%lx\n", idx, hook_addr);
        /* Re-insert the breakpoint */
        insert_breakpoint(cpu, hook_addr, 1);
        GET_GLOBAL_STATE()->api_hook_step_idx = -1;
        return;
    }
    /* Original MTF behavior (page dump) */
    kvm_remove_all_breakpoints(cpu);
    kvm_insert_breakpoint(cpu, GET_GLOBAL_STATE()->dump_page_addr, 1, 1);
    kvm_update_guest_debug(cpu, 0);
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3,
                   GET_GLOBAL_STATE()->pt_c3_filter);
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

void handle_hypercall_kafl_page_dump_bp(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg,
                                        uint64_t        page)
{
    kvm_arch_get_registers_fast(cpu);
    uint64_t hit_addr = page;  /* = run->debug.arch.pc */
    nyx_debug_p(CORE_PREFIX, "%s --> hit at 0x%lx\n", __func__, hit_addr);
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_MTF);
    /* Check if this is an API hook hit */
    if (GET_GLOBAL_STATE()->api_hook_mode) {
        for (int i = 0; i < GET_GLOBAL_STATE()->num_api_hooks; i++) {
            if (GET_GLOBAL_STATE()->api_hooks[i].active &&
                GET_GLOBAL_STATE()->api_hooks[i].addr == hit_addr) {
                nyx_debug_p(CORE_PREFIX, ">>> API HOOK HIT: %s @ 0x%lx <<<\n",
                           GET_GLOBAL_STATE()->api_hooks[i].name, hit_addr);
                /* Dump process memory via hprintf log */
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg),
                         "[API_HOOK] %s called at RIP=0x%lx\n",
                         GET_GLOBAL_STATE()->api_hooks[i].name, hit_addr);
                set_hprintf_auxiliary_buffer(
                    GET_GLOBAL_STATE()->auxilary_buffer,
                    log_msg, strlen(log_msg));
                /* Remove BP, enable single-step (MTF) to execute the original instruction,
                 * then re-insert BP */
                remove_breakpoint(cpu, hit_addr, 1);
                GET_GLOBAL_STATE()->api_hook_saved_rip = hit_addr;
                GET_GLOBAL_STATE()->api_hook_step_idx = i;
                kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_MTF);
                return;
            }
        }
    }
    /* Fallback to original page dump behavior */
    bool success = false;
    page_cache_fetch(GET_GLOBAL_STATE()->page_cache, page, &success, false);
    if (success) {
        nyx_debug("%s: SUCCESS: %d\n", __func__, success);
        kvm_remove_all_breakpoints(cpu);
        kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
    } else {
        nyx_debug("%s: FAIL: %d\n", __func__, success);
        kvm_remove_all_breakpoints(cpu);
        kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
        kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_MTF);
    }
}

static inline void set_page_dump_bp(CPUState *cpu, uint64_t cr3, uint64_t addr)
{
    nyx_debug("%s --> %lx %lx\n", __func__, cr3, addr);
    kvm_remove_all_breakpoints(cpu);
    kvm_insert_breakpoint(cpu, addr, 1, 1);
    kvm_update_guest_debug(cpu, 0);

    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3, cr3);
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

static void handle_hypercall_kafl_cr3(struct kvm_run *run,
                                      CPUState       *cpu,
                                      uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        uint64_t cr3_val = hypercall_arg & 0xFFFFFFFFFFFFF000ULL;
        if (cr3_val == 0) {
            /* arg=0: auto-capture current vCPU CR3 */
            kvm_arch_get_registers(cpu);
            CPUX86State *env = &(X86_CPU(cpu))->env;
            cr3_val = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;
        }
        nyx_debug_p(CORE_PREFIX, "Setting CR3 filter: %lx\n", cr3_val);
        GET_GLOBAL_STATE()->parent_cr3 = cr3_val;
        pt_set_cr3(cpu, cr3_val, false);
        if (GET_GLOBAL_STATE()->dump_page) {
            set_page_dump_bp(cpu, cr3_val,
                             GET_GLOBAL_STATE()->dump_page_addr);
        }
    }
}

static void handle_hypercall_kafl_submit_panic(struct kvm_run *run,
                                               CPUState       *cpu,
                                               uint64_t        hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_SUBMIT_PANIC")) {
        return;
    }

    if (hypercall_enabled) {
        nyx_debug_p(CORE_PREFIX, "Panic address: %lx\n", hypercall_arg);

        switch (get_current_mem_mode(cpu)) {
        case mm_32_protected:
        case mm_32_paging:
        case mm_32_pae:
            write_virtual_memory(hypercall_arg, (uint8_t *)PANIC_PAYLOAD_32,
                                 PAYLOAD_BUFFER_SIZE_32, cpu);
            break;
        case mm_64_l4_paging:
        case mm_64_l5_paging:
            write_virtual_memory(hypercall_arg, (uint8_t *)PANIC_PAYLOAD_64,
                                 PAYLOAD_BUFFER_SIZE_64, cpu);
            break;
        default:
            abort();
            break;
        }
    }
}

static void handle_hypercall_kafl_submit_kasan(struct kvm_run *run,
                                               CPUState       *cpu,
                                               uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        nyx_debug_p(CORE_PREFIX, "kASAN address:\t%lx\n", hypercall_arg);

        switch (get_current_mem_mode(cpu)) {
        case mm_32_protected:
        case mm_32_paging:
        case mm_32_pae:
            write_virtual_memory(hypercall_arg, (uint8_t *)KASAN_PAYLOAD_32,
                                 PAYLOAD_BUFFER_SIZE_32, cpu);
            break;
        case mm_64_l4_paging:
        case mm_64_l5_paging:
            write_virtual_memory(hypercall_arg, (uint8_t *)KASAN_PAYLOAD_64,
                                 PAYLOAD_BUFFER_SIZE_64, cpu);
            break;
        default:
            abort();
            break;
        }
    }
}

void handle_hypercall_kafl_panic(struct kvm_run *run,
                                 CPUState       *cpu,
                                 uint64_t        hypercall_arg)
{
    static char reason[1024];
    if (hypercall_enabled) {
        if (fast_reload_snapshot_exists(get_fast_reload_snapshot()) &&
            GET_GLOBAL_STATE()->in_fuzzing_mode)
        {
            // TODO: either remove or document + and apply for kasan/timeout as well
            if (hypercall_arg & 0x8000000000000000ULL) {
                reason[0] = '\x00';

                uint64_t address = hypercall_arg & 0x7FFFFFFFFFFFULL;
                uint64_t signal  = (hypercall_arg & 0x7800000000000ULL) >> 47;

                snprintf(reason, 1024, "PANIC IN USER MODE (SIG: %d\tat 0x%lx)\n",
                         (uint8_t)signal, address);
                set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                                  reason, strlen(reason));
            } else {
                switch (hypercall_arg) {
                case 0:
                    set_crash_reason_auxiliary_buffer(
                        GET_GLOBAL_STATE()->auxilary_buffer,
                        (char *)"PANIC IN KERNEL MODE!\n",
                        strlen("PANIC IN KERNEL MODE!\n"));
                    break;
                case 1:
                    set_crash_reason_auxiliary_buffer(
                        GET_GLOBAL_STATE()->auxilary_buffer,
                        (char *)"PANIC IN USER MODE!\n",
                        strlen("PANIC IN USER MODE!\n"));
                    break;
                default:
                    set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                                      (char *)"???\n",
                                                      strlen("???\n"));
                    break;
                }
            }
            synchronization_lock_crash_found();
        } else {
            nyx_abort("Agent has crashed before initializing the fuzzing loop...");
        }
    }
}

static void handle_hypercall_kafl_create_tmp_snapshot(struct kvm_run *run,
                                                      CPUState       *cpu,
                                                      uint64_t        hypercall_arg)
{
    if (!fast_reload_tmp_created(get_fast_reload_snapshot())) {
        /* decode PT data */
        pt_disable(qemu_get_cpu(0), false);

        request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                               REQUEST_SAVE_SNAPSHOT_TMP);
        set_tmp_snapshot_created(GET_GLOBAL_STATE()->auxilary_buffer, 1);
        handle_hypercall_kafl_release(run, cpu, hypercall_arg);
    } else {
        // TODO: raise an error?
    }
}

static void handle_hypercall_kafl_panic_extended(struct kvm_run *run,
                                                 CPUState       *cpu,
                                                 uint64_t        hypercall_arg)
{
    uint32_t hprintf_size = misc_data_size();
    read_virtual_memory(hypercall_arg, (uint8_t *)GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size, cpu);

    if (fast_reload_snapshot_exists(get_fast_reload_snapshot()) &&
        GET_GLOBAL_STATE()->in_fuzzing_mode)
    {
        set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                          GET_GLOBAL_STATE()->hprintf_tmp_buffer, strnlen(GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size));
        synchronization_lock_crash_found();
    } else {
        nyx_abort("Agent has crashed before initializing the fuzzing loop: %s",
                  GET_GLOBAL_STATE()->hprintf_tmp_buffer);
    }
}

static void handle_hypercall_kafl_kasan(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        if (fast_reload_snapshot_exists(get_fast_reload_snapshot())) {
            synchronization_lock_asan_found();
        } else {
            nyx_warn("KASAN detected during initialization stage!\n");
        }
    }
}

static void handle_hypercall_kafl_lock(struct kvm_run *run,
                                       CPUState       *cpu,
                                       uint64_t        hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_LOCK")) {
        return;
    }

    if (!GET_GLOBAL_STATE()->fast_reload_pre_image) {
        nyx_debug_p(CORE_PREFIX, "Skipping pre image creation (hint: set pre=on)\n");
        return;
    }

    nyx_debug_p(CORE_PREFIX, "Creating pre image snapshot <%s>\n",
                GET_GLOBAL_STATE()->fast_reload_pre_path);

    request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                           REQUEST_SAVE_SNAPSHOT_PRE);
}

static void handle_hypercall_kafl_printf(struct kvm_run *run,
                                         CPUState       *cpu,
                                         uint64_t        hypercall_arg)
{
    uint32_t hprintf_size = misc_data_size();
    read_virtual_memory(hypercall_arg, (uint8_t *)GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size, cpu);

    set_hprintf_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, GET_GLOBAL_STATE()->hprintf_tmp_buffer,
                                 strnlen(GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size));
    synchronization_lock();
}

static void handle_hypercall_kafl_user_range_advise(struct kvm_run *run,
                                                    CPUState       *cpu,
                                                    uint64_t        hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_USER_RANGE_ADVISE")) {
        return;
    }

    kAFL_ranges *buf = malloc(sizeof(kAFL_ranges));

    for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
        buf->ip[i]      = GET_GLOBAL_STATE()->pt_ip_filter_a[i];
        buf->size[i]    = (GET_GLOBAL_STATE()->pt_ip_filter_b[i] -
                        GET_GLOBAL_STATE()->pt_ip_filter_a[i]);
        buf->enabled[i] = (uint8_t)GET_GLOBAL_STATE()->pt_ip_filter_configured[i];
    }

    write_virtual_memory(hypercall_arg, (uint8_t *)buf, sizeof(kAFL_ranges), cpu);
    free(buf);
}

static void handle_hypercall_kafl_user_submit_mode(struct kvm_run *run,
                                                   CPUState       *cpu,
                                                   uint64_t        hypercall_arg)
{
    nyx_trace();

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_USER_SUBMIT_MODE")) {
        return;
    }

    switch (hypercall_arg) {
    case KAFL_MODE_64:
        nyx_debug_p(CORE_PREFIX, "SUBMIT_MODE set to KAFL_MODE_64\n");
        GET_GLOBAL_STATE()->disassembler_word_width = 64;
        break;
    case KAFL_MODE_32:
        nyx_debug_p(CORE_PREFIX, "SUBMIT_MODE set to KAFL_MODE_32\n");
        GET_GLOBAL_STATE()->disassembler_word_width = 32;
        break;
    case KAFL_MODE_16:
        /* not implemented in this version (due to hypertrash hacks) */
    default:
        nyx_abort("SUBMIT_MODE set to invalid value\n");
        break;
    }
}
/* =====================================================================
 * Async dump worker functions
 * ===================================================================== */

static void dump_job_free(dump_job_t *job)
{
    if (!job) return;
    for (int r = 0; r < job->num_regions; r++) {
        free(job->regions[r].data);
    }
    free(job->regions);
    free(job->dump_dir);
    free(job->map_content);
    free(job);
}

static void *dump_worker_func(void *arg)
{
    (void)arg;
    nyx_printf("[DUMP-WORKER] Thread started\n");

    while (1) {
        pthread_mutex_lock(&dump_queue_mutex);
        while (!dump_queue_head && !dump_worker_stop) {
            pthread_cond_wait(&dump_queue_cond, &dump_queue_mutex);
        }
        if (dump_worker_stop && !dump_queue_head) {
            pthread_mutex_unlock(&dump_queue_mutex);
            break;
        }
        dump_job_t *job = dump_queue_head;
        dump_queue_head = job->next;
        if (!dump_queue_head) dump_queue_tail = NULL;
        dump_queue_len--;
        pthread_mutex_unlock(&dump_queue_mutex);

        /* --- Emit phase: write captured data to disk --- */
        nyx_printf("[DUMP-WORKER] Writing job #%03d (%s): %d regions, %lu bytes\n",
                   job->seq, job->label, job->num_regions,
                   (unsigned long)job->total_bytes);

        mkdir(job->dump_dir, 0755);

        /* Write memory_map.txt */
        char *map_path = NULL;
        assert(asprintf(&map_path, "%s/memory_map.txt", job->dump_dir) != -1);
        FILE *map_f = fopen(map_path, "w");
        if (map_f) {
            fputs(job->map_content, map_f);
            fclose(map_f);
        }
        free(map_path);

        /* Write region files */
        for (int r = 0; r < job->num_regions; r++) {
            captured_region_t *reg = &job->regions[r];
            char perm_str[4];
            perm_str[0] = 'r';
            perm_str[1] = (reg->perm & 0x02) ? 'w' : '-';
            perm_str[2] = (reg->perm & 0x04) ? 'x' : '-';
            perm_str[3] = '\0';

            char *reg_path = NULL;
            assert(asprintf(&reg_path, "%s/region_%08x_%x_%s.bin",
                            job->dump_dir, reg->va_start,
                            reg->size, perm_str) != -1);
            FILE *rf = fopen(reg_path, "w");
            if (rf) {
                fwrite(reg->data, 1, reg->size, rf);
                fclose(rf);
            }
            free(reg_path);
        }

        nyx_printf("[DUMP-WORKER] Job #%03d done -> %s/\n",
                   job->seq, job->dump_dir);
        dump_job_free(job);
    }

    nyx_printf("[DUMP-WORKER] Thread exiting\n");
    return NULL;
}

static void dump_worker_init(void)
{
    if (dump_worker_running) return;
    dump_worker_stop = false;
    dump_queue_head = NULL;
    dump_queue_tail = NULL;
    dump_queue_len = 0;
    pthread_create(&dump_worker_thread, NULL, dump_worker_func, NULL);
    dump_worker_running = true;
    nyx_printf("[DUMP-WORKER] Initialized\n");
}

static void dump_worker_drain(void)
{
    if (!dump_worker_running) return;

    nyx_printf("[DUMP-WORKER] Draining %d pending jobs...\n", dump_queue_len);

    pthread_mutex_lock(&dump_queue_mutex);
    dump_worker_stop = true;
    pthread_cond_signal(&dump_queue_cond);
    pthread_mutex_unlock(&dump_queue_mutex);

    pthread_join(dump_worker_thread, NULL);
    dump_worker_running = false;
    nyx_printf("[DUMP-WORKER] All jobs drained, thread joined\n");
}

static void dump_worker_enqueue(dump_job_t *job)
{
    pthread_mutex_lock(&dump_queue_mutex);

    /* Backpressure: if queue is full, drop oldest job */
    while (dump_queue_len >= DUMP_QUEUE_MAX && dump_queue_head) {
        dump_job_t *old = dump_queue_head;
        dump_queue_head = old->next;
        if (!dump_queue_head) dump_queue_tail = NULL;
        dump_queue_len--;
        nyx_printf("[DUMP-WORKER] Queue full, dropping job #%03d (%s)\n",
                   old->seq, old->label);
        dump_job_free(old);
    }

    job->next = NULL;
    if (dump_queue_tail) {
        dump_queue_tail->next = job;
    } else {
        dump_queue_head = job;
    }
    dump_queue_tail = job;
    dump_queue_len++;

    pthread_cond_signal(&dump_queue_cond);
    pthread_mutex_unlock(&dump_queue_mutex);

    nyx_printf("[DUMP-WORKER] Enqueued job #%03d (%s), queue_len=%d\n",
               job->seq, job->label, dump_queue_len);
}

/* ===== Full process memory dump (capture + async emit) =====
 * Uses bulk page table walk + direct physical read.
 * Capture phase runs on VCPU thread (cpu_physical_memory_read).
 * Emit phase is enqueued to worker thread for async disk I/O.
 */
static void dump_full_process_memory(CPUState *cpu, CPUX86State *env,
                                     const char *label)
{
    int seq = dump_seq_counter++;

    /* Ensure worker is running */
    dump_worker_init();

    /* --- 1. Read TEB/PEB for module enumeration (32-bit WOW64) --- */
    uint32_t fs_base = (uint32_t)(env->segs[R_FS].base);
    uint32_t peb_ptr = 0;
    if (!read_virtual_memory((uint64_t)(fs_base + 0x30),
                             (uint8_t*)&peb_ptr, 4, cpu)) {
        nyx_printf("    [FULLDUMP] Failed to read PEB ptr (FS:0x%x+0x30)\n",
                   fs_base);
        return;
    }

    /* --- 2. Enumerate loaded modules via PEB->Ldr --- */
    dump_job_t *job = calloc(1, sizeof(dump_job_t));
    job->seq = seq;
    snprintf(job->label, sizeof(job->label), "%s", label);

    uint32_t ldr_ptr = 0;
    if (read_virtual_memory((uint64_t)(peb_ptr + 0x0C),
                            (uint8_t*)&ldr_ptr, 4, cpu) && ldr_ptr != 0) {
        uint32_t list_head = ldr_ptr + 0x14;
        uint32_t flink = 0;
        read_virtual_memory((uint64_t)list_head, (uint8_t*)&flink, 4, cpu);

        uint32_t cur = flink;
        while (cur != 0 && cur != list_head && job->num_modules < MAX_MODS) {
            uint32_t dll_base = 0, dll_size = 0;
            read_virtual_memory((uint64_t)(cur + 0x10), (uint8_t*)&dll_base, 4, cpu);
            read_virtual_memory((uint64_t)(cur + 0x18), (uint8_t*)&dll_size, 4, cpu);

            uint16_t name_len = 0;
            uint32_t name_buf = 0;
            read_virtual_memory((uint64_t)(cur + 0x24), (uint8_t*)&name_len, 2, cpu);
            read_virtual_memory((uint64_t)(cur + 0x24 + 4), (uint8_t*)&name_buf, 4, cpu);

            job->modules[job->num_modules].base = dll_base;
            job->modules[job->num_modules].size = dll_size;
            memset(job->modules[job->num_modules].name, 0, 128);

            if (name_len > 0 && name_buf != 0) {
                uint16_t wbuf[128];
                memset(wbuf, 0, sizeof(wbuf));
                int nchars = (name_len / 2 < 127) ? name_len / 2 : 127;
                read_virtual_memory((uint64_t)name_buf, (uint8_t*)wbuf,
                                    nchars * 2, cpu);
                for (int c = 0; c < nchars; c++)
                    job->modules[job->num_modules].name[c] =
                        (char)(wbuf[c] & 0xFF);
            }

            job->num_modules++;

            uint32_t next = 0;
            if (!read_virtual_memory((uint64_t)cur, (uint8_t*)&next, 4, cpu))
                break;
            if (next == cur) break;
            cur = next;
        }
    }

    nyx_printf("    [FULLDUMP] #%03d (%s): PEB=0x%x, %d modules loaded\n",
               seq, label, peb_ptr, job->num_modules);

    /* --- 3. Create dump directory path --- */
    assert(asprintf(&job->dump_dir, "%s/dump/fulldump_%03d_%s",
                    GET_GLOBAL_STATE()->workdir_path, seq, label) != -1);

    /* --- 4. Bulk page table walk to collect mapped user-space pages --- */
    int pg_capacity = 65536;
    int pg_count = 0;
    mapped_page_t *pages = malloc(pg_capacity * sizeof(mapped_page_t));

    uint64_t cr3 = env->cr[3];
    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    uint64_t pml4e = pml4_table[0];
    if (pml4e & 1) {
        bool pml4_w = !!(pml4e & (1ULL << 1));
        bool pml4_x = !(pml4e & (1ULL << 63));

        uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
        uint64_t pdpt_table[512];
        cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

        for (int pdpte_idx = 0; pdpte_idx < 2; pdpte_idx++) {
            uint64_t pdpte = pdpt_table[pdpte_idx];
            if (!(pdpte & 1)) continue;
            if (pdpte & (1ULL << 7)) continue;

            bool pdpt_w = pml4_w && !!(pdpte & (1ULL << 1));
            bool pdpt_x = pml4_x && !(pdpte & (1ULL << 63));

            uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
            uint64_t pd_table[512];
            cpu_physical_memory_read(pd_base, pd_table, 4096);

            for (int pde_idx = 0; pde_idx < 512; pde_idx++) {
                uint64_t pde = pd_table[pde_idx];
                if (!(pde & 1)) continue;

                bool pd_w = pdpt_w && !!(pde & (1ULL << 1));
                bool pd_x = pdpt_x && !(pde & (1ULL << 63));

                if (pde & (1ULL << 7)) {
                    uint64_t page_phys = pde & 0x000FFFFFFFE00000ULL;
                    uint32_t base_va = ((uint32_t)pdpte_idx << 30) |
                                       ((uint32_t)pde_idx << 21);
                    for (int k = 0; k < 512; k++) {
                        uint32_t va = base_va + ((uint32_t)k << 12);
                        if (va < 0x10000 || va >= 0x7FFF0000) continue;
                        if (pg_count >= pg_capacity) {
                            pg_capacity *= 2;
                            pages = realloc(pages,
                                            pg_capacity * sizeof(mapped_page_t));
                        }
                        pages[pg_count].va   = va;
                        pages[pg_count].phys = page_phys + ((uint64_t)k << 12);
                        pages[pg_count].perm = 0x01
                                             | (pd_w ? 0x02 : 0)
                                             | (pd_x ? 0x04 : 0);
                        pg_count++;
                    }
                    continue;
                }

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

                    uint64_t phys = pte & 0x000FFFFFFFFFF000ULL;
                    bool w = pd_w && !!(pte & (1ULL << 1));
                    bool x = pd_x && !(pte & (1ULL << 63));

                    if (pg_count >= pg_capacity) {
                        pg_capacity *= 2;
                        pages = realloc(pages,
                                        pg_capacity * sizeof(mapped_page_t));
                    }
                    pages[pg_count].va   = va;
                    pages[pg_count].phys = phys;
                    pages[pg_count].perm = 0x01
                                         | (w ? 0x02 : 0)
                                         | (x ? 0x04 : 0);
                    pg_count++;
                }
            }
        }
    }

    nyx_printf("    [FULLDUMP] PT walk done: %d mapped pages\n", pg_count);

    /* --- 5. Capture: read physical memory into buffers (VCPU thread) --- */
    int reg_capacity = 1024;
    int reg_count = 0;
    captured_region_t *regions = malloc(reg_capacity * sizeof(captured_region_t));
    uint64_t total_bytes = 0;

    /* Build memory_map.txt content in a buffer */
    size_t map_buf_size = 65536;
    size_t map_buf_used = 0;
    char *map_buf = malloc(map_buf_size);

    map_buf_used += snprintf(map_buf + map_buf_used, map_buf_size - map_buf_used,
                             "# Full process memory dump #%03d\n"
                             "# Trigger: %s\n"
                             "# Modules: %d\n\n"
                             "# %-10s  %-10s  %-10s  %-5s  %-40s  %s\n",
                             seq, label, job->num_modules,
                             "START", "END", "SIZE", "PERM", "FILE", "MODULE");

    for (int m = 0; m < job->num_modules; m++) {
        map_buf_used += snprintf(map_buf + map_buf_used, map_buf_size - map_buf_used,
                                 "# MODULE: %-30s  base=0x%08x  size=0x%08x\n",
                                 job->modules[m].name,
                                 job->modules[m].base,
                                 job->modules[m].size);
    }
    map_buf_used += snprintf(map_buf + map_buf_used, map_buf_size - map_buf_used, "\n");

    int pi = 0;
    while (pi < pg_count) {
        uint32_t region_start = pages[pi].va;
        uint8_t  region_perm  = pages[pi].perm;
        int      region_first = pi;

        while (pi + 1 < pg_count &&
               pages[pi + 1].va == pages[pi].va + 0x1000 &&
               pages[pi + 1].perm == region_perm) {
            pi++;
        }
        int region_last = pi;
        pi++;

        int n_pages = region_last - region_first + 1;
        uint32_t region_size = (uint32_t)n_pages * 0x1000;

        /* Capture: read all pages into a contiguous buffer */
        uint8_t *data = malloc(region_size);
        for (int p = 0; p < n_pages; p++) {
            cpu_physical_memory_read(pages[region_first + p].phys,
                                     data + p * 0x1000, 0x1000);
        }

        if (reg_count >= reg_capacity) {
            reg_capacity *= 2;
            regions = realloc(regions, reg_capacity * sizeof(captured_region_t));
        }
        regions[reg_count].va_start  = region_start;
        regions[reg_count].size      = region_size;
        regions[reg_count].perm      = region_perm;
        regions[reg_count].data      = data;
        regions[reg_count].num_pages = n_pages;
        reg_count++;
        total_bytes += region_size;

        /* Append to map content */
        char perm_str[4];
        perm_str[0] = 'r';
        perm_str[1] = (region_perm & 0x02) ? 'w' : '-';
        perm_str[2] = (region_perm & 0x04) ? 'x' : '-';
        perm_str[3] = '\0';

        const char *mod_name = NULL;
        for (int m = 0; m < job->num_modules; m++) {
            if (region_start >= job->modules[m].base &&
                region_start < job->modules[m].base + job->modules[m].size) {
                mod_name = job->modules[m].name;
                break;
            }
        }

        if (map_buf_used + 256 > map_buf_size) {
            map_buf_size *= 2;
            map_buf = realloc(map_buf, map_buf_size);
        }
        map_buf_used += snprintf(map_buf + map_buf_used, map_buf_size - map_buf_used,
                                 "  0x%08x  0x%08x  0x%08x  %-5s  "
                                 "region_%08x_%x_%s.bin  %s\n",
                                 region_start, region_start + region_size,
                                 region_size, perm_str,
                                 region_start, region_size, perm_str,
                                 mod_name ? mod_name : "");
    }

    if (map_buf_used + 128 > map_buf_size) {
        map_buf_size += 256;
        map_buf = realloc(map_buf, map_buf_size);
    }
    map_buf_used += snprintf(map_buf + map_buf_used, map_buf_size - map_buf_used,
                             "\n# Total: %d regions, %lu bytes (%d pages)\n",
                             reg_count, (unsigned long)total_bytes, pg_count);

    free(pages);

    /* --- 6. Enqueue job for async disk write --- */
    job->regions     = regions;
    job->num_regions = reg_count;
    job->total_bytes = total_bytes;
    job->map_content = map_buf;

    nyx_printf("    [FULLDUMP] Captured %d regions (%lu bytes) - enqueueing\n",
               reg_count, (unsigned long)total_bytes);

    dump_worker_enqueue(job);
}


/* =====================================================================
 * W⊕X (Write-then-Execute) Detection
 *
 * Detects unpacked code by finding pages that were:
 *   1. Written to AFTER the initial snapshot (PTE Dirty Bit tracking)
 *   2. Actually executed (Intel PT → page_cache tracking)
 *
 * Architecture:
 *   - Write tracking: x86 PTE Dirty Bit (bit 6), set automatically by CPU
 *   - Execute tracking: Intel PT → libxdc decode → page_cache hash keys
 *   - Detection: intersection of {newly written} ∩ {executed}
 * ===================================================================== */

#define WOX_USER_VA_START  0x10000
#define WOX_USER_VA_END    0x7FFF0000
#define WOX_PAGE_COUNT     ((WOX_USER_VA_END - WOX_USER_VA_START) / 0x1000)
#define WOX_BITMAP_BYTES   ((WOX_PAGE_COUNT + 7) / 8)

static uint8_t *wox_dirty_snapshot = NULL;
static bool     wox_snapshot_taken = false;
static int      wox_check_counter  = 0;
static uint8_t *wox_dirty_cumulative = NULL;  /* union of all observed dirty pages */
static uint8_t *wox_exec_baseline = NULL;     /* executed pages bitmap at round start */
static mod_info_t *wox_cached_modules = NULL;  /* cached module list from first successful PEB walk */
static int         wox_cached_num_modules = 0;
static uint8_t   **wox_page_content = NULL;   /* per-page content snapshot */
static uint8_t    *wox_page_present = NULL;   /* bitmap: pages mapped at snapshot */
static int         wox_content_snapshot_pages = 0;

static inline int wox_va_to_idx(uint32_t va)
{
    return (int)((va - WOX_USER_VA_START) / 0x1000);
}

static inline void wox_bitmap_set(uint8_t *bm, int idx)
{
    bm[idx >> 3] |= (1 << (idx & 7));
}

static inline bool wox_bitmap_test(const uint8_t *bm, int idx)
{
    return !!(bm[idx >> 3] & (1 << (idx & 7)));
}

/*
 * Bulk page-table walk collecting PTE Dirty bits for all mapped user pages.
 * Reuses the same PML4→PDPT→PD→PT pattern as dump_full_process_memory().
 */
static void wox_collect_dirty_bits(CPUX86State *env, uint8_t *bitmap)
{
    memset(bitmap, 0, WOX_BITMAP_BYTES);

    uint64_t cr3 = env->cr[3];
    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    uint64_t pml4e = pml4_table[0];
    if (!(pml4e & 1)) return;

    uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    uint64_t pdpt_table[512];
    cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

    for (int pdpte_idx = 0; pdpte_idx < 2; pdpte_idx++) {
        uint64_t pdpte = pdpt_table[pdpte_idx];
        if (!(pdpte & 1)) continue;
        if (pdpte & (1ULL << 7)) continue;  /* 1GB huge page — skip */

        uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
        uint64_t pd_table[512];
        cpu_physical_memory_read(pd_base, pd_table, 4096);

        for (int pde_idx = 0; pde_idx < 512; pde_idx++) {
            uint64_t pde = pd_table[pde_idx];
            if (!(pde & 1)) continue;

            if (pde & (1ULL << 7)) {
                /* 2MB huge page — dirty bit is on the PDE itself */
                if (!(pde & (1ULL << 6))) continue;  /* not dirty */
                uint32_t base_va = ((uint32_t)pdpte_idx << 30) |
                                   ((uint32_t)pde_idx << 21);
                for (int k = 0; k < 512; k++) {
                    uint32_t va = base_va + ((uint32_t)k << 12);
                    if (va >= WOX_USER_VA_START && va < WOX_USER_VA_END)
                        wox_bitmap_set(bitmap, wox_va_to_idx(va));
                }
                continue;
            }

            /* 4KB pages */
            uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
            uint64_t pt_table[512];
            cpu_physical_memory_read(pt_base, pt_table, 4096);

            for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                uint64_t pte = pt_table[pte_idx];
                if (!(pte & 1)) continue;
                if (!(pte & (1ULL << 6))) continue;  /* not dirty */

                uint32_t va = ((uint32_t)pdpte_idx << 30) |
                              ((uint32_t)pde_idx << 21) |
                              ((uint32_t)pte_idx << 12);
                if (va >= WOX_USER_VA_START && va < WOX_USER_VA_END)
                    wox_bitmap_set(bitmap, wox_va_to_idx(va));
            }
        }
    }
}

/*
 * Capture content of all mapped user-space pages (baseline for byte-level diff).
 */
static void wox_take_content_snapshot(CPUState *cpu, CPUX86State *env)
{
    if (!wox_page_content)
        wox_page_content = calloc(WOX_PAGE_COUNT, sizeof(uint8_t *));
    if (!wox_page_present)
        wox_page_present = calloc(1, WOX_BITMAP_BYTES);

    /* Free old content if re-snapshotting */
    for (int i = 0; i < WOX_PAGE_COUNT; i++) {
        if (wox_page_content[i]) {
            free(wox_page_content[i]);
            wox_page_content[i] = NULL;
        }
    }
    memset(wox_page_present, 0, WOX_BITMAP_BYTES);
    wox_content_snapshot_pages = 0;

    uint64_t cr3 = env->cr[3];
    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    uint64_t pml4e = pml4_table[0];
    if (!(pml4e & 1)) return;

    uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
    uint64_t pdpt_table[512];
    cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

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
                uint64_t page_phys = pde & 0x000FFFFFFFE00000ULL;
                uint32_t base_va = ((uint32_t)pdpte_idx << 30) |
                                   ((uint32_t)pde_idx << 21);
                for (int k = 0; k < 512; k++) {
                    uint32_t va = base_va + ((uint32_t)k << 12);
                    if (va < WOX_USER_VA_START || va >= WOX_USER_VA_END) continue;
                    int idx = wox_va_to_idx(va);
                    wox_page_content[idx] = malloc(0x1000);
                    cpu_physical_memory_read(page_phys + ((uint64_t)k << 12),
                                            wox_page_content[idx], 0x1000);
                    wox_bitmap_set(wox_page_present, idx);
                    wox_content_snapshot_pages++;
                }
                continue;
            }

            uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
            uint64_t pt_table[512];
            cpu_physical_memory_read(pt_base, pt_table, 4096);

            for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                uint64_t pte = pt_table[pte_idx];
                if (!(pte & 1)) continue;

                uint32_t va = ((uint32_t)pdpte_idx << 30) |
                              ((uint32_t)pde_idx << 21) |
                              ((uint32_t)pte_idx << 12);
                if (va < WOX_USER_VA_START || va >= WOX_USER_VA_END) continue;

                uint64_t phys = pte & 0x000FFFFFFFFFF000ULL;
                int idx = wox_va_to_idx(va);
                wox_page_content[idx] = malloc(0x1000);
                cpu_physical_memory_read(phys, wox_page_content[idx], 0x1000);
                wox_bitmap_set(wox_page_present, idx);
                wox_content_snapshot_pages++;
            }
        }
    }

    nyx_printf("[WOX] Content snapshot: %d pages captured (%d MB)\n",
               wox_content_snapshot_pages,
               (wox_content_snapshot_pages * 4096) / (1024 * 1024));
}

/*
 * Take initial PTE dirty-bit snapshot (baseline before unpacking).
 */
void wox_take_snapshot(CPUState *cpu)
{
    CPUX86State *env = &(X86_CPU(cpu)->env);
    if (!wox_dirty_snapshot) {
        wox_dirty_snapshot = calloc(1, WOX_BITMAP_BYTES);
    }
    wox_collect_dirty_bits(env, wox_dirty_snapshot);
    wox_snapshot_taken = true;

    /* Count baseline dirty pages */
    int baseline = 0;
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t v = wox_dirty_snapshot[i];
        while (v) { baseline++; v &= v - 1; }
    }
    nyx_printf("[WOX] Dirty-bit snapshot taken: %d baseline dirty pages\n",
               baseline);

    /* Content snapshot only at initial ACQUIRE (harness CR3, small).
     * Skip during round reset (target CR3, thousands of pages = too slow). */
    static bool initial_snapshot_done = false;
    if (!initial_snapshot_done) {
        wox_take_content_snapshot(cpu, env);
        initial_snapshot_done = true;
    }
}

/*
 * Log all newly-written (dirty) page addresses in user-space.
 *
 * Groups contiguous pages into regions and cross-references with loaded
 * modules via PEB->Ldr walk.  Output goes to both nyx_printf (console)
 * and a file under <workdir>/dump/dirty_log_<id>_<trigger>.txt.
 *
 * This is the "Write side" diagnostic: useful for verifying that the
 * packer's memory writes are correctly tracked before Intel PT (Execute
 * side) is activated.
 */
static void wox_log_written_pages(CPUState *cpu, CPUX86State *env,
                                  const uint8_t *newly_dirty,
                                  int newly_dirty_count,
                                  int check_id, const char *trigger)
{
    if (newly_dirty_count == 0) {
        nyx_printf("[DIRTY] Check #%d (%s): no newly written pages\n",
                   check_id, trigger);
        return;
    }

    /* --- 1. Collect all newly dirty VAs --- */
    int va_cap = newly_dirty_count + 16;
    uint32_t *dirty_vas = malloc(va_cap * sizeof(uint32_t));
    int va_count = 0;

    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t byte = newly_dirty[i];
        if (!byte) continue;
        for (int bit = 0; bit < 8; bit++) {
            if (byte & (1 << bit)) {
                int idx = i * 8 + bit;
                uint32_t va = WOX_USER_VA_START + (uint32_t)idx * 0x1000;
                if (va_count < va_cap)
                    dirty_vas[va_count++] = va;
            }
        }
    }

    /* --- 2. Enumerate modules for attribution (with cache) --- */
    mod_info_t *modules = NULL;
    int num_modules = 0;

    if (wox_cached_modules && wox_cached_num_modules > 0) {
        /* Use cached module list from previous successful PEB walk */
        modules = wox_cached_modules;
        num_modules = wox_cached_num_modules;
    } else {
        /* Try PEB walk */
        uint32_t fs_base = (uint32_t)(env->segs[R_FS].base);
        uint32_t peb_ptr = 0;
        modules = calloc(MAX_MODS, sizeof(mod_info_t));

        if (read_virtual_memory((uint64_t)(fs_base + 0x30),
                                (uint8_t*)&peb_ptr, 4, cpu) && peb_ptr != 0) {
            uint32_t ldr_ptr = 0;
            if (read_virtual_memory((uint64_t)(peb_ptr + 0x0C),
                                    (uint8_t*)&ldr_ptr, 4, cpu) && ldr_ptr != 0) {
                uint32_t list_head = ldr_ptr + 0x14;
                uint32_t flink = 0;
                read_virtual_memory((uint64_t)list_head, (uint8_t*)&flink, 4, cpu);

                uint32_t cur = flink;
                while (cur != 0 && cur != list_head && num_modules < MAX_MODS) {
                    uint32_t dll_base = 0, dll_size = 0;
                    read_virtual_memory((uint64_t)(cur + 0x10),
                                        (uint8_t*)&dll_base, 4, cpu);
                    read_virtual_memory((uint64_t)(cur + 0x18),
                                        (uint8_t*)&dll_size, 4, cpu);

                    uint16_t name_len = 0;
                    uint32_t name_buf = 0;
                    read_virtual_memory((uint64_t)(cur + 0x24),
                                        (uint8_t*)&name_len, 2, cpu);
                    read_virtual_memory((uint64_t)(cur + 0x24 + 4),
                                        (uint8_t*)&name_buf, 4, cpu);

                    modules[num_modules].base = dll_base;
                    modules[num_modules].size = dll_size;
                    memset(modules[num_modules].name, 0, 128);

                    if (name_len > 0 && name_buf != 0) {
                        uint16_t wbuf[128];
                        memset(wbuf, 0, sizeof(wbuf));
                        int nchars = (name_len / 2 < 127) ? name_len / 2 : 127;
                        read_virtual_memory((uint64_t)name_buf,
                                            (uint8_t*)wbuf, nchars * 2, cpu);
                        for (int c = 0; c < nchars; c++)
                            modules[num_modules].name[c] = (char)(wbuf[c] & 0xFF);
                    }
                    num_modules++;

                    uint32_t next = 0;
                    if (!read_virtual_memory((uint64_t)cur, (uint8_t*)&next, 4, cpu))
                        break;
                    if (next == cur) break;
                    cur = next;
                }
            }
        }

        /* Cache on first successful walk */
        if (num_modules > 0 && !wox_cached_modules) {
            wox_cached_modules = modules;
            wox_cached_num_modules = num_modules;
        }
    }

    /* --- 3. Group contiguous pages into regions --- */
    typedef struct { uint32_t start; uint32_t end; int page_count; } dirty_region_t;
    int reg_cap = 512;
    dirty_region_t *regions = malloc(reg_cap * sizeof(dirty_region_t));
    int reg_count = 0;

    int ri = 0;
    while (ri < va_count) {
        uint32_t region_start = dirty_vas[ri];
        uint32_t region_end   = dirty_vas[ri] + 0x1000;
        int      pg = 1;
        while (ri + 1 < va_count &&
               dirty_vas[ri + 1] == dirty_vas[ri] + 0x1000) {
            ri++;
            region_end = dirty_vas[ri] + 0x1000;
            pg++;
        }
        ri++;
        if (reg_count < reg_cap) {
            regions[reg_count].start      = region_start;
            regions[reg_count].end        = region_end;
            regions[reg_count].page_count = pg;
            reg_count++;
        }
    }

    /* --- 4. Log to console --- */
    nyx_printf("[DIRTY] Check #%d (%s): %d newly written pages in %d regions\n",
               check_id, trigger, newly_dirty_count, reg_count);

    for (int r = 0; r < reg_count; r++) {
        const char *mod_name = NULL;
        for (int m = 0; m < num_modules; m++) {
            if (regions[r].start >= modules[m].base &&
                regions[r].start < modules[m].base + modules[m].size) {
                mod_name = modules[m].name;
                break;
            }
        }
        nyx_printf("[DIRTY]   0x%08x - 0x%08x  (%3d pages, 0x%x bytes)  %s\n",
                   regions[r].start, regions[r].end,
                   regions[r].page_count,
                   regions[r].page_count * 0x1000,
                   mod_name ? mod_name : "(unmapped/heap/stack)");
    }

    /* --- 5. Save to file --- */
    char *dump_base = NULL;
    assert(asprintf(&dump_base, "%s/dump",
                    GET_GLOBAL_STATE()->workdir_path) != -1);
    mkdir(dump_base, 0755);
    free(dump_base);

    char *log_path = NULL;
    assert(asprintf(&log_path, "%s/dump/dirty_log_%03d_%s.txt",
                    GET_GLOBAL_STATE()->workdir_path,
                    check_id, trigger) != -1);
    FILE *lf = fopen(log_path, "w");
    if (lf) {
        fprintf(lf, "# Dirty Page Log (Write Tracking)\n");
        fprintf(lf, "# Check: #%d\n", check_id);
        fprintf(lf, "# Trigger: %s\n", trigger);
        fprintf(lf, "# Total newly written pages: %d\n", newly_dirty_count);
        fprintf(lf, "# Contiguous regions: %d\n", reg_count);
        fprintf(lf, "# Modules loaded: %d\n\n", num_modules);

        fprintf(lf, "# %-12s  %-12s  %-8s  %-10s  %s\n",
                "START", "END", "PAGES", "SIZE", "MODULE");
        for (int r = 0; r < reg_count; r++) {
            const char *mod_name = NULL;
            for (int m = 0; m < num_modules; m++) {
                if (regions[r].start >= modules[m].base &&
                    regions[r].start < modules[m].base + modules[m].size) {
                    mod_name = modules[m].name;
                    break;
                }
            }
            fprintf(lf, "  0x%08x    0x%08x    %5d     0x%08x  %s\n",
                    regions[r].start, regions[r].end,
                    regions[r].page_count,
                    regions[r].page_count * 0x1000,
                    mod_name ? mod_name : "(unmapped/heap/stack)");
        }

        fprintf(lf, "\n# Individual pages:\n");
        for (int v = 0; v < va_count; v++) {
            fprintf(lf, "0x%08x\n", dirty_vas[v]);
        }
        fclose(lf);
        nyx_printf("[DIRTY] Log saved: %s\n", log_path);
    }

    free(log_path);
    free(regions);
    if (modules != wox_cached_modules) free(modules);
    free(dirty_vas);
}

/*
 * Periodic dirty-page scanner — runs from pt_post_kvm_run() on every
 * VM exit, rate-limited to once per 500 ms.  Completely independent
 * of the API-hook path so that background packer writes are captured
 * even when no hook fires.
 */
void wox_periodic_dirty_scan(CPUState *cpu)
{
    /* --- 0. Quick guards (cheapest first) --- */
    if (!wox_snapshot_taken)
        return;

    uint64_t target_cr3 = GET_GLOBAL_STATE()->parent_cr3;
    if (target_cr3 == 0)
        return;

    CPUX86State *env = &(X86_CPU(cpu)->env);
    uint64_t current_cr3 = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;
    if (current_cr3 != target_cr3)
        return;                       /* not in target process context */

    /* --- 1. Rate-limit: 500 ms between scans --- */
    static struct timespec last_scan = {0, 0};
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    long elapsed_ms = (now.tv_sec  - last_scan.tv_sec)  * 1000
                    + (now.tv_nsec - last_scan.tv_nsec) / 1000000;
    if (elapsed_ms < 500)
        return;
    last_scan = now;

    /* --- 2. Collect dirty bits & compute newly-dirty set --- */
    static int periodic_counter = 0;
    static int wox_round = 0;
    int check_id = periodic_counter++;

    uint8_t *current_dirty = calloc(1, WOX_BITMAP_BYTES);
    wox_collect_dirty_bits(env, current_dirty);

    uint8_t *newly_dirty = calloc(1, WOX_BITMAP_BYTES);
    int newly_dirty_count = 0;
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        newly_dirty[i] = current_dirty[i] & ~wox_dirty_snapshot[i];
        uint8_t v = newly_dirty[i];
        while (v) { newly_dirty_count++; v &= v - 1; }
    }

    /* --- Accumulate into cumulative bitmap --- */
    if (!wox_dirty_cumulative)
        wox_dirty_cumulative = calloc(1, WOX_BITMAP_BYTES);
    for (int i = 0; i < WOX_BITMAP_BYTES; i++)
        wox_dirty_cumulative[i] |= newly_dirty[i];

    /* Count cumulative dirty pages for logging */
    int cumulative_count = 0;
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t v = wox_dirty_cumulative[i];
        while (v) { cumulative_count++; v &= v - 1; }
    }

    free(newly_dirty);
    free(current_dirty);

    /* --- 3. Real-time W⊕X cross-check: dirty ∩ executed --- */
    page_cache_t *pc = GET_GLOBAL_STATE()->page_cache;
    if (!pc || !GET_GLOBAL_STATE()->decoder) {
        /* Decoder not yet initialized — skip execute-side check.
         * Still accumulate dirty pages above for when decoder is ready. */
        nyx_printf("[WOX] Scan #%d: %d cumulative dirty pages (decoder not ready)\n",
                   check_id, cumulative_count);
        return;
    }

    /* Flush pending PT data so page_cache is fully up to date */
    pt_handle_overflow(cpu);

    /* Get executed pages from page_cache (populated by libxdc_decode) */
    int max_exec = 65536;
    uint64_t *exec_pages = malloc(max_exec * sizeof(uint64_t));
    int exec_count = page_cache_get_executed_pages(pc, exec_pages, max_exec);

    /* Build bitmap of currently-executed pages in user VA range */
    uint8_t *exec_bitmap = calloc(1, WOX_BITMAP_BYTES);
    for (int e = 0; e < exec_count; e++) {
        uint64_t va = exec_pages[e];
        if (va >= WOX_USER_VA_START && va < WOX_USER_VA_END)
            wox_bitmap_set(exec_bitmap, wox_va_to_idx((uint32_t)va));
    }

    /* Determine newly-executed pages (not in baseline from last round) */
    uint8_t *new_exec = calloc(1, WOX_BITMAP_BYTES);
    int new_exec_count = 0;
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        new_exec[i] = exec_bitmap[i] & ~(wox_exec_baseline ? wox_exec_baseline[i] : 0);
        uint8_t v = new_exec[i];
        while (v) { new_exec_count++; v &= v - 1; }
    }

    /* Cross-check: pages both written (dirty) AND executed since round start */
    int wox_count = 0;
    int wox_addrs_cap = 4096;
    uint32_t *wox_addrs = malloc(wox_addrs_cap * sizeof(uint32_t));

    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t wox_byte = wox_dirty_cumulative[i] & new_exec[i];
        if (!wox_byte) continue;
        for (int bit = 0; bit < 8; bit++) {
            if (wox_byte & (1 << bit)) {
                int idx = i * 8 + bit;
                uint32_t va = WOX_USER_VA_START + (uint32_t)idx * 0x1000;
                if (wox_count < wox_addrs_cap)
                    wox_addrs[wox_count] = va;
                wox_count++;
            }
        }
    }

    nyx_printf("[WOX] Scan #%d: dirty=%d, exec=%d (new=%d), W+X=%d\n",
               check_id, cumulative_count, exec_count, new_exec_count, wox_count);

    free(new_exec);
    free(exec_bitmap);

    /* --- 4. W⊕X detected! Dump memory and reset round --- */
    if (wox_count > 0) {
        nyx_printf("\n");
        nyx_printf("==================================================\n");
        nyx_printf("[WOX] *** WRITE-THEN-EXECUTE DETECTED (round %d) ***\n", wox_round);
        nyx_printf("[WOX] %d pages were written and then executed:\n", wox_count);

        /* Save W⊕X detection report */
        char *report_path = NULL;
        assert(asprintf(&report_path, "%s/dump/wox_detect_round%d.txt",
                        GET_GLOBAL_STATE()->workdir_path, wox_round) != -1);
        FILE *rf = fopen(report_path, "w");
        if (rf) {
            fprintf(rf, "# W⊕X Detection Report — Round %d\n", wox_round);
            fprintf(rf, "# Scan #%d\n", check_id);
            fprintf(rf, "# Cumulative dirty pages: %d\n", cumulative_count);
            fprintf(rf, "# Executed pages (PT): %d\n", exec_count);
            fprintf(rf, "# W⊕X pages: %d\n\n", wox_count);
            for (int w = 0; w < wox_count && w < wox_addrs_cap; w++) {
                fprintf(rf, "0x%08x\n", wox_addrs[w]);
                nyx_printf("[WOX]   0x%08x\n", wox_addrs[w]);
            }
            fclose(rf);
            nyx_printf("[WOX] Report saved: %s\n", report_path);
        }
        free(report_path);

        nyx_printf("[WOX] Triggering full process memory dump...\n");
        nyx_printf("==================================================\n\n");

        /* Dump full process memory */
        char dump_label[64];
        snprintf(dump_label, sizeof(dump_label), "wox_round%d", wox_round);
        // [TEST]         dump_full_process_memory(cpu, env, dump_label);

        /* Reset for next round */
        wox_round++;
        wox_reset_round(cpu);

        /* Exec baseline is saved inside wox_reset_round() so the
         * next round only detects NEW write-then-execute pages. */
    }

    free(wox_addrs);
    free(exec_pages);
}

/* Forward declaration */
static void wox_content_diff_report(CPUState *cpu, CPUX86State *env);

/*
 * Final dirty-page report — called at program termination
 * (HYPERCALL_KAFL_RELEASE).  Prints all pages that were written
 * after the baseline snapshot, regardless of execution status.
 */

/*
 * wox_offline_pt_decode - Deferred PT trace decoding at RELEASE time.
 *
 * Instead of decoding PT traces in real-time (which adds per-KVM-exit
 * overhead and kills VMP-packed GUI apps), we:
 *   1. Let PT hardware collect raw traces during execution (decoder==NULL)
 *   2. After synchronization_disable_pt() flushes the last traces,
 *      initialize the decoder here and bulk-decode the entire dump file.
 *   3. This populates page_cache with executed-page addresses so
 *      wox_final_wox_check() can perform the W+X cross-check.
 */
static void wox_offline_pt_decode(CPUState *cpu)
{
    if (GET_GLOBAL_STATE()->decoder) {
        nyx_printf("[WOX] Decoder already initialized, skipping offline decode\n");
        return;
    }

    /* Initialize decoder (same as pt_init_decoder but called at RELEASE) */
    if (GET_GLOBAL_STATE()->nyx_pt &&
        GET_GLOBAL_STATE()->cap_compile_time_tracing == false) {
        pt_init_decoder(cpu);
        nyx_printf("[WOX] PT decoder initialized (offline/deferred mode)\n");
    }

    if (!GET_GLOBAL_STATE()->decoder) {
        nyx_printf("[WOX] No decoder available, skipping offline decode\n");
        return;
    }

    /* Build PT dump file path: {workdir}/pt_trace_dump_0 */
    char *dump_path = NULL;
    assert(asprintf(&dump_path, "%s/pt_trace_dump_0",
                    GET_GLOBAL_STATE()->workdir_path) != -1);

    /* Read the entire raw PT dump file */
    int fd = open(dump_path, O_RDONLY);
    if (fd < 0) {
        nyx_printf("[WOX] Cannot open PT dump file %s: %s\n",
                   dump_path, strerror(errno));
        free(dump_path);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) {
        nyx_printf("[WOX] PT dump file empty or stat failed\n");
        close(fd);
        free(dump_path);
        return;
    }

    /* +1 for libxdc sentinel byte (0x55) required at data[len] */
    uint8_t *buf = malloc(st.st_size + 1);
    if (!buf) {
        nyx_printf("[WOX] Failed to allocate %ld bytes for PT decode\n",
                   (long)st.st_size);
        close(fd);
        free(dump_path);
        return;
    }

    ssize_t nread = read(fd, buf, st.st_size);
    close(fd);

    if (nread != st.st_size) {
        nyx_printf("[WOX] Short read: %ld / %ld bytes\n",
                   (long)nread, (long)st.st_size);
        free(buf);
        free(dump_path);
        return;
    }

    /* libxdc_decode asserts data[len] == 0x55 as sentinel */
    buf[st.st_size] = 0x55;

    nyx_printf("[WOX] Offline PT decode: %ld bytes from %s\n",
               (long)st.st_size, dump_path);

    /* Bulk decode — feed entire trace at once */
    decoder_result_t result =
        libxdc_decode(GET_GLOBAL_STATE()->decoder, buf, (size_t)st.st_size);

    switch (result) {
    case decoder_success:
        nyx_printf("[WOX] Offline decode: success\n");
        break;
    case decoder_success_pt_overflow:
        nyx_printf("[WOX] Offline decode: success (PT overflow detected)\n");
        break;
    case decoder_page_fault:
        nyx_printf("[WOX] Offline decode: page fault at 0x%lx\n",
                   libxdc_get_page_fault_addr(GET_GLOBAL_STATE()->decoder));
        break;
    case decoder_unkown_packet:
        nyx_printf("[WOX] Offline decode: unknown packet\n");
        break;
    case decoder_error:
        nyx_printf("[WOX] Offline decode: decoder error\n");
        break;
    }

    free(buf);
    free(dump_path);
    nyx_printf("[WOX] Offline PT decode complete\n");
}

/*
 * wox_final_wox_check - Final W+X cross-check at RELEASE time.
 *
 * Performs one last dirty & exec intersection check before the program
 * terminates.  This catches unpacked code that was written earlier
 * and executed just before RELEASE (e.g., the actual unpacked OEP).
 */
static void wox_final_wox_check(CPUState *cpu)
{
    if (!wox_snapshot_taken) return;

    CPUX86State *env = &(X86_CPU(cpu)->env);


    /* NOTE: pt_handle_overflow() is NOT called here because:
     * 1. synchronization_disable_pt() already flushed final PT data
     * 2. wox_offline_pt_decode() already bulk-decoded the entire trace
     * 3. PT hardware is disabled at this point (ioctl would be no-op)
     */
    /* Collect final dirty bits */
    uint8_t *current_dirty = calloc(1, WOX_BITMAP_BYTES);
    wox_collect_dirty_bits(env, current_dirty);

    if (!wox_dirty_cumulative)
        wox_dirty_cumulative = calloc(1, WOX_BITMAP_BYTES);
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t nd = current_dirty[i] & ~wox_dirty_snapshot[i];
        wox_dirty_cumulative[i] |= nd;
    }
    free(current_dirty);

    /* Get executed pages */
    page_cache_t *pc = GET_GLOBAL_STATE()->page_cache;
    if (!pc || !GET_GLOBAL_STATE()->decoder) {
        nyx_printf("[WOX] Final check: decoder not ready, skipping\n");
        return;
    }

    int max_exec = 65536;
    uint64_t *exec_pages = malloc(max_exec * sizeof(uint64_t));
    int exec_count = page_cache_get_executed_pages(pc, exec_pages, max_exec);

    uint8_t *exec_bitmap = calloc(1, WOX_BITMAP_BYTES);
    for (int e = 0; e < exec_count; e++) {
        uint64_t va = exec_pages[e];
        if (va >= WOX_USER_VA_START && va < WOX_USER_VA_END)
            wox_bitmap_set(exec_bitmap, wox_va_to_idx((uint32_t)va));
    }

    /* New exec = exec not in baseline */
    uint8_t *new_exec = calloc(1, WOX_BITMAP_BYTES);
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        new_exec[i] = exec_bitmap[i] & ~(wox_exec_baseline ? wox_exec_baseline[i] : 0);
    }

    /* Cross-check: dirty & new_exec */
    int wox_count = 0;
    int wox_addrs_cap = 4096;
    uint32_t *wox_addrs = malloc(wox_addrs_cap * sizeof(uint32_t));

    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t wox_byte = wox_dirty_cumulative[i] & new_exec[i];
        if (!wox_byte) continue;
        for (int bit = 0; bit < 8; bit++) {
            if (wox_byte & (1 << bit)) {
                int idx = i * 8 + bit;
                uint32_t va = WOX_USER_VA_START + (uint32_t)idx * 0x1000;
                if (wox_count < wox_addrs_cap)
                    wox_addrs[wox_count] = va;
                wox_count++;
            }
        }
    }

    nyx_printf("[WOX] Final check: exec=%d, W+X=%d\n",
               exec_count, wox_count);

    if (wox_count > 0) {
        static int final_round = 9000;
        nyx_printf("\n");
        nyx_printf("==================================================\n");
        nyx_printf("[WOX] *** FINAL W+X DETECTED ***\n");
        nyx_printf("[WOX] %d pages written-then-executed at termination:\n",
                   wox_count);

        char *report_path = NULL;
        assert(asprintf(&report_path, "%s/dump/wox_detect_final_%d.txt",
                        GET_GLOBAL_STATE()->workdir_path, final_round) != -1);
        FILE *rf = fopen(report_path, "w");
        if (rf) {
            fprintf(rf, "# W+X Final Detection Report\n");
            fprintf(rf, "# W+X pages: %d\n\n", wox_count);
            for (int w = 0; w < wox_count && w < wox_addrs_cap; w++) {
                fprintf(rf, "0x%08x\n", wox_addrs[w]);
                nyx_printf("[WOX]   0x%08x\n", wox_addrs[w]);
            }
            fclose(rf);
            nyx_printf("[WOX] Final report saved: %s\n", report_path);
        }
        free(report_path);

        nyx_printf("[WOX] Triggering final memory dump...\n");
        nyx_printf("==================================================\n\n");

        char dump_label[64];
        snprintf(dump_label, sizeof(dump_label), "wox_final_%d", final_round);
        // [TEST]         dump_full_process_memory(cpu, env, dump_label);

        final_round++;
    }

    free(wox_addrs);
    free(new_exec);
    free(exec_bitmap);
    free(exec_pages);
}

void wox_final_dirty_report(CPUState *cpu)
{
    if (!wox_snapshot_taken) {
        nyx_printf("[DIRTY] Final report: no snapshot was taken, skipping\n");
        return;
    }

    CPUX86State *env = &(X86_CPU(cpu)->env);

    /* Merge current dirty bits into cumulative bitmap one last time */
    uint8_t *current_dirty = calloc(1, WOX_BITMAP_BYTES);
    wox_collect_dirty_bits(env, current_dirty);

    if (!wox_dirty_cumulative)
        wox_dirty_cumulative = calloc(1, WOX_BITMAP_BYTES);

    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t nd = current_dirty[i] & ~wox_dirty_snapshot[i];
        wox_dirty_cumulative[i] |= nd;
    }
    free(current_dirty);

    /* Count total cumulative dirty pages */
    int cumulative_count = 0;
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t v = wox_dirty_cumulative[i];
        while (v) { cumulative_count++; v &= v - 1; }
    }

    /* Log using cumulative bitmap */
    static int final_counter = 0;
    wox_log_written_pages(cpu, env, wox_dirty_cumulative, cumulative_count,
                          final_counter++, "final");

    /* Byte-level content diff report */
    wox_content_diff_report(cpu, env);
}

/*
 * Byte-level content diff report.
 * Compares current page content against ACQUIRE-time snapshot for all
 * cumulative-dirty pages.  Outputs exact byte ranges that were modified.
 */
static void wox_content_diff_report(CPUState *cpu, CPUX86State *env)
{
    if (!wox_page_content || !wox_page_present) {
        nyx_printf("[WOX] Content diff: no content snapshot, skipping\n");
        return;
    }
    if (!wox_dirty_cumulative) {
        nyx_printf("[WOX] Content diff: no dirty data, skipping\n");
        return;
    }

    /* --- Build current physical address map via PT walk --- */
    uint64_t *cur_phys = calloc(WOX_PAGE_COUNT, sizeof(uint64_t));
    uint8_t  *cur_mapped = calloc(1, WOX_BITMAP_BYTES);

    uint64_t cr3 = env->cr[3];
    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    uint64_t pml4e = pml4_table[0];
    if (pml4e & 1) {
        uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
        uint64_t pdpt_table[512];
        cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

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
                    uint64_t page_phys = pde & 0x000FFFFFFFE00000ULL;
                    uint32_t base_va = ((uint32_t)pdpte_idx << 30) |
                                       ((uint32_t)pde_idx << 21);
                    for (int k = 0; k < 512; k++) {
                        uint32_t va = base_va + ((uint32_t)k << 12);
                        if (va < WOX_USER_VA_START || va >= WOX_USER_VA_END) continue;
                        int idx = wox_va_to_idx(va);
                        cur_phys[idx] = page_phys + ((uint64_t)k << 12);
                        wox_bitmap_set(cur_mapped, idx);
                    }
                    continue;
                }

                uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
                uint64_t pt_table[512];
                cpu_physical_memory_read(pt_base, pt_table, 4096);

                for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                    uint64_t pte = pt_table[pte_idx];
                    if (!(pte & 1)) continue;

                    uint32_t va = ((uint32_t)pdpte_idx << 30) |
                                  ((uint32_t)pde_idx << 21) |
                                  ((uint32_t)pte_idx << 12);
                    if (va < WOX_USER_VA_START || va >= WOX_USER_VA_END) continue;

                    int idx = wox_va_to_idx(va);
                    cur_phys[idx] = pte & 0x000FFFFFFFFFF000ULL;
                    wox_bitmap_set(cur_mapped, idx);
                }
            }
        }
    }

    /* --- Create output file --- */
    char *dump_base = NULL;
    assert(asprintf(&dump_base, "%s/dump",
                    GET_GLOBAL_STATE()->workdir_path) != -1);
    mkdir(dump_base, 0755);
    free(dump_base);

    static int diff_seq = 0;
    char *diff_path = NULL;
    assert(asprintf(&diff_path, "%s/dump/content_diff_%03d.txt",
                    GET_GLOBAL_STATE()->workdir_path, diff_seq++) != -1);
    FILE *df = fopen(diff_path, "w");
    if (!df) {
        nyx_printf("[WOX] Content diff: failed to create %s\n", diff_path);
        free(diff_path); free(cur_phys); free(cur_mapped);
        return;
    }

    mod_info_t *modules = wox_cached_modules;
    int num_modules = wox_cached_num_modules;

    int total_dirty = 0;
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t v = wox_dirty_cumulative[i];
        while (v) { total_dirty++; v &= v - 1; }
    }

    fprintf(df, "# Content Diff Report (Byte-level Write Tracking)\n");
    fprintf(df, "# Snapshot pages at ACQUIRE: %d\n", wox_content_snapshot_pages);
    fprintf(df, "# Cumulative dirty pages: %d\n", total_dirty);
    fprintf(df, "# Modules cached: %d\n\n", num_modules);

    /* --- Diff each dirty page --- */
    int pages_changed = 0, pages_new = 0, pages_unmapped = 0;
    uint64_t total_bytes_changed = 0;
    uint8_t cur_page[0x1000];

    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        uint8_t byte_val = wox_dirty_cumulative[i];
        if (!byte_val) continue;
        for (int bit = 0; bit < 8; bit++) {
            if (!(byte_val & (1 << bit))) continue;

            int idx = i * 8 + bit;
            if (idx >= WOX_PAGE_COUNT) break;
            uint32_t va = WOX_USER_VA_START + (uint32_t)idx * 0x1000;

            const char *mod_name = NULL;
            for (int m = 0; m < num_modules; m++) {
                if (va >= modules[m].base &&
                    va < modules[m].base + modules[m].size) {
                    mod_name = modules[m].name;
                    break;
                }
            }

            if (!wox_bitmap_test(cur_mapped, idx)) {
                pages_unmapped++;
                fprintf(df, "0x%08x  UNMAPPED  %s\n", va,
                        mod_name ? mod_name : "");
                continue;
            }

            cpu_physical_memory_read(cur_phys[idx], cur_page, 0x1000);

            if (!wox_bitmap_test(wox_page_present, idx) ||
                !wox_page_content[idx]) {
                pages_new++;
                total_bytes_changed += 0x1000;
                fprintf(df, "0x%08x  NEW       4096/4096 bytes  %s\n", va,
                        mod_name ? mod_name : "");
                continue;
            }

            /* Byte-by-byte comparison -- collect changed ranges */
            typedef struct { int start; int end; } brange_t;
            brange_t ranges[512];
            int range_count = 0;
            int changed_bytes = 0;
            int in_range = 0;
            int range_start = 0;

            for (int b = 0; b <= 0x1000; b++) {
                bool differs = (b < 0x1000) &&
                               (cur_page[b] != wox_page_content[idx][b]);
                if (differs && !in_range) {
                    range_start = b;
                    in_range = 1;
                } else if (!differs && in_range) {
                    if (range_count < 512) {
                        ranges[range_count].start = range_start;
                        ranges[range_count].end = b;
                        range_count++;
                    }
                    changed_bytes += (b - range_start);
                    in_range = 0;
                }
            }

            if (changed_bytes == 0) continue;

            pages_changed++;
            total_bytes_changed += changed_bytes;

            if (changed_bytes == 0x1000) {
                fprintf(df, "0x%08x  FULL      4096/4096 bytes  %s\n", va,
                        mod_name ? mod_name : "");
            } else {
                fprintf(df, "0x%08x  PARTIAL   %4d/4096 bytes  %s\n", va,
                        changed_bytes, mod_name ? mod_name : "");
                for (int r = 0; r < range_count; r++) {
                    fprintf(df, "  0x%03x - 0x%03x  (%d bytes)\n",
                            ranges[r].start, ranges[r].end,
                            ranges[r].end - ranges[r].start);
                }
            }
        }
    }

    fprintf(df, "\n# Summary:\n");
    fprintf(df, "# Pages with byte changes: %d\n", pages_changed);
    fprintf(df, "# New pages (not in snapshot): %d\n", pages_new);
    fprintf(df, "# Unmapped pages: %d\n", pages_unmapped);
    fprintf(df, "# Total bytes changed: %lu\n", (unsigned long)total_bytes_changed);
    fclose(df);

    nyx_printf("[WOX] Content diff: %d changed, %d new, %d unmapped, "
               "%lu bytes total -> %s\n",
               pages_changed, pages_new, pages_unmapped,
               (unsigned long)total_bytes_changed, diff_path);

    free(diff_path);
    free(cur_phys);
    free(cur_mapped);
}

/*
 * Reset W+X tracking for multi-round detection.
 * Clears cumulative dirty bitmap and re-takes both dirty-bit and
 * content snapshots from the current memory state.
 */
void wox_reset_round(CPUState *cpu)
{
    if (wox_dirty_cumulative)
        memset(wox_dirty_cumulative, 0, WOX_BITMAP_BYTES);

    /* Snapshot current executed pages as baseline for next round.
     * Pages executed before this point won't count as "new" in the
     * next round's W⊕X cross-check. */
    page_cache_t *pc = GET_GLOBAL_STATE()->page_cache;
    if (pc) {
        if (!wox_exec_baseline)
            wox_exec_baseline = calloc(1, WOX_BITMAP_BYTES);
        else
            memset(wox_exec_baseline, 0, WOX_BITMAP_BYTES);

        int max_exec = 65536;
        uint64_t *exec_pages = malloc(max_exec * sizeof(uint64_t));
        int exec_count = page_cache_get_executed_pages(pc, exec_pages, max_exec);
        for (int e = 0; e < exec_count; e++) {
            uint64_t va = exec_pages[e];
            if (va >= WOX_USER_VA_START && va < WOX_USER_VA_END)
                wox_bitmap_set(wox_exec_baseline, wox_va_to_idx((uint32_t)va));
        }
        free(exec_pages);
        nyx_printf("[WOX] Execution baseline saved: %d pages\n", exec_count);
    }

    wox_take_snapshot(cpu);

    nyx_printf("[WOX] Round reset: tracking cleared, new baseline established\n");
}

/*
 * Detect W⊕X (Write-then-Execute) pages.
 *
 * 1. Flush pending Intel PT data so page_cache is up to date.
 * 2. Collect current PTE dirty bits.
 * 3. Newly written = current_dirty & ~snapshot_dirty
 * 4. Executed pages = page_cache hash keys (populated by Intel PT decode)
 * 5. W⊕X = newly_written ∩ executed
 */
static void wox_detect(CPUState *cpu, CPUX86State *env, const char *trigger)
{
    int check_id = wox_check_counter++;

    if (!wox_snapshot_taken) {
        wox_take_snapshot(cpu);
        return;
    }

    /* 1. Flush pending PT trace data for up-to-date page_cache */
    if (cpu->pt_fd) {
        pt_handle_overflow(cpu);
    }

    /* 2. Collect current dirty bits */
    uint8_t *current_dirty = calloc(1, WOX_BITMAP_BYTES);
    wox_collect_dirty_bits(env, current_dirty);

    /* 3. Newly dirty = pages written AFTER snapshot */
    uint8_t *newly_dirty = calloc(1, WOX_BITMAP_BYTES);
    int newly_dirty_count = 0;
    for (int i = 0; i < WOX_BITMAP_BYTES; i++) {
        newly_dirty[i] = current_dirty[i] & ~wox_dirty_snapshot[i];
        uint8_t v = newly_dirty[i];
        while (v) { newly_dirty_count++; v &= v - 1; }
    }


    /* 4. Detect W⊕X pages */
    page_cache_t *pc = GET_GLOBAL_STATE()->page_cache;
    int exec_count = 0;
    int wox_count = 0;
    const char *detect_method = "unknown";

    /* Collect W⊕X page addresses for file output */
    int wox_addrs_cap = 4096;
    uint32_t *wox_addrs = malloc(wox_addrs_cap * sizeof(uint32_t));

    /* Try Intel PT page_cache first */
    bool use_pt = false;
    if (pc) {
        int max_exec = 65536;
        uint64_t *exec_pages = malloc(max_exec * sizeof(uint64_t));
        exec_count = page_cache_get_executed_pages(pc, exec_pages, max_exec);

        if (exec_count > 0) {
            use_pt = true;
            detect_method = "Intel PT page_cache";
            nyx_printf("[WOX] Check #%d (%s): newly_dirty=%d pages, "
                       "executed(PT)=%d pages\n",
                       check_id, trigger, newly_dirty_count, exec_count);

            /* Intersection: W ∩ X */
            for (int e = 0; e < exec_count; e++) {
                uint32_t va = (uint32_t)(exec_pages[e] & 0xFFFFFFFF);
                if (va < WOX_USER_VA_START || va >= WOX_USER_VA_END) continue;

                int idx = wox_va_to_idx(va);
                if (wox_bitmap_test(newly_dirty, idx)) {
                    nyx_printf("[WOX]   *** W+X page: VA=0x%08x ***\n", va);
                    if (wox_count < wox_addrs_cap)
                        wox_addrs[wox_count] = va;
                    wox_count++;
                }
            }
        }
        free(exec_pages);
    }

    /* NX-bit fallback: PT decoder inactive or page_cache empty */
    if (!use_pt) {
        detect_method = "NX-bit fallback";
        nyx_printf("[WOX] Check #%d (%s): newly_dirty=%d pages, "
                   "PT %s — using NX-bit fallback\n",
                   check_id, trigger, newly_dirty_count,
                   pc ? "page_cache empty (decoder inactive)" : "unavailable");

        /* Walk guest page tables to check NX bit for newly-dirty pages */
        uint64_t cr3 = env->cr[3];
        uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
        uint64_t pml4_table[512];
        cpu_physical_memory_read(pml4_base, pml4_table, 4096);

        uint64_t pml4e = pml4_table[0];
        if (pml4e & 1) {
            bool pml4_x = !(pml4e & (1ULL << 63));
            uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
            uint64_t pdpt_table[512];
            cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

            for (int pdpte_idx = 0; pdpte_idx < 2; pdpte_idx++) {
                uint64_t pdpte = pdpt_table[pdpte_idx];
                if (!(pdpte & 1)) continue;
                if (pdpte & (1ULL << 7)) continue;
                bool pdpt_x = pml4_x && !(pdpte & (1ULL << 63));

                uint64_t pd_base = pdpte & 0x000FFFFFFFFFF000ULL;
                uint64_t pd_table[512];
                cpu_physical_memory_read(pd_base, pd_table, 4096);

                for (int pde_idx = 0; pde_idx < 512; pde_idx++) {
                    uint64_t pde = pd_table[pde_idx];
                    if (!(pde & 1)) continue;
                    bool pd_x = pdpt_x && !(pde & (1ULL << 63));

                    if (pde & (1ULL << 7)) {
                        /* 2MB huge */
                        uint32_t base_va = ((uint32_t)pdpte_idx << 30) |
                                           ((uint32_t)pde_idx << 21);
                        for (int k = 0; k < 512; k++) {
                            uint32_t va = base_va + ((uint32_t)k << 12);
                            if (va < WOX_USER_VA_START || va >= WOX_USER_VA_END)
                                continue;
                            int idx = wox_va_to_idx(va);
                            if (wox_bitmap_test(newly_dirty, idx) && pd_x) {
                                nyx_printf("[WOX]   *** W+X page (NX-fb): "
                                           "VA=0x%08x ***\n", va);
                                if (wox_count < wox_addrs_cap)
                                    wox_addrs[wox_count] = va;
                                wox_count++;
                            }
                        }
                        continue;
                    }

                    uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
                    uint64_t pt_table[512];
                    cpu_physical_memory_read(pt_base, pt_table, 4096);

                    for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                        uint64_t pte = pt_table[pte_idx];
                        if (!(pte & 1)) continue;

                        uint32_t va = ((uint32_t)pdpte_idx << 30) |
                                      ((uint32_t)pde_idx << 21) |
                                      ((uint32_t)pte_idx << 12);
                        if (va < WOX_USER_VA_START || va >= WOX_USER_VA_END)
                            continue;

                        int idx = wox_va_to_idx(va);
                        bool x = pd_x && !(pte & (1ULL << 63));
                        if (wox_bitmap_test(newly_dirty, idx) && x) {
                            nyx_printf("[WOX]   *** W+X page (NX-fb): "
                                       "VA=0x%08x ***\n", va);
                            if (wox_count < wox_addrs_cap)
                                wox_addrs[wox_count] = va;
                            wox_count++;
                        }
                    }
                }
            }
        }
    }

    nyx_printf("[WOX] Result: %d W+X pages detected (check #%d, method: %s)\n",
               wox_count, check_id, detect_method);

    /* Save results to file */
    if (wox_count > 0) {
        char *result_path = NULL;
        char *dump_base = NULL;
        assert(asprintf(&dump_base, "%s/dump", GET_GLOBAL_STATE()->workdir_path) != -1);
        mkdir(dump_base, 0755);
        free(dump_base);
        assert(asprintf(&result_path, "%s/dump/wox_check_%03d_%s.txt",
                        GET_GLOBAL_STATE()->workdir_path,
                        check_id, trigger) != -1);
        FILE *rf = fopen(result_path, "w");
        if (rf) {
            fprintf(rf, "# W+X Detection Result\n");
            fprintf(rf, "# Check: #%d\n", check_id);
            fprintf(rf, "# Trigger: %s\n", trigger);
            fprintf(rf, "# Method: %s\n", detect_method);
            fprintf(rf, "# Newly written pages: %d\n", newly_dirty_count);
            fprintf(rf, "# Executed/Executable pages: %d\n",
                    use_pt ? exec_count : wox_count);
            fprintf(rf, "# W+X pages: %d\n\n", wox_count);

            int out_count = wox_count < wox_addrs_cap ? wox_count : wox_addrs_cap;
            for (int i = 0; i < out_count; i++) {
                fprintf(rf, "0x%08x\n", wox_addrs[i]);
            }
            fclose(rf);
            nyx_printf("[WOX] Results saved to %s\n", result_path);
        }
        free(result_path);
    }

    free(wox_addrs);
    free(current_dirty);
    free(newly_dirty);
}



bool handle_hypercall_kafl_hook(struct kvm_run *run,
                                CPUState       *cpu,
                                uint64_t        hypercall_arg)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;

    /* ===== API Hook check ===== */
    if (GET_GLOBAL_STATE()->api_hook_mode) {
        uint64_t hit_addr = run->debug.arch.pc;
        for (int i = 0; i < GET_GLOBAL_STATE()->num_api_hooks; i++) {
            if (GET_GLOBAL_STATE()->api_hooks[i].active &&
                GET_GLOBAL_STATE()->api_hooks[i].addr == hit_addr) {
                /* CR3 filter: only handle target process, skip system processes */
                uint64_t current_cr3 = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;
                uint64_t target_cr3 = GET_GLOBAL_STATE()->parent_cr3;

                if (current_cr3 != target_cr3) {
                    /* Non-target process hit the BP — still need to single-step past it */
                    goto hook_single_step;
                }

                const char *api_name = GET_GLOBAL_STATE()->api_hooks[i].name;
                nyx_printf(">>> API HOOK HIT: %s @ 0x%lx (CR3=0x%lx) <<<\n",
                           api_name, hit_addr, current_cr3);
                

                /* GetProcAddress argument logging + memory dump (32-bit stdcall) */
                if (strstr(api_name, "GetProcAddress") != NULL) {
                    uint32_t esp = env->regs[R_ESP] & 0xFFFFFFFF;
                    uint32_t hModule = 0, lpProcName = 0;
                    char proc_name[256];
                    memset(proc_name, 0, sizeof(proc_name));

                    /* Stack: [ESP+0]=RetAddr, [ESP+4]=hModule, [ESP+8]=lpProcName */
                    if (read_virtual_memory(esp + 4, (uint8_t*)&hModule, 4, cpu) &&
                        read_virtual_memory(esp + 8, (uint8_t*)&lpProcName, 4, cpu)) {

                        if (lpProcName > 0xFFFF) {
                            /* lpProcName is a string pointer */
                            if (read_virtual_memory(lpProcName, (uint8_t*)proc_name, 255, cpu)) {
                                nyx_printf("    -> GetProcAddress(0x%x, \"%s\")\n",
                                           hModule, proc_name);
                            } else {
                                nyx_printf("    -> GetProcAddress(0x%x, <read failed>)\n",
                                           hModule);
                            }
                        } else {
                            /* lpProcName is an ordinal */
                            snprintf(proc_name, sizeof(proc_name), "ordinal_%u", lpProcName);
                            nyx_printf("    -> GetProcAddress(0x%x, ordinal=%u)\n",
                                       hModule, lpProcName);
                        }
                    }

                    /* Full process memory dump */
                    {
                        const char *dump_label = (proc_name[0] != '\0') ? proc_name : "unknown";
                    // [TEST]                         dump_full_process_memory(cpu, env, dump_label);
                    }
                }
hook_single_step:
                /* Remove BP, single-step, then re-insert */
                remove_breakpoint(cpu, hit_addr, 1);
                GET_GLOBAL_STATE()->api_hook_saved_rip = hit_addr;
                GET_GLOBAL_STATE()->api_hook_step_idx = i;
                kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_MTF);
                return true;
            }
        }
        /* No hook matched - log first 3 misses only */
        {
            static int miss_count = 0;
            if (miss_count < 3) {
                nyx_printf("[DEBUG] KVM_EXIT_DEBUG: no hook match for pc=0x%lx (miss #%d)\n",
                           hit_addr, ++miss_count);
            }
        }
    }
    /* ===== End API Hook check ===== */

    for (uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++) {
        if (GET_GLOBAL_STATE()->redqueen_state &&
            (env->eip >= GET_GLOBAL_STATE()->pt_ip_filter_a[i]) &&
            (env->eip <= GET_GLOBAL_STATE()->pt_ip_filter_b[i]))
        {
            handle_hook(GET_GLOBAL_STATE()->redqueen_state);
            return true;
        } else if (cpu->singlestep_enabled &&
                   (GET_GLOBAL_STATE()->redqueen_state)->singlestep_enabled)
        {
            handle_hook(GET_GLOBAL_STATE()->redqueen_state);
            return true;
        }
    }
    return false;
}

static void handle_hypercall_kafl_user_abort(struct kvm_run *run,
                                             CPUState       *cpu,
                                             uint64_t        hypercall_arg)
{
    uint32_t hprintf_size = misc_data_size();
    read_virtual_memory(hypercall_arg, (uint8_t *)GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size, cpu);
    set_abort_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                      GET_GLOBAL_STATE()->hprintf_tmp_buffer,
                                      strnlen(GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size));
    synchronization_lock();
}

void pt_enable_rqi(CPUState *cpu)
{
    GET_GLOBAL_STATE()->redqueen_enable_pending = true;
}

void pt_disable_rqi(CPUState *cpu)
{
    GET_GLOBAL_STATE()->redqueen_disable_pending      = true;
    GET_GLOBAL_STATE()->redqueen_instrumentation_mode = REDQUEEN_NO_INSTRUMENTATION;
}

void pt_set_enable_patches_pending(CPUState *cpu)
{
    GET_GLOBAL_STATE()->patches_enable_pending = true;
}

void pt_set_redqueen_instrumentation_mode(CPUState *cpu, int redqueen_mode)
{
    GET_GLOBAL_STATE()->redqueen_instrumentation_mode = redqueen_mode;
}

void pt_set_redqueen_update_blacklist(CPUState *cpu, bool newval)
{
    assert(!newval || !GET_GLOBAL_STATE()->redqueen_update_blacklist);
    GET_GLOBAL_STATE()->redqueen_update_blacklist = newval;
}

void pt_set_disable_patches_pending(CPUState *cpu)
{
    GET_GLOBAL_STATE()->patches_disable_pending = true;
}

static void handle_hypercall_kafl_dump_file(struct kvm_run *run,
                                            CPUState       *cpu,
                                            uint64_t        hypercall_arg)
{
    kafl_dump_file_t file_obj;
    char             filename[256] = { 0 };
    char            *host_path     = NULL;
    FILE            *f             = NULL;

    uint64_t vaddr = hypercall_arg;
    memset((void *)&file_obj, 0, sizeof(kafl_dump_file_t));

    if (!read_virtual_memory(vaddr, (uint8_t *)&file_obj, sizeof(kafl_dump_file_t),
                             cpu))
    {
        nyx_error("Failed to read file_obj in %s. Skipping..\n", __func__);
        goto err_out1;
    }

    if (file_obj.file_name_str_ptr != 0) {
        if (!read_virtual_memory(file_obj.file_name_str_ptr, (uint8_t *)filename,
                                 sizeof(filename) - 1, cpu))
        {
            nyx_error("Failed to read file_name_str_ptr in %s. Skipping..\n",
                      __func__);
            goto err_out1;
        }
        filename[sizeof(filename) - 1] = 0;
    }

    // nyx_error("%s: dump %lu fbytes from %s (append=%u)\n",
    //	   	__func__, file_obj.bytes, filename, file_obj.append);

    // use a tempfile if file_name_ptr == NULL or points to empty string
    if (0 == strnlen(filename, sizeof(filename))) {
        strncpy(filename, "tmp.XXXXXX", sizeof(filename) - 1);
    }

    char *base_name = basename(filename); // clobbers the filename buffer!
    assert(asprintf(&host_path, "%s/dump/%s", GET_GLOBAL_STATE()->workdir_path,
                    base_name) != -1);

    // check if base_name is mkstemp() pattern, otherwise write/append to exact name
    char *pattern = strstr(base_name, "XXXXXX");
    if (pattern) {
        unsigned suffix = strlen(pattern) - strlen("XXXXXX");
        f               = fdopen(mkstemps(host_path, suffix), "w+");
        if (file_obj.append) {
            nyx_warn("Writing unique generated file in append mode?\n");
        }
    } else {
        if (file_obj.append) {
            f = fopen(host_path, "a+");
        } else {
            f = fopen(host_path, "w+");
        }
    }

    if (!f) {
        nyx_error("%s: %s - %s\n", __func__, host_path, strerror(errno));
        goto err_out1;
    }

    uint32_t pos     = 0;
    int32_t  bytes   = file_obj.bytes;
    void    *page    = malloc(PAGE_SIZE);
    uint32_t written = 0;

    nyx_debug_p(CORE_PREFIX, "Dump %d bytes to %s (append=%u)\n", bytes, host_path,
                file_obj.append);

    while (bytes > 0) {
        if (bytes >= PAGE_SIZE) {
            read_virtual_memory(file_obj.data_ptr + pos, (uint8_t *)page, PAGE_SIZE,
                                cpu);
            written = fwrite(page, 1, PAGE_SIZE, f);
        } else {
            read_virtual_memory(file_obj.data_ptr + pos, (uint8_t *)page, bytes, cpu);
            written = fwrite(page, 1, bytes, f);
            break;
        }

        if (!written) {
            nyx_error("%s: %s - %s\n", __func__, host_path, strerror(errno));
            goto err_out2;
        }

        bytes -= written;
        pos += written;
    }


err_out2:
    free(page);
    fclose(f);
err_out1:
    free(host_path);
}

static void handle_hypercall_kafl_persist_page_past_snapshot(struct kvm_run *run,
                                                             CPUState       *cpu,
                                                             uint64_t hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_PERSIST_PAGE_PAST_SNAPSHOT")) {
        return;
    }

    CPUX86State *env = &(X86_CPU(cpu))->env;
    kvm_arch_get_registers_fast(cpu);
    hwaddr phys_addr =
        (hwaddr)get_paging_phys_addr(cpu, env->cr[3], hypercall_arg & (~0xFFF));
    assert(phys_addr != 0xffffffffffffffffULL);
    fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
}

/*
 * API Hook handler - receives API addresses from harness,
 * installs INT3 breakpoints for Windows API call detection.
 */
static void handle_hypercall_kafl_hook_api(struct kvm_run *run,
                                           CPUState       *cpu,
                                           uint64_t        hypercall_arg)
{
    typedef struct {
        uint64_t num_hooks;
        uint64_t addresses[16];
        char     names[16][64];
    } __attribute__((packed)) kafl_api_hook_t;
    kafl_api_hook_t hook_data;
    kvm_arch_get_registers(cpu);
    read_virtual_memory(hypercall_arg, (uint8_t *)&hook_data, sizeof(hook_data), cpu);
    if (hook_data.num_hooks > 16) {
        nyx_error("HOOK_API: too many hooks (%lu)\n", hook_data.num_hooks);
        hook_data.num_hooks = 16;
    }
    nyx_printf("=== Installing %lu API hooks (using CR3: 0x%lx) ===\n", 
               hook_data.num_hooks, (uint64_t)GET_GLOBAL_STATE()->parent_cr3);
    /* Store hooks in global state */
    GET_GLOBAL_STATE()->num_api_hooks = (int)hook_data.num_hooks;
    GET_GLOBAL_STATE()->api_hook_mode = true;
    for (int i = 0; i < (int)hook_data.num_hooks; i++) {
        GET_GLOBAL_STATE()->api_hooks[i].addr = hook_data.addresses[i];
        GET_GLOBAL_STATE()->api_hooks[i].active = true;
        memcpy(GET_GLOBAL_STATE()->api_hooks[i].name, hook_data.names[i], 64);
        nyx_printf("  Hook[%d]: %s @ 0x%lx\n", i,
                   GET_GLOBAL_STATE()->api_hooks[i].name,
                   hook_data.addresses[i]);
        /* Install INT3 breakpoint */
        insert_breakpoint(cpu, hook_data.addresses[i], 1);
    }
    nyx_printf("=== API hooks installed ===\n");
}

int handle_kafl_hypercall(struct kvm_run *run,
                          CPUState       *cpu,
                          uint64_t        hypercall,
                          uint64_t        arg)
{
    int ret = -1;
    // nyx_debug("%s -> %ld\n", __func__, hypercall);

    // FIXME: ret is always 0. no default case.
    switch (hypercall) {
    case KVM_EXIT_KAFL_ACQUIRE:
        handle_hypercall_kafl_acquire(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_GET_PAYLOAD:
        handle_hypercall_get_payload(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_GET_PROGRAM:
        nyx_abort("Hypercall is deprecated: HYPERCALL_KAFL_GET_PROGRAM");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_GET_ARGV:
        nyx_abort("Hypercall is deprecated: HYPERCALL_KAFL_GET_ARGV");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_RELEASE:
        handle_hypercall_kafl_release(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_SUBMIT_CR3:
        handle_hypercall_kafl_cr3(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_SUBMIT_PANIC:
        handle_hypercall_kafl_submit_panic(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_SUBMIT_KASAN:
        handle_hypercall_kafl_submit_kasan(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PANIC:
        handle_hypercall_kafl_panic(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_KASAN:
        handle_hypercall_kafl_kasan(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_LOCK:
        handle_hypercall_kafl_lock(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_INFO:
        nyx_abort("Hypercall is deprecated: HYPERCALL_KAFL_INFO");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NEXT_PAYLOAD:
        handle_hypercall_kafl_next_payload(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PRINTF:
        handle_hypercall_kafl_printf(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PRINTK_ADDR:
        nyx_abort("Hypercall is deprecated: KVM_EXIT_KAFL_PRINTK_ADDR");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PRINTK:
        nyx_abort("Hypercall is deprecated: KVM_EXIT_KAFL_PRINTK");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_RANGE_ADVISE:
        handle_hypercall_kafl_user_range_advise(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_SUBMIT_MODE:
        handle_hypercall_kafl_user_submit_mode(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_FAST_ACQUIRE:
        if (handle_hypercall_kafl_next_payload(run, cpu, arg)) {
            handle_hypercall_kafl_cr3(run, cpu, arg);
            handle_hypercall_kafl_acquire(run, cpu, arg);
        }
        ret = 0;
        break;
    case KVM_EXIT_KAFL_TOPA_MAIN_FULL:
        pt_handle_overflow(cpu);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_ABORT:
        handle_hypercall_kafl_user_abort(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_CONFIG:
        handle_hypercall_kafl_nested_config(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_PREPARE:
        handle_hypercall_kafl_nested_prepare(run, cpu, arg);
        ret = 0;
        break;

    case KVM_EXIT_KAFL_NESTED_ACQUIRE:
        handle_hypercall_kafl_nested_acquire(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_RELEASE:
        handle_hypercall_kafl_nested_release(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_HPRINTF:
        handle_hypercall_kafl_nested_hprintf(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PAGE_DUMP_BP:
        handle_hypercall_kafl_page_dump_bp(run, cpu, arg, run->debug.arch.pc);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_MTF:
        handle_hypercall_kafl_mtf(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_RANGE_SUBMIT:
        handle_hypercall_kafl_range_submit(run, cpu, arg);
        ret = 0;
        break;
    case HYPERCALL_KAFL_REQ_STREAM_DATA:
        handle_hypercall_kafl_req_stream_data(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_EARLY_RELEASE:
        handle_hypercall_kafl_nested_early_release(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PANIC_EXTENDED:
        handle_hypercall_kafl_panic_extended(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_CREATE_TMP_SNAPSHOT:
        handle_hypercall_kafl_create_tmp_snapshot(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_DEBUG_TMP_SNAPSHOT:
        handle_hypercall_kafl_debug_tmp_snapshot(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_GET_HOST_CONFIG:
        handle_hypercall_kafl_get_host_config(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_SET_AGENT_CONFIG:
        handle_hypercall_kafl_set_agent_config(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_DUMP_FILE:
        handle_hypercall_kafl_dump_file(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_REQ_STREAM_DATA_BULK:
        handle_hypercall_kafl_req_stream_data_bulk(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PERSIST_PAGE_PAST_SNAPSHOT:
        handle_hypercall_kafl_persist_page_past_snapshot(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_HOOK_API:
        handle_hypercall_kafl_hook_api(run, cpu, arg);
        ret = 0;
        break;
    }
    return ret;
}
