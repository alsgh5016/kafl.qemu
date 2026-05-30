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
#include "nyx/synchronization.h"
#include "nyx/wte.h"
#include "nyx/api_hook.h"

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
                if(GET_GLOBAL_STATE()->nyx_pt && GET_GLOBAL_STATE()->cap_compile_time_tracing == false) {
                    for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
                        if (GET_GLOBAL_STATE()->pt_ip_filter_configured[i]) {
                            pt_enable_ip_filtering(cpu, i, true, false);
                        }
                    }
                    pt_init_decoder(cpu);
                }
                GET_GLOBAL_STATE()->in_fuzzing_mode = true;
                setup_snapshot_once = true;
            }
            acquire_print_once(cpu);

            /* WtE is now initialized by WTE_SETUP hypercall before ACQUIRE.
             * No fallback wte_init/activate here — target must call WTE_SETUP. */

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

            if (wte_is_active()) {
                /* WtE: final CoW detection */
                wte_pt_check(cpu);      /* CoW detection */
                /* wte_scan_dirty_ring() — disabled: NX storm on DLLs */

                /* Temporarily disable reload mode to prevent perform_reload()
                 * from restoring the snapshot. The harness will call habort()
                 * after receiving the WtE count, cleanly stopping kAFL. */
                bool saved_reload_mode = GET_GLOBAL_STATE()->in_reload_mode;
                GET_GLOBAL_STATE()->in_reload_mode = false;

                synchronization_disable_pt(cpu);

                GET_GLOBAL_STATE()->in_reload_mode = saved_reload_mode;

                wte_print_debug_summary();
                int wte_count = wte_get_state()->wte_count;
                /* Return WtE count to guest via EAX so harness can decide
                 * whether to start another round. */
                set_return_value(cpu, (uint64_t)wte_count);
                /* Deactivate WtE — single execution mode, no more rounds. */
                wte_deactivate();
            } else {
                synchronization_disable_pt(cpu);
            }

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

    /* WtE MTF: same-page write confirmation or JIT tap NX re-arm */
    if (wte_is_active() && wte_get_state()->mtf_active) {
        wte_handle_mtf(cpu);  /* wte_handle_mtf dispatches on mtf_reason */
        return;
    }

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

        /* WtE active: use target (child) CR3 for PT so Intel PT traces
         * the packed binary's execution, not the harness.  parent_cr3
         * is kept as harness CR3 for API hook filtering. */
        if (wte_is_active()) {
            uint64_t target_cr3 = wte_get_state()->target_cr3;
            pt_set_cr3(cpu, target_cr3, false);
            nyx_printf("[WtE] SUBMIT_CR3: PT CR3 set to target_cr3=0x%lx "
                       "(harness cr3=0x%lx stored in parent_cr3)\n",
                       (unsigned long)target_cr3,
                       (unsigned long)cr3_val);
        } else {
            pt_set_cr3(cpu, cr3_val, false);
        }
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
/* ===== Full process memory dump (reusable, optimized) =====
 * Uses bulk page table walk (Strategy 1) + direct physical read (Strategy 3)
 * to avoid per-page VA→PA translation overhead.
 *
 * Old approach: 520K × is_addr_mapped_cr3() = ~2M physical reads
 * New approach: ~4 table loads + N physical reads (N = mapped page count)
 *
 * Parameters:
 *   cpu   - CPU state
 *   env   - x86 CPU environment (must have fresh registers)
 *   label - human-readable label for this dump (e.g. API name, hook name)
 */
typedef struct { uint64_t va; uint64_t phys; uint8_t perm; } mapped_page_t;
#define MAX_MODS 256

static int dump_seq_counter = 0;

/* ── Cross-dump byte diff: previous snapshot state ────────────── */

typedef struct {
    uint64_t va;                              /* Virtual address of page   */
    uint8_t  content[WTE_PAGE_SIZE];          /* Page content (4096 bytes) */
} crossdump_page_t;

static struct {
    crossdump_page_t *pages;                  /* Array of saved pages      */
    int               count;                  /* Number of pages saved     */
    int               capacity;               /* Allocated capacity        */
    int               prev_seq;               /* Sequence # of prev dump   */
    bool              valid;                   /* Has previous snapshot?    */
} crossdump_prev = { NULL, 0, 0, -1, false };

void wte_crossdump_init(void)
{
    crossdump_prev.capacity = WTE_CROSSDUMP_MAX_PAGES;
    crossdump_prev.pages = calloc(crossdump_prev.capacity,
                                   sizeof(crossdump_page_t));
    crossdump_prev.count = 0;
    crossdump_prev.prev_seq = -1;
    crossdump_prev.valid = false;
    nyx_printf("[WtE] Cross-dump diff initialized (capacity=%d pages, ~%d MB)\n",
               crossdump_prev.capacity,
               (int)(crossdump_prev.capacity * sizeof(crossdump_page_t) / (1024*1024)));
}

void wte_crossdump_destroy(void)
{
    if (crossdump_prev.pages) {
        free(crossdump_prev.pages);
        crossdump_prev.pages = NULL;
    }
    crossdump_prev.count = 0;
    crossdump_prev.valid = false;
    nyx_printf("[WtE] Cross-dump diff destroyed\n");
}

/* Binary search helper — crossdump pages are sorted by VA */
static int crossdump_find_va(uint64_t va)
{
    int lo = 0, hi = crossdump_prev.count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (crossdump_prev.pages[mid].va == va) return mid;
        if (crossdump_prev.pages[mid].va < va) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;  /* not found */
}

void dump_full_process_memory(CPUState *cpu, CPUX86State *env,
                                     const char *label,
                                     const wte_dump_event_t *event,
                                     uint64_t cr3_override)
{
    int seq = dump_seq_counter++;

    /* --- 1+2. Enumerate loaded modules via PEB→Ldr (bitness-aware) --- */
    wte_dll_entry_t *modules = calloc(MAX_MODS, sizeof(wte_dll_entry_t));
    int num_modules = wte_walk_module_list(cpu, modules, MAX_MODS);

    nyx_printf("    [FULLDUMP] #%03d (%s): %d modules loaded\n",
               seq, label, num_modules);
    for (int m = 0; m < num_modules; m++) {
        nyx_printf("    [FULLDUMP]   %-30s @ 0x%016lx  size=0x%lx\n",
                   modules[m].name,
                   (unsigned long)modules[m].base,
                   (unsigned long)(modules[m].end - modules[m].base));
    }

    /* --- 3. Create dump directory --- */
    char *dump_dir = NULL;
    assert(asprintf(&dump_dir, "%s/dump/fulldump_%03d_%s",
                    GET_GLOBAL_STATE()->workdir_path,
                    seq, label) != -1);
    mkdir(dump_dir, 0755);

    /* --- 4. Open memory map file --- */
    char *map_path = NULL;
    assert(asprintf(&map_path, "%s/memory_map.txt", dump_dir) != -1);
    FILE *map_f = fopen(map_path, "w");
    if (!map_f) {
        nyx_printf("    [FULLDUMP] Failed to create %s\n", map_path);
        free(map_path); free(dump_dir); free(modules);
        return;
    }
    fprintf(map_f, "# Full process memory dump #%03d\n", seq);
    fprintf(map_f, "# Trigger: %s\n", label);
    fprintf(map_f, "# Modules: %d\n", num_modules);

    if (event) {
        fprintf(map_f, "#\n");
        fprintf(map_f, "# WtE Event:\n");
        fprintf(map_f, "#   Type:       %s\n", event->type);
        fprintf(map_f, "#   RIP:        0x%lx\n", (unsigned long)event->rip);
        fprintf(map_f, "#   Target VA:  0x%lx\n", (unsigned long)event->va);
        fprintf(map_f, "#   Target GFN: 0x%lx\n", (unsigned long)event->gfn);
        fprintf(map_f, "#   Diffs:      %d bytes changed in target page\n",
                event->diff_count);
        fprintf(map_f, "#   WtE#:       %d (total)\n",
                event->total_wte_count);
    }

    /* --- Guest register snapshot at dump time --- */
    {
        uint32_t cs_flags = env->segs[R_CS].flags;
        bool cs_l = !!(cs_flags & (1 << 21));  /* Long mode (64-bit) */
        bool cs_d = !!(cs_flags & (1 << 22));  /* Default size (32-bit) */
        const char *mode = cs_l ? "64-bit" : (cs_d ? "32-bit (compat)" : "16-bit");

        fprintf(map_f, "#\n");
        fprintf(map_f, "# Guest Registers (mode: %s, CS.L=%d CS.D=%d):\n",
                mode, cs_l, cs_d);
        fprintf(map_f, "#   RAX: 0x%016lx  RBX: 0x%016lx\n",
                (unsigned long)env->regs[R_EAX],
                (unsigned long)env->regs[R_EBX]);
        fprintf(map_f, "#   RCX: 0x%016lx  RDX: 0x%016lx\n",
                (unsigned long)env->regs[R_ECX],
                (unsigned long)env->regs[R_EDX]);
        fprintf(map_f, "#   RSI: 0x%016lx  RDI: 0x%016lx\n",
                (unsigned long)env->regs[R_ESI],
                (unsigned long)env->regs[R_EDI]);
        fprintf(map_f, "#   RBP: 0x%016lx  RSP: 0x%016lx\n",
                (unsigned long)env->regs[R_EBP],
                (unsigned long)env->regs[R_ESP]);
        fprintf(map_f, "#   R8:  0x%016lx  R9:  0x%016lx\n",
                (unsigned long)env->regs[8],
                (unsigned long)env->regs[9]);
        fprintf(map_f, "#   R10: 0x%016lx  R11: 0x%016lx\n",
                (unsigned long)env->regs[10],
                (unsigned long)env->regs[11]);
        fprintf(map_f, "#   R12: 0x%016lx  R13: 0x%016lx\n",
                (unsigned long)env->regs[12],
                (unsigned long)env->regs[13]);
        fprintf(map_f, "#   R14: 0x%016lx  R15: 0x%016lx\n",
                (unsigned long)env->regs[14],
                (unsigned long)env->regs[15]);
        fprintf(map_f, "#   RIP: 0x%016lx  RFLAGS: 0x%016lx\n",
                (unsigned long)env->eip,
                (unsigned long)env->eflags);
        fprintf(map_f, "#   CR3: 0x%016lx\n",
                (unsigned long)env->cr[3]);
    }

    fprintf(map_f, "\n");
    fprintf(map_f, "# %-10s  %-10s  %-10s  %-5s  %-40s  %s\n",
            "START", "END", "SIZE", "PERM", "FILE", "MODULE");

    for (int m = 0; m < num_modules; m++) {
        fprintf(map_f, "# MODULE: %-30s  base=0x%016lx  size=0x%lx\n",
                modules[m].name,
                (unsigned long)modules[m].base,
                (unsigned long)(modules[m].end - modules[m].base));
    }
    fprintf(map_f, "\n");

    /* --- 5. Bulk page table walk to collect mapped user-space pages --- */
    /*
     * Instead of probing 520K VAs one-by-one (each = 4-level PT walk),
     * we load entire page tables in bulk:
     *   PML4 (1 read) → PDPT (1 read) → PD (~2 reads) → PT (per valid PDE)
     * Total reads: ~tens to hundreds, vs ~2 million before.
     *
     * Permission bits extracted from PT entries:
     *   bit 1  (R/W): 0=read-only, 1=read-write
     *   bit 63 (NX):  0=executable, 1=no-execute
     *   Effective = AND of all levels (PML4, PDPT, PD, PT)
     */
    int pg_capacity = 65536;
    int pg_count = 0;
    mapped_page_t *pages = malloc(pg_capacity * sizeof(mapped_page_t));

    uint64_t cr3 = (cr3_override != 0) ? cr3_override : env->cr[3];
    uint64_t pml4_base = cr3 & 0x000FFFFFFFFFF000ULL;
    uint64_t pml4_table[512];
    cpu_physical_memory_read(pml4_base, pml4_table, 4096);

    /*
     * Walk all user-space PML4 entries (0-255 for Windows 64-bit user space).
     * Windows 64-bit places DLLs and PEs in the high user range (e.g.
     * 0x7FF6...), which falls in PML4[255].  The old code only read PML4[0]
     * and iterated PDPT[0..1], covering only VA 0-2 GB — entirely missing
     * 64-bit PE images.
     */
    for (int pml4_idx = 0; pml4_idx < 256; pml4_idx++) {
        uint64_t pml4e = pml4_table[pml4_idx];
        if (!(pml4e & 1)) continue;

        bool pml4_w = !!(pml4e & (1ULL << 1));
        bool pml4_x = !(pml4e & (1ULL << 63));

        uint64_t pdpt_base = pml4e & 0x000FFFFFFFFFF000ULL;
        uint64_t pdpt_table[512];
        cpu_physical_memory_read(pdpt_base, pdpt_table, 4096);

        for (int pdpte_idx = 0; pdpte_idx < 512; pdpte_idx++) {
            uint64_t pdpte = pdpt_table[pdpte_idx];
            if (!(pdpte & 1)) continue;

            if (pdpte & (1ULL << 7)) {
                /* 1GB huge page */
                bool hp_w = pml4_w && !!(pdpte & (1ULL << 1));
                bool hp_x = pml4_x && !(pdpte & (1ULL << 63));
                uint64_t page_phys = pdpte & 0x000FFFFFC0000000ULL;
                uint64_t base_va = ((uint64_t)pml4_idx << 39) |
                                   ((uint64_t)pdpte_idx << 30);
                for (int k = 0; k < 512 * 512; k++) {
                    uint64_t va = base_va + ((uint64_t)k << 12);
                    if (va < 0x10000) continue;
                    if (pg_count >= pg_capacity) {
                        pg_capacity *= 2;
                        pages = realloc(pages, pg_capacity * sizeof(mapped_page_t));
                    }
                    pages[pg_count].va   = va;
                    pages[pg_count].phys = page_phys + ((uint64_t)k << 12);
                    pages[pg_count].perm = 0x01
                                         | (hp_w ? 0x02 : 0)
                                         | (hp_x ? 0x04 : 0);
                    pg_count++;
                }
                continue;
            }

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

                uint64_t base_va = ((uint64_t)pml4_idx << 39) |
                                   ((uint64_t)pdpte_idx << 30) |
                                   ((uint64_t)pde_idx << 21);

                if (pde & (1ULL << 7)) {
                    /* 2MB huge page */
                    uint64_t page_phys = pde & 0x000FFFFFFFE00000ULL;
                    for (int k = 0; k < 512; k++) {
                        uint64_t va = base_va + ((uint64_t)k << 12);
                        if (va < 0x10000) continue;
                        if (pg_count >= pg_capacity) {
                            pg_capacity *= 2;
                            pages = realloc(pages, pg_capacity * sizeof(mapped_page_t));
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

                /* 4KB pages */
                uint64_t pt_base = pde & 0x000FFFFFFFFFF000ULL;
                uint64_t pt_table[512];
                cpu_physical_memory_read(pt_base, pt_table, 4096);

                for (int pte_idx = 0; pte_idx < 512; pte_idx++) {
                    uint64_t pte = pt_table[pte_idx];
                    if (!(pte & 1)) continue;

                    uint64_t va = base_va + ((uint64_t)pte_idx << 12);
                    if (va < 0x10000) continue;

                    uint64_t phys = pte & 0x000FFFFFFFFFF000ULL;
                    bool w = pd_w && !!(pte & (1ULL << 1));
                    bool x = pd_x && !(pte & (1ULL << 63));

                    if (pg_count >= pg_capacity) {
                        pg_capacity *= 2;
                        pages = realloc(pages, pg_capacity * sizeof(mapped_page_t));
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

    nyx_printf("    [FULLDUMP] PT walk done: %d mapped pages in user space\n",
               pg_count);

    /* --- 6. Read all pages into memory snapshot, then write only changes --- */
    /*
     * Phase 1: Read all pages by physical address into cur_snap (memory-only).
     * Phase 2: Compare with previous snapshot; write only changed/new pages
     *          to disk.  First dump (no previous) writes everything.
     */
    int region_count = 0;
    uint64_t total_bytes = 0;

    /* Always allocate current snapshot */
    crossdump_page_t *cur_snap = malloc(pg_count * sizeof(crossdump_page_t));
    int cur_snap_count = 0;

    /* Phase 1: Read all pages into cur_snap (fast — physical memory reads) */
    for (int p = 0; p < pg_count; p++) {
        cur_snap[cur_snap_count].va = pages[p].va;
        cpu_physical_memory_read(pages[p].phys,
                                 cur_snap[cur_snap_count].content, 0x1000);
        cur_snap_count++;
    }

    /* Phase 2: Determine which pages to write to disk */
    bool is_incremental = crossdump_prev.valid && crossdump_prev.count > 0;
    int written_pages = 0;
    int skipped_pages = 0;

    if (!is_incremental) {
        /* First dump: write all regions (full baseline) */
        int i = 0;
        while (i < pg_count) {
            uint64_t region_start = pages[i].va;
            uint8_t  region_perm  = pages[i].perm;
            int      region_first = i;

            while (i + 1 < pg_count &&
                   pages[i + 1].va == pages[i].va + 0x1000 &&
                   pages[i + 1].perm == region_perm) {
                i++;
            }
            int region_last = i;
            i++;

            uint64_t region_size = (uint64_t)(region_last - region_first + 1) * 0x1000;

            char perm_str[4];
            perm_str[0] = 'r';
            perm_str[1] = (region_perm & 0x02) ? 'w' : '-';
            perm_str[2] = (region_perm & 0x04) ? 'x' : '-';
            perm_str[3] = '\0';

            const char *mod_name = NULL;
            for (int m = 0; m < num_modules; m++) {
                if (region_start >= modules[m].base &&
                    region_start < modules[m].end) {
                    mod_name = modules[m].name;
                    break;
                }
            }

            char *reg_path = NULL;
            assert(asprintf(&reg_path, "%s/region_%016lx_%lx_%s.bin",
                            dump_dir, (unsigned long)region_start,
                            (unsigned long)region_size, perm_str) != -1);
            FILE *rf = fopen(reg_path, "w");
            if (rf) {
                for (int p = region_first; p <= region_last; p++) {
                    fwrite(cur_snap[p].content, 1, 0x1000, rf);
                }
                fclose(rf);
            }

            fprintf(map_f, "  0x%016lx  0x%016lx  0x%016lx  %-5s  region_%016lx_%lx_%s.bin  %s\n",
                    (unsigned long)region_start,
                    (unsigned long)(region_start + region_size),
                    (unsigned long)region_size,
                    perm_str,
                    (unsigned long)region_start,
                    (unsigned long)region_size,
                    perm_str,
                    mod_name ? mod_name : "");

            region_count++;
            total_bytes += region_size;
            written_pages += (region_last - region_first + 1);
            free(reg_path);
        }
    } else {
        /* Incremental dump: only write changed/new pages */
        fprintf(map_f, "# INCREMENTAL (base: dump #%03d)\n\n",
                crossdump_prev.prev_seq);

        for (int p = 0; p < cur_snap_count; p++) {
            uint64_t va = cur_snap[p].va;
            int prev_idx = crossdump_find_va(va);

            bool page_changed;
            if (prev_idx < 0) {
                page_changed = true;  /* New page */
            } else {
                page_changed = (memcmp(cur_snap[p].content,
                                       crossdump_prev.pages[prev_idx].content,
                                       WTE_PAGE_SIZE) != 0);
            }

            if (!page_changed) {
                skipped_pages++;
                continue;
            }

            /* Write individual changed page */
            uint8_t perm = pages[p].perm;
            char perm_str[4];
            perm_str[0] = 'r';
            perm_str[1] = (perm & 0x02) ? 'w' : '-';
            perm_str[2] = (perm & 0x04) ? 'x' : '-';
            perm_str[3] = '\0';

            const char *mod_name = NULL;
            for (int m = 0; m < num_modules; m++) {
                if (va >= modules[m].base &&
                    va < modules[m].end) {
                    mod_name = modules[m].name;
                    break;
                }
            }

            char *pg_path = NULL;
            assert(asprintf(&pg_path, "%s/page_%016lx_%s.bin",
                            dump_dir, (unsigned long)va, perm_str) != -1);
            FILE *pf = fopen(pg_path, "w");
            if (pf) {
                fwrite(cur_snap[p].content, 1, 0x1000, pf);
                fclose(pf);
            }

            fprintf(map_f, "  0x%016lx  0x%016lx  0x00001000  %-5s  page_%016lx_%s.bin  %-7s  %s\n",
                    (unsigned long)va, (unsigned long)(va + 0x1000),
                    perm_str, (unsigned long)va, perm_str,
                    prev_idx < 0 ? "NEW" : "CHANGED",
                    mod_name ? mod_name : "");

            region_count++;
            total_bytes += 0x1000;
            written_pages++;
            free(pg_path);
        }
    }

    free(pages);
    fprintf(map_f, "\n# Total: %d %s, %lu bytes written (%d pages total, %d skipped)\n",
            region_count, is_incremental ? "changed pages" : "regions",
            (unsigned long)total_bytes, pg_count, skipped_pages);
    fclose(map_f);

    nyx_printf("    [FULLDUMP] %s: wrote %d %s (%lu bytes, %d/%d pages) -> %s/\n",
               is_incremental ? "INCREMENTAL" : "FULL",
               region_count, is_incremental ? "changed pages" : "regions",
               (unsigned long)total_bytes, written_pages, pg_count, dump_dir);

    /* --- 6b. Append to cumulative WtE timeline --- */
    if (event) {
        char *tl_path = NULL;
        assert(asprintf(&tl_path, "%s/dump/wte_timeline.txt",
                        GET_GLOBAL_STATE()->workdir_path) != -1);
        FILE *tl_f = fopen(tl_path, "a");
        if (tl_f) {
            /* Write header on first event */
            if (seq == 0) {
                fprintf(tl_f, "# WtE Detection Timeline\n");
                fprintf(tl_f, "# SEQ  TYPE       RIP         VA          "
                        "GFN        FS_BASE     DIFFS  PAGES_WRITTEN  PAGES_TOTAL  "
                        "WTE#  LABEL\n");
            }
            fprintf(tl_f, "%03d  %-9s  0x%08lx  0x%08lx  0x%06lx  0x%08lx  %5d  %13d  %11d  "
                    "#%-4d  %s\n",
                    seq, event->type,
                    (unsigned long)event->rip, (unsigned long)event->va,
                    (unsigned long)event->gfn, (unsigned long)event->fs_base,
                    event->diff_count,
                    written_pages, pg_count,
                    event->total_wte_count, label);
            fclose(tl_f);
        }
        free(tl_path);
    }

    /* --- 7. Cross-dump byte diff: compare with previous snapshot --- */
    if (cur_snap && crossdump_prev.valid && crossdump_prev.count > 0) {
        char *diff_path = NULL;
        assert(asprintf(&diff_path, "%s/diff_report.txt", dump_dir) != -1);
        FILE *diff_f = fopen(diff_path, "w");
        if (diff_f) {
            fprintf(diff_f, "# Cross-dump byte diff report\n");
            fprintf(diff_f, "# Current dump:  #%03d (%s)\n", seq, label);
            fprintf(diff_f, "# Previous dump: #%03d\n", crossdump_prev.prev_seq);
            fprintf(diff_f, "# Current pages: %d, Previous pages: %d\n\n",
                    cur_snap_count, crossdump_prev.count);

            int changed_pages = 0;
            int new_pages = 0;
            int removed_pages = 0;
            uint64_t total_changed_bytes = 0;

            /* Compare each current page with previous snapshot */
            for (int c = 0; c < cur_snap_count; c++) {
                uint64_t va = cur_snap[c].va;
                int prev_idx = crossdump_find_va(va);

                if (prev_idx < 0) {
                    /* Page exists in current but not in previous = new page */
                    new_pages++;

                    /* Identify module */
                    const char *mname = NULL;
                    for (int m = 0; m < num_modules; m++) {
                        if (va >= modules[m].base &&
                            va < modules[m].end) {
                            mname = modules[m].name;
                            break;
                        }
                    }

                    fprintf(diff_f, "NEW   VA=0x%016lx  %s\n",
                            (unsigned long)va, mname ? mname : "(unmapped)");
                    continue;
                }

                /* Page exists in both — do byte-level comparison */
                const uint8_t *prev_data = crossdump_prev.pages[prev_idx].content;
                const uint8_t *cur_data  = cur_snap[c].content;

                if (memcmp(prev_data, cur_data, WTE_PAGE_SIZE) == 0) {
                    continue;  /* Identical — skip */
                }

                /* Find changed byte ranges within this page */
                changed_pages++;
                int range_count = 0;
                uint16_t range_offsets[WTE_MAX_DIFF_RANGES];
                uint16_t range_lengths[WTE_MAX_DIFF_RANGES];
                int page_changed_bytes = 0;

                int b = 0;
                while (b < WTE_PAGE_SIZE && range_count < WTE_MAX_DIFF_RANGES) {
                    if (prev_data[b] != cur_data[b]) {
                        int start = b;
                        while (b < WTE_PAGE_SIZE && prev_data[b] != cur_data[b])
                            b++;
                        range_offsets[range_count] = (uint16_t)start;
                        range_lengths[range_count] = (uint16_t)(b - start);
                        page_changed_bytes += (b - start);
                        range_count++;
                    } else {
                        b++;
                    }
                }

                total_changed_bytes += page_changed_bytes;

                /* Identify module */
                const char *mname = NULL;
                for (int m = 0; m < num_modules; m++) {
                    if (va >= modules[m].base &&
                        va < modules[m].end) {
                        mname = modules[m].name;
                        break;
                    }
                }

                fprintf(diff_f, "CHANGED  VA=0x%016lx  %d ranges  %d bytes  %s\n",
                        (unsigned long)va, range_count, page_changed_bytes,
                        mname ? mname : "(unmapped)");
                for (int r = 0; r < range_count; r++) {
                    fprintf(diff_f, "    offset=0x%04x  len=%d\n",
                            range_offsets[r], range_lengths[r]);
                }
            }

            /* Check for removed pages (in prev but not in current) */
            for (int p = 0; p < crossdump_prev.count; p++) {
                uint64_t prev_va = crossdump_prev.pages[p].va;
                bool found = false;
                int lo = 0, hi = cur_snap_count - 1;
                while (lo <= hi) {
                    int mid = (lo + hi) / 2;
                    if (cur_snap[mid].va == prev_va) { found = true; break; }
                    if (cur_snap[mid].va < prev_va) lo = mid + 1;
                    else hi = mid - 1;
                }
                if (!found) {
                    removed_pages++;
                    fprintf(diff_f, "REMOVED  VA=0x%016lx\n", (unsigned long)prev_va);
                }
            }

            fprintf(diff_f, "\n# Summary: %d changed, %d new, %d removed pages  "
                    "(%lu bytes changed total)\n",
                    changed_pages, new_pages, removed_pages,
                    (unsigned long)total_changed_bytes);
            fclose(diff_f);

            nyx_printf("    [FULLDUMP] Cross-dump diff: %d changed, %d new, %d removed "
                       "pages (%lu bytes changed) vs dump #%03d\n",
                       changed_pages, new_pages, removed_pages,
                       (unsigned long)total_changed_bytes,
                       crossdump_prev.prev_seq);
        }
        free(diff_path);
    } else if (cur_snap && !crossdump_prev.valid) {
        nyx_printf("    [FULLDUMP] Cross-dump diff: first dump, no previous to compare\n");
    }

    /* --- 8. Swap current snapshot into previous for next comparison --- */
    if (cur_snap) {
        /* Reuse the crossdump_prev.pages buffer if large enough */
        if (cur_snap_count > crossdump_prev.capacity) {
            free(crossdump_prev.pages);
            crossdump_prev.capacity = cur_snap_count + 1024;
            crossdump_prev.pages = malloc(crossdump_prev.capacity *
                                          sizeof(crossdump_page_t));
        }
        memcpy(crossdump_prev.pages, cur_snap,
               cur_snap_count * sizeof(crossdump_page_t));
        crossdump_prev.count = cur_snap_count;
        crossdump_prev.prev_seq = seq;
        crossdump_prev.valid = true;
        free(cur_snap);
    }

    free(modules);
    free(map_path);
    free(dump_dir);
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
                        dump_full_process_memory(cpu, env, dump_label, NULL, 0);
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

    /* Sanitize path: strip leading slashes, block directory traversal,
     * but preserve subdirectory structure for organized dumps */
    char *sanitized = filename;
    while (*sanitized == '/' || *sanitized == '\\') sanitized++;
    if (strstr(sanitized, "..")) {
        sanitized = basename(sanitized);  /* fallback: strip path if traversal detected */
    }
    assert(asprintf(&host_path, "%s/dump/%s", GET_GLOBAL_STATE()->workdir_path,
                    sanitized) != -1);

    /* Create parent directories if needed (supports round_N/ subdirs) */
    {
        char *dir_part = g_path_get_dirname(host_path);
        g_mkdir_with_parents(dir_part, 0755);
        g_free(dir_part);
    }

    // check if sanitized name is mkstemp() pattern, otherwise write/append to exact name
    char *pattern = strstr(sanitized, "XXXXXX");
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
    case KVM_EXIT_KAFL_WOX_SNAPSHOT:
    {
        /* DEPRECATED: Use KVM_EXIT_KAFL_WTE_SETUP instead.
         * WOX_SNAPSHOT is kept for backward compatibility but does nothing.
         * WTE_SETUP handles root snapshot + EPROCESS CR3 walk + eager NX. */
        nyx_printf("[WtE] WOX_SNAPSHOT: DEPRECATED \u2014 use WTE_SETUP instead\n");
        ret = 0;
        break;
    }
    case KVM_EXIT_KAFL_WTE:
    {
        /* EPT violation — write (W=0) or execute (X=0).
         * Dispatch based on violation type.
         * Also run CoW detection here (not on every VM exit). */
        kvm_arch_get_registers(cpu);
        uint64_t wte_gfn  = run->kafl_wte.gfn;
        uint64_t wte_gpa  = run->kafl_wte.gpa;
        uint64_t wte_rip  = run->kafl_wte.rip;
        uint64_t wte_cr3  = run->kafl_wte.cr3;
        uint32_t wte_type = run->kafl_wte.type;

        /* CoW detection: rescan PE VA→GFN only on EPT violation exits */
        wte_pt_check(cpu);

        /* Note: wte_check_deferred_pages() is now called at every VM
         * exit in kvm-all.c, so no need to call it here separately. */

        if (wte_type == WTE_VIOLATION_WRITE) {
            nyx_printf("[WtE] KVM exit (WRITE): GFN=0x%lx RIP=0x%lx\n",
                       (unsigned long)wte_gfn, (unsigned long)wte_rip);
            wte_handle_write_violation(wte_gfn, wte_gpa, wte_rip, cpu);
        } else {
            /* Non-target CR3: harness or OS hit a shared NX DLL page.
             * Clear NX quietly — no WtE event (page was not written). */
            if (wte_is_active() &&
                wte_get_state()->target_cr3 != 0 &&
                wte_cr3 != wte_get_state()->target_cr3) {
                wte_kvm_clear_nx(&wte_gfn, 1);
            } else {
                nyx_printf("[WtE] KVM exit (EXEC): GFN=0x%lx RIP=0x%lx\n",
                           (unsigned long)wte_gfn, (unsigned long)wte_rip);
                wte_handle_exec_violation(wte_gfn, wte_gpa, wte_rip, cpu);
            }
        }
        ret = 0;
        break;
    }
    case KVM_EXIT_KAFL_NYX_HOOK:
    {
        /* In-kernel hook table matched a registered RIP.
         * Dispatch to api_hook module (Phase 3 implements arg capture
         * + return-RIP one-shot + per-function callbacks). */
        kvm_arch_get_registers(cpu);
        uint64_t hk_rip = run->kafl_nyx_hook.rip;
        uint64_t hk_cr3 = run->kafl_nyx_hook.cr3;
        uint64_t hk_id  = run->kafl_nyx_hook.hook_id;

        nyx_api_hook_dispatch(cpu, hk_id, hk_rip, hk_cr3);
        ret = 0;
        break;
    }
    case KVM_EXIT_KAFL_WTE_SETUP:
    {
        /*
         * WTE_SETUP: Initialize WtE detection BEFORE target process executes.
         * Called by harness after CreateProcess(SUSPENDED), before ResumeThread.
         *
         * Flow:
         *   1. Read kafl_wte_setup_t from guest memory (target PID, image info)
         *   2. Create root snapshot for baseline memory content
         *      NOTE: If snapshot is created here, fast_reload_restore() resets
         *      RIP to the VMCALL instruction. The guest will re-execute VMCALL
         *      with correct RAX=0x1f, causing a second entry into this handler
         *      where the snapshot already exists. We must NOT call
         *      set_return_value() on the first entry because it would corrupt
         *      RAX (changing it from 0x1f to child_cr3), causing KVM to
         *      misidentify the re-executed VMCALL as a non-kAFL hypercall
         *      and return -ENOSYS (0xFFFFFFFFFFFFFFFF) to the guest.
         *   3. Walk EPROCESS list to find target process CR3 by PID
         *   4. wte_init() + wte_activate(child_cr3) — start WtE tracking
         *   5. Eagerly set EPT NX on all target PE pages
         *   6. Return discovered child CR3 to guest via EAX
         */
        kvm_arch_get_registers(cpu);
        CPUX86State *env = &(X86_CPU(cpu)->env);
        uint64_t harness_cr3 = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;

        /* Read kafl_wte_setup_t struct from guest memory */
        typedef struct {
            uint64_t target_pid;
            uint64_t image_base;
            uint64_t image_size;
            uint32_t flags;
            uint64_t sweep_flag_gva;  /* harness VA of force-JIT sweep flag */
        } __attribute__((packed)) kafl_wte_setup_t;

        kafl_wte_setup_t setup = {0};
        if (!read_virtual_memory(arg, (uint8_t *)&setup,
                                 sizeof(setup), cpu)) {
            nyx_printf("[WtE] WTE_SETUP: failed to read setup struct at 0x%lx\n",
                       (unsigned long)arg);
            set_return_value(cpu, 0);
            ret = 0;
            break;
        }

        bool is_32bit   = (setup.flags & (1 << 0)) != 0;  /* WTE_FLAG_32BIT */
        bool eager_nx    = (setup.flags & (1 << 1)) != 0;  /* WTE_FLAG_EAGER_NX */

        nyx_printf("[WtE] WTE_SETUP: PID=%lu image_base=0x%lx image_size=0x%lx "
                   "flags=0x%x (32bit=%d eager_nx=%d) harness_cr3=0x%lx\n",
                   (unsigned long)setup.target_pid,
                   (unsigned long)setup.image_base,
                   (unsigned long)setup.image_size,
                   setup.flags, is_32bit, eager_nx,
                   (unsigned long)harness_cr3);

        /* Step 1: Create root snapshot for baseline (if not already created)
         * If we create a snapshot here, fast_reload_restore() resets RIP to the
         * VMCALL instruction and restores all registers to pre-hypercall state.
         * We must skip all remaining work (WtE init, set_return_value) and let
         * the guest re-execute VMCALL cleanly — it will re-enter this handler
         * on the second call with the snapshot already in place. */
        if (!fast_reload_root_created(get_fast_reload_snapshot())) {
            nyx_printf("[WtE] WTE_SETUP: Creating root snapshot for baseline...\n");
            request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                   REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP);
            nyx_printf("[WtE] WTE_SETUP: Root snapshot created. "
                       "Deferring WtE init to next VMCALL re-entry.\n");
            ret = 0;
            break;
        }

        nyx_printf("[WtE] WTE_SETUP: Root snapshot already exists, "
                   "proceeding with WtE initialization\n");

        /* Step 2: Walk EPROCESS to find target process CR3 by PID */
        uint64_t child_cr3 = wte_find_cr3_by_pid(cpu, harness_cr3,
                                                   setup.target_pid);
        if (child_cr3 == 0) {
            nyx_printf("[WtE] WTE_SETUP: FAILED to find CR3 for PID %lu\n",
                       (unsigned long)setup.target_pid);
            set_return_value(cpu, 0);
            ret = 0;
            break;
        }

        /* Validate CR3: must be page-aligned, not a known garbage value,
         * and within reasonable physical address range */
        if ((child_cr3 & 0xFFF) != 0 ||
            child_cr3 == 0x1f ||  /* HYPERCALL_KAFL_RAX_ID — leftover from failed dispatch */
            child_cr3 < 0x10000) {  /* Too low to be a real page table base */
            nyx_printf("[WtE] WTE_SETUP: INVALID CR3=0x%lx for PID %lu "
                       "(page-aligned=%d, not-magic=%d)\n",
                       (unsigned long)child_cr3,
                       (unsigned long)setup.target_pid,
                       (child_cr3 & 0xFFF) == 0,
                       child_cr3 != 0x1f);
            set_return_value(cpu, 0);
            ret = 0;
            break;
        }
        nyx_printf("[WtE] WTE_SETUP: Found child CR3=0x%lx for PID %lu\n",
                   (unsigned long)child_cr3, (unsigned long)setup.target_pid);

        /* Step 3: Initialize and activate WtE with child CR3 */
        wte_init();
        wte_activate(child_cr3, !is_32bit);  /* is_64bit = !is_32bit */
        nyx_printf("[WtE] WTE_SETUP: WtE activated (cr3=0x%lx, %s)\n",
                   (unsigned long)child_cr3, is_32bit ? "32-bit" : "64-bit");

        /* Force-JIT sweep trigger: if the harness provided a flag GVA, wire
         * up JIT-idle detection to write it over the harness CR3.  Must run
         * AFTER wte_activate (which resets sweep_trigger state). */
        if (setup.sweep_flag_gva != 0) {
            wte_sweep_trigger_setup(setup.sweep_flag_gva, harness_cr3,
                                    500000 /* 500ms idle threshold */);
        }

        /* Step 4: Protect target PE pages with W=0 + X=0 (Dual-Watch) */
        if (setup.image_base != 0 && setup.image_size != 0) {
            wte_protect_pe_range(cpu, setup.image_base,
                                setup.image_size, child_cr3);
            nyx_printf("[WtE] WTE_SETUP: Dual-Watch protection set on PE "
                       "[0x%lx - 0x%lx]\n",
                       (unsigned long)setup.image_base,
                       (unsigned long)(setup.image_base + setup.image_size));
        }

        /* Step 5: Dynamic region NX is handled by periodic rescan
         * (wte_rescan_user_pages in kvm-all.c VM exit loop) AFTER
         * the Nyx handshake completes. Setting NX here at WTE_SETUP
         * causes NX violation storm on DLL pages before handshake,
         * crashing QEMU with 'Broken pipe'. */

        /* Step 6: Diagnostic — map target PE VA→GFN for tracking */
        if (setup.image_base != 0 && setup.image_size != 0) {
            wte_diagnose_target_pe(cpu, setup.image_base, setup.image_size);
        }

        /* Step 6b: Enumerate currently loaded DLLs (PEB→Ldr) and install
         * stealth API hooks on ntdll Nt* exports.  Hook hits replace the
         * timing-sensitive periodic rescan with deterministic event-driven
         * detection of LoadLibrary / VirtualAlloc / VirtualProtect /
         * MapViewOfSection. */
        wte_enumerate_dlls(cpu);
        {
            uint64_t ntdll_base = 0;
            wte_state_t *ws = wte_get_state();
            for (int i = 0; i < ws->dll_module_count; i++) {
                const char *n = ws->dll_modules[i].name;
                /* Case-insensitive match of "ntdll.dll" exactly */
                if (strncasecmp(n, "ntdll.dll", 9) == 0 && n[9] == '\0') {
                    ntdll_base = ws->dll_modules[i].base;
                    break;
                }
            }
            if (ntdll_base != 0) {
                nyx_api_hook_init();
                int n = nyx_api_hook_install(cpu, ntdll_base, !is_32bit);
                nyx_printf("[WtE] WTE_SETUP: nyx_api_hook installed=%d\n", n);
            } else {
                nyx_printf("[WtE] WTE_SETUP: ntdll.dll not found in PEB→Ldr — "
                           "API hooks not installed\n");
            }
        }

        /* Step 6: Initial dump — packed PE state before any execution.
         * This becomes fulldump_000 (EP entry point baseline).
         * WtE dumps will follow as fulldump_001, 002, ... */
        {
            nyx_printf("[WtE] WTE_SETUP: Taking initial EP dump "
                       "(packed baseline) with child CR3=0x%lx\n",
                       (unsigned long)child_cr3);
            wte_dump_event_t ep_evt = {
                .type            = "EP_INIT",
                .rip             = setup.image_base,
                .va              = setup.image_base,
                .gfn             = 0,
                .fs_base         = (uint64_t)env->segs[R_FS].base,
                .diff_count      = 0,
                .wte_count       = 0,
                .total_wte_count = 0,
            };
            dump_full_process_memory(cpu, env, "ep_initial_packed",
                                     &ep_evt, child_cr3);
        }

        /* Return child CR3 to guest so harness can use it for SUBMIT_CR3 */
        set_return_value(cpu, child_cr3);
        ret = 0;
        break;
    }
    }
    return ret;
}
