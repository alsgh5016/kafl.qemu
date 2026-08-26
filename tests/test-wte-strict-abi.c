#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __linux__
#define QEMU_NYX 1
#include "../linux-headers/linux/kvm.h"
#else
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint64_t __aligned_u64;

#define _IOC_NRBITS 8
#define _IOC_TYPEBITS 8
#define _IOC_SIZEBITS 14
#define _IOC_DIRBITS 2
#define _IOC_NRSHIFT 0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT (_IOC_SIZESHIFT + _IOC_SIZEBITS)
#define _IOC_NONE 0U
#define _IOC_WRITE 1U
#define _IOC_READ 2U
#define _IOC(dir, type, nr, size) \
    (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | \
     ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
#define _IOC_TYPECHECK(t) (sizeof(t))
#define _IOWR(type, nr, size) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOC_NR(nr) (((nr) >> _IOC_NRSHIFT) & ((1U << _IOC_NRBITS) - 1))
#define _IOC_DIR(nr) (((nr) >> _IOC_DIRSHIFT) & ((1U << _IOC_DIRBITS) - 1))
#define _IOC_SIZE(nr) (((nr) >> _IOC_SIZESHIFT) & ((1U << _IOC_SIZEBITS) - 1))

#define KVMIO 0xAE

#define KVM_EXIT_KAFL_WTE 142
#define KVM_EXIT_KAFL_WTE_SETUP 143
#define KVM_EXIT_KAFL_NYX_HOOK 144
#define KVM_EXIT_KAFL_STRICT_PT 145
#define KVM_CAP_NYX_STRICT_PT 514
#define KVM_NYX_STRICT_PT_CONTROL_SIZE 128
#define KVM_NYX_STRICT_PT_ABI_VERSION_1 1
#define KVM_NYX_STRICT_PT_QUERY 0
#define KVM_NYX_STRICT_PT_ENABLE 1
#define KVM_NYX_STRICT_PT_DISABLE 2
#define KVM_NYX_STRICT_PT_RESET 3
#define KVM_NYX_STRICT_PT_RANGE_ADD 4
#define KVM_NYX_STRICT_PT_RANGE_REMOVE 5
#define KVM_NYX_STRICT_PT_ACK 6
#define KVM_NYX_STRICT_PT_GET_STATUS 7
#define KVM_NYX_STRICT_PT_FEAT_CPU_PT_WRITE_TRACKING (1ULL << 0)
#define KVM_NYX_STRICT_PT_FEAT_ROOT_LOCAL_EPT (1ULL << 1)
#define KVM_NYX_STRICT_PT_FEAT_GENERATION_ACK (1ULL << 2)
#define KVM_NYX_STRICT_PT_FEAT_HUGE_GUEST_LEAVES (1ULL << 3)
#define KVM_NYX_STRICT_PT_FEAT_RESET (1ULL << 4)
#define KVM_NYX_STRICT_PT_EXIT_FIRST_EXEC (1U << 0)

struct kvm_nyx_strict_pt_query {
    __aligned_u64 features;
    __u32 abi_min_version;
    __u32 abi_max_version;
    __u32 max_ranges;
    __u32 max_pages_per_range;
    __u32 max_vcpus;
    __u32 exit_reason;
    __aligned_u64 reserved[10];
};

struct kvm_nyx_strict_pt_enable {
    __aligned_u64 target_cr3;
    __aligned_u64 session_id;
    __aligned_u64 reserved[12];
};

struct kvm_nyx_strict_pt_reset {
    __aligned_u64 session_id;
    __aligned_u64 new_session_id;
    __aligned_u64 reserved[12];
};

struct kvm_nyx_strict_pt_range_add {
    __aligned_u64 session_id;
    __aligned_u64 gva_start;
    __aligned_u64 gva_end;
    __aligned_u64 range_id;
    __aligned_u64 reserved[10];
};

struct kvm_nyx_strict_pt_range_remove {
    __aligned_u64 session_id;
    __aligned_u64 range_id;
    __aligned_u64 reserved[12];
};

struct kvm_nyx_strict_pt_ack {
    __aligned_u64 session_id;
    __aligned_u64 range_id;
    __aligned_u64 generation;
    __u32 page_index;
    __u32 reserved0;
    __aligned_u64 reserved[10];
};

struct kvm_nyx_strict_pt_status {
    __aligned_u64 session_id;
    __aligned_u64 next_generation;
    __u32 state;
    __u32 active_ranges;
    __u32 vcpu_count;
    __u32 reserved0;
    __aligned_u64 ranges_added;
    __aligned_u64 ranges_removed;
    __aligned_u64 resets;
    __aligned_u64 pt_write_events;
    __aligned_u64 mapping_changes;
    __aligned_u64 nx_arms;
    __aligned_u64 strict_exits;
    __aligned_u64 acks;
    __aligned_u64 stale_acks;
    __aligned_u64 fail_closed;
};

struct kvm_nyx_strict_pt_control {
    __u16 version;
    __u16 command;
    __u32 flags;
    __u32 size;
    __u32 reserved0;
    union {
        struct kvm_nyx_strict_pt_query query;
        struct kvm_nyx_strict_pt_enable enable;
        struct kvm_nyx_strict_pt_reset reset;
        struct kvm_nyx_strict_pt_range_add range_add;
        struct kvm_nyx_strict_pt_range_remove range_remove;
        struct kvm_nyx_strict_pt_ack ack;
        struct kvm_nyx_strict_pt_status status;
        __u8 reserved[112];
    } u;
};

struct kvm_nyx_strict_pt_exit {
    __u16 version;
    __u16 reserved0;
    __u32 flags;
    __aligned_u64 session_id;
    __aligned_u64 range_id;
    __aligned_u64 generation;
    __aligned_u64 gva;
    __aligned_u64 gpa;
    __aligned_u64 rip;
    __aligned_u64 cr3;
    __u32 page_index;
    __u32 reserved1;
    __aligned_u64 reserved[3];
};

#define KVM_NYX_STRICT_PT_CONTROL _IOWR(KVMIO, 0xfe, struct kvm_nyx_strict_pt_control)
#endif

#define STATIC_CHECK(_cond, _msg) _Static_assert((_cond), _msg)

STATIC_CHECK(KVM_CAP_NYX_STRICT_PT == 514, "strict cap must stay 514");
STATIC_CHECK(KVM_EXIT_KAFL_STRICT_PT == 145, "strict exit must stay 145");
STATIC_CHECK(KVM_EXIT_KAFL_WTE == 142, "legacy wte exit must stay 142");
STATIC_CHECK(KVM_EXIT_KAFL_WTE_SETUP == 143, "legacy setup exit must stay 143");
STATIC_CHECK(KVM_EXIT_KAFL_NYX_HOOK == 144, "legacy hook exit must stay 144");
STATIC_CHECK(KVM_NYX_STRICT_PT_CONTROL_SIZE == 128, "control size must stay 128");
STATIC_CHECK(KVM_NYX_STRICT_PT_ABI_VERSION_1 == 1, "abi version must stay 1");
STATIC_CHECK(KVM_NYX_STRICT_PT_QUERY == 0, "query command");
STATIC_CHECK(KVM_NYX_STRICT_PT_ENABLE == 1, "enable command");
STATIC_CHECK(KVM_NYX_STRICT_PT_DISABLE == 2, "disable command");
STATIC_CHECK(KVM_NYX_STRICT_PT_RESET == 3, "reset command");
STATIC_CHECK(KVM_NYX_STRICT_PT_RANGE_ADD == 4, "range add command");
STATIC_CHECK(KVM_NYX_STRICT_PT_RANGE_REMOVE == 5, "range remove command");
STATIC_CHECK(KVM_NYX_STRICT_PT_ACK == 6, "ack command");
STATIC_CHECK(KVM_NYX_STRICT_PT_GET_STATUS == 7, "status command");
STATIC_CHECK(KVM_NYX_STRICT_PT_FEAT_CPU_PT_WRITE_TRACKING == (1ULL << 0), "feature 0");
STATIC_CHECK(KVM_NYX_STRICT_PT_FEAT_ROOT_LOCAL_EPT == (1ULL << 1), "feature 1");
STATIC_CHECK(KVM_NYX_STRICT_PT_FEAT_GENERATION_ACK == (1ULL << 2), "feature 2");
STATIC_CHECK(KVM_NYX_STRICT_PT_FEAT_HUGE_GUEST_LEAVES == (1ULL << 3), "feature 3");
STATIC_CHECK(KVM_NYX_STRICT_PT_FEAT_RESET == (1ULL << 4), "feature 4");
STATIC_CHECK(KVM_NYX_STRICT_PT_EXIT_FIRST_EXEC == (1U << 0), "exit flag");
STATIC_CHECK(sizeof(struct kvm_nyx_strict_pt_control) == 128, "control layout size");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_control, version) == 0, "control version offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_control, command) == 2, "control command offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_control, flags) == 4, "control flags offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_control, size) == 8, "control size offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_control, reserved0) == 12, "control reserved0 offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_control, u) == 16, "control payload offset");
STATIC_CHECK(sizeof(struct kvm_nyx_strict_pt_exit) == 96, "exit layout size");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, version) == 0, "exit version offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, reserved0) == 2, "exit reserved0 offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, flags) == 4, "exit flags offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, session_id) == 8, "exit session offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, range_id) == 16, "exit range offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, generation) == 24, "exit generation offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, gva) == 32, "exit gva offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, gpa) == 40, "exit gpa offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, rip) == 48, "exit rip offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, cr3) == 56, "exit cr3 offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, page_index) == 64, "exit page index offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, reserved1) == 68, "exit reserved1 offset");
STATIC_CHECK(offsetof(struct kvm_nyx_strict_pt_exit, reserved) == 72, "exit reserved offset");
STATIC_CHECK(_IOC_NR(KVM_NYX_STRICT_PT_CONTROL) == 0xfe, "ioctl nr must stay 0xfe");
STATIC_CHECK(_IOC_DIR(KVM_NYX_STRICT_PT_CONTROL) == (_IOC_READ | _IOC_WRITE), "ioctl dir must stay iowr");
STATIC_CHECK(_IOC_SIZE(KVM_NYX_STRICT_PT_CONTROL) == sizeof(struct kvm_nyx_strict_pt_control), "ioctl size must match control");

int main(void)
{
    puts("TAP version 13");
    puts("1..1");
#ifdef __linux__
    puts("ok 1 - imported strict abi layout matches frozen contract");
#else
    puts("ok 1 - strict abi fallback layout matches frozen contract");
#endif
    return 0;
}
