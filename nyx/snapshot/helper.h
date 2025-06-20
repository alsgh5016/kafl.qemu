#pragma once

#include <stdint.h>

#define x86_64_PAGE_SIZE 4096

// NOTE: test_and_set_bit operates on 8-byte words, so bitmap sizes must be multiples of 8
#define BITMAP_SIZE(x)      (((((x / x86_64_PAGE_SIZE) >> 3) + 7) >> 3) << 3)
#define DIRTY_STACK_SIZE(x) ((x / x86_64_PAGE_SIZE) * sizeof(uint64_t))


uint64_t get_ram_size(void);
