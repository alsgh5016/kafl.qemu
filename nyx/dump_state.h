#pragma once

#include <stdbool.h>

typedef struct nyx_dump_snapshot_state {
    void *pages;
    int count;
    int capacity;
    int prev_seq;
    bool valid;
} nyx_dump_snapshot_state_t;

bool nyx_dump_snapshot_publish(nyx_dump_snapshot_state_t *state,
                               bool outputs_complete,
                               void **replacement_pages,
                               int replacement_count,
                               int replacement_capacity,
                               int replacement_seq,
                               void **old_pages_out);
