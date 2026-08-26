#include "dump_state.h"

#include <stddef.h>

bool nyx_dump_snapshot_publish(nyx_dump_snapshot_state_t *state,
                               bool outputs_complete,
                               void **replacement_pages,
                               int replacement_count,
                               int replacement_capacity,
                               int replacement_seq,
                               void **old_pages_out)
{
    void *old_pages;

    if (state == NULL || replacement_pages == NULL || old_pages_out == NULL) {
        return false;
    }

    *old_pages_out = NULL;
    if (!outputs_complete) {
        return false;
    }

    old_pages = state->pages;
    state->pages = *replacement_pages;
    state->count = replacement_count;
    state->capacity = replacement_capacity;
    state->prev_seq = replacement_seq;
    state->valid = true;
    *replacement_pages = NULL;
    *old_pages_out = old_pages;
    return true;
}
