#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../nyx/checked_io.h"
#include "../nyx/checked_io.c"
#include "../nyx/dump_state.h"
#include "../nyx/dump_state.c"

struct fake_file {
    int fd;
};

enum failure_mode {
    FAILURE_NONE = 0,
    FAILURE_OPEN,
    FAILURE_FORMAT,
    FAILURE_SHORT_WRITE,
    FAILURE_FLUSH,
    FAILURE_FSYNC,
    FAILURE_CLOSE,
    FAILURE_DIRSYNC,
};

struct fake_io_state {
    enum failure_mode mode;
    int open_calls;
    int close_calls;
    int dir_open_calls;
    int dir_close_calls;
    int fsync_calls;
    int flush_calls;
    int format_calls;
    int write_calls;
    int next_fd;
};

static FILE *cast_file(struct fake_file *fake)
{
    return (FILE *)fake;
}

static struct fake_file *uncast_file(FILE *stream)
{
    return (struct fake_file *)stream;
}

static struct fake_io_state *active_fake_io_state;

static FILE *fake_ops_fopen(const char *path, const char *mode)
{
    struct fake_file *file;

    (void)path;
    (void)mode;
    active_fake_io_state->open_calls++;
    if (active_fake_io_state->mode == FAILURE_OPEN) {
        return NULL;
    }

    file = malloc(sizeof(*file));
    if (file == NULL) {
        return NULL;
    }
    file->fd = ++active_fake_io_state->next_fd;
    return cast_file(file);
}

static int fake_ops_vfprintf(FILE *stream, const char *format, va_list args)
{
    (void)stream;
    (void)format;
    (void)args;
    active_fake_io_state->format_calls++;
    return active_fake_io_state->mode == FAILURE_FORMAT ? -1 : 1;
}

static size_t fake_ops_fwrite(const void *ptr, size_t size, size_t nmemb,
                              FILE *stream)
{
    (void)ptr;
    (void)size;
    (void)stream;
    active_fake_io_state->write_calls++;
    if (active_fake_io_state->mode == FAILURE_SHORT_WRITE) {
        if (nmemb == 0) {
            return 0;
        }
        return nmemb - 1;
    }
    return nmemb;
}

static int fake_ops_fflush(FILE *stream)
{
    (void)stream;
    active_fake_io_state->flush_calls++;
    return active_fake_io_state->mode == FAILURE_FLUSH ? -1 : 0;
}

static int fake_ops_fsync(int fd)
{
    active_fake_io_state->fsync_calls++;
    if (active_fake_io_state->mode == FAILURE_FSYNC) {
        return -1;
    }
    if (active_fake_io_state->mode == FAILURE_DIRSYNC && fd < 0) {
        return -1;
    }
    return 0;
}

static int fake_ops_fileno(FILE *stream)
{
    return uncast_file(stream)->fd;
}

static int fake_ops_fclose(FILE *stream)
{
    struct fake_file *file = uncast_file(stream);

    active_fake_io_state->close_calls++;
    free(file);
    return active_fake_io_state->mode == FAILURE_CLOSE ? -1 : 0;
}

static int fake_ops_open_dir(const char *path)
{
    (void)path;
    active_fake_io_state->dir_open_calls++;
    if (active_fake_io_state->mode == FAILURE_DIRSYNC) {
        return -1;
    }
    return -1 - active_fake_io_state->dir_open_calls;
}

static int fake_ops_close_fd(int fd)
{
    (void)fd;
    active_fake_io_state->dir_close_calls++;
    return 0;
}

static const nyx_checked_io_ops_t fake_ops = {
    .fopen_fn = fake_ops_fopen,
    .vfprintf_fn = fake_ops_vfprintf,
    .fwrite_fn = fake_ops_fwrite,
    .fflush_fn = fake_ops_fflush,
    .fileno_fn = fake_ops_fileno,
    .fsync_fn = fake_ops_fsync,
    .fclose_fn = fake_ops_fclose,
    .open_dir_fn = fake_ops_open_dir,
    .close_fd_fn = fake_ops_close_fd,
};

static void assert_true(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void test_open_failure_propagates(void)
{
    struct fake_io_state state = { .mode = FAILURE_OPEN };
    FILE *file = NULL;

    active_fake_io_state = &state;

    assert_true(!nyx_checked_fopen(&fake_ops, "x", "wb", &file),
                "open failure should propagate");
    assert_true(file == NULL, "failed open must not publish a file handle");
}

static void test_formatted_write_failure_propagates(void)
{
    struct fake_io_state state = { .mode = FAILURE_FORMAT };
    FILE *file;

    active_fake_io_state = &state;
    file = fake_ops_fopen("x", "wb");

    assert_true(!nyx_checked_fprintf(&fake_ops, file, "x=%d", 7),
                "formatted write failure should propagate");
    assert_true(fake_ops_fclose(file) == 0, "manual close after format failure");
}

static void test_short_write_failure_propagates(void)
{
    struct fake_io_state state = { .mode = FAILURE_SHORT_WRITE };
    FILE *file;
    const char payload[] = "abcd";

    active_fake_io_state = &state;
    file = fake_ops_fopen("x", "wb");

    assert_true(!nyx_checked_write_exact(&fake_ops, file, payload, sizeof(payload)),
                "short write should propagate as failure");
    assert_true(state.write_calls >= 2,
                "exact write helper should retry until failure is proven");
    assert_true(fake_ops_fclose(file) == 0, "manual close after short write failure");
}

static void test_flush_failure_propagates(void)
{
    struct fake_io_state state = { .mode = FAILURE_FLUSH };
    FILE *file;

    active_fake_io_state = &state;
    file = fake_ops_fopen("x", "wb");

    assert_true(!nyx_checked_flush_fsync_close(&fake_ops, file),
                "flush failure should propagate");
    assert_true(state.close_calls == 1,
                "flush failure must still close the file");
}

static void test_fsync_failure_propagates(void)
{
    struct fake_io_state state = { .mode = FAILURE_FSYNC };
    FILE *file;

    active_fake_io_state = &state;
    file = fake_ops_fopen("x", "wb");

    assert_true(!nyx_checked_flush_fsync_close(&fake_ops, file),
                "fsync failure should propagate");
    assert_true(state.flush_calls == 1, "fsync path must flush first");
    assert_true(state.close_calls == 1, "fsync failure must still close the file");
}

static void test_close_failure_propagates(void)
{
    struct fake_io_state state = { .mode = FAILURE_CLOSE };
    FILE *file;

    active_fake_io_state = &state;
    file = fake_ops_fopen("x", "wb");

    assert_true(!nyx_checked_flush_fsync_close(&fake_ops, file),
                "close failure should propagate");
    assert_true(state.flush_calls == 1, "close path must flush");
    assert_true(state.fsync_calls == 1, "close path must fsync");
}

static void test_directory_sync_failure_propagates(void)
{
    struct fake_io_state state = { .mode = FAILURE_DIRSYNC };

    active_fake_io_state = &state;

    assert_true(!nyx_checked_fsync_dir(&fake_ops, "dir"),
                "directory sync failure should propagate");
    assert_true(state.dir_open_calls == 1,
                "directory sync should attempt exactly one open");
}

static void test_snapshot_publish_requires_complete_outputs(void)
{
    int old_pages_value = 11;
    int new_pages_value = 22;
    void *replacement_pages = &new_pages_value;
    void *old_pages = NULL;
    nyx_dump_snapshot_state_t state = {
        .pages = &old_pages_value,
        .count = 1,
        .capacity = 4,
        .prev_seq = 7,
        .valid = true,
    };

    assert_true(!nyx_dump_snapshot_publish(&state, false, &replacement_pages,
                                           2, 8, 9, &old_pages),
                "incomplete outputs must block publication");
    assert_true(state.pages == &old_pages_value,
                "failed publication must preserve previous snapshot pointer");
    assert_true(state.prev_seq == 7,
                "failed publication must preserve previous sequence");
    assert_true(replacement_pages == &new_pages_value,
                "failed publication must preserve replacement ownership");
    assert_true(old_pages == NULL,
                "failed publication must not expose old storage");
}

int main(void)
{
    test_open_failure_propagates();
    test_formatted_write_failure_propagates();
    test_short_write_failure_propagates();
    test_flush_failure_propagates();
    test_fsync_failure_propagates();
    test_close_failure_propagates();
    test_directory_sync_failure_propagates();
    test_snapshot_publish_requires_complete_outputs();
    return 0;
}
