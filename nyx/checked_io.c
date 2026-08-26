#include "checked_io.h"

#include <fcntl.h>
#include <unistd.h>

static FILE *nyx_checked_io_fopen_default(const char *path, const char *mode)
{
    return fopen(path, mode);
}

static int nyx_checked_io_vfprintf_default(FILE *stream, const char *format,
                                           va_list args)
{
    return vfprintf(stream, format, args);
}

static size_t nyx_checked_io_fwrite_default(const void *ptr, size_t size,
                                            size_t nmemb, FILE *stream)
{
    return fwrite(ptr, size, nmemb, stream);
}

static int nyx_checked_io_fflush_default(FILE *stream)
{
    return fflush(stream);
}

static int nyx_checked_io_fileno_default(FILE *stream)
{
    return fileno(stream);
}

static int nyx_checked_io_fsync_default(int fd)
{
    return fsync(fd);
}

static int nyx_checked_io_fclose_default(FILE *stream)
{
    return fclose(stream);
}

static int nyx_checked_io_open_dir_default(const char *path)
{
    return open(path, O_RDONLY | O_DIRECTORY);
}

static int nyx_checked_io_close_fd_default(int fd)
{
    return close(fd);
}

static const nyx_checked_io_ops_t nyx_checked_io_default = {
    .fopen_fn = nyx_checked_io_fopen_default,
    .vfprintf_fn = nyx_checked_io_vfprintf_default,
    .fwrite_fn = nyx_checked_io_fwrite_default,
    .fflush_fn = nyx_checked_io_fflush_default,
    .fileno_fn = nyx_checked_io_fileno_default,
    .fsync_fn = nyx_checked_io_fsync_default,
    .fclose_fn = nyx_checked_io_fclose_default,
    .open_dir_fn = nyx_checked_io_open_dir_default,
    .close_fd_fn = nyx_checked_io_close_fd_default,
};

const nyx_checked_io_ops_t *nyx_checked_io_default_ops(void)
{
    return &nyx_checked_io_default;
}

bool nyx_checked_fopen(const nyx_checked_io_ops_t *ops, const char *path,
                       const char *mode, FILE **file_out)
{
    if (ops == NULL || ops->fopen_fn == NULL || path == NULL || mode == NULL ||
        file_out == NULL) {
        return false;
    }

    *file_out = ops->fopen_fn(path, mode);
    return *file_out != NULL;
}

bool nyx_checked_vfprintf(const nyx_checked_io_ops_t *ops, FILE *stream,
                          const char *format, va_list args)
{
    if (ops == NULL || ops->vfprintf_fn == NULL || stream == NULL ||
        format == NULL) {
        return false;
    }

    return ops->vfprintf_fn(stream, format, args) >= 0;
}

bool nyx_checked_fprintf(const nyx_checked_io_ops_t *ops, FILE *stream,
                         const char *format, ...)
{
    bool ok;
    va_list args;

    va_start(args, format);
    ok = nyx_checked_vfprintf(ops, stream, format, args);
    va_end(args);
    return ok;
}

bool nyx_checked_write_exact(const nyx_checked_io_ops_t *ops, FILE *stream,
                             const void *buffer, size_t size)
{
    const unsigned char *cursor = buffer;
    size_t remaining = size;

    if (size == 0) {
        return true;
    }

    if (ops == NULL || ops->fwrite_fn == NULL || stream == NULL ||
        buffer == NULL) {
        return false;
    }

    while (remaining > 0) {
        const size_t written = ops->fwrite_fn(cursor, 1, remaining, stream);
        if (written == 0) {
            return false;
        }
        cursor += written;
        remaining -= written;
    }

    return true;
}

bool nyx_checked_flush_fsync_close(const nyx_checked_io_ops_t *ops,
                                   FILE *stream)
{
    int fd;
    bool ok = true;

    if (ops == NULL || ops->fflush_fn == NULL || ops->fileno_fn == NULL ||
        ops->fsync_fn == NULL || ops->fclose_fn == NULL || stream == NULL) {
        return false;
    }

    if (ops->fflush_fn(stream) != 0) {
        ok = false;
    }

    fd = ops->fileno_fn(stream);
    if (fd < 0 || ops->fsync_fn(fd) != 0) {
        ok = false;
    }

    if (ops->fclose_fn(stream) != 0) {
        ok = false;
    }

    return ok;
}

bool nyx_checked_fsync_dir(const nyx_checked_io_ops_t *ops, const char *path)
{
    int dir_fd;
    bool ok = true;

    if (ops == NULL || ops->open_dir_fn == NULL || ops->fsync_fn == NULL ||
        ops->close_fd_fn == NULL || path == NULL) {
        return false;
    }

    dir_fd = ops->open_dir_fn(path);
    if (dir_fd < 0) {
        return false;
    }

    if (ops->fsync_fn(dir_fd) != 0) {
        ok = false;
    }

    if (ops->close_fd_fn(dir_fd) != 0) {
        ok = false;
    }

    return ok;
}
