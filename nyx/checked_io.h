#pragma once

#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

typedef struct nyx_checked_io_ops {
    FILE *(*fopen_fn)(const char *path, const char *mode);
    int (*vfprintf_fn)(FILE *stream, const char *format, va_list args);
    size_t (*fwrite_fn)(const void *ptr, size_t size, size_t nmemb,
                        FILE *stream);
    int (*fflush_fn)(FILE *stream);
    int (*fileno_fn)(FILE *stream);
    int (*fsync_fn)(int fd);
    int (*fclose_fn)(FILE *stream);
    int (*open_dir_fn)(const char *path);
    int (*close_fd_fn)(int fd);
} nyx_checked_io_ops_t;

const nyx_checked_io_ops_t *nyx_checked_io_default_ops(void);
bool nyx_checked_fopen(const nyx_checked_io_ops_t *ops, const char *path,
                       const char *mode, FILE **file_out);
bool nyx_checked_vfprintf(const nyx_checked_io_ops_t *ops, FILE *stream,
                          const char *format, va_list args);
bool nyx_checked_fprintf(const nyx_checked_io_ops_t *ops, FILE *stream,
                         const char *format, ...);
bool nyx_checked_write_exact(const nyx_checked_io_ops_t *ops, FILE *stream,
                             const void *buffer, size_t size);
bool nyx_checked_flush_fsync_close(const nyx_checked_io_ops_t *ops,
                                   FILE *stream);
bool nyx_checked_fsync_dir(const nyx_checked_io_ops_t *ops, const char *path);
