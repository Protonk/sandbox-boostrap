#ifndef SANDBOX_LORE_SANDBOX_IO_H
#define SANDBOX_LORE_SANDBOX_IO_H

/*
 * Shared helpers for sandbox_reader/sandbox_writer.
 *
 * These helpers keep the profile-apply and FD-path emission logic identical
 * across both entrypoints so runtime results stay comparable.
 */

int sandbox_io_read(const char *profile_path, const char *target_path);
int sandbox_io_write(const char *profile_path, const char *target_path);
int sandbox_io_read_openat(const char *profile_path, const char *target_path);
int sandbox_io_write_openat(const char *profile_path, const char *target_path);
int sandbox_io_read_openat_rootrel(const char *profile_path, const char *target_path);
int sandbox_io_write_openat_rootrel(const char *profile_path, const char *target_path);

#endif /* SANDBOX_LORE_SANDBOX_IO_H */
