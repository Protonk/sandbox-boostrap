/*
 * Shared SBPL profile loader for sandboxed probes.
 *
 * Keeping this logic in one place ensures sandboxed probe entrypoints
 * apply profiles and emit markers consistently.
 */
#ifndef SANDBOX_LORE_SANDBOX_PROFILE_H
#define SANDBOX_LORE_SANDBOX_PROFILE_H

int sbl_apply_profile_from_path(const char *profile_path);

#endif /* SANDBOX_LORE_SANDBOX_PROFILE_H */
