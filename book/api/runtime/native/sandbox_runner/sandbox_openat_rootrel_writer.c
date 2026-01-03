#include "sandbox_io.h"
#include <stdio.h>

/*
 * sandbox_openat_rootrel_writer: apply SBPL profile from file via sandbox_init,
 * then open the target path via openat(2) with a stable dirfd for "/" and a
 * relative path string (no leading '/').
 *
 * Usage: sandbox_openat_rootrel_writer <profile.sb> <path>
 */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <path>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    return sandbox_io_write_openat_rootrel(argv[1], argv[2]);
}

