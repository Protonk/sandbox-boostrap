#include "sandbox_io.h"
#include <stdio.h>

/*
 * sandbox_openat_writer: apply SBPL profile from file via sandbox_init, then open
 * the target path via openat(2) by first opening the parent directory and using a
 * relative leafname. Avoids execing external binaries.
 *
 * Usage: sandbox_openat_writer <profile.sb> <path>
 */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <path>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    return sandbox_io_write_openat(argv[1], argv[2]);
}

