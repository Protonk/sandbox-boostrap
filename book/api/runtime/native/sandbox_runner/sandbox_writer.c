#include "sandbox_io.h"
#include <stdio.h>

/*
 * sandbox_writer: apply SBPL profile from file via sandbox_init, then append
 * a line to the target path. Avoids execing external binaries.
 *
 * Usage: sandbox_writer <profile.sb> <path>
 */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <path>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    return sandbox_io_write(argv[1], argv[2]);
}
