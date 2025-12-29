#include "sandbox_io.h"
#include <stdio.h>

/*
 * sandbox_reader: apply SBPL profile from file via sandbox_init, then open
 * the target path read-only and write its contents to stdout. Avoids execing
 * external binaries so fewer allowances are needed.
 *
 * Usage: sandbox_reader <profile.sb> <path>
 */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <path>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    return sandbox_io_read(argv[1], argv[2]);
}
