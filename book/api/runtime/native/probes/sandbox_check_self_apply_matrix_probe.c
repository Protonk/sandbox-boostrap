/*
 * sandbox_check_self_apply_matrix_probe: apply an SBPL profile (from file) via sandbox_init,
 * then evaluate multiple seatbelt decisions via sandbox_check in a single process.
 *
 * This probe is intended for "AA vs BB" questions where BB is derived from AA
 * using the current PID, so all checks must occur in the same process context.
 *
 * Usage:
 *   sandbox_check_self_apply_matrix_probe <profile.sb> <aa>
 *
 * Prints raw sandbox_check rc and errno for:
 *   - operation ∈ {mach-register, mach-lookup}
 *   - name ∈ {AA, BB} where BB = AA + "." + getpid()
 *
 * Exits 0 on successful execution (denies are expected).
 */

#include "sandbox_profile.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int sandbox_check(pid_t pid, const char *operation, int type, ...);

/* sandbox_check filter namespace: global-name is type 2 on this baseline. */
#define SANDBOX_CHECK_FILTER_GLOBAL_NAME 2

/* Sandbox-check flags (bitwise OR with filter type). */
#define SANDBOX_CHECK_NO_REPORT 0x40000000

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <aa>\n", prog);
}

typedef struct {
    int rc;
    int err;
} check_result_t;

static check_result_t check_global_name(const char *operation, const char *name) {
    errno = 0;
    int rc = sandbox_check(
        getpid(), operation, SANDBOX_CHECK_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT, name);
    int err = errno;
    return (check_result_t){.rc = rc, .err = err};
}

static void print_cell(const char *operation, const char *label, const char *name, check_result_t result) {
    printf("%s %s name=%s rc=%d errno=%d\n", operation, label, name, result.rc, result.err);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    const char *profile_path = argv[1];
    const char *aa = argv[2];

    pid_t pid = getpid();
    size_t bb_len = strlen(aa) + 1 + 32;
    char *bb = (char *)malloc(bb_len);
    if (!bb) {
        fprintf(stderr, "oom\n");
        return 70; /* EX_SOFTWARE */
    }
    snprintf(bb, bb_len, "%s.%d", aa, (int)pid);

    int apply_rc = sbl_apply_profile_from_path(profile_path);
    if (apply_rc != 0) {
        free(bb);
        return apply_rc;
    }

    printf("pid=%d\n", (int)pid);
    printf("AA=%s\n", aa);
    printf("BB=%s\n", bb);

    check_result_t reg_aa = check_global_name("mach-register", aa);
    check_result_t reg_bb = check_global_name("mach-register", bb);
    check_result_t lookup_aa = check_global_name("mach-lookup", aa);
    check_result_t lookup_bb = check_global_name("mach-lookup", bb);

    print_cell("mach-register", "AA", aa, reg_aa);
    print_cell("mach-register", "BB", bb, reg_bb);
    print_cell("mach-lookup", "AA", aa, lookup_aa);
    print_cell("mach-lookup", "BB", bb, lookup_bb);

    free(bb);
    return 0;
}
