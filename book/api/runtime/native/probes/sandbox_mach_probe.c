/*
 * sandbox_mach_probe: apply an SBPL profile (from file) via sandbox_init, then
 * perform a single bootstrap_look_up for the given service name.
 *
 * Exits 0 on success, 1 on failure; prints {"kr":<code>} to stdout.
 *
 * Usage: sandbox_mach_probe <profile.sb> <service>
 */
#include "sandbox_profile.h"
#include "../tool_markers.h"
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <service>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    const char *profile_path = argv[1];
    const char *service = argv[2];

    int apply_rc = sbl_apply_profile_from_path(profile_path);
    if (apply_rc != 0) {
        return apply_rc;
    }

    sbl_maybe_seatbelt_callout_from_env("pre_syscall");

    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
        fprintf(stderr, "task_get_special_port failed\n");
        return 1;
    }

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap, service, &port);
    if (kr == KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), port);
    }

    printf("{\"kr\":%d}\n", kr);
    return kr == KERN_SUCCESS ? 0 : 1;
}
