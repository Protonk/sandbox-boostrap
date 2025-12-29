#include "../../api/runtime/native/tool_markers.h"
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>

/*
 * sandbox_mach_probe: apply an SBPL profile (from file) via sandbox_init, then
 * perform a single bootstrap_look_up for the given service name.
 *
 * Exits 0 on success, 1 on failure; prints {"kr":<code>} to stdout.
 *
 * Usage: sandbox_mach_probe <profile.sb> <service>
 */

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

    FILE *fp = fopen(profile_path, "r");
    if (!fp) {
        perror("open profile");
        return 66; /* EX_NOINPUT */
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fprintf(stderr, "oom\n");
        fclose(fp);
        return 70; /* EX_SOFTWARE */
    }
    size_t nread = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    buf[nread] = '\0';

    char *err = NULL;
    sbl_apply_report_t report = sbl_sandbox_init_with_markers(buf, 0, &err, profile_path);
    free(buf);
    if (report.rc != 0) {
        fprintf(stderr, "sandbox_init failed: %s\n", err ? err : "unknown");
        if (err) {
            sandbox_free_error(err);
        }
        return 1;
    }
    if (err) {
        sandbox_free_error(err);
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

