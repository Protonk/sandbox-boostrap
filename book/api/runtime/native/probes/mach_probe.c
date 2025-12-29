/*
 * mach_probe: perform a single bootstrap_look_up for the given service name.
 * Exits 0 on success, 1 on failure; prints {"kr":<code>} to stdout.
 *
 * Usage: mach_probe <service>
 */
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <service>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    const char *service = argv[1];
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
