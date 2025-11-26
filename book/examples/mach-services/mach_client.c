#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <unistd.h>

// Attempts mach-lookup against a demo service (if the server is running) and a
// couple of system services. `mach-lookup` is a sandbox-controlled operation;
// SBPL filters on `(global-name ...)` decide which services a process may talk
// to (see substrate/Appendix.md filter list).

static void lookup(const char *service) {
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
        fprintf(stderr, "No bootstrap port; cannot query %s\n", service);
        return;
    }

    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap, service, &port);
    if (kr == KERN_SUCCESS) {
        printf("mach-lookup \"%s\" -> success (port=%u)\n", service, port);
        mach_port_deallocate(mach_task_self(), port);
    } else {
        printf("mach-lookup \"%s\" -> kr=0x%x (%s)\n", service, kr, mach_error_string(kr));
    }
}

int main(void) {
    printf("Mach lookup client (PID %d)\n", getpid());
    printf("Try running the server first for the demo service.\n\n");

    lookup("com.example.xnusandbox.demo");    // should succeed if server is alive
    lookup("com.apple.cfprefsd.daemon");      // typically allowed
    lookup("com.apple.securityd");            // often denied/restricted

    return 0;
}
