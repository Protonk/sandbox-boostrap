#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <unistd.h>

// Registers a simple Mach service so the client can exercise mach-lookup. In
// SBPL, mach services are controlled via operations like `mach-lookup` and
// filters such as `(global-name "...")` (see book/substrate/Appendix.md). Platform
// policy may still deny registration/lookup even for ad-hoc services.

static const char *kServiceName = "com.example.xnusandbox.demo";

int main(void) {
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get bootstrap port\n");
        return 1;
    }

    mach_port_t recv_port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_port_allocate failed: %s\n", mach_error_string(kr));
        return 1;
    }
    kr = mach_port_insert_right(mach_task_self(), recv_port, recv_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_port_insert_right failed: %s\n", mach_error_string(kr));
        return 1;
    }

    // Register the service. bootstrap_register2 is newer but may be unavailable on some SDKs; fall back to bootstrap_register.
#ifdef bootstrap_register2
    kr = bootstrap_register2(bootstrap, kServiceName, recv_port, 0);
#else
    kr = bootstrap_register(bootstrap, (char *)kServiceName, recv_port);
#endif
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "bootstrap_register(\"%s\") failed: %s\n", kServiceName, mach_error_string(kr));
        return 1;
    }

    printf("Registered Mach service \"%s\". PID=%d\n", kServiceName, getpid());
    printf("Leave this running and start the client in another shell.\n");
    printf("mach-lookup checks are sandbox operations filtered on the service name.\n");

    // Keep the service alive briefly; we do not implement full message handling
    // because the point here is registration/lookup behavior.
    sleep(30);
    return 0;
}
