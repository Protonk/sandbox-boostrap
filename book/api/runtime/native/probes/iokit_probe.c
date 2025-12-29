/*
 * iokit_probe: attempt to open an IOKit service matching a registry entry class.
 *
 * This is used as an unsandboxed baseline for runtime discriminator matrices.
 * It prints a single JSON object to stdout:
 *   {"found":<bool>,"open_kr":<int|null>}
 *
 * Exit codes:
 * - 0: service found and IOServiceOpen succeeded (open_kr==0)
 * - 1: service found but IOServiceOpen failed (open_kr!=0)
 * - 2: no matching service found (unobservable in this process context)
 *
 * Usage: iokit_probe <registry_entry_class>
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <registry_entry_class>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    const char *class_name = argv[1];
    CFMutableDictionaryRef matching = IOServiceMatching(class_name);
    if (!matching) {
        printf("{\"found\":false,\"open_kr\":null}\n");
        return 2;
    }

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service == IO_OBJECT_NULL) {
        printf("{\"found\":false,\"open_kr\":null}\n");
        return 2;
    }

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
        IOServiceClose(conn);
    }
    IOObjectRelease(service);

    printf("{\"found\":true,\"open_kr\":%d}\n", kr);
    return kr == KERN_SUCCESS ? 0 : 1;
}
