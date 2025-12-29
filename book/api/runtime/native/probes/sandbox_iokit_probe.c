/*
 * sandbox_iokit_probe: apply an SBPL profile (from file) via sandbox_init, then
 * attempt to open an IOKit service matching a registry entry class and issue
 * a minimal post-open user-client call.
 *
 * It prints a single JSON object to stdout:
 *   {"found":<bool>,"open_kr":<int|null>,"call_kr":<int|null>,"call_selector":<int>}
 *
 * Exit codes:
 * - 0: service found, IOServiceOpen succeeded, and the post-open call succeeded
 * - 1: service found but IOServiceOpen failed or the post-open call failed
 * - 2: no matching service found (unobservable in this process context)
 *
 * Usage: sandbox_iokit_probe <profile.sb> <registry_entry_class>
 */
#include "sandbox_profile.h"
#include "../tool_markers.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <registry_entry_class>\n", prog);
}

static void print_no_service(void) {
    printf("{\"found\":false,\"open_kr\":null,\"call_kr\":null,\"call_selector\":0}\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    const char *profile_path = argv[1];
    const char *class_name = argv[2];

    int apply_rc = sbl_apply_profile_from_path(profile_path);
    if (apply_rc != 0) {
        return apply_rc;
    }

    sbl_maybe_seatbelt_callout_from_env("pre_syscall");

    CFMutableDictionaryRef matching = IOServiceMatching(class_name);
    if (!matching) {
        print_no_service();
        return 2;
    }

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service == IO_OBJECT_NULL) {
        print_no_service();
        return 2;
    }

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    kern_return_t call_kr = KERN_FAILURE;
    bool call_attempted = false;
    bool call_succeeded = false;
    uint32_t call_selector = 0;
    const uint32_t selectors[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
        for (size_t i = 0; i < (sizeof(selectors) / sizeof(selectors[0])); i++) {
            uint32_t output_scalar_count = 0;
            size_t output_struct_count = 0;
            call_attempted = true;
            call_selector = selectors[i];
            call_kr = IOConnectCallMethod(
                conn,
                selectors[i],
                NULL,
                0,
                NULL,
                0,
                NULL,
                &output_scalar_count,
                NULL,
                &output_struct_count);
            if (call_kr == KERN_SUCCESS) {
                call_succeeded = true;
                break;
            }
        }
        IOServiceClose(conn);
    }
    IOObjectRelease(service);

    if (call_attempted) {
        printf(
            "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_selector\":%u,\"call_kind\":\"IOConnectCallMethod\",\"call_succeeded\":%s}\n",
            kr,
            call_kr,
            call_selector,
            call_succeeded ? "true" : "false");
        printf(
            "{\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_selector\":%u,\"call_succeeded\":%s}\n",
            kr,
            call_kr,
            call_selector,
            call_succeeded ? "true" : "false");
    } else {
        printf(
            "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_selector\":null,\"call_kind\":\"IOConnectCallMethod\"}\n",
            kr);
        printf("{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_selector\":null}\n", kr);
    }
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    if (call_attempted && call_kr != KERN_SUCCESS) {
        return 1;
    }
    return 0;
}
