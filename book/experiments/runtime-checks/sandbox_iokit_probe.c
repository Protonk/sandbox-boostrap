#include "../../api/runtime_tools/native/tool_markers.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>

/*
 * sandbox_iokit_probe: apply an SBPL profile (from file) via sandbox_init, then
 * attempt to open an IOKit service matching a registry entry class.
 *
 * It prints a single JSON object to stdout:
 *   {"found":<bool>,"open_kr":<int|null>}
 *
 * Exit codes:
 * - 0: service found and IOServiceOpen succeeded (open_kr==0)
 * - 1: service found but IOServiceOpen failed (open_kr!=0)
 * - 2: no matching service found (unobservable in this process context)
 *
 * Usage: sandbox_iokit_probe <profile.sb> <registry_entry_class>
 */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <registry_entry_class>\n", prog);
}

static void print_no_service(void) {
    printf("{\"found\":false,\"open_kr\":null}\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    const char *profile_path = argv[1];
    const char *class_name = argv[2];

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
    if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
        IOServiceClose(conn);
    }
    IOObjectRelease(service);

    printf("{\"found\":true,\"open_kr\":%d}\n", kr);
    return kr == KERN_SUCCESS ? 0 : 1;
}

