/*
 * sandbox_iokit_probe: apply an SBPL profile (from file) via sandbox_init, then
 * attempt to open an IOKit service matching a registry entry class and issue
 * a minimal post-open user-client call.
 *
 * It prints a single JSON object to stdout:
 *   {"found":<bool>,"open_kr":<int|null>,"call_kr":<int|null>,"call_selector":<int|null>,"surface_create_ok":<bool|null>,"surface_create_signal":<int|null>}
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
#include <IOSurface/IOSurface.h>
#include <mach/error.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <registry_entry_class>\n", prog);
}

static void print_no_service(void) {
    printf("{\"found\":false,\"open_kr\":null,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":null,\"surface_create_signal\":null}\n");
}

static const char *derive_user_client_class(const char *registry_class, char *buf, size_t buf_len) {
    if (!registry_class || !buf || buf_len == 0) {
        return NULL;
    }
    int written = snprintf(buf, buf_len, "%sUserClient", registry_class);
    if (written < 0 || (size_t)written >= buf_len) {
        return NULL;
    }
    return buf;
}

static void emit_iokit_callout_string(
    const char *stage,
    const char *operation,
    long filter_type,
    const char *argument
) {
    const char *enabled = getenv(SANDBOX_LORE_ENV_SEATBELT_CALLOUT);
    if (!enabled || strcmp(enabled, "1") != 0) {
        return;
    }
    if (!operation || !argument) {
        return;
    }

    int token_kr = 0;
    audit_token_t token;
    if (sbl_get_self_audit_token(&token, &token_kr) != 0) {
        sbl_emit_seatbelt_callout(
            stage,
            operation,
            filter_type,
            argument,
            -1,
            0,
            "TASK_AUDIT_TOKEN unavailable",
            0,
            "token_unavailable",
            token_kr,
            "task_info_failed",
            filter_type,
            1
        );
        return;
    }
    sbl_sandbox_check_by_audit_token_fn fn = sbl_load_sandbox_check_by_audit_token();
    if (!fn) {
        sbl_emit_seatbelt_callout(
            stage,
            operation,
            filter_type,
            argument,
            -2,
            ENOSYS,
            "sandbox_check_by_audit_token missing",
            0,
            "symbol_missing",
            token_kr,
            "ok",
            filter_type,
            1
        );
        return;
    }

    int no_report_used = 0;
    const char *no_report_reason = NULL;
    int type_used = sbl_sb_check_type_with_no_report(filter_type, &no_report_used, &no_report_reason);
    if (!no_report_used && no_report_reason == NULL) {
        no_report_reason = "unknown";
    }
    errno = 0;
    int rc = fn(&token, operation, type_used, argument);
    int err = errno;
    sbl_emit_seatbelt_callout(
        stage,
        operation,
        filter_type,
        argument,
        rc,
        err,
        NULL,
        no_report_used,
        no_report_reason,
        token_kr,
        "ok",
        type_used,
        1
    );
}

static void emit_iokit_callout_number(
    const char *stage,
    const char *operation,
    long filter_type,
    long argument
) {
    const char *enabled = getenv(SANDBOX_LORE_ENV_SEATBELT_CALLOUT);
    if (!enabled || strcmp(enabled, "1") != 0) {
        return;
    }
    if (!operation) {
        return;
    }

    int token_kr = 0;
    audit_token_t token;
    if (sbl_get_self_audit_token(&token, &token_kr) != 0) {
        char arg_buf[32];
        snprintf(arg_buf, sizeof(arg_buf), "%ld", argument);
        sbl_emit_seatbelt_callout(
            stage,
            operation,
            filter_type,
            arg_buf,
            -1,
            0,
            "TASK_AUDIT_TOKEN unavailable",
            0,
            "token_unavailable",
            token_kr,
            "task_info_failed",
            filter_type,
            1
        );
        return;
    }
    sbl_sandbox_check_by_audit_token_fn fn = sbl_load_sandbox_check_by_audit_token();
    if (!fn) {
        char arg_buf[32];
        snprintf(arg_buf, sizeof(arg_buf), "%ld", argument);
        sbl_emit_seatbelt_callout(
            stage,
            operation,
            filter_type,
            arg_buf,
            -2,
            ENOSYS,
            "sandbox_check_by_audit_token missing",
            0,
            "symbol_missing",
            token_kr,
            "ok",
            filter_type,
            1
        );
        return;
    }

    int no_report_used = 0;
    const char *no_report_reason = NULL;
    int type_used = sbl_sb_check_type_with_no_report(filter_type, &no_report_used, &no_report_reason);
    if (!no_report_used && no_report_reason == NULL) {
        no_report_reason = "unknown";
    }
    errno = 0;
    int rc = fn(&token, operation, type_used, argument);
    int err = errno;
    char arg_buf[32];
    snprintf(arg_buf, sizeof(arg_buf), "%ld", argument);
    sbl_emit_seatbelt_callout(
        stage,
        operation,
        filter_type,
        arg_buf,
        rc,
        err,
        NULL,
        no_report_used,
        no_report_reason,
        token_kr,
        "ok",
        type_used,
        1
    );
}

static bool attempt_surface_create(int *signal_out) {
    int width = 1;
    int height = 1;
    int bytes_per_elem = 4;
    if (signal_out) {
        *signal_out = 0;
    }
    pid_t pid = fork();
    if (pid == 0) {
        CFNumberRef width_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &width);
        CFNumberRef height_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &height);
        CFNumberRef bpe_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytes_per_elem);
        if (!width_num || !height_num || !bpe_num) {
            if (width_num) CFRelease(width_num);
            if (height_num) CFRelease(height_num);
            if (bpe_num) CFRelease(bpe_num);
            _exit(1);
        }
        const void *keys[] = {kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement};
        const void *vals[] = {width_num, height_num, bpe_num};
        CFDictionaryRef props = CFDictionaryCreate(
            kCFAllocatorDefault, keys, vals, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFRelease(width_num);
        CFRelease(height_num);
        CFRelease(bpe_num);
        if (!props) {
            _exit(1);
        }
        IOSurfaceRef surface = IOSurfaceCreate(props);
        CFRelease(props);
        if (surface) {
            CFRelease(surface);
            _exit(0);
        }
        _exit(1);
    }
    if (pid < 0) {
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }
    if (WIFSIGNALED(status)) {
        if (signal_out) {
            *signal_out = WTERMSIG(status);
        }
        return false;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status) == 0;
    }
    return false;
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
    char user_client_class[256];
    const char *user_client_name = derive_user_client_class(class_name, user_client_class, sizeof(user_client_class));
    const long user_client_type = 0;
    emit_iokit_callout_string("pre_syscall", "iokit-open", SBL_FILTER_IOKIT_REGISTRY_ENTRY_CLASS, class_name);
    emit_iokit_callout_string("pre_syscall", "iokit-open-service", SBL_FILTER_IOKIT_REGISTRY_ENTRY_CLASS, class_name);
    if (user_client_name) {
        emit_iokit_callout_string("pre_syscall", "iokit-open-user-client", SBL_FILTER_IOKIT_USER_CLIENT_TYPE, user_client_name);
    }
    emit_iokit_callout_number("pre_syscall", "iokit-open-user-client", SBL_FILTER_IOKIT_USER_CLIENT_TYPE, user_client_type);
    emit_iokit_callout_number("pre_syscall", "iokit-open", SBL_FILTER_IOKIT_USER_CLIENT_TYPE, user_client_type);

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
    const char *call_kr_string = NULL;
    bool call_attempted = false;
    bool call_succeeded = false;
    uint32_t call_selector = 0;
    uint32_t call_input_scalar_count = 0;
    size_t call_input_struct_bytes = 0;
    uint32_t call_output_scalar_count = 0;
    size_t call_output_struct_bytes = 0;
    bool surface_ok = false;
    int surface_signal = 0;
    bool do_sweep = true;
    const uint32_t selectors[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const char *skip_sweep_env = getenv("SBL_IKIT_SKIP_SWEEP");
    if (skip_sweep_env && skip_sweep_env[0] != '\0' && skip_sweep_env[0] != '0') {
        do_sweep = false;
    }
    if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
        if (do_sweep) {
            for (size_t i = 0; i < (sizeof(selectors) / sizeof(selectors[0])); i++) {
                call_output_scalar_count = 0;
                call_output_struct_bytes = 0;
                call_attempted = true;
                call_selector = selectors[i];
                call_kr = IOConnectCallMethod(
                    conn,
                    selectors[i],
                    NULL,
                    call_input_scalar_count,
                    NULL,
                    call_input_struct_bytes,
                    NULL,
                    &call_output_scalar_count,
                    NULL,
                    &call_output_struct_bytes);
                call_kr_string = mach_error_string(call_kr);
                if (call_kr == KERN_SUCCESS) {
                    call_succeeded = true;
                    break;
                }
            }
        }
        surface_ok = attempt_surface_create(&surface_signal);
        IOServiceClose(conn);
    }
    IOObjectRelease(service);

    if (call_attempted) {
        const char *call_kr_string_value = call_kr_string ? call_kr_string : "unknown";
        if (surface_signal) {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"IOConnectCallMethod\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":%d}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false",
                surface_signal);
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":%d}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false",
                surface_signal);
        } else {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"IOConnectCallMethod\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":null}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false");
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":null}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false");
        }
    } else {
        if (surface_signal) {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"IOConnectCallMethod\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d}\n",
                kr,
                surface_ok ? "true" : "false",
                surface_signal);
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d}\n",
                kr,
                surface_ok ? "true" : "false",
                surface_signal);
        } else {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"IOConnectCallMethod\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":null}\n",
                kr,
                surface_ok ? "true" : "false");
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":null}\n",
                kr,
                surface_ok ? "true" : "false");
        }
    }
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    if (call_attempted && call_kr != KERN_SUCCESS && !surface_ok) {
        return 1;
    }
    return 0;
}
