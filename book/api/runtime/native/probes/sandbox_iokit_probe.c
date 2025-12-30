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
#include <IOKit/IOReturn.h>
#include <IOSurface/IOSurface.h>
#include <mach/error.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define SBL_IKIT_CALL_KIND_ENV "SANDBOX_LORE_IKIT_CALL_KIND"
#define SBL_IKIT_CALL_IN_SCALARS_ENV "SANDBOX_LORE_IKIT_CALL_IN_SCALARS"
#define SBL_IKIT_CALL_IN_STRUCT_BYTES_ENV "SANDBOX_LORE_IKIT_CALL_IN_STRUCT_BYTES"
#define SBL_IKIT_CALL_OUT_SCALARS_ENV "SANDBOX_LORE_IKIT_CALL_OUT_SCALARS"
#define SBL_IKIT_CALL_OUT_STRUCT_BYTES_ENV "SANDBOX_LORE_IKIT_CALL_OUT_STRUCT_BYTES"

typedef kern_return_t (*sbl_io_connect_method_scalarI_scalarO_fn)(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_scalar_inband_t output,
    mach_msg_type_number_t *outputCnt);

typedef kern_return_t (*sbl_io_connect_method_scalarI_structureO_fn)(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

typedef kern_return_t (*sbl_io_connect_method_scalarI_structureI_fn)(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t inputStruct,
    mach_msg_type_number_t inputStructCnt);

typedef kern_return_t (*sbl_io_connect_method_structureI_structureO_fn)(
    mach_port_t connection,
    int selector,
    io_struct_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

typedef kern_return_t (*sbl_io_async_method_scalarI_scalarO_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_scalar_inband_t output,
    mach_msg_type_number_t *outputCnt);

typedef kern_return_t (*sbl_io_async_method_scalarI_structureO_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

typedef kern_return_t (*sbl_io_async_method_scalarI_structureI_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t inputStruct,
    mach_msg_type_number_t inputStructCnt);

typedef kern_return_t (*sbl_io_async_method_structureI_structureO_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_struct_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

static sbl_io_connect_method_scalarI_scalarO_fn sbl_load_io_connect_method_scalarI_scalarO(void) {
    static sbl_io_connect_method_scalarI_scalarO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_scalarI_scalarO_fn)dlsym(RTLD_DEFAULT, "io_connect_method_scalarI_scalarO");
    return fn;
}

static sbl_io_connect_method_scalarI_structureO_fn sbl_load_io_connect_method_scalarI_structureO(void) {
    static sbl_io_connect_method_scalarI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_scalarI_structureO_fn)dlsym(RTLD_DEFAULT, "io_connect_method_scalarI_structureO");
    return fn;
}

static sbl_io_connect_method_scalarI_structureI_fn sbl_load_io_connect_method_scalarI_structureI(void) {
    static sbl_io_connect_method_scalarI_structureI_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_scalarI_structureI_fn)dlsym(RTLD_DEFAULT, "io_connect_method_scalarI_structureI");
    return fn;
}

static sbl_io_connect_method_structureI_structureO_fn sbl_load_io_connect_method_structureI_structureO(void) {
    static sbl_io_connect_method_structureI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_structureI_structureO_fn)dlsym(RTLD_DEFAULT, "io_connect_method_structureI_structureO");
    return fn;
}

static sbl_io_async_method_scalarI_scalarO_fn sbl_load_io_async_method_scalarI_scalarO(void) {
    static sbl_io_async_method_scalarI_scalarO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_scalarI_scalarO_fn)dlsym(RTLD_DEFAULT, "io_async_method_scalarI_scalarO");
    return fn;
}

static sbl_io_async_method_scalarI_structureO_fn sbl_load_io_async_method_scalarI_structureO(void) {
    static sbl_io_async_method_scalarI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_scalarI_structureO_fn)dlsym(RTLD_DEFAULT, "io_async_method_scalarI_structureO");
    return fn;
}

static sbl_io_async_method_scalarI_structureI_fn sbl_load_io_async_method_scalarI_structureI(void) {
    static sbl_io_async_method_scalarI_structureI_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_scalarI_structureI_fn)dlsym(RTLD_DEFAULT, "io_async_method_scalarI_structureI");
    return fn;
}

static sbl_io_async_method_structureI_structureO_fn sbl_load_io_async_method_structureI_structureO(void) {
    static sbl_io_async_method_structureI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_structureI_structureO_fn)dlsym(RTLD_DEFAULT, "io_async_method_structureI_structureO");
    return fn;
}

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
            "sandbox_check_by_audit_token",
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
            "sandbox_check_by_audit_token",
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
        "sandbox_check_by_audit_token",
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
            "sandbox_check_by_audit_token",
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
            "sandbox_check_by_audit_token",
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
        "sandbox_check_by_audit_token",
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

static void emit_iokit_callout_noarg(
    const char *stage,
    const char *operation
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
        sbl_emit_seatbelt_callout(
            stage,
            "sandbox_check_by_audit_token",
            operation,
            SBL_FILTER_NONE,
            "<none>",
            -1,
            0,
            "TASK_AUDIT_TOKEN unavailable",
            0,
            "token_unavailable",
            token_kr,
            "task_info_failed",
            SBL_FILTER_NONE,
            0
        );
        return;
    }
    sbl_sandbox_check_by_audit_token_fn fn = sbl_load_sandbox_check_by_audit_token();
    if (!fn) {
        sbl_emit_seatbelt_callout(
            stage,
            "sandbox_check_by_audit_token",
            operation,
            SBL_FILTER_NONE,
            "<none>",
            -2,
            ENOSYS,
            "sandbox_check_by_audit_token missing",
            0,
            "symbol_missing",
            token_kr,
            "ok",
            SBL_FILTER_NONE,
            0
        );
        return;
    }

    errno = 0;
    int rc = fn(&token, operation, SBL_FILTER_NONE);
    int err = errno;
    sbl_emit_seatbelt_callout(
        stage,
        "sandbox_check_by_audit_token",
        operation,
        SBL_FILTER_NONE,
        "<none>",
        rc,
        err,
        NULL,
        0,
        "not_applicable",
        token_kr,
        "ok",
        SBL_FILTER_NONE,
        0
    );
}

static size_t parse_selector_list(const char *env, uint32_t *out, size_t max_count) {
    if (!env || !out || max_count == 0) {
        return 0;
    }
    size_t count = 0;
    const char *p = env;
    while (*p && count < max_count) {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';') {
            p++;
        }
        if (!*p) {
            break;
        }
        char *end = NULL;
        unsigned long value = strtoul(p, &end, 10);
        if (end == p) {
            break;
        }
        out[count++] = (uint32_t)value;
        p = end;
    }
    return count;
}

static int parse_env_u32(const char *name, uint32_t *out) {
    if (!name || !out) {
        return 0;
    }
    const char *env = getenv(name);
    if (!env || !*env) {
        return 0;
    }
    char *end = NULL;
    unsigned long value = strtoul(env, &end, 10);
    if (!end || end == env || *end != '\0') {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

static int parse_env_size(const char *name, size_t *out) {
    if (!name || !out) {
        return 0;
    }
    const char *env = getenv(name);
    if (!env || !*env) {
        return 0;
    }
    char *end = NULL;
    unsigned long value = strtoul(env, &end, 10);
    if (!end || end == env || *end != '\0') {
        return 0;
    }
    *out = (size_t)value;
    return 1;
}

static const char *normalize_call_kind(const char *kind) {
    if (!kind || !*kind) {
        return "IOConnectCallMethod";
    }
    if (strcmp(kind, "IOConnectCallMethod") == 0) {
        return "IOConnectCallMethod";
    }
    if (strcmp(kind, "IOConnectCallScalarMethod") == 0) {
        return "IOConnectCallScalarMethod";
    }
    if (strcmp(kind, "IOConnectCallStructMethod") == 0) {
        return "IOConnectCallStructMethod";
    }
    if (strcmp(kind, "IOConnectCallAsyncScalarMethod") == 0) {
        return "IOConnectCallAsyncScalarMethod";
    }
    if (strcmp(kind, "IOConnectCallAsyncStructMethod") == 0) {
        return "IOConnectCallAsyncStructMethod";
    }
    if (strcmp(kind, "io_connect_method_scalarI_scalarO") == 0) {
        return "io_connect_method_scalarI_scalarO";
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureO") == 0) {
        return "io_connect_method_scalarI_structureO";
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureI") == 0) {
        return "io_connect_method_scalarI_structureI";
    }
    if (strcmp(kind, "io_connect_method_structureI_structureO") == 0) {
        return "io_connect_method_structureI_structureO";
    }
    if (strcmp(kind, "io_async_method_scalarI_scalarO") == 0) {
        return "io_async_method_scalarI_scalarO";
    }
    if (strcmp(kind, "io_async_method_scalarI_structureO") == 0) {
        return "io_async_method_scalarI_structureO";
    }
    if (strcmp(kind, "io_async_method_scalarI_structureI") == 0) {
        return "io_async_method_scalarI_structureI";
    }
    if (strcmp(kind, "io_async_method_structureI_structureO") == 0) {
        return "io_async_method_structureI_structureO";
    }
    return "IOConnectCallMethod";
}

static kern_return_t call_by_kind(
    const char *kind,
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *input_scalars,
    uint32_t input_scalar_count,
    const void *input_struct,
    size_t input_struct_bytes,
    uint64_t *output_scalars,
    uint32_t *output_scalar_count,
    void *output_struct,
    size_t *output_struct_bytes
) {
    if (!kind || strcmp(kind, "IOConnectCallMethod") == 0) {
        return IOConnectCallMethod(
            connection,
            selector,
            input_scalar_count ? input_scalars : NULL,
            input_scalar_count,
            input_struct_bytes ? input_struct : NULL,
            input_struct_bytes,
            output_scalar_count && *output_scalar_count ? output_scalars : NULL,
            output_scalar_count,
            output_struct_bytes && *output_struct_bytes ? output_struct : NULL,
            output_struct_bytes
        );
    }
    if (strcmp(kind, "IOConnectCallScalarMethod") == 0) {
        return IOConnectCallScalarMethod(
            connection,
            selector,
            input_scalar_count ? input_scalars : NULL,
            input_scalar_count,
            output_scalar_count && *output_scalar_count ? output_scalars : NULL,
            output_scalar_count
        );
    }
    if (strcmp(kind, "IOConnectCallStructMethod") == 0) {
        return IOConnectCallStructMethod(
            connection,
            selector,
            input_struct_bytes ? input_struct : NULL,
            input_struct_bytes,
            output_struct_bytes && *output_struct_bytes ? output_struct : NULL,
            output_struct_bytes
        );
    }
    if (strcmp(kind, "IOConnectCallAsyncScalarMethod") == 0) {
        uint64_t async_ref[8] = {0};
        return IOConnectCallAsyncScalarMethod(
            connection,
            selector,
            MACH_PORT_NULL,
            async_ref,
            0,
            input_scalar_count ? input_scalars : NULL,
            input_scalar_count,
            output_scalar_count && *output_scalar_count ? output_scalars : NULL,
            output_scalar_count
        );
    }
    if (strcmp(kind, "IOConnectCallAsyncStructMethod") == 0) {
        uint64_t async_ref[8] = {0};
        return IOConnectCallAsyncStructMethod(
            connection,
            selector,
            MACH_PORT_NULL,
            async_ref,
            0,
            input_struct_bytes ? input_struct : NULL,
            input_struct_bytes,
            output_struct_bytes && *output_struct_bytes ? output_struct : NULL,
            output_struct_bytes
        );
    }
    if (strcmp(kind, "io_connect_method_scalarI_scalarO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_scalar_inband_t out_scalars = {0};
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_scalar_count) {
            out_cnt = (mach_msg_type_number_t)(*output_scalar_count > 16 ? 16 : *output_scalar_count);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        sbl_io_connect_method_scalarI_scalarO_fn fn = sbl_load_io_connect_method_scalarI_scalarO();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, (int)selector, in_scalars, in_cnt, out_scalars, &out_cnt);
        if (output_scalar_count) {
            *output_scalar_count = (uint32_t)out_cnt;
        }
        if (output_scalars) {
            for (mach_msg_type_number_t i = 0; i < out_cnt; i++) {
                output_scalars[i] = out_scalars[i];
            }
        }
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t out_struct;
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        sbl_io_connect_method_scalarI_structureO_fn fn = sbl_load_io_connect_method_scalarI_structureO();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, (int)selector, in_scalars, in_cnt, out_struct, &out_cnt);
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureI") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t in_struct;
        memset(in_struct, 0, sizeof(in_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t struct_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        if (input_struct && struct_cnt > 0) {
            memcpy(in_struct, input_struct, struct_cnt);
        }
        sbl_io_connect_method_scalarI_structureI_fn fn = sbl_load_io_connect_method_scalarI_structureI();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, (int)selector, in_scalars, in_cnt, in_struct, struct_cnt);
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_connect_method_structureI_structureO") == 0) {
        io_struct_inband_t in_struct;
        io_struct_inband_t out_struct;
        memset(in_struct, 0, sizeof(in_struct));
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        if (input_struct && in_cnt > 0) {
            memcpy(in_struct, input_struct, in_cnt);
        }
        sbl_io_connect_method_structureI_structureO_fn fn = sbl_load_io_connect_method_structureI_structureO();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, (int)selector, in_struct, in_cnt, out_struct, &out_cnt);
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_scalarI_scalarO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_scalar_inband_t out_scalars = {0};
        io_async_ref_t async_ref = {0};
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_scalar_count) {
            out_cnt = (mach_msg_type_number_t)(*output_scalar_count > 16 ? 16 : *output_scalar_count);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        sbl_io_async_method_scalarI_scalarO_fn fn = sbl_load_io_async_method_scalarI_scalarO();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, MACH_PORT_NULL, async_ref, 0, (int)selector, in_scalars, in_cnt, out_scalars, &out_cnt);
        if (output_scalar_count) {
            *output_scalar_count = (uint32_t)out_cnt;
        }
        if (output_scalars) {
            for (mach_msg_type_number_t i = 0; i < out_cnt; i++) {
                output_scalars[i] = out_scalars[i];
            }
        }
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_scalarI_structureO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t out_struct;
        io_async_ref_t async_ref = {0};
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        sbl_io_async_method_scalarI_structureO_fn fn = sbl_load_io_async_method_scalarI_structureO();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, MACH_PORT_NULL, async_ref, 0, (int)selector, in_scalars, in_cnt, out_struct, &out_cnt);
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_scalarI_structureI") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t in_struct;
        io_async_ref_t async_ref = {0};
        memset(in_struct, 0, sizeof(in_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t struct_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        if (input_struct && struct_cnt > 0) {
            memcpy(in_struct, input_struct, struct_cnt);
        }
        sbl_io_async_method_scalarI_structureI_fn fn = sbl_load_io_async_method_scalarI_structureI();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, MACH_PORT_NULL, async_ref, 0, (int)selector, in_scalars, in_cnt, in_struct, struct_cnt);
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_structureI_structureO") == 0) {
        io_struct_inband_t in_struct;
        io_struct_inband_t out_struct;
        io_async_ref_t async_ref = {0};
        memset(in_struct, 0, sizeof(in_struct));
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        if (input_struct && in_cnt > 0) {
            memcpy(in_struct, input_struct, in_cnt);
        }
        sbl_io_async_method_structureI_structureO_fn fn = sbl_load_io_async_method_structureI_structureO();
        if (!fn) {
            return kIOReturnUnsupported;
        }
        kern_return_t kr = fn(connection, MACH_PORT_NULL, async_ref, 0, (int)selector, in_struct, in_cnt, out_struct, &out_cnt);
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    return kIOReturnUnsupported;
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
        emit_iokit_callout_string("pre_syscall", "iokit-open-user-client", SBL_FILTER_IOKIT_REGISTRY_ENTRY_CLASS, user_client_name);
        emit_iokit_callout_string("pre_syscall", "iokit-open-user-client", SBL_FILTER_IOKIT_USER_CLIENT_TYPE, user_client_name);
    }
    emit_iokit_callout_string("pre_syscall", "iokit-open-user-client", SBL_FILTER_IOKIT_REGISTRY_ENTRY_CLASS, class_name);
    emit_iokit_callout_string("pre_syscall", "iokit-open-user-client", SBL_FILTER_IOKIT_CONNECTION, "IOAccelerator");
    emit_iokit_callout_number("pre_syscall", "iokit-open-user-client", SBL_FILTER_IOKIT_USER_CLIENT_TYPE, user_client_type);
    emit_iokit_callout_number("pre_syscall", "iokit-open", SBL_FILTER_IOKIT_USER_CLIENT_TYPE, user_client_type);
    emit_iokit_callout_noarg("pre_syscall", "iokit-open-user-client");
    const char *oracle_only = getenv("SANDBOX_LORE_IOKIT_ORACLE_ONLY");
    if (oracle_only && oracle_only[0] != '\0' && oracle_only[0] != '0') {
        printf("SBL_PROBE_DETAILS {\"oracle_only\":true}\n");
        return 0;
    }

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
    const char *call_kind_env = getenv(SBL_IKIT_CALL_KIND_ENV);
    const char *call_kind = normalize_call_kind(call_kind_env);
    const char *call_kind_used = call_kind;
    const uint32_t default_selectors[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const uint32_t *selectors = default_selectors;
    size_t selector_count = sizeof(default_selectors) / sizeof(default_selectors[0]);
    uint32_t selector_buf[128];
    const char *selector_env = getenv("SANDBOX_LORE_IKIT_SELECTOR_LIST");
    if (selector_env && selector_env[0] != '\0') {
        size_t parsed = parse_selector_list(selector_env, selector_buf, sizeof(selector_buf) / sizeof(selector_buf[0]));
        if (parsed > 0) {
            selectors = selector_buf;
            selector_count = parsed;
        }
    }
    const char *skip_sweep_env = getenv("SBL_IKIT_SKIP_SWEEP");
    if (skip_sweep_env && skip_sweep_env[0] != '\0' && skip_sweep_env[0] != '0') {
        do_sweep = false;
    }
    uint32_t input_scalar_override = 0;
    size_t input_struct_override = 0;
    uint32_t output_scalar_override = 0;
    size_t output_struct_override = 0;
    bool call_shape_override = false;
    call_shape_override |= parse_env_u32(SBL_IKIT_CALL_IN_SCALARS_ENV, &input_scalar_override);
    call_shape_override |= parse_env_size(SBL_IKIT_CALL_IN_STRUCT_BYTES_ENV, &input_struct_override);
    call_shape_override |= parse_env_u32(SBL_IKIT_CALL_OUT_SCALARS_ENV, &output_scalar_override);
    call_shape_override |= parse_env_size(SBL_IKIT_CALL_OUT_STRUCT_BYTES_ENV, &output_struct_override);
    if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
        if (do_sweep) {
            uint32_t input_scalar_count = 0;
            uint32_t output_scalar_capacity = 0;
            size_t input_struct_bytes = 0;
            size_t output_struct_bytes = 0;
            if (call_shape_override) {
                input_scalar_count = input_scalar_override;
                input_struct_bytes = input_struct_override;
                output_scalar_capacity = output_scalar_override;
                output_struct_bytes = output_struct_override;
            } else if (selectors != default_selectors) {
                input_scalar_count = 1;
                input_struct_bytes = 16;
                output_struct_bytes = 16;
            }
            uint64_t *input_scalars = NULL;
            uint64_t *output_scalars = NULL;
            uint8_t *input_struct = NULL;
            uint8_t *output_struct = NULL;
            if (input_scalar_count > 0) {
                input_scalars = (uint64_t *)calloc(input_scalar_count, sizeof(uint64_t));
                if (!input_scalars) {
                    input_scalar_count = 0;
                }
            }
            if (output_scalar_capacity > 0) {
                output_scalars = (uint64_t *)calloc(output_scalar_capacity, sizeof(uint64_t));
                if (!output_scalars) {
                    output_scalar_capacity = 0;
                }
            }
            if (input_struct_bytes > 0) {
                input_struct = (uint8_t *)calloc(1, input_struct_bytes);
                if (!input_struct) {
                    input_struct_bytes = 0;
                }
            }
            if (output_struct_bytes > 0) {
                output_struct = (uint8_t *)calloc(1, output_struct_bytes);
                if (!output_struct) {
                    output_struct_bytes = 0;
                }
            }
            bool saw_non_invalid = false;
            uint32_t non_invalid_selector = 0;
            int non_invalid_kr = 0;
            const char *non_invalid_kr_string = NULL;
            uint32_t non_invalid_output_scalar_count = 0;
            size_t non_invalid_output_struct_bytes = 0;
            for (size_t i = 0; i < selector_count; i++) {
                call_output_scalar_count = output_scalar_capacity;
                call_output_struct_bytes = output_struct_bytes;
                call_attempted = true;
                call_selector = selectors[i];
                call_input_scalar_count = input_scalar_count;
                call_input_struct_bytes = input_struct_bytes;
                call_kind_used = call_kind;
                call_kr = call_by_kind(
                    call_kind,
                    conn,
                    selectors[i],
                    input_scalars,
                    input_scalar_count,
                    input_struct,
                    input_struct_bytes,
                    output_scalars,
                    &call_output_scalar_count,
                    output_struct,
                    &call_output_struct_bytes
                );
                call_kr_string = mach_error_string(call_kr);
                if (!saw_non_invalid && call_kr != kIOReturnBadArgument) {
                    saw_non_invalid = true;
                    non_invalid_selector = selectors[i];
                    non_invalid_kr = call_kr;
                    non_invalid_kr_string = call_kr_string;
                    non_invalid_output_scalar_count = call_output_scalar_count;
                    non_invalid_output_struct_bytes = call_output_struct_bytes;
                }
                if (call_kr == KERN_SUCCESS) {
                    call_succeeded = true;
                    break;
                }
            }
            if (saw_non_invalid && !call_succeeded) {
                call_selector = non_invalid_selector;
                call_kr = non_invalid_kr;
                call_kr_string = non_invalid_kr_string;
                call_output_scalar_count = non_invalid_output_scalar_count;
                call_output_struct_bytes = non_invalid_output_struct_bytes;
            }
            if (input_scalars) free(input_scalars);
            if (output_scalars) free(output_scalars);
            if (input_struct) free(input_struct);
            if (output_struct) free(output_struct);
        }
        surface_ok = attempt_surface_create(&surface_signal);
        IOServiceClose(conn);
    }
    IOObjectRelease(service);

    if (call_attempted) {
        const char *call_kr_string_value = call_kr_string ? call_kr_string : "unknown";
        if (surface_signal) {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"%s\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":%d}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_kind_used,
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
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"%s\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":null}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_kind_used,
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
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"%s\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d}\n",
                kr,
                call_kind_used,
                surface_ok ? "true" : "false",
                surface_signal);
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d}\n",
                kr,
                surface_ok ? "true" : "false",
                surface_signal);
        } else {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"%s\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":null}\n",
                kr,
                call_kind_used,
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
