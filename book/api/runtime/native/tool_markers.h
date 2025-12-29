/*
 * Shared JSONL marker emitter helpers for SANDBOX_LORE runtime tooling.
 *
 * Markers are emitted to stderr as single-line JSON objects. Downstream
 * normalization treats them as tool inputs, not as canonical stderr payload.
 *
 * Marker families:
 * - tool:"sbpl-apply" with stage apply|applied|exec
 * - tool:"sbpl-preflight" with stage preflight (static apply-gate avoidance)
 * - tool:"seatbelt-callout" for optional sandbox_check_by_audit_token callouts
 * - tool:"entitlement-check" for optional runtime-effective entitlement probes
 *
 * NOTE: This header is intentionally header-only with static helpers to keep
 * build integration minimal across ad-hoc experiment binaries.
 *
 * Emitting structured markers is safer than scraping stderr text.
 * It gives the Python layer a stable contract to parse across tool versions.
 */

#ifndef SANDBOX_LORE_RUNTIME_TOOL_MARKERS_H
#define SANDBOX_LORE_RUNTIME_TOOL_MARKERS_H

#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <sandbox.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Compiler helpers keep warnings stable across header-only uses. */
#if defined(__clang__)
#define SBL_DIAGNOSTIC_PUSH _Pragma("clang diagnostic push")
#define SBL_DIAGNOSTIC_POP _Pragma("clang diagnostic pop")
#define SBL_DIAGNOSTIC_IGNORED_DEPRECATED _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
#else
#define SBL_DIAGNOSTIC_PUSH
#define SBL_DIAGNOSTIC_POP
#define SBL_DIAGNOSTIC_IGNORED_DEPRECATED
#endif

#if defined(__GNUC__) || defined(__clang__)
#define SBL_UNUSED __attribute__((unused))
#else
#define SBL_UNUSED
#endif

/* Schema versions are centralized here to keep marker compatibility explicit. */
#define SANDBOX_LORE_SBPL_APPLY_MARKER_SCHEMA_VERSION 1
#define SANDBOX_LORE_SEATBELT_CALLOUT_MARKER_SCHEMA_VERSION 2
#define SANDBOX_LORE_SBPL_COMPILE_MARKER_SCHEMA_VERSION 1
#define SANDBOX_LORE_SBPL_PREFLIGHT_MARKER_SCHEMA_VERSION 1
#define SANDBOX_LORE_ENTITLEMENT_CHECK_MARKER_SCHEMA_VERSION 1

#define SANDBOX_LORE_SBPL_APPLY_TOOL "sbpl-apply"
#define SANDBOX_LORE_SBPL_PREFLIGHT_TOOL "sbpl-preflight"
#define SANDBOX_LORE_SEATBELT_CALLOUT_TOOL "seatbelt-callout"
#define SANDBOX_LORE_SBPL_COMPILE_TOOL "sbpl-compile"
#define SANDBOX_LORE_ENTITLEMENT_CHECK_TOOL "entitlement-check"

#define SANDBOX_LORE_ENV_SEATBELT_CALLOUT "SANDBOX_LORE_SEATBELT_CALLOUT"
#define SANDBOX_LORE_ENV_SEATBELT_OP "SANDBOX_LORE_SEATBELT_OP"
#define SANDBOX_LORE_ENV_SEATBELT_FILTER_TYPE "SANDBOX_LORE_SEATBELT_FILTER_TYPE"
#define SANDBOX_LORE_ENV_SEATBELT_ARG "SANDBOX_LORE_SEATBELT_ARG"

typedef struct sbl_apply_report {
    const char *mode;
    const char *api;
    int rc;
    int err;
    const char *errbuf;
    const char *err_class;
    const char *err_class_source;
    const char *profile;
} sbl_apply_report_t;

typedef int (*sbl_sandbox_apply_fn)(void *compiled_profile);

static void sbl_emit_sbpl_applied_marker(const char *mode, const char *api, const char *profile_path);

typedef struct sbl_compiled_profile {
    uint32_t profile_type;
    uint32_t reserved;
    const void *bytecode;
    size_t bytecode_length;
} sbl_compiled_profile_t;

static void sbl_json_write_string(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; p && *p; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", out);
            break;
        case '"':
            fputs("\\\"", out);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        case '\f':
            fputs("\\f", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20) {
                fprintf(out, "\\u%04x", (unsigned int)*p);
            } else {
                fputc(*p, out);
            }
        }
    }
    fputc('"', out);
}

static void sbl_json_emit_kv_string(FILE *out, int *first, const char *key, const char *value) {
    if (!value) return;
    if (!*first) fputc(',', out);
    *first = 0;
    sbl_json_write_string(out, key);
    fputc(':', out);
    sbl_json_write_string(out, value);
}

static void sbl_json_emit_kv_int(FILE *out, int *first, const char *key, long value) {
    if (!*first) fputc(',', out);
    *first = 0;
    sbl_json_write_string(out, key);
    fprintf(out, ":%ld", value);
}

static void sbl_json_emit_kv_bool(FILE *out, int *first, const char *key, int value) {
    if (!*first) fputc(',', out);
    *first = 0;
    sbl_json_write_string(out, key);
    fputs(value ? ":true" : ":false", out);
}

static int sbl_contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle || !*needle) return 0;
    size_t nlen = strlen(needle);
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < nlen && p[i]) {
            unsigned char a = (unsigned char)p[i];
            unsigned char b = (unsigned char)needle[i];
            if (tolower(a) != tolower(b)) break;
            i++;
        }
        if (i == nlen) return 1;
    }
    return 0;
}

static void sbl_classify_apply_err_class(
    const char *api,
    int rc,
    int err,
    const char *errbuf,
    const char **out_class,
    const char **out_source
) {
    const char *err_class = NULL;
    const char *err_class_source = NULL;

    if (rc == 0) {
        err_class = "ok";
        err_class_source = "none";
    } else if (api && strcmp(api, "sandbox_init") == 0 && errbuf && sbl_contains_ci(errbuf, "already") &&
               sbl_contains_ci(errbuf, "sandbox")) {
        err_class = "already_sandboxed";
        err_class_source = "errbuf_regex";
    } else if (err == EPERM) {
        err_class = "errno_eperm";
        err_class_source = "errno_only";
    } else if (err == EACCES) {
        err_class = "errno_eacces";
        err_class_source = "errno_only";
    } else if (err != 0) {
        err_class = "errno_other";
        err_class_source = "errno_only";
    } else if (errbuf && *errbuf) {
        err_class = "unknown";
        err_class_source = "errbuf_present";
    } else {
        err_class = "unknown";
        err_class_source = "none";
    }

    if (out_class) *out_class = err_class;
    if (out_source) *out_source = err_class_source;
}

static void sbl_emit_sbpl_apply_marker(
    const char *mode,
    const char *api,
    int rc,
    int err,
    const char *errbuf,
    const char *profile_path
) {
    FILE *out = stderr;
    int first = 1;

    const char *err_class = NULL;
    const char *err_class_source = NULL;
    sbl_classify_apply_err_class(api, rc, err, errbuf, &err_class, &err_class_source);

    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_SBPL_APPLY_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_SBPL_APPLY_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", "apply");
    sbl_json_emit_kv_string(out, &first, "mode", mode);
    sbl_json_emit_kv_string(out, &first, "api", api);
    sbl_json_emit_kv_int(out, &first, "rc", rc);
    sbl_json_emit_kv_int(out, &first, "errno", err);
    sbl_json_emit_kv_string(out, &first, "errbuf", errbuf);
    sbl_json_emit_kv_string(out, &first, "err_class", err_class);
    sbl_json_emit_kv_string(out, &first, "err_class_source", err_class_source);
    sbl_json_emit_kv_string(out, &first, "profile", profile_path);
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    fputs("}\n", out);
    fflush(out);
}

static void sbl_emit_sbpl_compile_marker(
    const char *api,
    int rc,
    int err,
    const char *errbuf,
    const char *profile_path,
    const sbl_compiled_profile_t *profile
) {
    FILE *out = stderr;
    int first = 1;

    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_SBPL_COMPILE_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_SBPL_COMPILE_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", "compile");
    sbl_json_emit_kv_string(out, &first, "api", api);
    sbl_json_emit_kv_int(out, &first, "rc", rc);
    sbl_json_emit_kv_int(out, &first, "errno", err);
    sbl_json_emit_kv_string(out, &first, "errbuf", errbuf);
    sbl_json_emit_kv_string(out, &first, "profile", profile_path);
    if (profile) {
        sbl_json_emit_kv_int(out, &first, "profile_type", (long)profile->profile_type);
        sbl_json_emit_kv_int(out, &first, "bytecode_length", (long)profile->bytecode_length);
    }
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    fputs("}\n", out);
    fflush(out);
}

static sbl_apply_report_t sbl_apply_report_from_parts(
    const char *mode,
    const char *api,
    int rc,
    int err,
    const char *errbuf,
    const char *profile
) {
    const char *err_class = NULL;
    const char *err_class_source = NULL;
    sbl_classify_apply_err_class(api, rc, err, errbuf, &err_class, &err_class_source);
    sbl_apply_report_t report;
    report.mode = mode;
    report.api = api;
    report.rc = rc;
    report.err = err;
    report.errbuf = errbuf;
    report.err_class = err_class;
    report.err_class_source = err_class_source;
    report.profile = profile;
    return report;
}

static SBL_UNUSED sbl_apply_report_t sbl_sandbox_init_with_markers(
    const char *profile_text,
    uint64_t flags,
    char **errorbuf_out,
    const char *profile_path
) {
    char *tmp_err = NULL;
    char **errp = errorbuf_out ? errorbuf_out : &tmp_err;

    errno = 0;
    SBL_DIAGNOSTIC_PUSH
    SBL_DIAGNOSTIC_IGNORED_DEPRECATED
    int rc = sandbox_init(profile_text, flags, errp);
    int saved_errno = errno;
    const char *errbuf = (errp && *errp) ? *errp : NULL;

    sbl_emit_sbpl_apply_marker("sbpl", "sandbox_init", rc, saved_errno, errbuf, profile_path);
    if (rc == 0) {
        sbl_emit_sbpl_applied_marker("sbpl", "sandbox_init", profile_path);
    }
    if (!errorbuf_out && tmp_err) {
        sandbox_free_error(tmp_err);
    }
    SBL_DIAGNOSTIC_POP
    return sbl_apply_report_from_parts("sbpl", "sandbox_init", rc, saved_errno, errbuf, profile_path);
}

static SBL_UNUSED sbl_apply_report_t sbl_sandbox_apply_with_markers(
    sbl_sandbox_apply_fn apply_fn,
    void *compiled_profile,
    const char *profile_path
) {
    errno = 0;
    int rc = apply_fn ? apply_fn(compiled_profile) : -1;
    int saved_errno = errno;
    const char *errbuf = (saved_errno != 0) ? strerror(saved_errno) : NULL;

    sbl_emit_sbpl_apply_marker("blob", "sandbox_apply", rc, saved_errno, errbuf, profile_path);
    if (rc == 0) {
        sbl_emit_sbpl_applied_marker("blob", "sandbox_apply", profile_path);
    }
    return sbl_apply_report_from_parts("blob", "sandbox_apply", rc, saved_errno, errbuf, profile_path);
}

static SBL_UNUSED void sbl_sandbox_free_error(char *errbuf) {
    if (!errbuf) return;
    SBL_DIAGNOSTIC_PUSH
    SBL_DIAGNOSTIC_IGNORED_DEPRECATED
    sandbox_free_error(errbuf);
    SBL_DIAGNOSTIC_POP
}

static void sbl_emit_sbpl_applied_marker(const char *mode, const char *api, const char *profile_path) {
    FILE *out = stderr;
    int first = 1;
    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_SBPL_APPLY_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_SBPL_APPLY_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", "applied");
    sbl_json_emit_kv_string(out, &first, "mode", mode);
    sbl_json_emit_kv_string(out, &first, "api", api);
    sbl_json_emit_kv_int(out, &first, "rc", 0);
    sbl_json_emit_kv_string(out, &first, "profile", profile_path);
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    fputs("}\n", out);
    fflush(out);
}

static SBL_UNUSED void sbl_emit_sbpl_exec_marker(int rc, int err, const char *argv0) {
    FILE *out = stderr;
    int first = 1;
    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_SBPL_APPLY_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_SBPL_APPLY_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", "exec");
    sbl_json_emit_kv_int(out, &first, "rc", rc);
    sbl_json_emit_kv_int(out, &first, "errno", err);
    sbl_json_emit_kv_string(out, &first, "argv0", argv0);
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    fputs("}\n", out);
    fflush(out);
}

/*
 * Emit a marker for wrapper-side static preflight checks.
 *
 * This marker is intended as an input to normalization (and is stripped from
 * canonical stderr). It records whether preflight ran, what policy was in
 * effect, and the preflight tool's exit code.
 */
static SBL_UNUSED void sbl_emit_sbpl_preflight_marker(
    const char *mode,
    const char *policy,
    const char *profile_path,
    int rc,
    const char *record_json,
    const char *error
) {
    FILE *out = stderr;
    int first = 1;
    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_SBPL_PREFLIGHT_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_SBPL_PREFLIGHT_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", "preflight");
    sbl_json_emit_kv_string(out, &first, "mode", mode);
    sbl_json_emit_kv_string(out, &first, "policy", policy);
    sbl_json_emit_kv_string(out, &first, "profile", profile_path);
    sbl_json_emit_kv_int(out, &first, "rc", rc);
    sbl_json_emit_kv_string(out, &first, "record_json", record_json);
    sbl_json_emit_kv_string(out, &first, "error", error);
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    fputs("}\n", out);
    fflush(out);
}

/*
 * Emit a marker for runtime-effective entitlement checks performed by tools.
 *
 * This is intended as correlation evidence (e.g., "does this applying process
 * have the message-filter entitlement?") and is not used for classification.
 *
 * - rc: 0 for "query performed", nonzero for tool-side failure to query.
 * - present: 0/1 when rc==0, or -1 to omit.
 * - value_bool: 0/1 when the entitlement value is boolean, or -1 to omit.
 */
static SBL_UNUSED void sbl_emit_entitlement_check_marker(
    const char *stage,
    const char *entitlement,
    int rc,
    int present,
    int value_bool,
    const char *value_type,
    const char *error
) {
    FILE *out = stderr;
    int first = 1;
    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_ENTITLEMENT_CHECK_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_ENTITLEMENT_CHECK_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", stage);
    sbl_json_emit_kv_string(out, &first, "entitlement", entitlement);
    sbl_json_emit_kv_int(out, &first, "pid", (long)getpid());
    sbl_json_emit_kv_int(out, &first, "rc", rc);
    if (present != -1) {
        sbl_json_emit_kv_bool(out, &first, "present", present ? 1 : 0);
    }
    if (value_bool != -1) {
        sbl_json_emit_kv_bool(out, &first, "value_bool", value_bool ? 1 : 0);
    }
    sbl_json_emit_kv_string(out, &first, "value_type", value_type);
    sbl_json_emit_kv_string(out, &first, "error", error);
    fputs("}\n", out);
    fflush(out);
}

typedef int (*sbl_sandbox_check_by_audit_token_fn)(audit_token_t *token, const char *operation, int type, ...);

static void *sbl_load_libsystem_sandbox_handle(void) {
    static void *handle = NULL;
    static int attempted = 0;
    if (attempted) return handle;
    attempted = 1;
    handle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW | RTLD_LOCAL);
    return handle;
}

static void *sbl_load_libsandbox_handle(void) {
    static void *handle = NULL;
    static int attempted = 0;
    if (attempted) return handle;
    attempted = 1;
    handle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW | RTLD_LOCAL);
    return handle;
}

static sbl_sandbox_check_by_audit_token_fn sbl_load_sandbox_check_by_audit_token(void) {
    static sbl_sandbox_check_by_audit_token_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    void *handle = sbl_load_libsystem_sandbox_handle();
    if (!handle) return NULL;
    fn = (sbl_sandbox_check_by_audit_token_fn)dlsym(handle, "sandbox_check_by_audit_token");
    return fn;
}

typedef sbl_compiled_profile_t *(*sbl_sandbox_compile_file_fn)(const char *path, uint64_t flags, char **errorbuf);
typedef sbl_compiled_profile_t *(*sbl_sandbox_compile_string_fn)(const char *profile, uint64_t flags, char **errorbuf);
typedef void (*sbl_sandbox_free_profile_fn)(sbl_compiled_profile_t *profile);

static sbl_sandbox_compile_file_fn sbl_load_sandbox_compile_file(void) {
    static sbl_sandbox_compile_file_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    void *handle = sbl_load_libsandbox_handle();
    if (!handle) return NULL;
    fn = (sbl_sandbox_compile_file_fn)dlsym(handle, "sandbox_compile_file");
    return fn;
}

static sbl_sandbox_compile_string_fn sbl_load_sandbox_compile_string(void) {
    static sbl_sandbox_compile_string_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    void *handle = sbl_load_libsandbox_handle();
    if (!handle) return NULL;
    fn = (sbl_sandbox_compile_string_fn)dlsym(handle, "sandbox_compile_string");
    return fn;
}

static sbl_sandbox_free_profile_fn sbl_load_sandbox_free_profile(void) {
    static sbl_sandbox_free_profile_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    void *handle = sbl_load_libsandbox_handle();
    if (!handle) return NULL;
    fn = (sbl_sandbox_free_profile_fn)dlsym(handle, "sandbox_free_profile");
    return fn;
}

static SBL_UNUSED sbl_compiled_profile_t *sbl_sandbox_compile_file_with_markers(
    const char *path,
    uint64_t flags,
    char **errorbuf_out
) {
    sbl_sandbox_compile_file_fn compile_fn = sbl_load_sandbox_compile_file();
    char *tmp_err = NULL;
    char **errp = errorbuf_out ? errorbuf_out : &tmp_err;
    if (errp) *errp = NULL;

    errno = 0;
    sbl_compiled_profile_t *profile = compile_fn ? compile_fn(path, flags, errp) : NULL;
    int saved_errno = errno;
    const char *errbuf = (errp && *errp) ? *errp : NULL;

    sbl_emit_sbpl_compile_marker("sandbox_compile_file", profile ? 0 : -1, saved_errno, errbuf, path, profile);

    if (!errorbuf_out && tmp_err) {
        free(tmp_err);
    }
    return profile;
}

static SBL_UNUSED sbl_compiled_profile_t *sbl_sandbox_compile_string_with_markers(
    const char *profile_src,
    uint64_t flags,
    char **errorbuf_out,
    const char *profile_path
) {
    sbl_sandbox_compile_string_fn compile_fn = sbl_load_sandbox_compile_string();
    char *tmp_err = NULL;
    char **errp = errorbuf_out ? errorbuf_out : &tmp_err;
    if (errp) *errp = NULL;

    errno = 0;
    sbl_compiled_profile_t *profile = compile_fn ? compile_fn(profile_src, flags, errp) : NULL;
    int saved_errno = errno;
    const char *errbuf = (errp && *errp) ? *errp : NULL;

    sbl_emit_sbpl_compile_marker("sandbox_compile_string", profile ? 0 : -1, saved_errno, errbuf, profile_path, profile);

    if (!errorbuf_out && tmp_err) {
        free(tmp_err);
    }
    return profile;
}

static SBL_UNUSED void sbl_sandbox_free_profile(sbl_compiled_profile_t *profile) {
    if (!profile) return;
    sbl_sandbox_free_profile_fn free_fn = sbl_load_sandbox_free_profile();
    if (free_fn) {
        free_fn(profile);
    }
}

static const int *sbl_load_sandbox_check_no_report_flag(void) {
    static const int *flag = NULL;
    static int attempted = 0;
    if (attempted) return flag;
    attempted = 1;
    void *handle = sbl_load_libsystem_sandbox_handle();
    if (!handle) return NULL;
    flag = (const int *)dlsym(handle, "SANDBOX_CHECK_NO_REPORT");
    return flag;
}

static int sbl_get_self_audit_token(audit_token_t *out, int *mach_kr_out) {
    if (!out) return -1;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)out, &count);
    if (mach_kr_out) {
        *mach_kr_out = (int)kr;
    }
    return kr == KERN_SUCCESS ? 0 : -1;
}

static const char *sbl_callout_decision_from_rc(int rc) {
    if (rc == 0) return "allow";
    if (rc == 1) return "deny";
    return "error";
}

enum {
    SBL_FILTER_PATH = 0,
    SBL_FILTER_GLOBAL_NAME = 5,
    SBL_FILTER_LOCAL_NAME = 6,
    SBL_FILTER_RIGHT_NAME = 26,
    SBL_FILTER_PREFERENCE_DOMAIN = 27,
};

static const char *sbl_filter_type_name(long filter_type) {
    switch (filter_type) {
    case SBL_FILTER_PATH:
        return "path";
    case SBL_FILTER_GLOBAL_NAME:
        return "global-name";
    case SBL_FILTER_LOCAL_NAME:
        return "local-name";
    case SBL_FILTER_RIGHT_NAME:
        return "right-name";
    case SBL_FILTER_PREFERENCE_DOMAIN:
        return "preference-domain";
    default:
        return "unknown";
    }
}

static int sbl_filter_type_is_string_arg(long filter_type) {
    switch (filter_type) {
    case SBL_FILTER_PATH:
    case SBL_FILTER_GLOBAL_NAME:
    case SBL_FILTER_LOCAL_NAME:
    case SBL_FILTER_RIGHT_NAME:
    case SBL_FILTER_PREFERENCE_DOMAIN:
        return 1;
    default:
        return 0;
    }
}

static int sbl_sb_check_type_with_no_report(long filter_type, int *no_report_used, const char **no_report_reason) {
    int used = 0;
    const char *reason = "symbol_missing";
    long type_used = filter_type;
    const int *flagp = sbl_load_sandbox_check_no_report_flag();
    if (flagp) {
        int flag_value = *flagp;
        if (flag_value != 0) {
            type_used = filter_type | flag_value;
            used = 1;
            reason = NULL;
        } else {
            reason = "flag_zero";
        }
    }
    if (no_report_used) *no_report_used = used;
    if (no_report_reason) *no_report_reason = reason;
    return (int)type_used;
}

static void sbl_emit_seatbelt_callout(
    const char *stage,
    const char *operation,
    long filter_type,
    const char *argument,
    int rc,
    int err,
    const char *error_msg,
    int no_report,
    const char *no_report_reason,
    int token_mach_kr,
    const char *token_status,
    long check_type,
    int varargs_count
) {
    FILE *out = stderr;
    int first = 1;
    fputc('{', out);
    sbl_json_emit_kv_string(out, &first, "tool", SANDBOX_LORE_SEATBELT_CALLOUT_TOOL);
    sbl_json_emit_kv_int(out, &first, "marker_schema_version", SANDBOX_LORE_SEATBELT_CALLOUT_MARKER_SCHEMA_VERSION);
    sbl_json_emit_kv_string(out, &first, "stage", stage);
    sbl_json_emit_kv_string(out, &first, "api", "sandbox_check_by_audit_token");
    sbl_json_emit_kv_string(out, &first, "operation", operation);
    sbl_json_emit_kv_int(out, &first, "filter_type", filter_type);
    sbl_json_emit_kv_string(out, &first, "filter_type_name", sbl_filter_type_name(filter_type));
    sbl_json_emit_kv_int(out, &first, "check_type", check_type);
    sbl_json_emit_kv_int(out, &first, "varargs_count", varargs_count);
    sbl_json_emit_kv_string(out, &first, "argument", argument);
    sbl_json_emit_kv_bool(out, &first, "no_report", no_report);
    sbl_json_emit_kv_string(out, &first, "no_report_reason", no_report_reason);
    sbl_json_emit_kv_string(out, &first, "token_status", token_status);
    sbl_json_emit_kv_int(out, &first, "token_mach_kr", token_mach_kr);
    sbl_json_emit_kv_int(out, &first, "rc", rc);
    sbl_json_emit_kv_int(out, &first, "errno", err);
    sbl_json_emit_kv_string(out, &first, "decision", sbl_callout_decision_from_rc(rc));
    sbl_json_emit_kv_string(out, &first, "error", error_msg);
    fputs("}\n", out);
    fflush(out);
}

static SBL_UNUSED void sbl_maybe_seatbelt_callout_from_env(const char *stage) {
    const char *enabled = getenv(SANDBOX_LORE_ENV_SEATBELT_CALLOUT);
    if (!enabled || strcmp(enabled, "1") != 0) return;
    const char *op = getenv(SANDBOX_LORE_ENV_SEATBELT_OP);
    const char *filter_s = getenv(SANDBOX_LORE_ENV_SEATBELT_FILTER_TYPE);
    const char *arg = getenv(SANDBOX_LORE_ENV_SEATBELT_ARG);
    if (!op || !filter_s || !arg) return;
    char *end = NULL;
    long filter = strtol(filter_s, &end, 10);
    if (!end || *end != '\0') return;

    int token_kr = 0;
    audit_token_t token;
    if (sbl_get_self_audit_token(&token, &token_kr) != 0) {
        sbl_emit_seatbelt_callout(
            stage,
            op,
            filter,
            arg,
            -1,
            0,
            "TASK_AUDIT_TOKEN unavailable",
            0,
            "token_unavailable",
            token_kr,
            "task_info_failed",
            filter,
            1
        );
        return;
    }
    sbl_sandbox_check_by_audit_token_fn fn = sbl_load_sandbox_check_by_audit_token();
    if (!fn) {
        sbl_emit_seatbelt_callout(
            stage,
            op,
            filter,
            arg,
            -2,
            ENOSYS,
            "sandbox_check_by_audit_token missing",
            0,
            "symbol_missing",
            token_kr,
            "ok",
            filter,
            1
        );
        return;
    }
    if (!sbl_filter_type_is_string_arg(filter)) {
        sbl_emit_seatbelt_callout(
            stage,
            op,
            filter,
            arg,
            -2,
            ENOTSUP,
            "unsupported filter type (string-arg only)",
            0,
            "unsupported_filter_type",
            token_kr,
            "ok",
            filter,
            1
        );
        return;
    }

    int no_report_used = 0;
    const char *no_report_reason = NULL;
    int type_used = sbl_sb_check_type_with_no_report(filter, &no_report_used, &no_report_reason);
    if (!no_report_used && no_report_reason == NULL) {
        no_report_reason = "unknown";
    }
    errno = 0;
    int rc = fn(&token, op, type_used, arg);
    int err = errno;
    sbl_emit_seatbelt_callout(
        stage,
        op,
        filter,
        arg,
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

static SBL_UNUSED void sbl_maybe_seatbelt_process_exec_callout(const char *stage, const char *argv0) {
    const char *enabled = getenv(SANDBOX_LORE_ENV_SEATBELT_CALLOUT);
    if (!enabled || strcmp(enabled, "1") != 0) return;
    if (!argv0) return;
    int token_kr = 0;
    audit_token_t token;
    if (sbl_get_self_audit_token(&token, &token_kr) != 0) {
        sbl_emit_seatbelt_callout(
            stage,
            "process-exec*",
            SBL_FILTER_PATH,
            argv0,
            -1,
            0,
            "TASK_AUDIT_TOKEN unavailable",
            0,
            "token_unavailable",
            token_kr,
            "task_info_failed",
            SBL_FILTER_PATH,
            1
        );
        return;
    }
    sbl_sandbox_check_by_audit_token_fn fn = sbl_load_sandbox_check_by_audit_token();
    if (!fn) {
        sbl_emit_seatbelt_callout(
            stage,
            "process-exec*",
            SBL_FILTER_PATH,
            argv0,
            -2,
            ENOSYS,
            "sandbox_check_by_audit_token missing",
            0,
            "symbol_missing",
            token_kr,
            "ok",
            SBL_FILTER_PATH,
            1
        );
        return;
    }

    int no_report_used = 0;
    const char *no_report_reason = NULL;
    int type_used = sbl_sb_check_type_with_no_report(SBL_FILTER_PATH, &no_report_used, &no_report_reason);
    if (!no_report_used && no_report_reason == NULL) {
        no_report_reason = "unknown";
    }
    errno = 0;
    int rc = fn(&token, "process-exec*", type_used, argv0);
    int err = errno;
    sbl_emit_seatbelt_callout(
        stage,
        "process-exec*",
        SBL_FILTER_PATH,
        argv0,
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

#endif /* SANDBOX_LORE_RUNTIME_TOOL_MARKERS_H */
