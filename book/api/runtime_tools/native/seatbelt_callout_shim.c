#include "seatbelt_callout_shim.h"

#include <dlfcn.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/task_info.h>

enum {
    SBL_FILTER_PATH = 0,
    SBL_FILTER_GLOBAL_NAME = 5,
    SBL_FILTER_LOCAL_NAME = 6,
    SBL_FILTER_RIGHT_NAME = 26,
    SBL_FILTER_PREFERENCE_DOMAIN = 27,
};

typedef int (*sbl_sandbox_check_by_audit_token_fn)(audit_token_t *token, const char *operation, int type, ...);

static void *sbl_load_libsystem_sandbox_handle(void) {
    static void *handle = NULL;
    static int attempted = 0;
    if (attempted) return handle;
    attempted = 1;
    handle = dlopen("/usr/lib/system/libsystem_sandbox.dylib", RTLD_NOW | RTLD_LOCAL);
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

int sbl_seatbelt_callout_self(
    const char *operation,
    int filter_type,
    const char *arg0,
    const char *arg1,
    int *errno_out,
    int *type_used_out,
    int *no_report_used_out,
    int *no_report_reason_out,
    int *token_mach_kr_out
) {
    (void)arg1;
    if (errno_out) *errno_out = 0;
    if (type_used_out) *type_used_out = filter_type;
    if (no_report_used_out) *no_report_used_out = 0;
    if (no_report_reason_out) *no_report_reason_out = SBL_NO_REPORT_SYMBOL_MISSING;
    if (token_mach_kr_out) *token_mach_kr_out = 0;

    if (!operation || !*operation) {
        if (errno_out) *errno_out = EINVAL;
        return -2;
    }

    audit_token_t token;
    int token_kr = 0;
    if (sbl_get_self_audit_token(&token, &token_kr) != 0) {
        if (token_mach_kr_out) *token_mach_kr_out = token_kr;
        return -1;
    }
    if (token_mach_kr_out) *token_mach_kr_out = token_kr;

    sbl_sandbox_check_by_audit_token_fn fn = sbl_load_sandbox_check_by_audit_token();
    if (!fn) {
        if (errno_out) *errno_out = ENOSYS;
        return -2;
    }

    switch (filter_type) {
    case SBL_FILTER_PATH:
    case SBL_FILTER_GLOBAL_NAME:
    case SBL_FILTER_LOCAL_NAME:
    case SBL_FILTER_RIGHT_NAME:
    case SBL_FILTER_PREFERENCE_DOMAIN:
        if (!arg0) {
            if (errno_out) *errno_out = EINVAL;
            return -2;
        }
        break;
    default:
        if (errno_out) *errno_out = ENOTSUP;
        return -2;
    }

    int type_used = filter_type;
    int no_report_used = 0;
    int no_report_reason = SBL_NO_REPORT_SYMBOL_MISSING;
    const int *no_report_flag = sbl_load_sandbox_check_no_report_flag();
    if (no_report_flag) {
        int flag_value = *no_report_flag;
        if (flag_value != 0) {
            type_used = filter_type | flag_value;
            no_report_used = 1;
            no_report_reason = SBL_NO_REPORT_USED;
        } else {
            no_report_reason = SBL_NO_REPORT_FLAG_ZERO;
        }
    }
    if (type_used_out) *type_used_out = type_used;
    if (no_report_used_out) *no_report_used_out = no_report_used;
    if (no_report_reason_out) *no_report_reason_out = no_report_reason;

    errno = 0;
    int rc = fn(&token, operation, type_used, arg0);
    int err = errno;
    if (errno_out) *errno_out = err;
    return rc;
}
