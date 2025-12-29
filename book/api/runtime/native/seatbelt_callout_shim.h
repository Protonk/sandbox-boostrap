#ifndef SANDBOX_LORE_SEATBELT_CALLOUT_SHIM_H
#define SANDBOX_LORE_SEATBELT_CALLOUT_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SBL_NO_REPORT_USED = 0,
    SBL_NO_REPORT_SYMBOL_MISSING = 1,
    SBL_NO_REPORT_FLAG_ZERO = 2,
};

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
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SANDBOX_LORE_SEATBELT_CALLOUT_SHIM_H */
