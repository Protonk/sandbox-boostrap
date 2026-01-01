/*
 * Seatbelt callout shim interface for runtime probes.
 *
 * This header exposes a tiny C ABI used by probes to call
 * sandbox_check_by_audit_token-like APIs and collect structured metadata.
 *
 * Callout results are a side channel. They are useful for debugging
 * but should not be confused with syscall-level evidence.
 */

#ifndef SANDBOX_LORE_SEATBELT_CALLOUT_SHIM_H
#define SANDBOX_LORE_SEATBELT_CALLOUT_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
    /* Stable no-report reason codes surfaced by the callout shim. */
    SBL_NO_REPORT_USED = 0,
    SBL_NO_REPORT_SYMBOL_MISSING = 1,
    SBL_NO_REPORT_FLAG_ZERO = 2,
    /* Canonicalization flag outcomes. */
    SBL_CANONICAL_USED = 0,
    SBL_CANONICAL_NOT_REQUESTED = 1,
    SBL_CANONICAL_SYMBOL_MISSING = 2,
    SBL_CANONICAL_FLAG_ZERO = 3,
};

/* Invoke a seatbelt callout for the current process and capture metadata. */
int sbl_seatbelt_callout_self(
    const char *operation,
    int filter_type,
    const char *arg0,
    const char *arg1,
    int canonicalize,
    int *errno_out,
    int *type_used_out,
    int *no_report_used_out,
    int *no_report_reason_out,
    int *canonical_used_out,
    int *canonical_reason_out,
    int *token_mach_kr_out
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SANDBOX_LORE_SEATBELT_CALLOUT_SHIM_H */
