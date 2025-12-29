/*
 ToolMarkers emits JSONL "marker" records for SANDBOX_LORE runtime tools,
 bridging Swift helpers to libsandbox and optional seatbelt callouts. The
 output is intentionally side-effecting (stderr) so normalization can ingest
 markers without treating them as canonical runtime stderr.

 These markers capture stage-labeled facts (apply/exec/callout) that
 are later normalized into runtime IR; they are not policy semantics by
 themselves.
*/
import Foundation
import Darwin

@_silgen_name("sandbox_init")
private func sbl_sandbox_init(
    _ profile: UnsafePointer<CChar>,
    _ flags: UInt64,
    _ errorbuf: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>!
) -> Int32

@_silgen_name("sandbox_free_error")
private func sbl_sandbox_free_error(_ errorbuf: UnsafeMutablePointer<CChar>!)

@_silgen_name("sbl_seatbelt_callout_self")
private func sbl_seatbelt_callout_self(
    _ operation: UnsafePointer<CChar>,
    _ filterType: Int32,
    _ arg0: UnsafePointer<CChar>?,
    _ arg1: UnsafePointer<CChar>?,
    _ errnoOut: UnsafeMutablePointer<Int32>,
    _ typeUsedOut: UnsafeMutablePointer<Int32>,
    _ noReportUsedOut: UnsafeMutablePointer<Int32>,
    _ noReportReasonOut: UnsafeMutablePointer<Int32>,
    _ tokenMachKrOut: UnsafeMutablePointer<Int32>
) -> Int32

/// Namespaced helpers for emitting runtime marker JSONL records.
enum ToolMarkers {
    static let sbplApplyMarkerSchemaVersion: Int = 1
    static let seatbeltCalloutMarkerSchemaVersion: Int = 2

    // Minimal struct matching the libsandbox sandbox_profile_t layout used by sandbox_apply.
    struct SandboxProfile {
        var builtin: UnsafeMutablePointer<CChar>?
        var data: UnsafePointer<UInt8>?
        var size: Int
    }

    typealias SandboxApplyFn = @convention(c) (UnsafeMutableRawPointer?) -> Int32

    struct ApplyReport {
        let mode: String
        let api: String
        let rc: Int32
        let err: Int32
        let errbuf: String?
        let errClass: String
        let errClassSource: String
        let profile: String
    }

    /// Emit a marker for an SBPL apply attempt before any exec is observed.
    static func emitSbplApply(
        mode: String,
        api: String,
        rc: Int32,
        err: Int32,
        errbuf: String?,
        profile: String
    ) {
        let (errClass, errClassSource) = classifyApplyError(api: api, rc: rc, err: err, errbuf: errbuf)
        emitJsonl(
            [
                "tool": "sbpl-apply",
                "marker_schema_version": sbplApplyMarkerSchemaVersion,
                "stage": "apply",
                "mode": mode,
                "api": api,
                "rc": rc,
                "errno": err,
                "errbuf": errbuf ?? NSNull(),
                "err_class": errClass,
                "err_class_source": errClassSource,
                "profile": profile,
                "pid": getpid(),
            ]
        )
    }

    /// Emit a marker for a direct seatbelt callout probe.
    static func emitSeatbeltCallout(
        stage: String,
        operation: String,
        filterType: Int,
        argument: String?,
        rc: Int32,
        err: Int32,
        error: String?,
        noReport: Bool,
        noReportReason: String?,
        tokenStatus: String,
        tokenMachKr: Int32,
        checkType: Int32,
        varargsCount: Int
    ) {
        emitJsonl(
            [
                "tool": "seatbelt-callout",
                "marker_schema_version": seatbeltCalloutMarkerSchemaVersion,
                "stage": stage,
                "api": "sandbox_check_by_audit_token",
                "operation": operation,
                "filter_type": filterType,
                "filter_type_name": filterTypeName(filterType),
                "check_type": checkType,
                "varargs_count": varargsCount,
                "argument": argument ?? NSNull(),
                "no_report": noReport,
                "no_report_reason": noReportReason ?? NSNull(),
                "token_status": tokenStatus,
                "token_mach_kr": tokenMachKr,
                "rc": rc,
                "errno": err,
                "decision": calloutDecisionFromRc(rc),
                "error": error ?? NSNull(),
            ]
        )
    }

    /// Emit a marker indicating the profile was applied successfully.
    static func emitSbplApplied(mode: String, api: String, profile: String) {
        emitJsonl(
            [
                "tool": "sbpl-apply",
                "marker_schema_version": sbplApplyMarkerSchemaVersion,
                "stage": "applied",
                "mode": mode,
                "api": api,
                "rc": 0,
                "profile": profile,
                "pid": getpid(),
            ]
        )
    }

    /// Emit a marker for the exec stage when an exec attempt is observed.
    static func emitSbplExec(rc: Int32, err: Int32, argv0: String) {
        emitJsonl(
            [
                "tool": "sbpl-apply",
                "marker_schema_version": sbplApplyMarkerSchemaVersion,
                "stage": "exec",
                "rc": rc,
                "errno": err,
                "argv0": argv0,
                "pid": getpid(),
            ]
        )
    }

    /// Call sandbox_init with markers and return a summarized apply report.
    static func sandboxInitWithMarkers(profileText: String, flags: UInt64 = 0, profilePath: String) -> ApplyReport {
        var errBuf: UnsafeMutablePointer<CChar>? = nil
        errno = 0
        let rc = profileText.withCString { cstr in
            sbl_sandbox_init(cstr, flags, &errBuf)
        }
        let savedErrno = errno
        let message = errBuf.map { String(cString: $0) }

        emitSbplApply(mode: "sbpl", api: "sandbox_init", rc: rc, err: savedErrno, errbuf: message, profile: profilePath)
        if let errBuf {
            sbl_sandbox_free_error(errBuf)
        }
        if rc == 0 {
            emitSbplApplied(mode: "sbpl", api: "sandbox_init", profile: profilePath)
        }

        let (errClass, errClassSource) = classifyApplyError(api: "sandbox_init", rc: rc, err: savedErrno, errbuf: message)
        return ApplyReport(
            mode: "sbpl",
            api: "sandbox_init",
            rc: rc,
            err: savedErrno,
            errbuf: message,
            errClass: errClass,
            errClassSource: errClassSource,
            profile: profilePath
        )
    }

    /// Emit an apply marker for a precomputed sandbox_init failure.
    static func sandboxInitFailureWithMarkers(rc: Int32, err: Int32, errbuf: String?, profilePath: String) -> ApplyReport {
        emitSbplApply(mode: "sbpl", api: "sandbox_init", rc: rc, err: err, errbuf: errbuf, profile: profilePath)
        let (errClass, errClassSource) = classifyApplyError(api: "sandbox_init", rc: rc, err: err, errbuf: errbuf)
        return ApplyReport(
            mode: "sbpl",
            api: "sandbox_init",
            rc: rc,
            err: err,
            errbuf: errbuf,
            errClass: errClass,
            errClassSource: errClassSource,
            profile: profilePath
        )
    }

    /// Emit apply markers around a sandbox_apply attempt (blob mode).
    static func sandboxApplyWithMarkers(applyRc: Int32, applyErrno: Int32, profilePath: String) -> ApplyReport {
        // Swift tools may call into a private sandbox_apply shim; keep the marker emission
        // in one place even when the apply itself is done elsewhere.
        let errbuf = (applyErrno == 0) ? nil : String(cString: strerror(applyErrno))
        emitSbplApply(mode: "blob", api: "sandbox_apply", rc: applyRc, err: applyErrno, errbuf: errbuf, profile: profilePath)
        if applyRc == 0 {
            emitSbplApplied(mode: "blob", api: "sandbox_apply", profile: profilePath)
        }
        let (errClass, errClassSource) = classifyApplyError(api: "sandbox_apply", rc: applyRc, err: applyErrno, errbuf: errbuf)
        return ApplyReport(
            mode: "blob",
            api: "sandbox_apply",
            rc: applyRc,
            err: applyErrno,
            errbuf: errbuf,
            errClass: errClass,
            errClassSource: errClassSource,
            profile: profilePath
        )
    }

    /// Load a compiled blob and apply it via libsandbox, emitting markers.
    static func sandboxApplyBlobFileWithMarkers(blobPath: String) -> ApplyReport {
        guard let handle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW | RTLD_LOCAL) else {
            return sandboxApplyWithMarkers(applyRc: -1, applyErrno: errno, profilePath: blobPath)
        }
        defer { dlclose(handle) }

        guard let symbol = dlsym(handle, "sandbox_apply") else {
            return sandboxApplyWithMarkers(applyRc: -1, applyErrno: errno, profilePath: blobPath)
        }
        let apply = unsafeBitCast(symbol, to: SandboxApplyFn.self)

        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: blobPath))
            let rc: Int32 = data.withUnsafeBytes { buf in
                var profile = SandboxProfile(builtin: nil, data: buf.bindMemory(to: UInt8.self).baseAddress, size: data.count)
                return withUnsafeMutablePointer(to: &profile) { ptr in
                    errno = 0
                    return apply(UnsafeMutableRawPointer(ptr))
                }
            }
            let savedErrno = errno
            return sandboxApplyWithMarkers(applyRc: rc, applyErrno: savedErrno, profilePath: blobPath)
        } catch {
            return sandboxApplyWithMarkers(applyRc: -2, applyErrno: errno, profilePath: blobPath)
        }
    }

    /// If env vars request it, issue a seatbelt callout and emit a marker.
    static func maybeSeatbeltCalloutFromEnv(stage: String) {
        let env = ProcessInfo.processInfo.environment
        // The callout is opt-in so most tools can avoid extra runtime work.
        guard env["SANDBOX_LORE_SEATBELT_CALLOUT"] == "1" else { return }
        guard let op = env["SANDBOX_LORE_SEATBELT_OP"],
              let filterS = env["SANDBOX_LORE_SEATBELT_FILTER_TYPE"],
              let arg = env["SANDBOX_LORE_SEATBELT_ARG"],
              let filter = Int(filterS) else { return }
        var outErrno: Int32 = 0
        var typeUsed: Int32 = Int32(filter)
        var noReportUsed: Int32 = 0
        var noReportReasonCode: Int32 = 0
        var tokenMachKr: Int32 = 0
        let rc = op.withCString { opC in
            arg.withCString { argC in
                sbl_seatbelt_callout_self(
                    opC,
                    Int32(filter),
                    argC,
                    nil,
                    &outErrno,
                    &typeUsed,
                    &noReportUsed,
                    &noReportReasonCode,
                    &tokenMachKr
                )
            }
        }

        let tokenStatus = (tokenMachKr == 0) ? "ok" : "task_info_failed"
        // Determine whether the callout executed versus failed to invoke.
        let executed = (rc == 0 || rc == 1 || (rc == -1 && outErrno != 0))

        var noReport = false
        var noReportReason: String? = nil
        if executed {
            noReport = (noReportUsed == 1)
            if !noReport {
                noReportReason = noReportReasonString(noReportReasonCode)
            }
        } else {
            noReport = false
            if tokenMachKr != 0 {
                noReportReason = "token_unavailable"
            } else if rc == -2, outErrno == ENOTSUP {
                noReportReason = "unsupported_filter_type"
            } else if rc == -2, outErrno == EINVAL {
                noReportReason = "invalid_argument"
            } else if rc == -2, outErrno == ENOSYS {
                noReportReason = "symbol_missing"
            } else {
                noReportReason = "function_missing"
            }
        }

        let error: String?
        if executed {
            error = nil
        } else if tokenMachKr != 0 {
            error = "TASK_AUDIT_TOKEN unavailable"
        } else if rc == -2, outErrno == ENOTSUP {
            error = "unsupported filter type (string-arg only)"
        } else if rc == -2, outErrno == EINVAL {
            error = "invalid argument"
        } else {
            error = "sandbox_check_by_audit_token missing"
        }

        emitSeatbeltCallout(
            stage: stage,
            operation: op,
            filterType: filter,
            argument: arg,
            rc: rc,
            err: outErrno,
            error: error,
            noReport: noReport,
            noReportReason: noReportReason,
            tokenStatus: tokenStatus,
            tokenMachKr: tokenMachKr,
            checkType: typeUsed,
            varargsCount: 1
        )
    }

    private static func filterTypeName(_ filterType: Int) -> String {
        switch filterType {
        case 0:
            return "path"
        case 5:
            return "global-name"
        case 6:
            return "local-name"
        case 26:
            return "right-name"
        case 27:
            return "preference-domain"
        default:
            return "unknown"
        }
    }

    private static func noReportReasonString(_ code: Int32) -> String {
        switch code {
        case 1:
            return "symbol_missing"
        case 2:
            return "flag_zero"
        default:
            return "unknown"
        }
    }

    private static func classifyApplyError(api: String, rc: Int32, err: Int32, errbuf: String?) -> (String, String) {
        if rc == 0 {
            return ("ok", "none")
        }

        if api == "sandbox_init", let errbuf {
            let lower = errbuf.lowercased()
            if lower.contains("already"), lower.contains("sandbox") {
                return ("already_sandboxed", "errbuf_regex")
            }
        }

        if err == EPERM {
            return ("errno_eperm", "errno_only")
        }
        if err == EACCES {
            return ("errno_eacces", "errno_only")
        }
        if err != 0 {
            return ("errno_other", "errno_only")
        }
        if let errbuf, !errbuf.isEmpty {
            return ("unknown", "errbuf_present")
        }
        return ("unknown", "none")
    }

    private static func calloutDecisionFromRc(_ rc: Int32) -> String {
        if rc == 0 { return "allow" }
        if rc == 1 { return "deny" }
        return "error"
    }

    private static func emitJsonl(_ payload: [String: Any]) {
        guard JSONSerialization.isValidJSONObject(payload) else {
            return
        }
        // Best-effort emission: drop markers rather than throwing.
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: []) else {
            return
        }
        FileHandle.standardError.write(data)
        FileHandle.standardError.write("\n".data(using: .utf8)!)
    }
}
