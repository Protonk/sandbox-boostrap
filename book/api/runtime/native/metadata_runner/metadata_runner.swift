/*
 * Metadata runner: apply SBPL (text or blob) and exercise metadata syscalls,
 * emitting JSON per operation. Used to probe alias vs canonical path handling
 * for file-read-metadata and metadata write proxies on the host baseline.
 */

import Foundation
import Darwin

// Swift does not surface lutimes directly; link to the libc symbol instead.
@_silgen_name("lutimes")
func lutimes(_ file: UnsafePointer<CChar>!, _ times: UnsafePointer<timeval>!) -> Int32

/// Shape of a single metadata probe result emitted as JSON.
struct RunResult: Codable {
    let op: String
    let path: String
    let syscall: String
    let attr_payload: String?
    let status: String
    let errno: Int32?
    let errno_name: String?
    let message: String?
    let apply_rc: Int32
    let apply_errno: Int32?
    let apply_errno_name: String?
    let apply_mode: String
    let apply_message: String?
}

/// Map common errno values to stable names for JSON output.
func errnoName(_ code: Int32) -> String {
    switch code {
    case 0: return "OK"
    case EPERM: return "EPERM"
    case EACCES: return "EACCES"
    case ENOENT: return "ENOENT"
    case ENOTDIR: return "ENOTDIR"
    case ENOSPC: return "ENOSPC"
    case EROFS: return "EROFS"
    case EINVAL: return "EINVAL"
    case ENOTSUP: return "ENOTSUP"
    case EIO: return "EIO"
    default: return "errno_\(code)"
    }
}

/// Print usage guidance and exit with EX_USAGE.
func usage() -> Never {
    fputs("Usage: metadata_runner (--sbpl <profile.sb> | --blob <profile.sb.bin>) --op <file-read-metadata|file-write*> --path <target> [--syscall <lstat|getattrlist|setattrlist|chmod|utimes>] [--attr-payload <cmn|cmn-name|cmn-times|file-size>] [--chmod-mode <octal>]\n", stderr)
    exit(64) // EX_USAGE
}

/// Apply an SBPL profile (text or blob) and emit tool markers for the stage.
func applySandbox(blobPath: String?, sbplPath: String?) -> ToolMarkers.ApplyReport {
    if let sbplPath {
        guard let sbpl = try? String(contentsOfFile: sbplPath, encoding: .utf8) else {
            let err = errno
            return ToolMarkers.sandboxInitFailureWithMarkers(rc: -2, err: err, errbuf: "failed to read sbpl", profilePath: sbplPath)
        }
        return ToolMarkers.sandboxInitWithMarkers(profileText: sbpl, flags: 0, profilePath: sbplPath)
    }

    guard let blobPath else {
        return ToolMarkers.sandboxApplyWithMarkers(applyRc: -3, applyErrno: EINVAL, profilePath: "none")
    }
    return ToolMarkers.sandboxApplyBlobFileWithMarkers(blobPath: blobPath)
}

struct AttrPayload {
    let attrlist: attrlist
    let buffer: [UInt8]
}

/// Build the attrlist and payload buffer for getattrlist/setattrlist probes.
func makeAttrPayload(kind: String) -> AttrPayload {
    var attr = attrlist()
    attr.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
    var buf = [UInt8]()
    switch kind {
    case "cmn-name":
        attr.commonattr = UInt32(ATTR_CMN_NAME)
        buf = Array(repeating: 0, count: 256)
    case "cmn-times":
        attr.commonattr = UInt32(ATTR_CMN_MODTIME | ATTR_CMN_CHGTIME)
        var timespecs = [
            timespec(tv_sec: time_t(time(nil)), tv_nsec: 0),
            timespec(tv_sec: time_t(time(nil)), tv_nsec: 0),
        ]
        buf = withUnsafeBytes(of: &timespecs) { Array($0) }
    case "file-size":
        attr.fileattr = UInt32(ATTR_FILE_TOTALSIZE)
        var size: UInt64 = 0
        buf = withUnsafeBytes(of: &size) { Array($0) }
    case "cmn":
        fallthrough
    default:
        attr.commonattr = UInt32(ATTR_CMN_NAME)
        buf = Array(repeating: 0, count: 256)
    }
    return AttrPayload(attrlist: attr, buffer: buf)
}

/// Run a single metadata syscall and return a status/errno tuple.
func performOperation(op: String, syscall: String, path: String, chmodMode: mode_t, attrPayload: AttrPayload?) -> (status: String, err: Int32?, message: String?) {
    var opErrno: Int32 = 0
    let cPath = path.cString(using: .utf8)!

    // Optional oracle lane: emit a sandbox_check callout before the syscall.
    ToolMarkers.maybeSeatbeltCalloutFromEnv(stage: "pre_syscall")

    func openFd(_ flags: Int32 = O_RDONLY) -> Int32 {
        errno = 0
        let fd = open(cPath, flags)
        if fd == -1 {
            opErrno = errno
        }
        return fd
    }

    switch (op, syscall) {
    case ("file-read-metadata", "lstat"):
        var st = stat()
        errno = 0
        let rv = lstat(cPath, &st)
        if rv == 0 {
            return ("ok", 0, "stat-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-read-metadata", "getattrlist"):
        // getattrlist is our highest-signal metadata probe and needs a payload buffer.
        let payload = attrPayload ?? makeAttrPayload(kind: "cmn")
        var attr = payload.attrlist
        var buf = payload.buffer
        errno = 0
        let rv = buf.withUnsafeMutableBytes { bytes -> Int32 in
            return getattrlist(cPath, &attr, bytes.baseAddress, bytes.count, 0)
        }
        if rv == 0 {
            return ("ok", 0, "getattrlist-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-read-metadata", "setattrlist"):
        let payload = attrPayload ?? makeAttrPayload(kind: "cmn")
        var attr = payload.attrlist
        var buf = payload.buffer
        errno = 0
        let rv = buf.withUnsafeMutableBytes { bytes -> Int32 in
            return setattrlist(cPath, &attr, bytes.baseAddress, bytes.count, 0)
        }
        if rv == 0 {
            return ("ok", 0, "setattrlist-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-read-metadata", "fstat"):
        let fd = openFd()
        if fd == -1 {
            return ("op_failed", opErrno, "open failed")
        }
        var st = stat()
        errno = 0
        let rv = fstat(fd, &st)
        let savedErr = errno
        close(fd)
        if rv == 0 {
            return ("ok", 0, "fstat-ok")
        } else {
            opErrno = savedErr
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "chmod"):
        // chmod is the simplest metadata write proxy for file-write*.
        errno = 0
        let rv = chmod(cPath, chmodMode)
        if rv == 0 {
            return ("ok", 0, "chmod-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "utimes"):
        let now = time_t(time(nil))
        let times = [
            timeval(tv_sec: now, tv_usec: 0),
            timeval(tv_sec: now, tv_usec: 0),
        ]
        errno = 0
        let rv = times.withUnsafeBufferPointer { ptr -> Int32 in
            return utimes(cPath, ptr.baseAddress)
        }
        if rv == 0 {
            return ("ok", 0, "utimes-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "fchmod"):
        let fd = openFd(O_WRONLY)
        if fd == -1 {
            return ("op_failed", opErrno, "open failed")
        }
        errno = 0
        let rv = fchmod(fd, chmodMode)
        let savedErr = errno
        close(fd)
        if rv == 0 {
            return ("ok", 0, "fchmod-ok")
        } else {
            opErrno = savedErr
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "futimes"):
        let fd = openFd(O_WRONLY)
        if fd == -1 {
            return ("op_failed", opErrno, "open failed")
        }
        let now = time_t(time(nil))
        let times = [
            timeval(tv_sec: now, tv_usec: 0),
            timeval(tv_sec: now, tv_usec: 0),
        ]
        errno = 0
        let rv = times.withUnsafeBufferPointer { ptr -> Int32 in
            return futimes(fd, ptr.baseAddress)
        }
        let savedErr = errno
        close(fd)
        if rv == 0 {
            return ("ok", 0, "futimes-ok")
        } else {
            opErrno = savedErr
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "lchown"):
        let uid = getuid()
        let gid = getgid()
        errno = 0
        let rv = lchown(cPath, uid, gid)
        if rv == 0 {
            return ("ok", 0, "lchown-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "fchown"):
        let fd = openFd(O_WRONLY)
        if fd == -1 {
            return ("op_failed", opErrno, "open failed")
        }
        let uid = getuid()
        let gid = getgid()
        errno = 0
        let rv = fchown(fd, uid, gid)
        let savedErr = errno
        close(fd)
        if rv == 0 {
            return ("ok", 0, "fchown-ok")
        } else {
            opErrno = savedErr
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "fchownat"):
        let uid = getuid()
        let gid = getgid()
        errno = 0
        let rv = fchownat(AT_FDCWD, cPath, uid, gid, 0)
        if rv == 0 {
            return ("ok", 0, "fchownat-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case ("file-write*", "lutimes"):
        let now = time_t(time(nil))
        let times = [
            timeval(tv_sec: now, tv_usec: 0),
            timeval(tv_sec: now, tv_usec: 0),
        ]
        errno = 0
        let rv = times.withUnsafeBufferPointer { ptr -> Int32 in
            return lutimes(cPath, ptr.baseAddress)
        }
        if rv == 0 {
            return ("ok", 0, "lutimes-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    default:
        return ("invalid_op", nil, "unsupported \(op) syscall \(syscall)")
    }
}

/// Parse CLI args, apply the sandbox, perform the syscall, and print JSON.
func run() {
    let args = CommandLine.arguments
    var blobPath: String?
    var sbplPath: String?
    var op: String?
    var targetPath: String?
    var chmodMode: mode_t = 0o640
    var syscallName: String?
    var attrPayloadKind: String?

    var idx = 1
    while idx < args.count {
        let arg = args[idx]
        switch arg {
        case "--blob":
            guard idx + 1 < args.count else { usage() }
            blobPath = args[idx + 1]
            idx += 2
        case "--op":
            guard idx + 1 < args.count else { usage() }
            op = args[idx + 1]
            idx += 2
        case "--sbpl":
            guard idx + 1 < args.count else { usage() }
            sbplPath = args[idx + 1]
            idx += 2
        case "--path":
            guard idx + 1 < args.count else { usage() }
            targetPath = args[idx + 1]
            idx += 2
        case "--chmod-mode":
            guard idx + 1 < args.count else { usage() }
            let value = args[idx + 1]
            if let parsed = Int(value, radix: 8) {
                chmodMode = mode_t(parsed)
            }
            idx += 2
        case "--syscall":
            guard idx + 1 < args.count else { usage() }
            syscallName = args[idx + 1]
            idx += 2
        case "--attr-payload":
            guard idx + 1 < args.count else { usage() }
            attrPayloadKind = args[idx + 1]
            idx += 2
        default:
            usage()
        }
    }

    guard (blobPath != nil || sbplPath != nil), let op, let targetPath else {
        usage()
    }
    if op != "file-read-metadata" && op != "file-write*" {
        usage()
    }
    if syscallName == nil {
        syscallName = (op == "file-read-metadata") ? "lstat" : "chmod"
    }
    // Attr payloads only matter for getattrlist/setattrlist; other syscalls ignore them.
    let attrPayload = makeAttrPayload(kind: attrPayloadKind ?? "cmn")

    let applyResult = applySandbox(blobPath: blobPath, sbplPath: sbplPath)
    if applyResult.rc != 0 {
        let applyErrno: Int32? = (applyResult.err == 0) ? nil : applyResult.err
        let result = RunResult(
            op: op,
            path: targetPath,
            syscall: syscallName ?? "unknown",
            attr_payload: attrPayloadKind,
            status: "apply_failed",
            errno: nil,
            errno_name: nil,
            message: "sandbox apply rc \(applyResult.rc)",
            apply_rc: applyResult.rc,
            apply_errno: applyErrno,
            apply_errno_name: applyErrno.map { errnoName($0) },
            apply_mode: applyResult.mode,
            apply_message: applyResult.errbuf
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(result) {
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write("\n".data(using: .utf8)!)
        }
        exit(0)
    }

    let opResult = performOperation(op: op, syscall: syscallName ?? "unknown", path: targetPath, chmodMode: chmodMode, attrPayload: attrPayload)
    let applyErrno: Int32? = (applyResult.err == 0) ? nil : applyResult.err
    let final = RunResult(
        op: op,
        path: targetPath,
        syscall: syscallName ?? "unknown",
        attr_payload: attrPayloadKind,
        status: opResult.status,
        errno: opResult.err,
        errno_name: opResult.err.map { errnoName($0) },
        message: opResult.message,
        apply_rc: applyResult.rc,
        apply_errno: applyErrno,
        apply_errno_name: applyErrno.map { errnoName($0) },
        apply_mode: applyResult.mode,
        apply_message: applyResult.errbuf
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(final) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    }
}

@main
struct MetadataRunnerMain {
    static func main() {
        run()
    }
}
