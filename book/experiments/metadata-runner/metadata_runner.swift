import Foundation
import Darwin

@_silgen_name("sandbox_init")
func sandbox_init(_ profile: UnsafePointer<CChar>, _ flags: UInt64, _ errorbuf: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>!) -> Int32

@_silgen_name("sandbox_free_error")
func sandbox_free_error(_ errorbuf: UnsafeMutablePointer<CChar>!)

// Minimal struct matching libsandbox sandbox_profile_t
struct SandboxProfile {
    var builtin: UnsafeMutablePointer<CChar>?
    var data: UnsafePointer<UInt8>?
    var size: Int
}

typealias SandboxApplyFn = @convention(c) (UnsafeMutableRawPointer?) -> Int32

struct RunResult: Codable {
    let op: String
    let path: String
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

func usage() -> Never {
    fputs("Usage: metadata_runner (--sbpl <profile.sb> | --blob <profile.sb.bin>) --op <file-read-metadata|file-write*> --path <target> [--chmod-mode <octal>]\n", stderr)
    exit(64) // EX_USAGE
}

func applySandbox(blobPath: String?, sbplPath: String?) -> (rc: Int32, err: Int32?, message: String?, mode: String) {
    if let sbplPath {
        errno = 0
        guard let sbpl = try? String(contentsOfFile: sbplPath, encoding: .utf8) else {
            return (rc: -2, err: errno, message: "failed to read sbpl", mode: "sbpl")
        }
        var errBuf: UnsafeMutablePointer<CChar>? = nil
        let rc = sbpl.withCString { cstr in
            sandbox_init(cstr, 0, &errBuf)
        }
        let message = errBuf.map { String(cString: $0) }
        if let errBuf {
            sandbox_free_error(errBuf)
        }
        let applyErr = errno == 0 ? nil : errno
        return (rc: rc, err: applyErr, message: message, mode: "sbpl")
    }

    guard let blobPath else {
        return (rc: -3, err: nil, message: "no profile path provided", mode: "none")
    }

    guard let handle = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW | RTLD_LOCAL) else {
        return (rc: -1, err: errno, message: "dlopen libsandbox failed", mode: "blob")
    }
    defer { dlclose(handle) }

    guard let symbol = dlsym(handle, "sandbox_apply") else {
        return (rc: -1, err: errno, message: "dlsym sandbox_apply failed", mode: "blob")
    }
    let apply = unsafeBitCast(symbol, to: SandboxApplyFn.self)

    do {
        let data = try Data(contentsOf: URL(fileURLWithPath: blobPath))
        let rc: Int32 = data.withUnsafeBytes { buf -> Int32 in
            var profile = SandboxProfile(builtin: nil, data: buf.bindMemory(to: UInt8.self).baseAddress, size: data.count)
            return withUnsafeMutablePointer(to: &profile) { ptr -> Int32 in
                errno = 0
                return apply(UnsafeMutableRawPointer(ptr))
            }
        }
        let applyErrno = rc == 0 ? nil : errno
        return (rc: rc, err: applyErrno, message: nil, mode: "blob")
    } catch {
        return (rc: -2, err: errno, message: "failed to load blob", mode: "blob")
    }
}

func performOperation(op: String, path: String, chmodMode: mode_t) -> (status: String, err: Int32?, message: String?) {
    var opErrno: Int32 = 0
    let cPath = path.cString(using: .utf8)!

    switch op {
    case "file-read-metadata":
        var st = stat()
        errno = 0
        let rv = lstat(cPath, &st)
        if rv == 0 {
            return ("ok", 0, "stat-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    case "file-write*":
        errno = 0
        let rv = chmod(cPath, chmodMode)
        if rv == 0 {
            return ("ok", 0, "chmod-ok")
        } else {
            opErrno = errno
            return ("op_failed", opErrno, String(cString: strerror(opErrno)))
        }
    default:
        return ("invalid_op", nil, "unsupported op \(op)")
    }
}

func main() {
    let args = CommandLine.arguments
    var blobPath: String?
    var sbplPath: String?
    var op: String?
    var targetPath: String?
    var chmodMode: mode_t = 0o640

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

    let applyResult = applySandbox(blobPath: blobPath, sbplPath: sbplPath)
    if applyResult.rc != 0 {
        let result = RunResult(
            op: op,
            path: targetPath,
            status: "apply_failed",
            errno: nil,
            errno_name: nil,
            message: "sandbox apply rc \(applyResult.rc)",
            apply_rc: applyResult.rc,
            apply_errno: applyResult.err,
            apply_errno_name: applyResult.err.map { errnoName($0) },
            apply_mode: applyResult.mode,
            apply_message: applyResult.message
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(result) {
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write("\n".data(using: .utf8)!)
        }
        exit(0)
    }

    let opResult = performOperation(op: op, path: targetPath, chmodMode: chmodMode)
    let final = RunResult(
        op: op,
        path: targetPath,
        status: opResult.status,
        errno: opResult.err,
        errno_name: opResult.err.map { errnoName($0) },
        message: opResult.message,
        apply_rc: applyResult.rc,
        apply_errno: applyResult.err,
        apply_errno_name: applyResult.err.map { errnoName($0) },
        apply_mode: applyResult.mode,
        apply_message: applyResult.message
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if let data = try? encoder.encode(final) {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    }
}

main()
