import Foundation
import Darwin

// Containers reshape where app data lives. Seatbelt’s path-based filters
// (`subpath`, `literal`, `regex` in book/substrate/Appendix.md) see the resolved
// filesystem path, not the human-facing alias, so understanding redirects and
// symlinks is key when reasoning about sandboxed file I/O.

let args = Array(CommandLine.arguments.dropFirst())
var jsonMode = false
var limit = 5
var i = 0
while i < args.count {
    let arg = args[i]
    if arg == "--json" {
        jsonMode = true
    } else if arg == "--limit", i + 1 < args.count, let n = Int(args[i + 1]) {
        limit = n
        i += 1
    } else if arg == "--help" {
        fputs("usage: containers_demo [--json] [--limit N]\\n", stderr)
        exit(64)
    } else {
        fputs("unknown arg: \(arg)\\n", stderr)
        exit(64)
    }
    i += 1
}

let fm = FileManager.default
let home = fm.homeDirectoryForCurrentUser
let containerRoot = home.appendingPathComponent("Library/Containers")
let groupRoot = home.appendingPathComponent("Library/Group Containers")

func homeRelativize(_ path: String) -> String {
    let homePath = home.path
    if path.hasPrefix(homePath) {
        let rest = path.dropFirst(homePath.count)
        return "~" + rest
    }
    return path
}

func listTopEntries(_ url: URL, limit: Int) {
    print("\nListing up to \(limit) entries under \(url.path):")
    guard let entries = try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isSymbolicLinkKey], options: [.skipsHiddenFiles]) else {
        print("  (unreadable or missing)")
        return
    }
    for entry in entries.prefix(limit) {
        let isSymlink = (try? entry.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) ?? false
        print("  \(entry.lastPathComponent)\(isSymlink ? " (symlink)" : "")")
    }
    if entries.count > limit {
        print("  ... \(entries.count - limit) more")
    }
}

func describePath(_ path: String) {
    // Expand ~ and resolve symlinks to show what Seatbelt will actually check.
    let expanded = NSString(string: path).expandingTildeInPath
    let url = URL(fileURLWithPath: expanded)
    let resolved = url.resolvingSymlinksInPath()
    print("\nLogical path: \(path)")
    print("Expanded path: \(expanded)")
    print("Resolved path: \(resolved.path)")
}

func jsonListTopEntries(_ url: URL, limit: Int) -> [String: Any] {
    let listingPath = homeRelativize(url.path)
    guard let entries = try? fm.contentsOfDirectory(at: url, includingPropertiesForKeys: [.isSymbolicLinkKey], options: [.skipsHiddenFiles]) else {
        return ["path": listingPath, "status": "unreadable_or_missing", "entries": []]
    }
    var out: [[String: Any]] = []
    for entry in entries.prefix(limit) {
        let isSymlink = (try? entry.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) ?? false
        out.append(["name": entry.lastPathComponent, "is_symlink": isSymlink])
    }
    return ["path": listingPath, "status": "ok", "entry_count": entries.count, "entries": out]
}

func jsonDescribePath(_ path: String) -> [String: Any] {
    let expandedAbs = NSString(string: path).expandingTildeInPath
    let url = URL(fileURLWithPath: expandedAbs)
    let resolvedAbs = url.resolvingSymlinksInPath().path
    return [
        "logical": path,
        "expanded": homeRelativize(expandedAbs),
        "resolved": homeRelativize(resolvedAbs),
    ]
}

if jsonMode {
    let samplePaths = [
        "~/Documents",
        "~/Library/Containers",
        "~/Library/Group Containers",
        "~/Library/Containers/com.apple.finder/Data",
    ]
    let payload: [String: Any] = [
        "pid": getpid(),
        "container_root": homeRelativize(containerRoot.path),
        "group_root": homeRelativize(groupRoot.path),
        "listings": [
            "containers": jsonListTopEntries(containerRoot, limit: limit),
            "group_containers": jsonListTopEntries(groupRoot, limit: limit),
        ],
        "paths": samplePaths.map(jsonDescribePath),
    ]
    let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    if let s = String(data: data, encoding: .utf8) {
        print(s)
    }
    exit(0)
}

print("Container + redirect inspection (PID \(getpid()))")

listTopEntries(containerRoot, limit: limit)
listTopEntries(groupRoot, limit: limit)

// Common user-facing locations that are often redirected into containers.
let samplePaths = [
    "~/Documents",
    "~/Library/Containers",
    "~/Library/Group Containers",
    "~/Library/Containers/com.apple.finder/Data"
]
samplePaths.forEach(describePath)

print("""

Notes:
- Sandboxed processes typically see their data in containerized locations under ~/Library/Containers.
- Symlinks (e.g., redirects from user-visible paths into containers) do not bypass sandbox checks; filters run on the resolved path.
- When reading decoded SBPL that uses (subpath "/Users/.../Containers/..."), remember that the resolved path, not the shortcut you navigated in Finder, drives the decision.
""")
