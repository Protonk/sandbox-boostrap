import Foundation
import Darwin

// Containers reshape where app data lives. Seatbelt’s path-based filters
// (`subpath`, `literal`, `regex` in substrate/Appendix.md) see the resolved
// filesystem path, not the human-facing alias, so understanding redirects and
// symlinks is key when reasoning about sandboxed file I/O.

let fm = FileManager.default
let home = fm.homeDirectoryForCurrentUser
let containerRoot = home.appendingPathComponent("Library/Containers")
let groupRoot = home.appendingPathComponent("Library/Group Containers")

func listTopEntries(_ url: URL, limit: Int = 5) {
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

print("Container + redirect inspection (PID \(getpid()))")

listTopEntries(containerRoot)
listTopEntries(groupRoot)

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
