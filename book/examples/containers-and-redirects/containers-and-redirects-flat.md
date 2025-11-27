## 1. What this example is about

This example is a small, read-only probe for how app containers and redirects show up on disk from a process’s point of view:

* It inspects `~/Library/Containers` and `~/Library/Group Containers`.
* It prints a short listing of what’s in those directories.
* It then takes a few user-facing paths (like `~/Documents`) and:

  * expands `~` to your full home directory, and
  * resolves any symlinks in the path.

The key lesson: **Seatbelt’s path-based filters (like `subpath` and `regex` in profiles) see the resolved, real filesystem path, not whatever shortcut you clicked in Finder.**

Running this alongside decoded profiles helps you understand why certain reads/writes are allowed or denied.

---

## 2. How to run and what to expect

There is a single Swift file:

* `containers_demo.swift`

You can run it in a few ways, for example:

* Directly with the Swift interpreter:

  * `swift containers_demo.swift`

* Or compile, then run:

  * `swiftc containers_demo.swift -o containers_demo`
  * `./containers_demo`

When you run it, you will see output like:

* A header line with the process ID.
* A short listing of entries under:

  * `~/Library/Containers`
  * `~/Library/Group Containers`
* For each sample path:

  * the “logical” path (what you typed),
  * the expanded path (with `~` resolved),
  * the fully resolved path after following symlinks.

This is safe to run in your normal user environment. It only reads directories and prints information; it does not modify anything.

---

## 3. Lessons

1. **Containers relocate data into `~/Library/Containers/...` and group containers.**
   User-facing paths (what you click or type) might be symlinks or redirects, but the sandbox engine evaluates file rules based on where those paths lead.

2. **Symlinks do not bypass sandbox checks.**
   The effective policy applies to the final, resolved path, which is what the SBPL path filters see.

3. **Knowing container layout is necessary to read profiles correctly.**
   When you see a rule like `(allow file-read* (subpath "/Users/you/Library/Containers/..."))` in decoded SBPL, you can now map that back to the “same-looking” paths you interact with as a user and understand why a sandboxed app behaves differently from an unsandboxed tool.

You can treat `containers_demo.swift` as an executable illustration for these bullets: run it, look at the concrete paths on your machine, and then cross-check them against any decoded profiles or sandbox logs you are studying.

## 4. Walking through the code

### 4.1 Setup and container roots

```swift
let fm = FileManager.default
let home = fm.homeDirectoryForCurrentUser
let containerRoot = home.appendingPathComponent("Library/Containers")
let groupRoot = home.appendingPathComponent("Library/Group Containers")
```

Here the program:

* Uses `FileManager.default` as its main filesystem handle.
* Fetches your home directory in a robust way (`homeDirectoryForCurrentUser`).
* Constructs URLs for:

  * the *per-app* container root (`~/Library/Containers`),
  * the *group* container root (`~/Library/Group Containers`).

These are the primary hubs where sandboxed applications’ data actually lives.

---

### 4.2 Listing container entries

```swift
func listTopEntries(_ url: URL, limit: Int = 5) {
    print("\nListing up to \(limit) entries under \(url.path):")
    guard let entries = try? fm.contentsOfDirectory(
        at: url,
        includingPropertiesForKeys: [.isSymbolicLinkKey],
        options: [.skipsHiddenFiles]
    ) else {
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
```

What this does:

* Tries to read the contents of the directory at `url`.

  * If it can’t (missing directory, no permissions), it prints a friendly message and returns.
* Requests the `.isSymbolicLinkKey` for each entry so it can tell which entries are symlinks.
* Prints up to `limit` entries (default 5), marking symlinks.
* If there are more entries than the limit, it notes how many are omitted.

Why this matters:

* It gives you a quick sense of how populated your container roots are.
* It shows which entries are symlinks, which is important when understanding how user-visible paths might redirect into container directories.

---

### 4.3 Showing logical vs resolved paths

```swift
func describePath(_ path: String) {
    // Expand ~ and resolve symlinks to show what Seatbelt will actually check.
    let expanded = NSString(string: path).expandingTildeInPath
    let url = URL(fileURLWithPath: expanded)
    let resolved = url.resolvingSymlinksInPath()
    print("\nLogical path: \(path)")
    print("Expanded path: \(expanded)")
    print("Resolved path: \(resolved.path)")
}
```

This function is the core of the “redirect” lesson:

* Input:

  * A path string such as `"~/Documents"`.
* Steps:

  1. `expandingTildeInPath` converts `~` into something like `/Users/you`.
  2. `URL(fileURLWithPath:)` makes a file URL from that string.
  3. `resolvingSymlinksInPath()` walks the path and follows any symlinks along the way.
* Output:

  * `Logical path`: what you typed or what Finder might show.
  * `Expanded path`: your full absolute path with home directory filled in.
  * `Resolved path`: the final, real path after following all symlinks.

In sandbox terms, the **resolved** path is the one that matters, because path-based checks operate on this “real” path, not the logical alias.

---

### 4.4 Driving the inspection

The main body of the script:

```swift
print("Container + redirect inspection (PID \(getpid()))")

listTopEntries(containerRoot)
listTopEntries(groupRoot)

let samplePaths = [
    "~/Documents",
    "~/Library/Containers",
    "~/Library/Group Containers",
    "~/Library/Containers/com.apple.finder/Data"
]
samplePaths.forEach(describePath)
```

This:

* Prints a header with the current process ID (useful if you want to correlate with external tools or logs).
* Lists the top entries in:

  * `~/Library/Containers`
  * `~/Library/Group Containers`
* Chooses some representative user-facing paths:

  * `~/Documents` – often subject to special treatment for sandboxed apps.
  * `~/Library/Containers` – the root we just inspected.
  * `~/Library/Group Containers` – the group container root.
  * `~/Library/Containers/com.apple.finder/Data` – a specific container’s data directory.

For each, it calls `describePath` to show you how that string resolves on your system.

The goal is to connect what you think “Documents” is with where those bytes actually live and how they appear to the kernel at enforcement time.

---

### 4.5 Notes block and conceptual recap

At the end, the script prints a multi-line note:

```swift
print("""

Notes:
- Sandboxed processes typically see their data in containerized locations under ~/Library/Containers.
- Symlinks (e.g., redirects from user-visible paths into containers) do not bypass sandbox checks; filters run on the resolved path.
- When reading decoded SBPL that uses (subpath "/Users/.../Containers/..."), remember that the resolved path, not the shortcut you navigated in Finder, drives the decision.
""")
```

These bullet points summarize the intended takeaways:

* Containers are the “real” home for app data.
* Symlinks are just convenience; they do not weaken sandbox enforcement.
* When you see paths in decoded profiles (especially `subpath` rules), you should think in terms of **resolved paths** that look like `~/Library/Containers/...`, not whichever alias you followed in Finder.

---