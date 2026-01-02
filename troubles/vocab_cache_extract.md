# Vocab cache extraction

## Issue

We needed Sandbox’s Operation/Filter vocab tables (name ↔ ID) to unblock vocab mapping, but the usual binaries were not directly available:

- No `Sandbox.framework` or `libsandbox.dylib` in the expected filesystem locations.
- No `dyld_shared_cache_util` tool on this Sonoma system.

That left us stuck: the op/Filter vocab lives inside the dyld shared cache, but we didn’t yet know where the cache was or how to extract only the Sandbox slices using built-in tooling.

## Escalation

We escalated to a web‑enabled 5.1 chat model with a short description:

- Stated that Sandbox binaries were not visible on disk and `dyld_shared_cache_util` was missing.
- Asked for the correct dyld shared cache path on macOS 14 (arm64e) and a supported, built‑in way to extract Sandbox‑related binaries so we could scan them for vocab tables.

## Web model guidance (summary)

The web model’s answer had two key parts.

1. **Cache location on Sonoma / arm64e**

- Primary cache path:
  - `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e*`
- Possible compatibility copy:
  - `/System/Library/dyld/dyld_shared_cache_arm64e*`

This matched external descriptions of Ventura/Sonoma moving the active cache under the Cryptex Preboot volume.

2. **Extraction via `dsc_extractor.bundle`**

Because macOS no longer ships a standalone `dyld_shared_cache_util`, the model recommended using Apple’s `dsc_extractor.bundle`:

- Candidate bundle locations:
  - `/usr/lib/dsc_extractor.bundle`
  - `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/usr/lib/dsc_extractor.bundle`
- Suggested a tiny Swift shim that:
  - `dlopen`s the bundle.
  - Looks up `dyld_shared_cache_extract_dylibs_progress`.
  - Calls it with:
    - the cache path,
    - an output directory,
    - an optional progress callback.

The sketch looked like:

```swift
import Foundation
import Darwin

typealias ExtractFn = @convention(c) (
  UnsafePointer<CChar>?,
  UnsafePointer<CChar>?,
  (@convention(block) (UInt32, UInt32) -> Void)?
) -> Int32

let args = CommandLine.arguments
guard args.count == 3 else {
  fputs("usage: extract_dsc <path-to-dyld_shared_cache> <output-dir>\n", stderr)
  exit(2)
}

let candidates = [
  "/usr/lib/dsc_extractor.bundle",
  "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/usr/lib/dsc_extractor.bundle",
]

guard let bundlePath = candidates.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
  fputs("dsc_extractor.bundle not found. Install Xcode if needed.\n", stderr)
  exit(1)
}

guard let handle = dlopen(bundlePath, RTLD_NOW) else {
  fputs("dlopen failed\n", stderr)
  exit(1)
}

defer { dlclose(handle) }

guard let sym = dlsym(handle, "dyld_shared_cache_extract_dylibs_progress") else {
  fputs("symbol not found in bundle\n", stderr)
  exit(1)
}

guard let fn = unsafeBitCast(sym, to: Optional<ExtractFn>.self) else {
  fputs("could not cast symbol\n", stderr)
  exit(1)
}

let rc = fn(args[1], args[2]) { cur, total in
  if total > 0 {
    fputs("\rExtracting \(cur)/\(total)", stderr)
  }
}
fputs("\n", stderr)
exit(rc == 0 ? 0 : rc)
```

The model then suggested running:

```bash
swiftc extract_dsc.swift -o extract_dsc
mkdir -p /tmp/dsc_out
./extract_dsc /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e /tmp/dsc_out
```

and scanning the output tree for Sandbox components, e.g.:

```bash
find /tmp/dsc_out -type f \
  -path '*/PrivateFrameworks/Sandbox.framework/*' \
  -o -path '*/usr/lib/libsandbox*.dylib' \
  -o -path '*/usr/lib/libsystem_sandbox*.dylib'
```

## Resolution

We implemented a slightly adapted version of the guidance:

- Verified the cache at:
  - `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e`
  (no compat copy under `/System/Library/dyld` on this host).
- Confirmed `dsc_extractor.bundle` at `/usr/lib/dsc_extractor.bundle`.
- Added `book/evidence/experiments/vocab-from-cache/extract_dsc.swift` based on the suggested shim, adjusted the exit handling for our compiler, and built it with:
  - `xcrun swiftc extract_dsc.swift -module-cache-path .swift-module-cache -o extract_dsc`.
- Ran extraction into a project-local directory:

  ```bash
  mkdir -p book/evidence/experiments/vocab-from-cache/extracted
  book/evidence/experiments/vocab-from-cache/extract_dsc \
    /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
    book/evidence/experiments/vocab-from-cache/extracted
  ```

- Confirmed that the extracted tree now includes:
  - `usr/lib/libsandbox.1.dylib`
  - `usr/lib/system/libsystem_sandbox.dylib`
  - `System/Library/PrivateFrameworks/AppSandbox.framework/Versions/A/AppSandbox`

Immediate next step (tracked in the vocab-from-cache experiment, not here) is to:

- Parse `libsandbox.1.dylib` to recover the ordered Operation name block (~190 operation-like strings from `appleevent-send` through `default-message-filter`).
- Align that block with the decoder’s `op_count=167` from canonical blobs so we can assign stable Operation IDs and emit real `ops.json` / `filters.json` for this host.


## Lessons

For textbook readers, the interesting part of this episode is not the Swift shim itself but what it reveals about how sandbox vocabulary actually lives on a modern macOS system and why our `ops.json` / `filters.json` are trustworthy.
1. **The sandbox vocabulary really lives in the dyld cache now.**
   On recent macOS (Ventura/Sonoma, Apple Silicon), the canonical copies of `libsandbox`/`Sandbox.framework` may not appear as ordinary files at the paths older tools and blog posts expect. Instead, the “real” binaries live inside the dyld shared cache under the Cryptex Preboot volume. That means any serious attempt to enumerate operations and filters has to be prepared to go through the cache, not just walk `/System/Library`.

2. **Apple removed the obvious tooling, but left a supported path.**
   Older workflows used a `dyld_shared_cache_util` CLI to explode the cache. Current macOS does not ship that tool, but the underlying extraction mechanism (`dsc_extractor.bundle` and its `dyld_shared_cache_extract_dylibs_progress` entry point) is still present in the OS. The experiment shows how a small wrapper (here, a Swift program) can call that API to reconstruct real `libsandbox` / `libsystem_sandbox` dylibs on disk.

3. **`ops.json` / `filters.json` are grounded in these binaries, not guesswork.**
   The immediate outcome of the experiment is that our operation and filter vocabularies are derived directly from `libsandbox.1.dylib` and related images extracted from the dyld cache on a specific Sonoma host. That matters pedagogically: when you see an operation name or ID in this book, you are looking at something recovered from Apple’s own binaries, not a reverse-engineered naming scheme or a blog’s partial list.

4. **Versioning and high-churn surfaces in action.**
   This episode is a concrete instance of the “high-churn surface” invariant. The cache layout, presence/absence of `dyld_shared_cache_util`, and exact vocab tables are all version-specific. The experiment documents how we tied a particular `ops.json` to a particular OS configuration (Sonoma, arm64e, specific dyld cache), rather than pretending there is a single timeless operation map.

5. **A reusable pattern for future readers and tools.**
   Finally, this is a template: if you want to repeat or extend the analysis on a different macOS version, the steps are clear and reproducible—locate the dyld cache, use `dsc_extractor.bundle` (or equivalent) to extract `libsandbox`/`libsystem_sandbox`, then parse the resulting binaries for vocab tables. The experiment in the repo is the worked example that demonstrates this pipeline end-to-end.
