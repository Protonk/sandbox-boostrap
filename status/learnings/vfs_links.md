# VFS layer

The “VFS layer” is the kernel’s Virtual File System subsystem: the code that takes a pathname string from a syscall (like “open this path”), resolves it through mounts and name lookup, follows things like symlinks (and on macOS, firmlink-style redirections), and hands back a concrete kernel object (a vnode / file descriptor) backed by a specific filesystem (e.g., APFS).

In SANDBOX_LORE, “VFS canonicalization” is attributed to this layer because the project’s evidence comes from kernel-reported FD path spellings (`F_GETPATH` / `F_GETPATH_NOFIRMLINK`), which reflect how VFS resolved the request (e.g., `/tmp/...` resolving to `/private/tmp/...`) rather than what the SBPL text literally contained. If you want the repo’s own framing, see `book/api/runtime/SPEC.md` (path-witness IR) and `book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/Report.md`.

# Why the VFS reports a different path spelling

The VFS isn’t “choosing a different file” than everyone else; it’s the kernel component that *authoritatively* resolves a pathname string into an actual kernel object (a vnode) by doing name lookup (mounts, `.`/`..`, symlinks, and on macOS also firmlink-style redirections). Other “actors” often operate on *strings* (or preserve the spelling you typed) and may never ask the kernel what the resolved object’s “real” path is.

A key split is: **before `open(2)`** you have only a *spelling* (`"/tmp/foo"`), but **after `open(2)`** you have a *handle* (a file descriptor) that points at a vnode. That fd does not inherently “remember” the input spelling; multiple different spellings can resolve to the same vnode (aliases, symlinks, multiple mountpoints, hardlinks).

When this project says it records `F_GETPATH` / `F_GETPATH_NOFIRMLINK`, it’s talking about the kernel taking an fd/vnode and producing a *string representation* of “a path to this object” (a spelling). It’s not a second handle; it’s a reported spelling for the same underlying opened object. See how the project treats this as “FD path witness” IR in `book/api/runtime/SPEC.md:1` and `book/api/runtime/execution/lanes/path_witnesses.py:1`.

So why do you see a difference like `/tmp/foo` vs `/private/tmp/foo`? Because `/tmp` is a classic alias on macOS (commonly a symlink to `/private/tmp`). If you request `/tmp/foo`, the VFS resolves that during lookup and the opened vnode is effectively under `/private/tmp/foo`; when you later ask “what path is this fd?”, the kernel reports the resolved/canonical family.

Firmlinks add another macOS-specific wrinkle: the system presents a unified root while the backing storage is split (System vs Data). For the *same* opened object, there can be two plausible spellings (e.g. a “firmlink-normalized” one vs a “no-firmlink” one), which is why the harness records both `F_GETPATH` and `F_GETPATH_NOFIRMLINK` as separate spellings for the same fd when available (`book/api/runtime/SPEC.md:1`).

The practical reason the repo cares is sandbox matching: the VFS canonicalization suite shows cases where the compiled structure contains distinct literals/anchors for alias vs canonical spellings, but runtime behavior aligns with the canonical spelling being the one that “matters” for `file-read*`/`file-write*` in that suite on this host. The project is careful not to claim “Seatbelt matches exactly on the `F_GETPATH` string”; it only claims “requested vs kernel-reported FD spellings differ, and profiles that only mention the alias can fail while canonical-only succeeds,” bounded to the Sonoma baseline (`book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/Report.md:1`).

# web agent guess

“VFS canonicalization” is not a standard macOS / UNIX term of art. What you’re describing *does* correspond to real, well-defined behavior, but it’s better described as:

* **pathname resolution** (especially **symlink resolution**) during lookup/open, and
* on modern macOS, **APFS volume-group “firmlink/firm-link” translation** affecting which *spelling* of a path is reported or reconstructed.

### Why your /tmp tri-profiles behave the way they do

On macOS, **`/tmp` is a symlink to `/private/tmp`**, and (critically for Seatbelt) **sandbox path filters are applied after symlink resolution**, so rules written against the symlink spelling don’t match the resolved target spelling.

Apple’s sandbox profile guide spells this out explicitly: symlinks are resolved, and a path filter for `"/tmp/testfile"` fails because `"/tmp"` is a symlink to `"/private/tmp"`, so the correct filter is `"/private/tmp/testfile"`. ([Reverse Engineering][1])

That statement alone explains your headline result:

* request `open("/tmp/foo", ...)`
* kernel resolves `/tmp` → `/private/tmp`
* enforcement and/or any reconstructed “fd path” is now in the `/private/tmp/...` family
* a profile with only `/tmp/...` literals looks right statically but loses at runtime

This is not “Seatbelt magically canonicalizes strings at compile time”; it’s simply that **the object being authorized is the resolved vnode**, and the path used for matching is based on that resolved identity.

### Why F_GETPATH vs “no firmlink” gives different spellings

Your witness strategy (recording `F_GETPATH` and an alternate “no firmlink” form) lines up with XNU’s API surface:

* `F_GETPATH` is defined as “return the full path of the fd”
* `F_GETPATH_NOFIRMLINK` is defined as “return the full path **without firmlinks** of the fd” ([fergofrog’s blog][2])

In kernel vnode APIs you can see the same split: there is a `vn_getpath_no_firmlink()` whose purpose is “get a vnode’s path without a **firm-link translation**,” and Apple also documents that vnode paths are not always unique (hardlinks) or even always recoverable. ([fergofrog’s blog][3])

So, when you sometimes observe a Data-volume spelling (e.g. `/System/Volumes/Data/...`) versus a “user-facing” root spelling, that’s exactly the kind of divergence those APIs are designed to expose.

This ties to macOS’s modern system/data volume architecture: Apple describes “firmlinks” as traversal points from a directory on the system volume to a directory on the data volume (volume groups). ([Apple Developer][4])

### Why compile-time “literal pools” don’t collapse but runtime still “picks a winner”

What you’re seeing (distinct literals in the compiled graph, but only one spelling “matters” at runtime) is the natural consequence of:

* **Compilation**: string literals are just strings; the compiler doesn’t (and generally can’t safely) consult the live filesystem to decide that `/tmp` is an alias for `/private/tmp`.
* **Runtime**: the kernel resolves the path (symlinks, firmlinks, mount traversal, etc.) to a vnode; any downstream check that compares against a pathname is comparing against a **resolved/reconstructed path**.

That makes your “tri-profile” method (alias-only vs canonical-only vs both) a reasonable way to detect whether a given family behaves like “must match the resolved spelling” on that host.

It’s also consistent with how real-world sandboxes are written. For example, Mozilla’s macOS content-process sandbox policy includes explicit literals for `"/private/tmp"` and `"/private/var/tmp"` (not `"/tmp"` / `"/var/tmp"`). ([Searchfox][5])

### What I think is “going on,” in one sentence

You’ve discovered that **Seatbelt’s path-based file rules effectively operate on the post-resolution vnode path (symlink-resolved, and often firmlink-translated),** so “alias spellings” like `/tmp/...` are frequently *dead* in practice unless you also include the resolved spelling (`/private/tmp/...`) on that machine. ([Reverse Engineering][1])

### Two practical implications for your project framing

1. **Your “canonicalization map” is a reasonable operational artifact**, but it’s really mapping *resolution/translation behavior* (symlink + firmlink) rather than a mysterious VFS-only canonicalization step.
2. **Be careful generalizing from “F_GETPATH shows X” to “sandbox matched X”**: you’ve already scoped this correctly. The kernel APIs themselves warn that vnode → path reconstruction is not always straightforward/unique, and there is explicit support for “no firmlink translation” variants. ([fergofrog’s blog][3])

[1]: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf "Apple Sandbox Guide v1.0"
[2]: https://fergofrog.com/code/codebrowser/xnu/bsd/sys/fcntl.h.html "fcntl.h source code [xnu/bsd/sys/fcntl.h] - Woboq Code Browser"
[3]: https://fergofrog.com/code/codebrowser/xnu/bsd/sys/vnode.h.html "vnode.h source code [xnu/bsd/sys/vnode.h] - Woboq Code Browser"
[4]: https://developer.apple.com/la/videos/play/wwdc2019/710/ "What's New in Apple File Systems - WWDC19 - Videos - Apple Developer"
[5]: https://searchfox.org/firefox-main/source/security/sandbox/mac/SandboxPolicyContent.h "SandboxPolicyContent.h - mozsearch"

## response

Most of what you wrote matches how SANDBOX_LORE is using “VFS canonicalization” on the `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` baseline: it’s an internal, operational label for “the kernel resolves/rewrites path spellings (symlinks + firmlink-style translation), and the spelling you *requested* can differ from the spelling the kernel later reports for the opened FD.”

I agree that `/tmp` tri-profile behavior is very plausibly explained by ordinary pathname resolution: `/tmp` is an alias of `/private/tmp` on macOS, so a profile that only names `/tmp/...` can look fine statically but lose at runtime if enforcement is effectively operating on the resolved vnode identity / reconstructed resolved path spelling.

I also agree that the project’s `F_GETPATH` vs `F_GETPATH_NOFIRMLINK` witness split is best understood as “two different reconstructed spellings for the same fd/vnode,” not “a different handle.” That’s exactly why the repo records both spellings and keeps them distinct in `path_witnesses.json`.

The main place I’d stay more conservative than your writeup is the step where you equate “the path F_GETPATH reports” with “the literal Seatbelt matched.” The repo intentionally avoids that claim: vnode→path reconstruction isn’t guaranteed unique (hardlinks, multiple spellings), and denied opens produce no FD witness at all, so the mapping generator refuses to infer canonicalization from denies.

So I’d summarize the repo’s stance as: your “resolution/translation behavior” framing is probably the right mental model, but SANDBOX_LORE keeps the broader “VFS canonicalization” label to avoid overcommitting to a single mechanism (symlink vs firmlink vs other normalization) and to keep the evidence bounded to the specific path families and ops the suite probes.

## Web agent convo

### Questions

1. We see `/tmp/...` requests yield FD witnesses in `/private/tmp/...` on the `sonoma-14.4.1-23E224-arm64-dyld-2c0602c5` baseline, and the sandbox behaves as if the resolved spelling is what matters for `file-read*`/`file-write*`; does Seatbelt ever match against the *pre-resolution* user-supplied pathname spelling as well, or is matching exclusively against a vnode-derived/reconstructed path (i.e., post-lookup/post-symlink)? Concretely: for file ops, is the decisive check in a vnode-only hook (no original string available) versus a lookup/pathname hook where the original spelling could still be seen?

2. We record both `F_GETPATH` (firmlink-translated) and `F_GETPATH_NOFIRMLINK` (no-firmlink/Data-volume spelling) for the same FD; when Seatbelt evaluates a path-based rule for a file op on modern macOS, does it normalize/match using the firmlink-translated spelling, the no-firmlink spelling, or both? Put differently: are there known cases where a profile must name `/System/Volumes/Data/...` to match, or is the user-facing/firmlink-translated spelling the canonical match domain?

3. Our current evidence route can’t observe canonicalization on denies (no FD → no `F_GETPATH*`); is there an alternative, authoritative route to recover the resolved vnode path spelling for *denied* file attempts (e.g., audit records, sandboxd/Seatbelt logging/callouts, or a lookup-stage hook output)? If there are multiple routes, which one is closest to “what Seatbelt actually compared against” for `file-read*`/`file-write*`?

### Answer

“VFS canonicalization” is not a standard macOS / UNIX term of art. What your repo is calling that is a real phenomenon, but it’s better described as:

* **Name lookup / path resolution effects** (especially **symlink resolution** like `/tmp` → `/private/tmp`), and
* **Path reconstruction effects** (deriving a printable path from a **vnode**), which on modern macOS can also involve **firmlink translation**.

With that framing, here are best-effort answers to your three questions.

---

#### 1) Does Seatbelt match the user-supplied spelling, or only the resolved/vnode-derived spelling?

Two key facts constrain what’s even *possible* at the decisive enforcement points:

* Apple’s sandbox (“Seatbelt”) is implemented as a **TrustedBSD MAC policy module**.
* The core MAC hooks for actual file use are **vnode-based**. For example, the MAC hook for `open(2)` is:

  `mpo_vnode_check_open_t(cred, vp, label, acc_mode)` — **no pathname string is passed**. ([NewOSXBook][wa1])

That strongly suggests:

* For **open/read/write-style checks**, there is **no original user pathname spelling available at the vnode open/read/write hook**, so any path-based policy decision at those hooks must be based on:

  * a **vnode-derived / reconstructed path** (e.g., via `vn_getpath*`-family routines), and/or
  * object attributes (labels, mount properties, etc.),
    but not the caller’s original string.

There *are* MAC hooks that *do* see a path string at lookup time:

* `mpo_vnode_check_lookup_preflight_t(..., const char *path, size_t pathlen)` exists, and the interface explicitly notes that if lookup encounters a symlink, this hook is called again with an **updated path**. ([NewOSXBook][wa1])

That note matters for your “does it also match the pre-resolution spelling?” question: even in the lookup-preflight world where a string is available, the framework’s model is already “follow symlinks → update the path → re-check.”

Most importantly, Apple’s own sandbox documentation for SBPL path filters explicitly states the behavior you are seeing:

* macOS resolves symlinks, and `/tmp` is a symlink to `/private/tmp`, so a rule allowing `/tmp/testfile` won’t match; you must allow `/private/tmp/testfile`. ([Reverse Engineering][wa2])

##### Practical conclusion for file-read*/file-write* on macOS

For the kinds of file operations you’re testing, the evidence is most consistent with:

* **decisive matching in vnode-based hooks (post-lookup)**, where only the resolved object is available, and
* any path-string use is effectively in a **post-resolution namespace** (because name lookup + symlink following has already happened, and/or because the path is reconstructed from the vnode).

I do not know of any public documentation or interface guarantee that Seatbelt “ORs” in the *original* user-supplied spelling for file ops, and the `/tmp` example in Apple’s guide is an explicit demonstration that **the resolved spelling is what matters** for path filters. ([Reverse Engineering][wa2])

---

#### 2) Firmlink translation vs no-firmlink spelling: which path domain does Seatbelt match?

There is no Apple public statement that says “Seatbelt matches against F_GETPATH’s spelling” vs “F_GETPATH_NOFIRMLINK’s spelling.”

But the kernel API surface gives a strong hint about what the “default” notion of a vnode path is:

* XNU exposes `vn_getpath_no_firmlink()` specifically to obtain a vnode path **without firmlink translation**, and also defines a flag `VN_GETPATH_NO_FIRMLINK`. ([fergofrog’s blog][wa3])

The existence of a dedicated “no firmlink translation” API/flag implies that the normal vnode→path path is in a **firmlink-translated** (i.e., user-facing) namespace unless you explicitly ask otherwise.

And firmlinks are an OS-level mechanism used to present a unified filesystem view (notably since Catalina’s split system/data volumes). ([Der Flounder][wa4])

##### What this suggests for Seatbelt path filters

Given:

* sandbox profiles are authored in user-visible paths,
* the common sandbox documentation and logging examples talk in the traditional namespace (`/private/tmp`, etc.), not `/System/Volumes/Data/...`, and
* the kernel’s default vnode path reconstruction is firmlink-translated unless you opt out, ([fergofrog’s blog][wa3])

…the most likely situation on modern macOS is:

* **Seatbelt’s path matching domain is the firmlink-translated / user-facing path**, not the “no-firmlink Data-volume” spelling.

##### Are there known cases where you must name `/System/Volumes/Data/...` in a profile?

I’m not aware of a well-established, documented requirement that SBPL profiles must name `/System/Volumes/Data/...` to match ordinary file rules. The API design (`vn_getpath_no_firmlink` existing as the *special* case) points the other way: `/System/Volumes/Data/...` is the internal spelling you get when you explicitly disable firmlink translation. ([fergofrog’s blog][wa3])

Given Seatbelt is closed-source and behavior can be host/version dependent, your repo’s conservative stance (“we observed both spellings; we do not claim which one is compared”) is reasonable. But if you need an operational rule of thumb for profiles on modern macOS: **write rules in the firmlink-translated namespace**, and only add Data-volume spellings if you have host-specific evidence that some checks are being performed in that namespace.

---

#### 3) Getting the resolved/canonical path for DENIED file attempts (no FD)

You’re correct that you can’t use `F_GETPATH*` without a file descriptor.

There are two “closest-to-Seatbelt” alternatives that *do* exist for denied attempts:

##### A) Sandbox denial logging (what the system prints for the deny)

Apple’s sandbox guide demonstrates that denial output includes the resolved path:

* attempting `/tmp/test` yields a sandbox denial message referring to `/private/tmp/test`. ([Reverse Engineering][wa2])

That log line is not a proof of the exact internal compare string, but it is strong evidence of what the sandbox subsystem believes the target path is at decision time, and it works even when the open is denied (no FD).

This is typically the most practical “authoritative-ish” channel when you can’t get a vnode/FD witness.

##### B) SBPL “trace” / sandbox tracing channel

The sandbox system has a tracing mechanism where access checks can be preceded by a message from kernel to userspace for logging. Blazakis describes:

* a **trace directive** in the sandbox profile that causes kernel access control checks to generate **Mach messages** to userspace for logging, useful for bootstrapping profiles.

##### Which is closest to “what Seatbelt compared against”?

* The **trace/logging emitted by the sandbox itself** (deny log lines and/or trace messages) is the closest you can get in userspace, because it originates from the sandbox subsystem’s enforcement/tracing path. ([Reverse Engineering][wa2])
* OS audit records (OpenBSM) are more likely to reflect syscall arguments (i.e., **user-supplied strings**) than the canonical vnode-derived path, so they’re usually not the best tool if your main goal is “what did the sandbox compare.”

If you need something closer than logging/tracing, you generally end up in privileged instrumentation territory (kernel tracing, Endpoint Security, etc.), which is outside what a sandboxed process can do by design.

##### Synthesis with your repo’s observation (/tmp → /private/tmp)

What you’re seeing is exactly what Apple documents: **symlink resolution changes the spelling**, and path filters must typically be written against the resolved spelling. ([Reverse Engineering][wa2])
The MAC hook surface also aligns with your operational definition: for key file ops, the enforcement point is vnode-based (no original pathname), making vnode-derived/reconstructed paths the natural “match domain.” ([NewOSXBook][wa1])

[wa1]: https://newosxbook.com/src.php?file=%2Fsecurity%2Fmac_policy.h&tree=xnu "Source of /security/mac_policy.h (From xnu-12377.1.9) "
[wa2]: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v0.2.pdf "Apple Sandbox Guide v0.2"
[wa3]: https://fergofrog.com/code/codebrowser/xnu/bsd/sys/vnode.h.html?utm_source=chatgpt.com "vnode.h source code [xnu/bsd/sys/vnode.h]"
[wa4]: https://derflounder.wordpress.com/2020/01/18/creating-root-level-directories-and-symbolic-links-on-macos-catalina/?utm_source=chatgpt.com "Creating root-level directories and symbolic links on macOS ..."

### Follow-up answers (Q1–Q5)

Below are the best-supported answers to your specific questions, with clear separation between what’s directly evidenced vs. what’s an inference from the architecture.

---

## 1) Pre-resolution pathname vs. post-lookup/vnode-derived pathname for file ops

### What’s strongly supported

For path-filtered file operations (your `file-read*` / `file-write*` probes), the sandbox behavior you’re seeing (`/tmp/...` requests producing `/private/tmp/...` FD witnesses and “only `/private/tmp` matters”) matches the documented expectation that **symlinks are resolved and the sandbox compares against the resolved path** (i.e., post-resolution spelling), not the original user spelling. ([Reverse Engineering][wa5])

So: if Seatbelt were matching against the *pre-resolution* string as well (or primarily), `/tmp/...` literals would be expected to work in the `/tmp -> /private/tmp` case. The fact that they don’t (per both your experiments and Apple’s own guidance) is strong evidence that **the decisive comparison is against the resolved target spelling** for these operations. ([Reverse Engineering][wa5])

### What the MAC hook surface implies (important architectural constraint)

You already note `mpo_vnode_check_open` is vnode-only. The TrustedBSD MAC framework also has `mpo_vnode_check_lookup_preflight`, and its contract is that it can be called repeatedly during lookup when symlinks are encountered, with the path buffer updated as resolution proceeds. ([NewOSXBook][wa6])

That combination strongly suggests:

* Even if Seatbelt performs a decision during lookup (where a path string exists), that path is **not “the original string forever”**; it’s an evolving “remaining path” that gets rewritten on symlink traversal. ([NewOSXBook][wa6])
* For vnode-only hooks (open, mmap/file-map-executable-style checks, etc.), **there is no user-supplied pathname available**, so any path-based decision there necessarily uses a **vnode-derived/reconstructed path** (or some token carried forward from lookup).

### Practical conclusion

For the file-read*/file-write* family you’re testing, the best explanation consistent with both docs and hook realities is:

* **Seatbelt’s effective path match domain is post-lookup/post-symlink** (your “canonical spelling”), not the user-typed alias spelling. ([Reverse Engineering][wa5])
* I would not assume there is a “double match” against both pre- and post-resolution spellings for the same operation; your `/tmp` tri-profile results are evidence against that.

---

## 2) Firmlink-translated vs. “no-firmlink” `/System/Volumes/Data/...` spelling: what does Seatbelt match?

### What the APIs prove (multiple spellings exist)

macOS explicitly supports retrieving *two different* path spellings for the same FD:

* `F_GETPATH` (the usual “user-facing” spelling in the firmlinked view), and
* `F_GETPATH_NOFIRMLINK`, documented as returning the **non-firmlinked path**. ([FreeBSD Manual Pages][wa7])

Kernel interfaces also encode this as a “no firmlink” flag for vnode path retrieval (`VN_GETPATH_NO_FIRMLINK`). ([fergofrog’s blog][wa8])

So your harness design (recording both) is directly aligned with real kernel-supported dual spellings.

### What’s evidenced about sandbox matching (the most useful external datapoints)

There is strong ecosystem evidence that **writing sandbox profiles using `/System/Volumes/Data/...` is unreliable and often wrong**, and that the sandbox effectively “wants” the firmlink-translated namespace:

* Chromium’s maintained macOS sandbox profile (`common.sb`) contains a detailed comment describing a macOS 11/12 sandbox bug where paths inside the Data volume *outside firmlink locations* are effectively treated as if they **don’t have `/System/Volumes/Data` as a prefix**, leading to denials when the profile names `/System/Volumes/Data/...`. Chromium works around this by stripping the Data-volume prefix and allowing the non-Data spelling instead.
* The Bazel issue you found is consistent with that: using a Data-prefixed path in the profile fails on Big Sur, while using the non-Data spelling works.

### Practical conclusion

On “modern macOS” (especially post-Catalina volume group / firmlink era), the safest operational assumption is:

* **Seatbelt’s path matching generally behaves as if the firmlink-translated/user-facing spelling is the canonical match domain**, and `/System/Volumes/Data/...` is a brittle spelling that may fail to match (and has known-version bugs).

That aligns well with your observation that even when a Data-volume spelling shows up via a “no firmlink” path query, the “effective literal” behavior still tracks the non-Data/firmlink spelling.

If you need robustness across hosts/versions, the conservative profile strategy is: **include both spellings when you see both in witnesses**, but treat the firmlink-translated spelling (what `F_GETPATH` returns) as the primary one.

---

## 3) How to recover “the path Seatbelt compared against” for denied file attempts

You’re correct that “no FD → no `F_GETPATH*`” blocks your current witness path approach.

### Closest thing to authoritative in userland: sandbox denial logging

SBPL supports debug logging of denies via `(debug deny)` (and related logging modifiers).
Chromium’s profile also explicitly notes enabling logging to syslog and then conditionally enables `(debug deny)`.

Those denial logs often include an explicit **path string** alongside the operation. For example, Apple Community posts show sandbox denial lines of the form:

> `Sandbox: ... deny(1) file-read-metadata /private/var/folders/.../sessions.plist`

This doesn’t *prove* “this is byte-for-byte the internal compare string,” but it is typically the best **decision-time path witness** you can get for denied attempts without kernel instrumentation.

### Other routes (less authoritative for *resolved* spelling)

* **Audit/BSM records**: generally capture syscall arguments (often the user-supplied path), not necessarily the post-resolution vnode path; they’re useful, but not a guarantee of “what Seatbelt compared.”
* **Kernel-level observation** (KEXT / custom MAC policy / tracing): would be closest to ground truth (e.g., observing what `mpo_vnode_check_lookup_preflight` sees), but is not generally available/viable on stock modern macOS in typical environments.

### Practical conclusion

If your goal is “what did Seatbelt probably compare against on deny?” then:

* **Use `(debug deny)` as a first-class witness channel** and treat its reported path as your best available “decision-stage” spelling for denied attempts.
* Your project’s stance (“don’t infer canonicalization from denies unless you have a direct witness”) is conservative, but if you want coverage, denial logs are the least-bad way to extend observation.

---

## Lookup-preflight caching vs. vnode-path reconstruction: A vs B?

You framed:

* (A) Decide in `lookup_preflight` and cache result on the vnode (label/cached state)
* (B) Reconstruct a path from the vnode at decision time for each check

### What can be said with confidence

A pure “cache allow/deny on the vnode” design is hard to reconcile with how macOS sandboxing is applied **per process**. The sandbox policy is associated with the process (MAC labels attached to processes/credentials are a key part of the model), so an allow/deny cached *on the vnode itself* would be dangerously global unless it’s keyed by sandbox context. ([Bdash][wa9])

### What’s most plausible in practice (hybrid, but with B as fundamental)

Given the hook surface and the existence of vnode-only checks, Seatbelt must be capable of **vnode-based evaluation** for some operations (meaning: some form of vnode→path derivation exists somewhere in the implementation).

At the same time, for classic “resource acquisition time” file permissions, sandboxing is typically enforced when the resource is acquired (e.g., at open), not on every subsequent read/write.
That makes it plausible that a lot of `file-read*`/`file-write*` policy is decided during lookup/open, and later I/O doesn’t need a path decision.

So the most defensible model is:

* Seatbelt may **use lookup-stage hooks** (like `lookup_preflight`) where a path string is available and updated across symlink traversal. ([NewOSXBook][wa6])
* But it cannot rely exclusively on lookup-stage pathname strings for all path-filtered operations, because vnode-only decision points exist in the MAC framework.
* Any caching is more plausibly:

  * internal memoization **within the per-process sandbox context**, or
  * caching of derived path/classification data in a way that’s not a simple “vnode is allowed/denied globally.”

In other words: I would not bet on (A) “cache allow/deny on vnode label,” and I would treat (B) “vnode-derived path match exists” as the safer foundational assumption.

---

## Lexical normalization beyond symlink/firmlink

### Trailing slashes

SBPL’s `subpath` filter is explicitly documented to take a PATH that “never ends with a slash (/).” ([Reverse Engineering][wa5])
So at least for that major path filter form, the matching domain is already specified as “no trailing slash,” i.e., you shouldn’t expect `/private/tmp/` and `/private/tmp` to be distinct for rule-writing purposes (and you shouldn’t write the slash form). ([Reverse Engineering][wa5])

### `.` / `..` and repeated slashes

If the sandbox is comparing against a resolved, vnode-derived path (your `/tmp → /private/tmp` evidence strongly suggests it is), then these lexical variations are typically eliminated by the time you have a vnode and/or a reconstructed path. Put differently: you don’t necessarily need Seatbelt to implement a separate “lexical normalizer”; VFS lookup itself and vnode-based path reconstruction naturally produce a cleaned-up spelling.

There isn’t a clean, public statement that “Seatbelt applies X lexical normalizations,” but your operational approach (“treat the kernel-reported path spelling as the match-relevant spelling”) is exactly the safe stance.

### Case and Unicode normalization

Here the file system matters:

* APFS preserves both case and normalization *on disk*, supports both case-sensitive and case-insensitive variants on macOS (case-insensitive is the default), and is normalization-insensitive (so normalization variants shouldn’t create distinct files in the same directory).

That implies a subtle but important consequence for any sandbox that matches by a kernel-derived path string:

* A user can supply a path with different case and/or Unicode normalization and still resolve the same file (on a case-insensitive / normalization-insensitive volume), but a “canonical” path derived from the vnode will tend to reflect the stored directory-entry spelling.
* If Seatbelt’s path matching is bytewise/case-sensitive at the SBPL string level (common for literal/prefix matches), the *profile must name the spelling that the kernel produces*, not whatever spelling the user typed.

So: treat **case/Unicode normalization differences as another “canonicalization axis”**—just like `/tmp` vs `/private/tmp`—and prefer matching strategies that don’t depend on exact leafname spellings unless you’ve derived the literal from a witness on that exact host/filesystem.

---

## Bottom line for your project’s working model

Your current operational definition (“we observed requested_path ≠ FD path witness; treat the FD path witness as canonical; don’t overclaim about Seatbelt internals”) is consistent with:

* the documented `/tmp` symlink mismatch behavior in sandbox path filters, ([Reverse Engineering][wa5])
* the fact that lookup-preflight’s path argument is explicitly updated across symlink traversal, ([NewOSXBook][wa6])
* the existence of distinct firmlink vs no-firmlink path spellings for the same FD, ([FreeBSD Manual Pages][wa7])
* and real-world sandbox profile engineering in Chromium/Bazel that treats `/System/Volumes/Data/...` spellings as hazardous and works around them by using the non-Data spelling.

If you want one practical refinement: promote sandbox denial logs (`(debug deny)`) into your witness IR as a “deny-path witness” channel, clearly labeled as “decision-log path string” (not FD-derived), because it’s the closest you’ll get to a resolved spelling on denies without kernel instrumentation.

[wa5]: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf "Apple Sandbox Guide v1.0"
[wa6]: https://newosxbook.com/src.php?file=%2Fsecurity%2Fmac_policy.h&tree=xnu&utm_source=chatgpt.com "Source of /security/mac_policy.h (From xnu-12377.1.9)"
[wa7]: https://man.freebsd.org/cgi/man.cgi?manpath=macOS+14.8&query=fcntl&sektion=2&utm_source=chatgpt.com "fcntl(2)"
[wa8]: https://fergofrog.com/code/codebrowser/xnu/bsd/sys/vnode.h.html?utm_source=chatgpt.com "vnode.h source code [xnu/bsd/sys/vnode.h]"
[wa9]: https://bdash.net.nz/posts/sandboxing-on-macos/ "Sandboxing on macOS // Mark Rowe"

### Follow-up answers (Q6–Q7)

#### 1) What does `SANDBOX_CHECK_CANONICAL` actually do?

The best public, concrete description of `SANDBOX_CHECK_CANONICAL` (as used with `sandbox_check_by_audit_token(..., SANDBOX_FILTER_PATH | … | SANDBOX_CHECK_CANONICAL, path)`) is that it makes the check **fail if the supplied path is not already “canonical”**—specifically, *if the path contains a symbolic link component or `..` traversal components*. ([The Sequence][wa10])

That implies it is **not just lexical prettification** (e.g., collapsing `//`), because detecting “contains a symbolic link” requires filesystem-backed knowledge (or an equivalent kernel-backed resolution / validation pass). In other words, it’s intended as a *safety/anti-confusion/anti-TOCTOU* option: “only accept already-canonical, non-symlink, non-traversal paths,” rather than “please canonicalize this for me and then check.”

There’s also independent context from WebKit’s history around “canonical” relating to the idea that a path “contains no symlinks,” consistent with that interpretation. ([Chromium Git Repositories][wa11])

##### Consequence for your `/tmp` example

If `/tmp` is a symlink to `/private/tmp` (as on macOS), then:

* `sandbox_check(... | SANDBOX_CHECK_CANONICAL, "/tmp/foo")` should be expected to **fail** (because the supplied spelling includes a symlink component), even if `/private/tmp/foo` would otherwise be allowed. ([The Sequence][wa10])
* Therefore, it should **not** behave equivalently to `sandbox_check(... raw, "/private/tmp/foo")`.

If you want to use the “canonical” flag in a way that has a chance to succeed, you generally need to pass the *already canonical* spelling (e.g., `/private/tmp/foo`) and ensure there are no symlink components anywhere in the path you pass.

One more nuance: some researchers also note that the sandbox check logic “internally … will resolve symbolic links” in its normal flow. ([The Sequence][wa10]) That’s compatible with the above: the “canonical” flag can be understood as *tightening* the check to **reject** any input that would require such resolution (or that differs from its fully-resolved form), rather than simply performing resolution and continuing.

---

#### 2) What does `SANDBOX_CHECK_NO_REPORT` do, and will disabling it give you a structured “post-canonicalization path” report?

Everything that’s publicly visible suggests:

* `SANDBOX_CHECK_NO_REPORT` controls whether a *denied* `sandbox_check*` call produces a **sandbox violation report** (logging/telemetry/backtrace-style reporting), not whether the API returns a report object.
* WebKit explicitly describes the failure case as generating “an expensive violation report” that can even “task_suspend” the process being checked, and uses `SANDBOX_CHECK_NO_REPORT` to suppress that. ([trac.webkit.org][wa12])
* Levin’s “Hack in the (sand)Box” slides similarly describe `sandbox_check` as commonly used with `SANDBOX_CHECK_NO_REPORT` and “silent” (no user-mode output). ([NewOSXBook][wa13])

On the API surface: a WebKit SPI header discussion shows `sandbox_check(...)` as returning an `int` and taking varargs for filters—there’s no extra out-parameter shown for a “report object” or “resolved path.” ([WebKit Bugzilla][wa14])

##### So: if you flip `no_report=false`, do you get a structured report back?

Based on the above, **no**: you should expect the call to still return only allow/deny, while the system may additionally emit a **violation report** via the sandbox reporting pipeline (e.g., unified logging / sandboxd-side reporting), with associated overhead. ([trac.webkit.org][wa12])

##### Will that emitted report contain the “post-canonicalization spelling” it compared against?

You can often *see a path string* in sandbox violation logs in general, but:

* That string is not documented as “the exact string Seatbelt compared,” and it may be the argument after userland-side fixups, or it may be the originally supplied argument depending on where the failure occurred (e.g., “canonical” flag failing due to symlink/traversal validation may naturally report the *input*).
* There is no strong, public guarantee (that I can cite) that the report will include a “post-canonicalization path,” nor that it will disambiguate firmlink vs no-firmlink domains.

Given your specific question (F_GETPATH vs F_GETPATH_NOFIRMLINK domain): with current public sources, the safest operational stance is:

* **Do not assume** toggling `no_report` will give you an authoritative “compared path” string in either domain.
* Treat any logged path as a *diagnostic hint*, not ground truth, and continue to rely on your FD witness machinery for “what the kernel says this FD is,” since that is at least directly observable for allows.

---

#### Practical takeaway for your harness

* Treat `SANDBOX_CHECK_CANONICAL` as “**reject non-canonical inputs** (symlinks / `..`)” rather than “canonicalize then check.” Your `/tmp` → `/private/tmp` case is exactly the kind of input this flag is meant to reject. ([The Sequence][wa10])
* Treat `SANDBOX_CHECK_NO_REPORT` as “**suppress expensive violation reporting**.” Removing it is primarily about visibility in logs/telemetry and has real cost (and can affect the checked process). ([trac.webkit.org][wa12])
* Do not plan on `sandbox_check*` to hand you a structured “post-canonicalization path spelling” on deny; the API contract visible in SPI discussions doesn’t expose that. ([WebKit Bugzilla][wa14])

[wa10]: https://the-sequence.com/macos-audit-story-part2?utm_source=chatgpt.com "diskarbitrationd and storagekitd Audit Part 2"
[wa11]: https://chromium.googlesource.com/external/github.com/WebKit/webkit/%2B/refs/heads/safari-612.1.29.14-branch/Source/WTF/ChangeLog "Source/WTF/ChangeLog - external/github.com/WebKit/webkit - Git at Google"
[wa12]: https://trac.webkit.org/timeline?authors=&daysback=4&from=2021-05-11 "Timeline – WebKit"
[wa13]: https://newosxbook.com/files/HITSB.pdf?utm_source=chatgpt.com "Hack in the (sand)Box"
[wa14]: https://bugs.webkit.org/show_bug.cgi?id=151981 "151981 – Create a Sandbox SPI header"

#### response

This meaningfully changes how to interpret our existing `seatbelt-callout` “canonical” variants on this host: the canonical flag is best treated as a *rejection predicate* (“fail if the input path includes symlinks or `..`”), not as “canonicalize for me and then check.” On the Sonoma baseline, that implies `/tmp/...` is exactly the kind of spelling that a canonical-flagged check should reject even when the corresponding `/private/tmp/...` access would otherwise be allowed.

Given that, the “canonical” callout path is still useful in experiments, but as a *guardrail axis*: it can help us distinguish “this was denied because the input spelling was non-canonical” from “this was denied because the canonical spelling is disallowed.” It is not a good route to discover the canonical spelling; that still needs FD-path witnesses (allows) or a separately captured decision-log witness (denies).

On `NO_REPORT`, the take-away is to treat it as an observability/overhead knob (and potentially a confounder) rather than a way to extract structured “compared path” data. If we pursue deny-side path spellings, we should do it via an explicit, captureable log/witness channel (for example, SBPL `(debug deny)` or other sandbox decision logging) and keep it clearly labeled as “decision-log spelling,” not as “Seatbelt compared exactly this string.”
