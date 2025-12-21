> NOTE (docs-only)
>
> The runnable probe source has moved to `book/api/lifecycle_probes/c/entitlements_example.c`. This example directory is documentation only.
> Use `python -m book.api.lifecycle_probes entitlements` to build/run the probe and (optionally) write `validation/out/lifecycle/entitlements.json`.

## 1. What this example is about

This example shows how **code-signing metadata** (signing identifier + entitlements) is exposed at runtime and how it relates to Seatbelt’s filters:

* It does **not** talk to the sandbox directly.
* Instead, it asks the Security framework:

  * “Who am I?” (signing identifier)
  * “What entitlements do I have?”
* The output demonstrates that:

  * Entitlements live in the **code signature**, not in the binary’s text segment.
  * The **same compiled binary** can produce **different sandbox outcomes** depending only on how it is signed.

You can use this as a lab tool: build once, then run different signed variants and see how the entitlement plist changes while the machine code stays identical. That is exactly the shape of data that SBPL filters like `(entitlement-is-present ...)` and `(signing-identifier ...)` see.

---

## 2. How to build and run

Runnnable probe source:

* `book/api/lifecycle_probes/c/entitlements_example.c`

You can build it like:

```sh
clang book/api/lifecycle_probes/c/entitlements_example.c \
  -o book/api/lifecycle_probes/build/entitlements_example \
  -framework Security -framework CoreFoundation
```

Then run:

```sh
book/api/lifecycle_probes/build/entitlements_example
```

To emit a machine-readable summary (JSON on stdout):

```sh
book/api/lifecycle_probes/build/entitlements_example --json
```

To write the canonical validation output:

```sh
python -m book.api.lifecycle_probes entitlements \
  --out book/graph/concepts/validation/out/lifecycle/entitlements.json
```

On an unsigned build, you will typically see:

* A signing identifier (may be generic or missing depending on how you built).
* “Entitlements present: no”.

If you create a **signed** variant (e.g., via Xcode or `codesign` with an entitlement plist), and re-run:

* The printed **code** path and PID remain the same kind of values.
* The **entitlements plist** now appears, serialized as XML, showing exactly what the sandbox can test against.

The example is read-only and introspective: it only inspects your own process; it does not escalate anything or modify system state.

---

## 3. Walking through the code

### 3.1 Includes and helper for CFStrings

```c
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
```

These give:

* `Security.h` – for `SecCodeCopySelf` and `SecCodeCopySigningInformation`.
* `CoreFoundation.h` – for CF types (`CFString`, `CFDictionary`, `CFData`, `CFPropertyList...`).
* `libproc.h` – to get the executable path of the current PID.
* Standard C headers for I/O and string handling.

The helper:

```c
static void print_cfstring(const char *label, CFStringRef str) {
    if (!str) {
        printf("%s: <none>\n", label);
        return;
    }
    char buffer[256];
    if (CFStringGetCString(str, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
        printf("%s: %s\n", label, buffer);
    } else {
        printf("%s: <unprintable CFString>\n", label);
    }
}
```

Purpose:

* Convert CoreFoundation `CFStringRef` into a UTF-8 C string so it can be printed.
* Handles three cases:

  * `NULL` string → prints `<none>`.
  * Successfully converted → prints the actual value.
  * Conversion failure → prints `<unprintable CFString>`.

You can reuse this pattern anytime you need to debug CFStrings.

---

### 3.2 Basic process info and context

```c
char exec_path[PROC_PIDPATHINFO_MAX] = {0};
if (proc_pidpath(getpid(), exec_path, sizeof(exec_path)) <= 0) {
    strncpy(exec_path, "<unknown>", sizeof(exec_path) - 1);
}

printf("Seatbelt entitlement probe\n");
printf("PID: %d\n", getpid());
printf("Executable: %s\n\n", exec_path);
```

This:

* Uses `proc_pidpath` to retrieve the full path to the current executable.
* Falls back to `"<unknown>"` if it fails.
* Prints:

  * PID
  * Executable path

This context is useful when you are running several differently signed copies and want to confirm which binary image produced which entitlement dump.

The comment that follows:

```c
// Seatbelt and SBPL can test entitlements/signing metadata via filters
// like (entitlement-is-present ...) or (signing-identifier ...).
// Those predicates are evaluated against the code signature, not against
// anything this process does at runtime (see book/substrate/Appendix.md).
```

Key point:

* SBPL predicates about entitlements and signing are **purely about static metadata** in the code signature.
* Runtime behavior does not alter entitlements; you must change the **signature** to change what the sandbox sees.

---

### 3.3 Getting a `SecCodeRef` for the current process

```c
SecCodeRef self_code = NULL;
OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &self_code);
if (status != errSecSuccess) {
    fprintf(stderr, "SecCodeCopySelf failed: %d\n", (int)status);
    return 1;
}
```

This uses the Security framework:

* `SecCodeCopySelf` creates a `SecCodeRef` representing “this running code”.
* If it fails:

  * The program reports the status code and exits.

Conceptually: `SecCodeRef` is the handle that lets you ask, “What’s my signature? What’s my signing identifier? What entitlements do I have?”

---

### 3.4 Fetching signing information

```c
CFDictionaryRef signing_info = NULL;
status = SecCodeCopySigningInformation(self_code, kSecCSSigningInformation, &signing_info);
if (status != errSecSuccess || !signing_info) {
    fprintf(stderr, "SecCodeCopySigningInformation failed: %d\n", (int)status);
    CFRelease(self_code);
    return 1;
}
```

Here:

* `SecCodeCopySigningInformation` returns a `CFDictionaryRef` containing various keys about the signature:

  * Identifier
  * Entitlements dictionary
  * Other metadata not used here.
* The option `kSecCSSigningInformation` requests the full signing info block.

If this fails, there is no point continuing; the tool can’t see the metadata the sandbox would see.

---

### 3.5 Printing the signing identifier

```c
CFStringRef identifier =
    (CFStringRef)CFDictionaryGetValue(signing_info, kSecCodeInfoIdentifier);
print_cfstring("Signing identifier", identifier);
```

The code:

* Looks up `kSecCodeInfoIdentifier` in the `signing_info` dictionary.
* Uses `print_cfstring` to print it, if present.

The **signing identifier** is exactly the string that SBPL filters like `(signing-identifier "com.example.app")` test against in platform or App Sandbox profiles.

This reinforces that:

* The identifier is part of the signature, not embedded in your code as a variable.
* Changing the identifier means changing the signature (and possibly provisioning).

---

### 3.6 Entitlements dictionary and serialization

```c
CFDictionaryRef entitlements =
    (CFDictionaryRef)CFDictionaryGetValue(signing_info, kSecCodeInfoEntitlementsDict);
if (!entitlements) {
    printf("Entitlements present: no (run a signed build to compare)\n");
} else {
    printf("Entitlements present: yes\n");
    ...
}
```

Here the program:

* Looks up `kSecCodeInfoEntitlementsDict` in the signing info.
* If the value is `NULL`:

  * There are no entitlements.
  * This is typical for an ad-hoc or unsigned build.
* If present:

  * It prints “Entitlements present: yes” and proceeds to serialize and display them.

The serialization block:

```c
CFErrorRef error = NULL;
CFDataRef plist_data = CFPropertyListCreateData(
    kCFAllocatorDefault,
    entitlements,
    kCFPropertyListXMLFormat_v1_0,
    0,
    &error);
```

* `CFPropertyListCreateData` converts the entitlements dictionary into a serialized property list.
* It requests XML format (`kCFPropertyListXMLFormat_v1_0`) so that humans can read it easily.
* On success, `plist_data` is a `CFDataRef` containing the XML plist bytes.

Error handling if serialization fails:

```c
if (!plist_data) {
    char desc[256] = "<unknown>";
    if (error) {
        CFStringRef err_str = CFErrorCopyDescription(error);
        if (err_str) {
            CFStringGetCString(err_str, desc, sizeof(desc), kCFStringEncodingUTF8);
            CFRelease(err_str);
        }
    }
    fprintf(stderr, "Failed to serialize entitlements: %s\n", desc);
}
```

Otherwise, on success:

```c
printf("Entitlements (XML plist):\n");
fwrite(CFDataGetBytePtr(plist_data), 1, CFDataGetLength(plist_data), stdout);
printf("\n");
CFRelease(plist_data);
```

This prints:

* A label.
* The exact entitlement plist as XML.

This is effectively the ground truth of what the sandbox sees when evaluating `(entitlement-is-present "com.apple.security.files.user-selected.read-write")` or similar predicates.

Finally:

```c
if (error) {
    CFRelease(error);
}
```

cleans up any error object created by CoreFoundation.

---

### 3.7 Cleanup and conceptual reminder

At the end:

```c
CFRelease(signing_info);
CFRelease(self_code);

printf("\nRe-run this binary with different signatures/entitlements to see how\n");
printf("the metadata changes even though the compiled code stays identical.\n");
printf("Seatbelt filters in the platform/App Sandbox profiles use that metadata\n");
printf("as inputs when evaluating operations.\n");
return 0;
```

This does three things:

1. Releases all CoreFoundation objects (`signing_info`, `self_code`) to avoid leaks.
2. Prints the core experimental instruction:

   * Keep the **binary** the same.
   * Change the **signature/entitlements**.
   * Observe how the entitlement plist changes across runs.
3. Connects back to Seatbelt:

   * Platform and App Sandbox profiles treat this metadata as **inputs**.
   * They gate operations (file, network, hardware) based partly on these entitlements.

This is the bridge from introspection to sandbox behavior: you can now see the exact metadata that will be referenced on the policy side.

---

## 4. How to use this as a learning tool

A practical sequence:

1. **Baseline run (unsigned/ad-hoc)**

   * Compile with `clang` as above, run without signing.
   * Observe:

     * A simple identifier or `<none>`.
     * “Entitlements present: no”.

2. **Signed run without extra entitlements**

   * Sign the binary with a development certificate but no special entitlements:

     * `codesign -s "Developer ID Application: ..." book/api/lifecycle_probes/build/entitlements_example`
   * Run again.
   * Note:

     * The new signing identifier.
     * Any default entitlements attached by your signing configuration.

3. **Signed run with explicit entitlements plist**

   * Create a small entitlements plist (e.g., request a specific sandbox exemption).
   * Sign with `--entitlements`:

     * `codesign -s "..." --entitlements my.entitlements.plist book/api/lifecycle_probes/build/entitlements_example`
   * Run again.
   * Compare:

     * The diff in the XML entitlement plist.
     * How that would change evaluations of `(entitlement-is-present ...)` predicates.

This experiment makes concrete that sandbox behavior is **entitlement-driven**: you are not changing the program’s logic, only the metadata that Seatbelt uses to decide whether a given operation is allowed.

---

## 5. Lessons`

The example code provides the runnable demonstration behind each bullet:

1. **Entitlements as signature metadata**

   * The code never opens “entitlement files” or checks environment variables.
   * It only talks to `SecCodeCopySigningInformation`, illustrating that entitlements are part of the code signature.
   * SBPL uses filters like `(entitlement-is-present ...)` and `(signing-identifier ...)` to interrogate that metadata.

2. **Metadata predicates gating powerful operations**

   * Platform/App Sandbox profiles can combine:

     * `signing-identifier` predicates,
     * `entitlement-is-present`,
     * and other metadata filters (like `system-attribute`).
   * Together these form multi-factor checks: “only binaries signed as X, with entitlement Y, on a certain platform configuration, may perform operation Z.”

3. **Platform policy vs per-process profile**

   * Even if a per-process profile (e.g., an app’s SBPL) **allows** an operation, the **platform** or App Sandbox policy can still deny it based on entitlements.
   * This example shows you exactly what entitlements the platform policy sees when making that decision.

4. **Empirical toggling as a probe method**

   * By signing the same binary in different ways and observing the entitlement plist here, you can:

     * run it under a sandboxed configuration,
     * and empirically measure how Seatbelt’s behavior changes with entitlements held constant vs changed.
   * This is a clean probe pattern: **fix the code, vary the entitlements**, and watch the effect on sandbox outcomes.

Reading `book/api/lifecycle_probes/c/entitlements_example.c` alongside `lessons.md` lets you connect abstract language about “entitlement-driven behavior” with concrete handles and output that you can manipulate on your own system.
