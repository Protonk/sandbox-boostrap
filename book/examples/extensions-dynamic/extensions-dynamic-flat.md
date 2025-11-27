## 1. What this example is about

This example demonstrates the **sandbox extension** mechanism as exposed by `libsandbox`:

* It does a baseline `open()` on a protected path to show failure.
* It dynamically loads `libsandbox.dylib` and locates the extension APIs.
* It attempts to issue a file read extension (`"com.apple.app-sandbox.read"`), consume it, and then retry the `open()`.
* It finally releases the token.

On a stock macOS system, without the right entitlements, **issuance is expected to fail**. That is intentional: the example is about understanding the **API pattern** and the conceptual role of extensions, not about successfully bypassing system protections.

The key mapping is: **extensions → `(extension ...)` filters in SBPL**, which act as temporary, dynamic capabilities layered on top of platform and per-process policy.

---

## 2. How to build and run

Single source file:

* `extensions_demo.c`

Typical build:

```sh
clang extensions_demo.c -o extensions_demo -ldl
```

(Depending on your SDK/headers, `-ldl` may not be needed, but the code uses `dlopen`/`dlsym`.)

Then run:

```sh
./extensions_demo
```

You should expect:

* One `open()` attempt that fails with `EACCES` or similar.
* An attempt to issue an extension that likely fails and prints an explanatory message.
* Even if issuance fails, the example traces the intended lifecycle:

  * issue → consume → use → release.

---

## 3. Walking through the code

### 3.1 Includes and function pointer typedefs

```c
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
```

These provide:

* Dynamic loading (`dlopen`, `dlsym`, `dlclose`).
* Error reporting (`errno`, `strerror`).
* File operations (`open`, `close`).

The extension API signatures are modeled as:

```c
typedef int (*issue_fn)(const char *ext, const char *path, int flags, char **token);
typedef int (*consume_fn)(const char *token);
typedef int (*release_fn)(const char *token);
```

These correspond to private `libsandbox` functions:

* `sandbox_extension_issue_file`
* `sandbox_extension_consume`
* `sandbox_extension_release`

Conceptually:

* `issue` asks `libsandbox` to mint a token representing a temporary capability.
* `consume` installs that token into the current process’s sandbox label.
* `release` tells `libsandbox` the token is no longer needed.

---

### 3.2 Helper: `try_open`

```c
static int try_open(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        printf("open(\"%s\") -> success (fd=%d)\n", path, fd);
        close(fd);
        return 0;
    }
    printf("open(\"%s\") -> errno=%d (%s)\n", path, errno, strerror(errno));
    return -1;
}
```

Purpose:

* Encapsulates a simple read-only `open()` attempt.
* Prints whether it succeeded and, if not, the `errno` and its string form.
* Returns 0 on success, −1 on failure.

You can treat this as the “probe” for whether the effective sandbox allows reading the target.

---

### 3.3 Main: baseline behavior and expectations

```c
const char *target = "/private/var/db/ConfigurationProfiles"; // usually protected
printf("Sandbox extension demo targeting: %s\n", target);
printf("Expect issuance to fail without entitlements; focus on the API steps.\n\n");

try_open(target); // baseline attempt without any extension
```

Here:

* `target` is a path that is typically readable only with elevated privileges or appropriate sandbox permissions.
* The comment sets the expectation: **you are not supposed to succeed** in opening this path from an unentitled CLI.
* The initial `try_open()` acts as a baseline: “what happens with no extensions at all?”

This gives you a reference to compare with after an attempted extension issuance.

---

### 3.4 Loading `libsandbox` and resolving symbols

```c
void *handle = dlopen("/usr/lib/libsandbox.dylib", RTLD_LAZY);
if (!handle) {
    fprintf(stderr, "Failed to load libsandbox: %s\n", dlerror());
    return 1;
}
```

This:

* Explicitly loads `libsandbox.dylib` at runtime.
* If it fails, the program prints the loader error and exits.

Then:

```c
issue_fn issue = (issue_fn)dlsym(handle, "sandbox_extension_issue_file");
consume_fn consume = (consume_fn)dlsym(handle, "sandbox_extension_consume");
release_fn release = (release_fn)dlsym(handle, "sandbox_extension_release");
if (!issue || !consume || !release) {
    fprintf(stderr, "Required symbols not found in libsandbox\n");
    dlclose(handle);
    return 1;
}
```

This:

* Resolves the three extension-related symbols.
* Checks that all are present before proceeding.

The pattern to note:

* The example does not rely on headers for these private APIs.
* Instead, it uses `dlsym` with manually defined function pointer types.
* This is a generic approach for experimenting with private `libsandbox` APIs.

---

### 3.5 Issuing an extension

```c
char *token = NULL;
int rc = issue("com.apple.app-sandbox.read", target, 0, &token);
if (rc != 0) {
    printf("sandbox_extension_issue_file failed rc=%d errno=%d (%s)\n",
           rc, errno, strerror(errno));
    printf("On systems without the right entitlements, issuance is denied by design.\n");
} else {
    ...
}
```

Key aspects:

* The requested extension class is `"com.apple.app-sandbox.read"`:

  * This is a read-capability extension type.
  * SBPL policies can test for this via `(extension "com.apple.app-sandbox.read")`.
* `target` is the path for which this extra capability is requested.
* `token` receives a dynamically allocated string if issuance succeeds.

The important conceptual point:

* Issuance is **guarded by entitlements and trust**:

  * On a typical unentitled command-line process, this call will fail.
  * That failure is expected and correct behavior.
* The example’s role is to show **what a successful issuance would look like** and how the token feeds into `(extension ...)` filters.

---

### 3.6 Consuming and using the token

In the success path:

```c
printf("Issued extension token: %s\n", token);
// Consume installs the token into this process’s label so SBPL filters
// like (extension \"com.apple.app-sandbox.read\") can match during checks.
if (consume(token) == 0) {
    printf("Consumed extension token, retrying open...\n");
    try_open(target);
} else {
    printf("Consuming extension failed errno=%d (%s)\n", errno, strerror(errno));
}
```

Logic:

* If issuance succeeded:

  * Print the raw token string (for inspection, though real clients typically treat it as opaque).
  * Call `consume(token)`:

    * This alters the process’s sandbox label to indicate that the extension is active.
    * From this point on, SBPL `(extension ...)` predicates can match this token.
* If `consume` succeeds:

  * The program retries `try_open(target)` to see whether the new capability changes the result.
* If `consume` fails:

  * It prints the error.

Conceptually:

* **Issuance** creates a token.
* **Consumption** activates it for the current process, changing the effective sandbox permissions without rewriting the underlying profile.
* SBPL does not “pull” this token; instead, the sandbox label now carries it, and `(extension ...)` filters see it as an extra true predicate.

---

### 3.7 Releasing the token and cleanup

Still in the success path:

```c
// Release returns the token to libsandbox; real clients do this once the
// temporary capability is no longer needed.
release(token);
```

This:

* Informs `libsandbox` that the extension is no longer in use.
* Real clients use this to bound the lifetime of temporary capabilities.

Finally:

```c
dlclose(handle);
printf("\nExtensions act as a third dimension: platform policy ∧ process policy ∧ active extensions.\n");
printf("Tokens map directly to `(extension ...)` filters compiled into the policy graph.\n");
return 0;
```

The program:

* Closes the `libsandbox` handle.
* Prints a summary tying the demo back to the conceptual model:

  * Effective permission = platform policy ∧ per-process policy ∧ active extensions.
  * Tokens are the runtime handle for `(extension ...)` filters compiled into the policy.

---

## 4. How to use this as a learning tool

Because issuance is expected to fail on a stock, unentitled CLI, you can treat this as a **pattern sketch** for extension usage:

1. **Baseline experiment**

   * Run the program as-is.
   * Note:

     * Baseline `open()` failure.
     * `sandbox_extension_issue_file` error code and errno.
   * Understand that this is how a “normal” process is kept from minting powerful tokens.

2. **Compare behavior in different contexts**

   * If you ever run similar code from a process that is known to be able to issue extensions (e.g., system component, entitlements present), you can:

     * Observe successful issuance.
     * See how `try_open()` changes between pre- and post-consumption.
   * This highlights the dynamic nature of extensions: the base profile stays the same, but an active extension flips `(extension ...)` filters from false to true.

3. **Connect to decoded SBPL**

   * In decoded profiles, look for rules like:

     * `(allow file-read* (extension "com.apple.app-sandbox.read"))`
   * Map that back to:

     * The `issue("com.apple.app-sandbox.read", ...)` call here.
     * The `consume(token)` step that actually activates the capability.

---

## 5. Lessons

1. **Scoped, dynamic capabilities via `(extension ...)` filters**

   * Issuing and consuming a token is the runtime side.
   * `(extension "…")` filters in SBPL are the policy side.
   * Together, they let you widen the sandbox temporarily without changing the base profile text.

2. **Third axis: platform ∧ process ∧ extension**

   * Platform policy: global rules for the OS / App Sandbox.
   * Per-process policy: the SBPL profile attached to this process.
   * Extension: live tokens added at runtime.
   * Effective permission is the conjunction: an operation is allowed only if all three agree.

3. **Entitlement and trust gating**

   * The failure of `sandbox_extension_issue_file` in this CLI context illustrates that:

     * Only trusted/entitled processes can mint meaningful tokens.
     * This protects the system from arbitrary users granting themselves extra capabilities via the extension mechanism.

4. **User-driven grants and temporary exceptions**

   * In real systems, extensions are commonly issued in response to:

     * user choosing a file in an open panel,
     * selecting photos, contacts, or similar sensitive content,
     * cross-process handoffs via Launch Services.
   * The static sandbox profile remains tight; extensions allow **specific, time-bound** exceptions.

