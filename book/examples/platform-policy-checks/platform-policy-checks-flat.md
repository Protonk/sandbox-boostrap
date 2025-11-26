## 1. What this example is about

This example is a **platform-policy probe**, not a sandbox profile demo:

* It runs **unsandboxed**.
* It pokes three classes of operations that are often guarded by global platform rules:

  * `sysctl` (kernel tunables and security knobs),
  * filesystem access to SIP-protected system paths,
  * Mach service lookup for privileged daemons.
* It logs `errno` and return codes so you can see the **final outcome** of each syscall.

The key lesson from `lessons.md`:

* Seatbelt evaluates a **global platform/App Sandbox policy first**.
* If that layer says “deny”, the syscall fails **before** your per-process SBPL profile is even considered.
* So “I allowed this in my custom profile, but it still fails” often means: platform policy blocked it.

`platform_policy.c` gives you concrete probes for this invisible first layer.

---

## 2. How to build and run

Single file:

* `platform_policy.c`

Typical build:

```sh
clang platform_policy.c -o platform_policy \
  -framework CoreServices
```

(Depending on your SDK, you may not need extra frameworks; the core needs are standard libc and Mach/Bootstrap headers.)

Then run:

```sh
./platform_policy
```

You will see:

* A header with the process PID.
* Results for:

  * Two `sysctl` names,
  * Two `open()` attempts (read and write),
  * Two `mach-lookup` attempts.
* Each line prints either a concrete value (on success) or `errno` / Mach status.

This run is your **baseline**: it shows how an unsandboxed user process fares against platform policy and SIP.

---

## 3. Lessons from `lessons.md`

The `lessons.md` framing is:

* Platform policy runs **before** per-process SBPL:

  * A global deny short-circuits the syscall.
  * Your own profile never gets a chance to say “allow”.
* Platform rules often guard:

  * `sysctl` operations via `sysctl-name` predicates,
  * filesystem operations on SIP-protected volumes via `csr` / `system-attribute` filters,
  * Mach services via filters keyed on service names.
* From the outside you only see:

  * `errno` for syscalls,
  * `kern_return_t` for Mach calls.
* When a “harmless-looking” operation fails even under a permissive profile, you infer platform involvement.

`platform_policy.c` supplies concrete examples in each category.

---

## 4. Walking through `platform_policy.c`

### 4.1 Includes and context

```c
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>
```

* `sysctl.h` for `sysctlbyname`.
* `fcntl.h` for `open` flags like `O_CREAT`.
* `mach.h` and `bootstrap.h` for Mach ports and `bootstrap_look_up`.
* `errno` + `strerror` for user-level error reporting.

The file-level comment makes the intent explicit:

> We log errno so you can reason about whether platform policy likely short-circuited the attempt before any per-process SBPL rules mattered.

This is a **diagnostic harness**, not a sandbox.

---

### 4.2 `try_sysctl`: probing kernel tunables

```c
static void try_sysctl(const char *name) {
    int value = 0;
    size_t size = sizeof(value);
    int rc = sysctlbyname(name, &value, &size, NULL, 0);
    if (rc == 0) {
        printf("sysctl %s succeeded -> %d\n", name, value);
    } else {
        printf("sysctl %s failed rc=%d errno=%d (%s)\n", name, rc, errno, strerror(errno));
    }
}
```

What it does:

* Calls `sysctlbyname` to read an integer value for a given `name`.
* On success:

  * Prints the sysctl name and the read value.
* On failure:

  * Prints the return code (`rc`) and `errno` plus its string form.

Sysctl lens:

* Some sysctls are readable by any user.
* Others are restricted to root or require entitlements / platform privileges.
* Seatbelt has `sysctl` operations and `sysctl-name` filters, but **platform policy can deny regardless of per-process SBPL**.

In `main`:

```c
try_sysctl("kern.bootsessionuuid");          // usually allowed
try_sysctl("security.mac.vnode_enforce_name"); // often restricted to root/platform
```

* First call is a “safe” sysctl that tends to succeed.
* Second call is a more security-sensitive tunable that often fails for non-root processes.

Comparing the two:

* Same code path, different sysctl names.
* Different outcomes highlight where platform policy draws boundaries.

---

### 4.3 `try_open`: SIP-protected filesystem paths

```c
static void try_open(const char *path, int flags) {
    int fd = open(path, flags, 0644);
    if (fd >= 0) {
        printf("open(\"%s\", flags=0x%x) -> success (fd=%d)\n", path, flags, fd);
        close(fd);
    } else {
        printf("open(\"%s\", flags=0x%x) -> errno=%d (%s)\n", path, flags, errno, strerror(errno));
    }
}
```

What it does:

* Attempts `open(path, flags, 0644)`.
* On success:

  * Prints that it succeeded, with the file descriptor.
* On failure:

  * Prints the `errno` and its description.

In `main`:

```c
try_open("/System/Library/CoreServices/SystemVersion.plist", O_RDONLY);
try_open("/System/Library/PlatformPolicyDemo.txt", O_WRONLY | O_CREAT | O_TRUNC);
```

Scenarios:

1. `O_RDONLY` on a system plist:

   * Reading is often allowed even on SIP-protected paths, but can be tightened by platform policy.
   * If this fails with `EPERM` or another error, it’s a hint that platform rules are involved.

2. `O_WRONLY | O_CREAT | O_TRUNC` on a path under `/System`:

   * Writing or creating on the sealed system volume is typically blocked:

     * `EPERM`, `EROFS`, or a similar error.
   * This is a classic SIP guard: even if a custom SBPL profile allowed `file-write*` on `/System`, platform rules override it.

Takeaway:

* The per-process profile never gets a chance to allow writes to paths the platform has sealed.
* When your “sandbox profile says yes” but `open(O_CREAT)` still yields `EPERM`, this is a symptom of platform policy winning.

---

### 4.4 `try_mach_lookup`: privileged Mach services

```c
static void try_mach_lookup(const char *service) {
    mach_port_t port = MACH_PORT_NULL;
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
        printf("mach-lookup %s skipped: no bootstrap port\n", service);
        return;
    }

    kern_return_t kr = bootstrap_look_up(bootstrap, service, &port);
    if (kr == KERN_SUCCESS) {
        printf("mach-lookup \"%s\" -> success (port=%u)\n", service, port);
        mach_port_deallocate(mach_task_self(), port);
    } else {
        printf("mach-lookup \"%s\" -> kr=0x%x (%s)\n", service, kr, mach_error_string(kr));
    }
}
```

What it does:

* Fetches the process’s bootstrap port (`TASK_BOOTSTRAP_PORT`).
* Calls `bootstrap_look_up` to resolve a service name to a Mach port.
* On success:

  * Prints the service name and port, then deallocates it.
* On failure:

  * Prints the `kern_return_t` and a human-readable description.

In `main`:

```c
try_mach_lookup("com.apple.cfprefsd.daemon"); // likely succeeds
try_mach_lookup("com.apple.securityd");       // often denied/not found
```

Scenarios:

1. `com.apple.cfprefsd.daemon`:

   * A common, comparatively non-privileged service.
   * Lookup usually succeeds for normal user processes.

2. `com.apple.securityd`:

   * A high-privilege security daemon.
   * Platform policy often restricts who can talk to it.
   * You may see failures:

     * Not found,
     * Or denied based on bootstrap namespace / sandbox rules.

Sandbox lens:

* `mach-lookup` is a sandbox operation.
* SBPL filters on service names (e.g., `(global-name "com.apple.securityd")`).
* But **platform rules can deny lookups to certain names for everyone except trusted components**, regardless of any per-process profile.

---

### 4.5 `main`: pulling the probes together

```c
int main(void) {
    printf("Platform policy probes (PID %d)\n\n", getpid());

    // sysctl probes
    try_sysctl("kern.bootsessionuuid");          
    try_sysctl("security.mac.vnode_enforce_name");

    // Filesystem probes
    try_open("/System/Library/CoreServices/SystemVersion.plist", O_RDONLY);
    try_open("/System/Library/PlatformPolicyDemo.txt", O_WRONLY | O_CREAT | O_TRUNC);

    // Mach probes
    try_mach_lookup("com.apple.cfprefsd.daemon");
    try_mach_lookup("com.apple.securityd");

    printf("\nRemember: platform policy runs before any per-process sandbox (substrate/Orientation.md §2),\n");
    printf("so failures here can come from global rules even if a custom SBPL profile looks permissive.\n");
    return 0;
}
```

The structure is:

* Print PID and a brief description.
* Run:

  * Two sysctl probes,
  * Two filesystem probes,
  * Two Mach lookups.
* Print a final reminder that **platform policy is evaluated first**.

You can treat each group (sysctl / open / Mach) as a separate axis of “platform vs app policy”.

---

## 5. How to use this example as a learning tool

A practical workflow:

1. **Baseline unsandboxed run**

   * Run `./platform_policy` as a normal user.
   * Record:

     * Which probes succeed,
     * What `errno` you see on failures,
     * What Mach status codes appear.
   * This gives you a snapshot of platform policy as experienced by a plain process.

2. **Compare with custom SBPL**

   * Create a permissive SBPL profile that:

     * allows corresponding sysctls,
     * allows `file-read*`/`file-write*` for the tested paths,
     * allows `mach-lookup` for the tested services.
   * Run **other test programs** under that profile, trying the same operations.
   * When you see failures despite permissive rules, recall this program:

     * If unsandboxed behavior already failed, the blocker is platform policy, not your profile.

3. **Change context (root / entitlements / SIP state)**

   * If you can experiment in a controlled environment:

     * Run `platform_policy` as root.
     * Run it on a system with different SIP settings.
   * Compare outputs.
   * This shows you how platform-layer decisions shift with privileges and configuration, independently of per-process profiles.

4. **Use errno as a hint, not a proof**

   * `EPERM`, `EACCES`, `EROFS`, `ENOTSUP`, and Mach errors can originate from many layers.
   * This program helps you build intuition:

     * “This sysctl always fails as a user but not as root.”
     * “This path can never be created under `/System`.”
     * “This Mach service is globally off-limits.”
   * That intuition helps when debugging later SBPL experiments.

Overall, `platform_policy.c` is a **baseline probe** for the global platform layer. It reminds you that not all denials are about your SBPL profiles: some operations are blocked long before Seatbelt ever looks at your per-process rules.
