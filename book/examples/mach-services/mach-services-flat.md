## 1. What this example is about

This example is a **Mach service probe** focused on the sandboxed `mach-lookup` operation:

* `mach_server.c` registers a simple Mach bootstrap service name.
* `mach_client.c` tries to look that name up, plus a couple of real system services.
* You observe which lookups succeed or fail.

The key idea: **`mach-lookup` is itself a sandbox operation**. Seatbelt evaluates filters like `(global-name "com.apple.securityd")` to decide whether a process may talk to a given bootstrap service. This example gives you a small, controlled repro for that path.

---

## 2. How to build and run

There’s no Makefile here in the snapshot, but the files are standalone C programs. A typical workflow:

1. Build the server:

   ```sh
   clang mach_server.c -o mach_server
   ```

2. Build the client:

   ```sh
   clang mach_client.c -o mach_client
   ```

3. Run the server in one terminal:

   ```sh
   ./mach_server
   ```

   You should see something like:

   * “Registered Mach service "com.example.xnusandbox.demo". PID=…”
   * Instructions to leave it running.

4. While the server is still running, run the client in another terminal:

   ```sh
   ./mach_client
   ```

   You’ll see:

   * A header with the client PID.
   * Lookup results for:

     * `com.example.xnusandbox.demo`
     * `com.apple.cfprefsd.daemon`
     * `com.apple.securityd`

You do **not** implement full Mach message handling here; the goal is just registration and lookup, which exercises the same kernel path Seatbelt filters.

---

## 3. Lessons

- `mach-lookup` is a first-class sandbox operation; SBPL filters on `(global-name "...")` or related predicates to control which bootstrap services a process can talk to.
- Platform policy may deny lookups/registrations regardless of per-process profiles—especially for privileged services like `com.apple.securityd`.
- Watching success/failure against different names shows how service strings become sandbox inputs, matching the operation/filter vocabulary in book/substrate/Appendix.md.
- Even without full message handling, registering a name and trying to look it up mirrors the kernel path that Seatbelt protects via the policy graph.
- Lookup failures can also reflect bootstrap namespace limits or missing services, so compare runs under different sandbox profiles to distinguish policy from “service not present”.


---

## 4. Server: registering a Mach service (`mach_server.c`)

### 4.1 Getting the bootstrap port

```c
static const char *kServiceName = "com.example.xnusandbox.demo";

int main(void) {
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get bootstrap port\n");
        return 1;
    }
```

* `TASK_BOOTSTRAP_PORT` is the process’s handle into the launchd bootstrap namespace.
* If this call fails, you can’t register a service name, so the server exits.

The sandbox side:

* The ability to talk to the bootstrap port itself can be sandboxed.
* This is the entry point for both registration and lookup.

### 4.2 Allocating a receive port

```c
    mach_port_t recv_port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv_port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_port_allocate failed: %s\n", mach_error_string(kr));
        return 1;
    }
    kr = mach_port_insert_right(mach_task_self(), recv_port, recv_port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "mach_port_insert_right failed: %s\n", mach_error_string(kr));
        return 1;
    }
```

This:

* Allocates a Mach receive right (`recv_port`).
* Inserts a send right for the same port into your task’s namespace.

Conceptual mapping:

* `recv_port` is where clients would send messages.
* The example doesn’t implement message handling; it just needs a **valid port** to hang the service name on.

### 4.3 Registering the service name

```c
    // bootstrap_register2 is the modern way to register a service port.
    kr = bootstrap_register2(bootstrap, kServiceName, recv_port, 0);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "bootstrap_register2(\"%s\") failed: %s\n", kServiceName, mach_error_string(kr));
        return 1;
    }

    printf("Registered Mach service \"%s\". PID=%d\n", kServiceName, getpid());
    printf("Leave this running and start the client in another shell.\n");
    printf("mach-lookup checks are sandbox operations filtered on the service name.\n");
```

* `bootstrap_register2` associates `kServiceName` with `recv_port` in the local bootstrap namespace.
* If registration fails, you’ll see the error; potential reasons include:

  * sandbox policy,
  * bootstrap restrictions,
  * name conflicts.

From the sandbox perspective:

* Registration of certain names may be restricted by platform policy.
* This is the **inverse operation** to `mach-lookup`: both are mediated by Seatbelt rules over bootstrap names.

### 4.4 Keeping the service alive

```c
    // Keep the service alive briefly; we do not implement full message handling
    // because the point here is registration/lookup behavior.
    sleep(30);
    return 0;
}
```

* The `sleep(30)` keeps the process alive long enough for you to run the client.
* No message loop is required for this example, because you’re only interested in registration and lookup, not actual RPC behavior.

---

## 5. Client: exercising `mach-lookup` (`mach_client.c`)

### 5.1 Getting the bootstrap port

```c
static void lookup(const char *service) {
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
        fprintf(stderr, "No bootstrap port; cannot query %s\n", service);
        return;
    }
```

Same pattern:

* Fetch the bootstrap port for the current process.
* If unavailable, you can’t perform `mach-lookup`.

### 5.2 Doing the lookup

```c
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap, service, &port);
    if (kr == KERN_SUCCESS) {
        printf("mach-lookup \"%s\" -> success (port=%u)\n", service, port);
        mach_port_deallocate(mach_task_self(), port);
    } else {
        printf("mach-lookup \"%s\" -> kr=0x%x (%s)\n", service, kr, mach_error_string(kr));
    }
}
```

* `bootstrap_look_up` asks the bootstrap server for the port registered under `service`.
* On success:

  * You get a send right in `port`.
  * The client prints the port number and deallocates it.
* On failure:

  * It prints the `kern_return_t` and string description.

Sandbox lens:

* `mach-lookup` is the operation Seatbelt sees.
* The **service string** (e.g., `"com.apple.securityd"`) feeds into SBPL predicates like `(global-name "com.apple.securityd")`.
* The platform/App Sandbox profiles can deny lookups even if the server exists.

### 5.3 Driving the lookups

```c
int main(void) {
    printf("Mach lookup client (PID %d)\n", getpid());
    printf("Try running the server first for the demo service.\n\n");

    lookup("com.example.xnusandbox.demo");    // should succeed if server is alive
    lookup("com.apple.cfprefsd.daemon");      // typically allowed
    lookup("com.apple.securityd");            // often denied/restricted

    return 0;
}
```

Three cases:

1. `com.example.xnusandbox.demo`

   * Uses the service name from the server.
   * If the server is running and policy allows it, this lookup should succeed.
   * This tests an **ad-hoc, unprivileged name**.

2. `com.apple.cfprefsd.daemon`

   * A common system service.
   * Typically allowed for most processes, so you often see `KERN_SUCCESS`.
   * This is a representative “normal” system name.

3. `com.apple.securityd`

   * A privileged security daemon.
   * Often protected more strictly; lookups may be denied or restricted.
   * Here you can see how the same client, same code path, gets different behavior just because of the **service string**.

Watching these three calls side-by-side gives you a concrete feel for the policy’s string-based decisions.

---

## 6. How to use this as a learning tool

To get value from this example:

1. **Baseline behavior**

   * Run `mach_server`, then `mach_client`.
   * Note:

     * Whether the custom service lookup succeeds.
     * The return codes for the two system service lookups.

2. **Sandboxed vs unsandboxed**

   * If you have a way to run the client under a sandbox profile (e.g., via `sandbox-exec` or a custom Seatbelt profile), compare:

     * Lookup results for the same three services.
   * In decoded SBPL, look for:

     * operations like `mach-lookup`,
     * filters like `(global-name "com.apple.cfprefsd.daemon")`,
     * and see how they align with what you observe.

3. **Varying service names**

   * Try additional known system services:

     * `com.apple.Finder`,
     * others from launchd plists.
   * Observe which names are allowed vs denied, treating each name as an **input to the policy graph**.

4. **Connect to the lessons**

   * The concrete lookups in `mach_client.c` are the runtime probes.
   * `lessons.md` explains:

     * why `mach-lookup` matters as an operation,
     * how `global-name` predicates are used in SBPL,
     * and why platform policy can override or narrow what per-process profiles suggest.

Reading and running `mach_server.c` and `mach_client.c` alongside `lessons.md` turns Mach services from an abstract mention in the filter vocabulary into something you can see and poke: service names in, sandbox decisions out.
