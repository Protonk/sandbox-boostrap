## 1. What this example is about

This example is a small **network probe** that lets you see how different socket calls show up to the sandbox as `network-outbound` operations:

* It opens a **TCP** socket and does `connect()`.
* It opens a **UDP** socket and does `sendto()`.
* It opens an **AF_UNIX** (local) socket and does `connect()`.

The code itself is intentionally simple; the point is to:

* Fix the process-side behavior (the same `socket`/`connect`/`sendto` calls),
* Then run under different sandbox policies and watch how **domain**, **type**, and **remote endpoint** become filter inputs for `network-outbound`.

You can think of `network_demo.c` as a reusable client: keep the client fixed, change SBPL, and observe which calls succeed or fail.

---

## 2. How to build and run

Single file:

* `network_demo.c`

Typical build:

```sh
clang network_demo.c -o network_demo
```

Then run:

```sh
./network_demo
```

On an unsandboxed system you will typically see:

* TCP:

  * Socket creation succeeds.
  * `connect()` returns `-1` with `ECONNREFUSED` unless something is listening on port 80.
* UDP:

  * Socket creation succeeds.
  * `sendto()` returns a positive byte count (even if nothing is listening).
* AF_UNIX:

  * Socket creation usually succeeds.
  * `connect()` to `/var/run/syslog` may succeed or fail depending on your system and permissions.

When you wrap this under `sandbox-exec` with various SBPL profiles, you’re looking for cases where **the sandbox denies the operation**, producing errors like `EPERM`, even though the unsandboxed behavior would have been “normal” (success or `ECONNREFUSED`).

---

## 3. How this maps to sandbox filters (from `lessons.md`)

The `lessons.md` file gives the conceptual framing:

* Network syscalls are grouped into operations like `network-outbound`.
* Filters include:

  * `socket-domain` (e.g., `AF_INET`, `AF_UNIX`),
  * `socket-type` (e.g., `SOCK_STREAM`, `SOCK_DGRAM`),
  * endpoint details (IP/port or path).
* TCP, UDP, and AF_UNIX exercise different combinations of those attributes.
* By keeping the client constant and changing policy, you see how SBPL rules like:

  * `network-outbound` + `(remote-address ...)`
  * `network-outbound` + `(local-address ...)`
  * `network-outbound` + `(socket-domain af_unix)` / `(socket-type datagram)`

  affect real syscalls.

The code is the concrete side of that: it generates a concise set of network calls that hit the `network-outbound` operation with different parameter combinations.

---

## 4. Walking through `network_demo.c`

### 4.1 Includes and context

```c
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
```

These give you:

* Socket APIs (`socket`, `connect`, `sendto`, `AF_INET`, `AF_UNIX`, etc.).
* Structures for IPv4 (`sockaddr_in`) and Unix domain sockets (`sockaddr_un`).
* `errno` and `strerror` for error reporting.

The comment ties it back to sandbox semantics:

```c
// Network operations surface as sandbox operations like `network-outbound`
// with filters on socket domain/type/remote (book/substrate/Appendix.md). This demo
// performs a few socket types so you can map process-side calls to sandbox
// vocabulary when reasoning about profiles.
```

The key idea: when the process makes these calls, Seatbelt sees:

* Operation: `network-outbound` (or similar).
* Attributes:

  * domain: `AF_INET` or `AF_UNIX`,
  * type: `SOCK_STREAM` or `SOCK_DGRAM`,
  * remote IP/port or Unix socket path.

---

### 4.2 TCP probe: `try_tcp`

```c
static void try_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("TCP socket creation failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    printf("TCP connect to %s:%d -> rc=%d errno=%d (%s)\n", ip, port, rc, errno, strerror(errno));
    close(fd);
}
```

What this does:

* Calls `socket(AF_INET, SOCK_STREAM, 0)`:

  * Domain: IPv4 (`AF_INET`).
  * Type: stream (`SOCK_STREAM`, i.e., TCP).
* Fills `sockaddr_in` with:

  * Family `AF_INET`,
  * Network-order port (via `htons`),
  * Parsed IPv4 address from `ip`.
* Calls `connect()` to that address.
* Prints:

  * return code `rc`,
  * `errno` and its string form.

Sandbox perspective:

* This is a `network-outbound` probe with:

  * `socket-domain` = `AF_INET`,
  * `socket-type` = `SOCK_STREAM`,
  * remote IP = `ip`, remote port = `port`.

Using it in `main`:

```c
try_tcp("127.0.0.1", 80);     // likely ECONNREFUSED unless a server is listening
```

On a typical system:

* If no server on port 80: `rc=-1`, `errno=ECONNREFUSED`.
* Under a restrictive sandbox: you may see `EPERM` or another sandbox-related error instead.

---

### 4.3 UDP probe: `try_udp`

```c
static void try_udp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("UDP socket creation failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    const char payload[] = "sandbox network demo";
    ssize_t sent = sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&addr, sizeof(addr));
    printf("UDP send to %s:%d -> bytes=%zd errno=%d (%s)\n", ip, port, sent, errno, strerror(errno));
    close(fd);
}
```

What this does:

* Calls `socket(AF_INET, SOCK_DGRAM, 0)`:

  * Domain: IPv4.
  * Type: datagram (`SOCK_DGRAM`, i.e., UDP).
* Sets up a similar `sockaddr_in`.
* Uses `sendto()` to send a small payload.

Sandbox perspective:

* Another `network-outbound` probe, but with:

  * `socket-type` = `SOCK_DGRAM` (datagram),
  * same IP/port pattern.

In `main`:

```c
try_udp("127.0.0.1", 5353);   // mDNS port; sendto may succeed silently
```

Typical behavior:

* Even if no one listens, a UDP send often returns the payload size and does not set `errno` to an error.
* Under a sandbox that forbids UDP but allows TCP, you might see:

  * creation or `sendto` fail with `EPERM`,
  * even though the TCP case is allowed.

This lets you test policies that distinguish **type** (`SOCK_STREAM` vs `SOCK_DGRAM`) while holding other variables constant.

---

### 4.4 AF_UNIX probe: `try_unix`

```c
static void try_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("AF_UNIX socket creation failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    printf("AF_UNIX connect to %s -> rc=%d errno=%d (%s)\n", path, rc, errno, strerror(errno));
    close(fd);
}
```

What this does:

* Calls `socket(AF_UNIX, SOCK_STREAM, 0)`:

  * Domain: Unix domain (`AF_UNIX`).
  * Type: stream.
* Fills a `sockaddr_un` with:

  * Family `AF_UNIX`,
  * Path `path` (copied with `strncpy`).
* Calls `connect()` to that Unix domain socket.
* Prints result and `errno`.

Sandbox perspective:

* This probes a different slice of `network-outbound` (or similar) where the “remote” is a **local path**, not an IP/port.
* Filters may apply to:

  * `socket-domain` = `af_unix`,
  * the `sun_path` path component,
  * perhaps combined with file-related predicates.

In `main`:

```c
try_unix("/var/run/syslog");  // illustrates AF_UNIX addressing
```

Behavior:

* On many systems, `/var/run/syslog` is a Unix domain socket used for syslog.
* The connect may succeed or fail depending on system configuration and permissions.
* Under a sandbox that restricts Unix-domain connections, you may see a sandbox-specific failure.

---

### 4.5 Main function: tying it together

```c
int main(void) {
    printf("Network filter probes (PID %d)\n\n", getpid());
    printf("Each call maps to `network-outbound` with filters like socket-domain/type/remote.\n");

    try_tcp("127.0.0.1", 80);     // likely ECONNREFUSED unless a server is listening
    try_udp("127.0.0.1", 5353);   // mDNS port; sendto may succeed silently
    try_unix("/var/run/syslog");  // illustrates AF_UNIX addressing

    printf("\nIf you apply a sandbox profile later, watch how rules on domain/type/remote\n");
    printf("affect these calls without changing the process-side code.\n");
    return 0;
}
```

The program:

* Prints its PID (useful for correlating with logs).
* Describes that each probe corresponds to a `network-outbound` operation.
* Then runs:

  * a TCP probe,
  * a UDP probe,
  * an AF_UNIX probe.
* Finishes with a reminder:

  * **Do not change the code; change the SBPL profile.**
  * Then observe how different policy rules affect these same syscalls.

This is the core usage pattern: keep the client constant; let the sandbox vary.

---

## 5. Using this example as a sandbox lab

A practical way to use this demo:

1. **Baseline unsandboxed run**

   * Run `./network_demo` normally.
   * Note:

     * Which probes succeed,
     * Which ones fail due to normal networking reasons (e.g., `ECONNREFUSED`).

2. **Apply a restrictive profile**

   * Write an SBPL profile that denies certain network combinations, e.g.:

     * Deny all `network-outbound`.
     * Allow only `AF_INET` TCP to loopback on some ports.
     * Deny all `AF_UNIX` sockets.

   * Run the program under `sandbox-exec`:

     * `sandbox-exec -f my_network_profile.sb ./network_demo`

   * Compare:

     * Are failures now `EPERM` instead of `ECONNREFUSED`?
     * Does UDP get denied while TCP is allowed (or vice versa)?
     * Does AF_UNIX behave differently from AF_INET?

3. **Iterate**

   * Adjust the profile:

     * Use filters like `socket-domain`, `socket-type`, `remote-address` (as per your filter vocabulary).
   * Re-run the same binary.
   * Treat the differences as a concrete visualization of how SBPL’s network filter vocabulary maps onto real syscalls.

In short, `network_demo.c` is a minimal, repeatable client that touches three common network shapes (TCP, UDP, AF_UNIX). `lessons.md` tells you how to interpret these as `network-outbound` operations with different domains, types, and endpoints. Together they make it easier to reason about network policy rules by grounding them in observed behavior.

## Lessons

- Network syscalls map to sandbox operations such as `network-outbound`, with filters for `socket-domain`, `socket-type`, and remote/local addresses (book/substrate/Appendix.md).
- TCP, UDP, and AF_UNIX sockets exercise different combinations of those filters; the same code path looks different to the sandbox depending on domain/type/port/path.
- Outside a sandbox these calls usually succeed (or fail with ECONNREFUSED), but under SBPL rules you can target very specific combinations, making network policy richer than early Seatbelt examples.
- Running a consistent client while changing policy is a good way to see how the filter vocabulary translates to real syscalls.