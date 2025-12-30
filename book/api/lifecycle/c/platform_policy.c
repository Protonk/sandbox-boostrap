#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

// This program runs unsandboxed but pokes operations that platform policy or SIP
// commonly restricts. We log errno so you can reason about whether platform
// policy (evaluated first per book/substrate/Orientation.md) likely short-circuited
// the attempt before any per-process SBPL rules mattered.

static void json_print_string(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c == '\n') {
            fputs("\\n", stdout);
        } else if (c == '\r') {
            fputs("\\r", stdout);
        } else if (c == '\t') {
            fputs("\\t", stdout);
        } else if (c < 0x20) {
            printf("\\u%04x", c);
        } else {
            putchar(c);
        }
    }
    putchar('"');
}

static void json_print_nullable_error(int err) {
    if (err == 0) {
        fputs("null", stdout);
        return;
    }
    json_print_string(strerror(err));
}

static void jsonl_sysctl(const char *name) {
    errno = 0;
    int value = 0;
    size_t size = sizeof(value);
    int rc = sysctlbyname(name, &value, &size, NULL, 0);
    int err = (rc == 0) ? 0 : errno;
    printf("{\"kind\":\"sysctl\",\"pid\":%d,\"name\":", getpid());
    json_print_string(name);
    printf(",\"rc\":%d,\"errno\":%d,\"error\":", rc, err);
    json_print_nullable_error(err);
    printf(",\"value\":");
    if (rc == 0 && size == sizeof(value)) {
        printf("%d", value);
    } else {
        fputs("null", stdout);
    }
    printf("}\n");
}

static void jsonl_open(const char *path, int flags) {
    errno = 0;
    int fd = open(path, flags, 0644);
    int err = (fd >= 0) ? 0 : errno;
    printf("{\"kind\":\"open\",\"pid\":%d,\"path\":", getpid());
    json_print_string(path);
    printf(",\"flags\":%d,\"fd\":", flags);
    if (fd >= 0) {
        printf("%d", fd);
    } else {
        fputs("null", stdout);
    }
    printf(",\"errno\":%d,\"error\":", err);
    json_print_nullable_error(err);
    printf("}\n");
    if (fd >= 0) {
        close(fd);
    }
}

static void jsonl_mach_lookup(const char *service) {
    mach_port_t port = MACH_PORT_NULL;
    mach_port_t bootstrap = MACH_PORT_NULL;
    kern_return_t kr = task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap);
    if (kr != KERN_SUCCESS) {
        printf("{\"kind\":\"mach_lookup\",\"pid\":%d,\"service\":", getpid());
        json_print_string(service);
        printf(",\"kr\":%d,\"kr_string\":", (int)kr);
        json_print_string(mach_error_string(kr));
        printf(",\"port\":null,\"note\":\"no_bootstrap_port\"}\n");
        return;
    }

    kr = bootstrap_look_up(bootstrap, service, &port);
    printf("{\"kind\":\"mach_lookup\",\"pid\":%d,\"service\":", getpid());
    json_print_string(service);
    printf(",\"kr\":%d,\"kr_string\":", (int)kr);
    json_print_string(mach_error_string(kr));
    printf(",\"port\":");
    if (kr == KERN_SUCCESS) {
        printf("%u", port);
    } else {
        fputs("null", stdout);
    }
    printf("}\n");
    if (kr == KERN_SUCCESS && port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), port);
    }
}

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

static void try_open(const char *path, int flags) {
    int fd = open(path, flags, 0644);
    if (fd >= 0) {
        printf("open(\"%s\", flags=0x%x) -> success (fd=%d)\n", path, flags, fd);
        close(fd);
    } else {
        printf("open(\"%s\", flags=0x%x) -> errno=%d (%s)\n", path, flags, errno, strerror(errno));
    }
}

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

int main(int argc, char **argv) {
    bool jsonl_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--jsonl") == 0) {
            jsonl_mode = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "usage: %s [--jsonl]\n", argv[0]);
            return 64;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 64;
        }
    }

    if (jsonl_mode) {
        jsonl_sysctl("kern.bootsessionuuid");
        jsonl_sysctl("security.mac.vnode_enforce_name");
        jsonl_open("/System/Library/CoreServices/SystemVersion.plist", O_RDONLY);
        jsonl_open("/System/Library/PlatformPolicyDemo.txt", O_WRONLY | O_CREAT | O_TRUNC);
        jsonl_mach_lookup("com.apple.cfprefsd.daemon");
        jsonl_mach_lookup("com.apple.securityd");
        return 0;
    }

    printf("Platform policy probes (PID %d)\n\n", getpid());

    // sysctl probes: some names are readable by anyone, others are root/entitlement
    // gated. SBPL has `sysctl` operations, but platform policy can deny regardless
    // of per-process rules.
    try_sysctl("kern.bootsessionuuid");            // usually allowed
    try_sysctl("security.mac.vnode_enforce_name"); // often restricted to root/platform

    // Filesystem probes: SIP + platform policy guard system paths even when your
    // own profile would allow file-write*. O_CREAT on the sealed system volume
    // typically yields EPERM/EROFS.
    try_open("/System/Library/CoreServices/SystemVersion.plist", O_RDONLY);
    try_open("/System/Library/PlatformPolicyDemo.txt", O_WRONLY | O_CREAT | O_TRUNC);

    // Mach probes: mach-lookup is a sandbox operation; platform policy frequently
    // denies lookups to privileged services regardless of process SBPL.
    try_mach_lookup("com.apple.cfprefsd.daemon"); // likely succeeds
    try_mach_lookup("com.apple.securityd");       // often denied/not found

    printf("\nRemember: platform policy runs before any per-process sandbox (book/substrate/Orientation.md §2),\n");
    printf("so failures here can come from global rules even if a custom SBPL profile looks permissive.\n");
    return 0;
}
