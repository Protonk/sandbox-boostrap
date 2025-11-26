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
// policy (evaluated first per substrate/Orientation.md) likely short-circuited
// the attempt before any per-process SBPL rules mattered.

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

int main(void) {
    printf("Platform policy probes (PID %d)\n\n", getpid());

    // sysctl probes: some names are readable by anyone, others are root/entitlement
    // gated. SBPL has `sysctl` operations, but platform policy can deny regardless
    // of per-process rules.
    try_sysctl("kern.bootsessionuuid");          // usually allowed
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

    printf("\nRemember: platform policy runs before any per-process sandbox (substrate/Orientation.md §2),\n");
    printf("so failures here can come from global rules even if a custom SBPL profile looks permissive.\n");
    return 0;
}
