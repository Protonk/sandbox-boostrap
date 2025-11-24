#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Minimal illustration of the libsandbox extension API pattern. Real issuance
// typically requires entitlements and trusted callers; on a stock macOS 14.1
// build this program will likely fail to issue anything meaningful. The point
// is to show how SBPL’s `(extension ...)` filters map to tokens that widen a
// sandbox dynamically (guidance/Appendix.md §5).

typedef int (*issue_fn)(const char *ext, const char *path, int flags, char **token);
typedef int (*consume_fn)(const char *token);
typedef int (*release_fn)(const char *token);

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

int main(void) {
    const char *target = "/private/var/db/ConfigurationProfiles"; // usually protected
    printf("Sandbox extension demo targeting: %s\n", target);
    printf("Expect issuance to fail without entitlements; focus on the API steps.\n\n");

    try_open(target); // baseline attempt without any extension

    void *handle = dlopen("/usr/lib/libsandbox.dylib", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Failed to load libsandbox: %s\n", dlerror());
        return 1;
    }

    issue_fn issue = (issue_fn)dlsym(handle, "sandbox_extension_issue_file");
    consume_fn consume = (consume_fn)dlsym(handle, "sandbox_extension_consume");
    release_fn release = (release_fn)dlsym(handle, "sandbox_extension_release");
    if (!issue || !consume || !release) {
        fprintf(stderr, "Required symbols not found in libsandbox\n");
        dlclose(handle);
        return 1;
    }

    char *token = NULL;
    int rc = issue("com.apple.app-sandbox.read", target, 0, &token);
    if (rc != 0) {
        printf("sandbox_extension_issue_file failed rc=%d errno=%d (%s)\n",
               rc, errno, strerror(errno));
        printf("On systems without the right entitlements, issuance is denied by design.\n");
    } else {
        printf("Issued extension token: %s\n", token);
        // Consume installs the token into this process’s label so SBPL filters
        // like (extension \"com.apple.app-sandbox.read\") can match during checks.
        if (consume(token) == 0) {
            printf("Consumed extension token, retrying open...\n");
            try_open(target);
        } else {
            printf("Consuming extension failed errno=%d (%s)\n", errno, strerror(errno));
        }

        // Release returns the token to libsandbox; real clients do this once the
        // temporary capability is no longer needed.
        release(token);
    }

    dlclose(handle);
    printf("\nExtensions act as a third dimension: platform policy ∧ process policy ∧ active extensions.\n");
    printf("Tokens map directly to `(extension ...)` filters compiled into the policy graph.\n");
    return 0;
}
