#include <errno.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "../../../../api/runtime/native/tool_markers.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int read_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf));
    (void)n;
    close(fd);
    return 0;
}

static int mach_lookup(const char *service, int *kr_out) {
    mach_port_t bootstrap = MACH_PORT_NULL;
    if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
        return -1;
    }
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap, service, &port);
    if (kr_out) {
        *kr_out = (int)kr;
    }
    if (kr == KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), port);
    }
    return 0;
}

static char *read_file_to_buf(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long len = ftell(f);
    if (len < 0) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    char *buf = (char *)calloc((size_t)len + 1, 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

static void maybe_seatbelt_callout(const char *stage, const char *operation, long filter_type, const char *argument) {
    const char *enabled = getenv(SANDBOX_LORE_ENV_SEATBELT_CALLOUT);
    if (!enabled || strcmp(enabled, "1") != 0) return;
    if (!operation || !argument) return;

    int use_pid = 0;
    const char *api_env = getenv(SANDBOX_LORE_ENV_SEATBELT_API);
    if (api_env && (strcmp(api_env, "pid") == 0 || strcmp(api_env, "sandbox_check") == 0)) {
        use_pid = 1;
    }

    int call_raw = 1;
    int call_canonical = 0;
    const char *canonical_env = getenv(SANDBOX_LORE_ENV_SEATBELT_CANONICAL);
    if (canonical_env) {
        if (strcmp(canonical_env, "both") == 0) {
            call_raw = 1;
            call_canonical = 1;
        } else if (strcmp(canonical_env, "1") == 0 || strcmp(canonical_env, "canonical") == 0) {
            call_raw = 0;
            call_canonical = 1;
        }
    }

    if (call_raw) {
        sbl_seatbelt_callout_variant(stage, operation, filter_type, argument, use_pid, 0, "raw");
    }
    if (call_canonical) {
        sbl_seatbelt_callout_variant(stage, operation, filter_type, argument, use_pid, 1, "canonical");
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <sbpl_path> <allowed_path> <denied_path> <mach_service>\n", argv[0]);
        return 2;
    }
    const char *sbpl_path = argv[1];
    const char *allowed_path = argv[2];
    const char *denied_path = argv[3];
    const char *mach_service = argv[4];

    char *profile = read_file_to_buf(sbpl_path);
    if (!profile) {
        fprintf(stderr, "failed to read SBPL from %s\n", sbpl_path);
        return 3;
    }

    char *err = NULL;
    sbl_apply_report_t report = sbl_sandbox_init_with_markers(profile, 0, &err, sbpl_path);
    int rc = report.rc;
    free(profile);
    if (rc != 0) {
        fprintf(stderr, "sandbox_init failed: %s\n", err ? err : "unknown");
        if (err) {
            sbl_sandbox_free_error(err);
        }
        return 4;
    }
    if (err) {
        sbl_sandbox_free_error(err);
    }

    maybe_seatbelt_callout("pre_allowed_read", "file-read*", SBL_FILTER_PATH, allowed_path);
    int allowed_rc = read_file(allowed_path);
    maybe_seatbelt_callout("pre_denied_read", "file-read*", SBL_FILTER_PATH, denied_path);
    int denied_rc = read_file(denied_path);
    int allowed_errno = allowed_rc < 0 ? -allowed_rc : 0;
    int denied_errno = denied_rc < 0 ? -denied_rc : 0;

    int kr = 0;
    maybe_seatbelt_callout("pre_mach_lookup", "mach-lookup", SBL_FILTER_GLOBAL_NAME, mach_service);
    mach_lookup(mach_service, &kr);

    printf("{\"sandbox_init\":%d,", rc);
    printf("\"allowed_read_rc\":%d,", allowed_rc);
    printf("\"allowed_errno\":%d,", allowed_errno);
    printf("\"denied_read_rc\":%d,", denied_rc);
    printf("\"denied_errno\":%d,", denied_errno);
    printf("\"mach_lookup_kr\":%d}\n", kr);

    return 0;
}
