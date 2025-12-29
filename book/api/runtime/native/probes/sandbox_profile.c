/*
 * Shared SBPL profile application helper for sandboxed probes.
 *
 * This keeps the apply path and marker emission consistent across
 * sandbox_mach_probe and sandbox_iokit_probe.
 */

#include "sandbox_profile.h"

#include "../tool_markers.h"
#include <stdio.h>
#include <stdlib.h>

int sbl_apply_profile_from_path(const char *profile_path) {
    FILE *fp = fopen(profile_path, "r");
    if (!fp) {
        perror("open profile");
        return 66; /* EX_NOINPUT */
    }
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fprintf(stderr, "oom\n");
        fclose(fp);
        return 70; /* EX_SOFTWARE */
    }
    size_t nread = fread(buf, 1, (size_t)len, fp);
    fclose(fp);
    buf[nread] = '\0';

    char *err = NULL;
    sbl_apply_report_t report = sbl_sandbox_init_with_markers(buf, 0, &err, profile_path);
    free(buf);
    if (report.rc != 0) {
        fprintf(stderr, "sandbox_init failed: %s\n", err ? err : "unknown");
        if (err) {
            sbl_sandbox_free_error(err);
        }
        return 1;
    }
    if (err) {
        sbl_sandbox_free_error(err);
    }
    return 0;
}
