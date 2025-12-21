#include "../../api/runtime_tools/native/tool_markers.h"

/*
 * sandbox_runner: apply an SBPL profile (from file) to the current process via
 * sandbox_init, then exec the provided command.
 *
 * Usage: sandbox_runner <profile.sb> -- <cmd> [args...]
 */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> -- <cmd> [args...]\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    /* find "--" separator */
    int sep = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            sep = i;
            break;
        }
    }
    if (sep < 0 || sep == argc - 1) {
        usage(argv[0]);
        return 64;
    }

    const char *profile_path = argv[1];
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
            sandbox_free_error(err);
        }
        return 1;
    }
    if (err) {
        sandbox_free_error(err);
    }

    /* exec command after "--" */
    char **cmd = &argv[sep + 1];
    sbl_maybe_seatbelt_callout_from_env("preflight");
    execvp(cmd[0], cmd);
    int saved_errno = errno;
    if (saved_errno == EPERM) {
        sbl_maybe_seatbelt_process_exec_callout("bootstrap_exec", cmd[0]);
    }
    sbl_emit_sbpl_exec_marker(-1, saved_errno, cmd[0]);
    perror("execvp");
    return 127;
}
