#include "../../api/runtime_tools/native/tool_markers.h"
#include <fcntl.h>
#include <unistd.h>

/*
 * sandbox_reader: apply SBPL profile from file via sandbox_init, then open
 * the target path read-only and write its contents to stdout. Avoids execing
 * external binaries so fewer allowances are needed.
 *
 * Usage: sandbox_reader <profile.sb> <path>
 */

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <profile.sb> <path>\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }
    const char *profile_path = argv[1];
    const char *target = argv[2];

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
        if (err) sandbox_free_error(err);
        return 1;
    }
    if (err) sandbox_free_error(err);

    sbl_maybe_seatbelt_callout_from_env("pre_syscall");
    int fd = open(target, O_RDONLY);
    if (fd < 0) {
        perror("open target");
        return 2;
    }
    char buf2[4096];
    ssize_t nr;
    while ((nr = read(fd, buf2, sizeof(buf2))) > 0) {
        if (write(STDOUT_FILENO, buf2, (size_t)nr) < 0) {
            perror("write");
            close(fd);
            return 3;
        }
    }
    if (nr < 0) {
        perror("read");
        close(fd);
        return 4;
    }
    close(fd);
    return 0;
}
