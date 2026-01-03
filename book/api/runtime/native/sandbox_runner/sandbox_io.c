/*
 * Shared sandbox_reader/sandbox_writer implementation.
 *
 * This file centralizes SBPL profile loading, sandbox_init application, and
 * FD-path emission so the read/write entrypoints stay behavior-identical.
 */

#include "sandbox_io.h"

#include "../tool_markers.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <unistd.h>

// Opt-in precreate for oracle calibration: ensure the target exists after apply.
#define SANDBOX_LORE_ENV_FILE_PRECREATE "SANDBOX_LORE_FILE_PRECREATE"

// Opt-in FD identity emission: record (st_dev, st_ino) and mount identity for
// successful opens. This is *diagnostic* evidence used to join alias spellings
// to the same underlying object; it is not a claim about Seatbelt's internal
// compare string.
//
// Non-fatal by design: if the sandbox denies metadata calls (e.g., fstat) after
// a successful open, the probe still proceeds with its read/write behavior.
#define SANDBOX_LORE_ENV_FD_IDENTITY "SANDBOX_LORE_FD_IDENTITY"

static int apply_profile(const char *profile_path) {
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

static void maybe_precreate_target(const char *target_path) {
    const char *precreate = getenv(SANDBOX_LORE_ENV_FILE_PRECREATE);
    if (!precreate || precreate[0] == '\0' || precreate[0] == '0') {
        return;
    }
    if (!target_path) {
        return;
    }
    int fd = open(target_path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        fprintf(stderr, "precreate target: %s\n", strerror(errno));
        return;
    }
    close(fd);
}

static void emit_fd_paths(int fd) {
    char pathbuf[PATH_MAX];
    if (fcntl(fd, F_GETPATH, pathbuf) == 0) {
        fprintf(stderr, "F_GETPATH:%s\n", pathbuf);
    } else {
        fprintf(stderr, "F_GETPATH_ERROR:%d\n", errno);
    }
#ifdef F_GETPATH_NOFIRMLINK
    char nofirmlink_buf[PATH_MAX];
    if (fcntl(fd, F_GETPATH_NOFIRMLINK, nofirmlink_buf) == 0) {
        fprintf(stderr, "F_GETPATH_NOFIRMLINK:%s\n", nofirmlink_buf);
    } else {
        fprintf(stderr, "F_GETPATH_NOFIRMLINK_ERROR:%d\n", errno);
    }
#else
    fprintf(stderr, "F_GETPATH_NOFIRMLINK_UNAVAILABLE\n");
#endif
}

static int env_truthy(const char *name) {
    const char *value = getenv(name);
    return value && value[0] != '\0' && value[0] != '0';
}

static void emit_fd_identity(int fd) {
    if (!env_truthy(SANDBOX_LORE_ENV_FD_IDENTITY)) {
        return;
    }

    fprintf(stderr, "FD_IDENTITY:1\n");

    struct stat st;
    if (fstat(fd, &st) == 0) {
        fprintf(stderr, "FSTAT_ST_DEV:%lld\n", (long long)st.st_dev);
        fprintf(stderr, "FSTAT_ST_INO:%lld\n", (long long)st.st_ino);
    } else {
        fprintf(stderr, "FSTAT_ERROR:%d\n", errno);
    }

    struct statfs sfs;
    if (fstatfs(fd, &sfs) == 0) {
        fprintf(stderr, "FSTATFS_FSTYPENAME:%s\n", sfs.f_fstypename);
        fprintf(stderr, "FSTATFS_MNTONNAME:%s\n", sfs.f_mntonname);
        fprintf(stderr, "FSTATFS_FSID0:%d\n", sfs.f_fsid.val[0]);
        fprintf(stderr, "FSTATFS_FSID1:%d\n", sfs.f_fsid.val[1]);
    } else {
        fprintf(stderr, "FSTATFS_ERROR:%d\n", errno);
    }
}

int sandbox_io_read(const char *profile_path, const char *target_path) {
    int rc = apply_profile(profile_path);
    if (rc != 0) {
        return rc;
    }

    maybe_precreate_target(target_path);
    sbl_maybe_seatbelt_callout_from_env("pre_syscall");
    int fd = open(target_path, O_RDONLY);
    if (fd < 0) {
        perror("open target");
        return 2;
    }
    emit_fd_paths(fd);
    emit_fd_identity(fd);
    char buf[4096];
    ssize_t nr;
    while ((nr = read(fd, buf, sizeof(buf))) > 0) {
        if (write(STDOUT_FILENO, buf, (size_t)nr) < 0) {
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

int sandbox_io_write(const char *profile_path, const char *target_path) {
    int rc = apply_profile(profile_path);
    if (rc != 0) {
        return rc;
    }

    sbl_maybe_seatbelt_callout_from_env("pre_syscall");
    int fd = open(target_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        perror("open target");
        return 2;
    }
    emit_fd_paths(fd);
    emit_fd_identity(fd);
    const char *line = "runtime-check\n";
    ssize_t nw = write(fd, line, strlen(line));
    if (nw < 0) {
        perror("write");
        close(fd);
        return 3;
    }
    close(fd);
    return 0;
}
