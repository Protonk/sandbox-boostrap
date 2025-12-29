/*
 * Minimal file probe for runtime allow/deny checks.
 *
 * The probe performs a single read or write and emits a tiny JSON summary so
 * higher-level tooling can normalize results without parsing stderr text.
 *
 * Small probes reduce ambiguity. A single open/read/write maps more
 * cleanly to a sandbox operation than a full-featured tool.
 */

#define _DARWIN_C_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* Entry point: run a single read/write probe and emit JSON on stdout. */
int main(int argc, char **argv) {
    if (argc < 3) {
        dprintf(2, "Usage: %s <read|write> <path>\n", argv[0]);
        return 2;
    }
    const char *op = argv[1];
    const char *path = argv[2];
    int rc = 0;
    if (!strcmp(op, "read")) {
        int fd = open(path, O_RDONLY);
        if (fd == -1) rc = errno; else {
            char buf[16];
            if (read(fd, buf, sizeof(buf)) == -1) rc = errno;
            close(fd);
        }
    } else if (!strcmp(op, "write")) {
        int fd = open(path, O_WRONLY | O_CREAT, 0644);
        if (fd == -1) rc = errno; else {
            const char *msg = "probe\n";
            if (write(fd, msg, strlen(msg)) == -1) rc = errno;
            close(fd);
        }
    } else {
        dprintf(2, "unknown op: %s\n", op);
        return 2;
    }
    /* Emit a tiny JSON summary to keep parsing deterministic. */
    dprintf(1, "{\"op\":\"%s\",\"path\":\"%s\",\"rc\":%d,\"errno\":%d}\n", op, path, rc, rc ? rc : 0);
    return rc ? 1 : 0;
}
