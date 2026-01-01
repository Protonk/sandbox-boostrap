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
#include <limits.h>
#include <sys/attr.h>
#include <sys/time.h>

static int build_search_name(const char *path, char *out, size_t out_len) {
    if (!path || !out || out_len == 0) return -1;
    size_t len = strnlen(path, out_len - 1);
    memcpy(out, path, len);
    out[len] = '\0';
    while (len > 1 && out[len - 1] == '/') {
        out[len - 1] = '\0';
        len--;
    }
    const char *base = strrchr(out, '/');
    if (base) {
        base++;
    } else {
        base = out;
    }
    memmove(out, base, strlen(base) + 1);
    return 0;
}

/* Entry point: run a single read/write probe and emit JSON on stdout. */
int main(int argc, char **argv) {
    if (argc < 3) {
        dprintf(2, "Usage: %s <read|write|search> <path>\n", argv[0]);
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
    } else if (!strcmp(op, "search")) {
        char name_buf[PATH_MAX];
        name_buf[0] = '\0';
        unsigned long matches = 0;
        int search_rc = -1;
        int search_errno = 0;
        int result_rc = 0;
        if (build_search_name(path, name_buf, sizeof(name_buf)) != 0) {
            result_rc = EINVAL;
            search_errno = EINVAL;
        } else {
            struct attrlist searchattrs;
            memset(&searchattrs, 0, sizeof(searchattrs));
            searchattrs.bitmapcount = ATTR_BIT_MAP_COUNT;
            searchattrs.commonattr = ATTR_CMN_NAME;

            struct attrlist returnattrs;
            memset(&returnattrs, 0, sizeof(returnattrs));
            returnattrs.bitmapcount = ATTR_BIT_MAP_COUNT;
            returnattrs.commonattr = ATTR_CMN_NAME;

            size_t name_len = strlen(name_buf) + 1;
            size_t params_len = sizeof(uint32_t) + sizeof(attrreference_t) + name_len;
            if (params_len > SEARCHFS_MAX_SEARCHPARMS) {
                result_rc = EINVAL;
                search_errno = EINVAL;
            } else {
                uint8_t *params = calloc(1, params_len);
                void *return_buf = calloc(1, 4096);
                if (!params || !return_buf) {
                    result_rc = ENOMEM;
                    search_errno = ENOMEM;
                } else {
                    *(uint32_t *)params = (uint32_t)params_len;
                    attrreference_t *ref = (attrreference_t *)(params + sizeof(uint32_t));
                    ref->attr_dataoffset = (int32_t)sizeof(attrreference_t);
                    ref->attr_length = (uint32_t)name_len;
                    memcpy(params + sizeof(uint32_t) + sizeof(attrreference_t), name_buf, name_len);

                    struct fssearchblock search;
                    memset(&search, 0, sizeof(search));
                    search.returnattrs = &returnattrs;
                    search.returnbuffer = return_buf;
                    search.returnbuffersize = 4096;
                    search.maxmatches = 1;
                    search.timelimit.tv_sec = 0;
                    search.timelimit.tv_usec = 200000;
                    search.searchparams1 = params;
                    search.sizeofsearchparams1 = params_len;
                    search.searchparams2 = NULL;
                    search.sizeofsearchparams2 = 0;
                    search.searchattrs = searchattrs;

                    struct searchstate state;
                    memset(&state, 0, sizeof(state));
                    errno = 0;
                    search_rc = searchfs(
                        path,
                        &search,
                        &matches,
                        0x08000103,
                        SRCHFS_START | SRCHFS_MATCHDIRS | SRCHFS_MATCHFILES,
                        &state
                    );
                    search_errno = (search_rc == -1) ? errno : 0;
                    if (search_rc == 0 || (search_rc == -1 && search_errno == EAGAIN)) {
                        result_rc = 0;
                    } else {
                        result_rc = search_errno ? search_errno : EIO;
                    }
                }
                if (params) free(params);
                if (return_buf) free(return_buf);
            }
        }
        rc = result_rc;
        dprintf(
            1,
            "{\"op\":\"%s\",\"path\":\"%s\",\"rc\":%d,\"errno\":%d,\"search_rc\":%d,\"search_errno\":%d,\"matches\":%lu,\"search_name\":\"%s\"}\n",
            op,
            path,
            rc,
            rc ? rc : 0,
            search_rc,
            search_errno,
            matches,
            name_buf
        );
        return rc ? 1 : 0;
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
