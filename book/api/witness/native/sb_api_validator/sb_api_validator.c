#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define SANDBOX_CHECK_NO_REPORT    0x40000000

enum sandbox_filter_type {
    SANDBOX_FILTER_NONE                     = 0,
    SANDBOX_FILTER_PATH                     = 1,
    SANDBOX_FILTER_GLOBAL_NAME              = 2,
    SANDBOX_FILTER_LOCAL_NAME               = 3,
    SANDBOX_FILTER_APPLEEVENT_DESTINATION   = 4,
    SANDBOX_FILTER_RIGHT_NAME               = 5,
    SANDBOX_FILTER_PREFERENCE_DOMAIN        = 6,
    SANDBOX_FILTER_KEXT_BUNDLE_ID           = 7,
    SANDBOX_FILTER_INFO_TYPE                = 8,
    SANDBOX_FILTER_NOTIFICATION             = 9,
    SANDBOX_FILTER_FILE_DESCRIPTOR          = 10,
    SANDBOX_FILTER_AUDIT_TOKEN_ATTR         = 11,
    SANDBOX_FILTER_XPC_SERVICE_NAME         = 12,
    SANDBOX_FILTER_IOKIT_CONNECTION         = 13,
    SANDBOX_FILTER_IOKIT_USER_CLIENT_CLASS  = 14,
    SANDBOX_FILTER_NVRAM_VARIABLE           = 15,
    SANDBOX_FILTER_SYSCTL_NAME              = 16,
    SANDBOX_FILTER_POSIX_IPC_NAME           = 17,
    SANDBOX_FILTER_MESSAGE_FILTER           = 18,
};

static const char *filter_names[] = {
    "NONE", "PATH", "GLOBAL_NAME", "LOCAL_NAME", "APPLEEVENT_DESTINATION",
    "RIGHT_NAME", "PREFERENCE_DOMAIN", "KEXT_BUNDLE_ID", "INFO_TYPE",
    "NOTIFICATION", "FILE_DESCRIPTOR", "AUDIT_TOKEN_ATTR", "XPC_SERVICE_NAME",
    "IOKIT_CONNECTION", "IOKIT_USER_CLIENT_CLASS", "NVRAM_VARIABLE",
    "SYSCTL_NAME", "POSIX_IPC_NAME", "MESSAGE_FILTER"
};

int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);

static void json_print_string(const char *value) {
    if (!value) {
        fputs("null", stdout);
        return;
    }
    fputc('"', stdout);
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        switch (*p) {
            case '\\':
            case '"':
                fputc('\\', stdout);
                fputc(*p, stdout);
                break;
            case '\n':
                fputs("\\n", stdout);
                break;
            case '\r':
                fputs("\\r", stdout);
                break;
            case '\t':
                fputs("\\t", stdout);
                break;
            default:
                if (*p < 0x20) {
                    fprintf(stdout, "\\u%04x", *p);
                } else {
                    fputc(*p, stdout);
                }
        }
    }
    fputc('"', stdout);
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--json] <pid> <operation> [<filter_type> <value> [extra]]\n", prog);
    fprintf(stderr, "       %s [--json] <pid>\n", prog);
    fprintf(stderr, "       %s [--json] <pid> --list-fds\n", prog);
}

static int parse_filter(const char *str) {
    if (!str || !*str) {
        return -1;
    }
    char *end = NULL;
    long val = strtol(str, &end, 10);
    if (end && *end == '\0' && val >= 0 && val <= 18) {
        return (int)val;
    }
    for (size_t i = 0; i < sizeof(filter_names) / sizeof(filter_names[0]); i++) {
        if (strcasecmp(str, filter_names[i]) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static const char *filter_name_for_id(int filter) {
    if (filter < 0) {
        return NULL;
    }
    size_t idx = (size_t)filter;
    if (idx >= sizeof(filter_names) / sizeof(filter_names[0])) {
        return NULL;
    }
    return filter_names[idx];
}

static int process_exists(pid_t pid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    return (sysctl(mib, 4, &info, &size, NULL, 0) == 0 && size > 0);
}

static const char *fd_type_name(uint32_t fd_type) {
    switch (fd_type) {
        case PROX_FDTYPE_VNODE:
            return "VNODE";
        case PROX_FDTYPE_SOCKET:
            return "SOCKET";
        case PROX_FDTYPE_PIPE:
            return "PIPE";
        case PROX_FDTYPE_KQUEUE:
            return "KQUEUE";
        case PROX_FDTYPE_PSEM:
            return "POSIX_SEM";
        case PROX_FDTYPE_PSHM:
            return "POSIX_SHM";
        case PROX_FDTYPE_FSEVENTS:
            return "FSEVENTS";
        default:
            return "UNKNOWN";
    }
}

static void emit_fd_list_json(pid_t pid) {
    int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bufsize <= 0) {
        printf("{\"kind\":\"sb_api_validator_fds\",\"schema_version\":1,\"pid\":%d,\"error\":", pid);
        json_print_string(strerror(errno));
        printf(",\"errno\":%d}\n", errno);
        return;
    }

    struct proc_fdinfo *fds = malloc(bufsize);
    if (!fds) {
        printf("{\"kind\":\"sb_api_validator_fds\",\"schema_version\":1,\"pid\":%d,\"error\":", pid);
        json_print_string("out_of_memory");
        printf("}\n");
        return;
    }

    int ret = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufsize);
    if (ret <= 0) {
        int saved = errno;
        free(fds);
        printf("{\"kind\":\"sb_api_validator_fds\",\"schema_version\":1,\"pid\":%d,\"error\":", pid);
        json_print_string(strerror(saved));
        printf(",\"errno\":%d}\n", saved);
        return;
    }

    int count = ret / (int)sizeof(struct proc_fdinfo);
    printf("{\"kind\":\"sb_api_validator_fds\",\"schema_version\":1,\"pid\":%d,\"fds\":[", pid);
    for (int i = 0; i < count; i++) {
        if (i > 0) {
            printf(",");
        }
        printf("{\"fd\":%d,\"type\":", fds[i].proc_fd);
        json_print_string(fd_type_name(fds[i].proc_fdtype));
        if (fds[i].proc_fdtype == PROX_FDTYPE_VNODE) {
            struct vnode_fdinfowithpath vinfo;
            if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO, &vinfo, sizeof(vinfo)) > 0) {
                printf(",\"path\":");
                json_print_string(vinfo.pvip.vip_path);
            }
        }
        printf("}");
    }
    printf("]}\n");
    free(fds);
}

static void emit_result_json(
    pid_t pid,
    const char *operation,
    int filter,
    const char *value,
    const char *extra,
    int rc,
    int err
) {
    const char *filter_name = filter_name_for_id(filter);
    bool allowed = (rc == 0);
    bool denied = (rc == 1 || err == EPERM);
    printf("{\"kind\":\"sb_api_validator_result\",\"schema_version\":1");
    printf(",\"pid\":%d", pid);
    printf(",\"operation\":");
    json_print_string(operation);
    printf(",\"filter_type\":");
    json_print_string(filter_name);
    printf(",\"filter_type_id\":%d", filter);
    printf(",\"filter_value\":");
    json_print_string(value);
    printf(",\"extra\":");
    json_print_string(extra);
    printf(",\"rc\":%d", rc);
    printf(",\"errno\":%d", err);
    printf(",\"allowed\":%s", allowed ? "true" : "false");
    printf(",\"denied\":%s", denied ? "true" : "false");
    if (rc < 0 && err != 0) {
        printf(",\"error\":");
        json_print_string(strerror(err));
    }
    printf("}\n");
}

static void emit_status_json(pid_t pid, int rc, int err) {
    bool sandboxed = (rc == 1 || err == EPERM);
    printf("{\"kind\":\"sb_api_validator_status\",\"schema_version\":1");
    printf(",\"pid\":%d", pid);
    printf(",\"rc\":%d", rc);
    printf(",\"errno\":%d", err);
    printf(",\"sandboxed\":%s", sandboxed ? "true" : "false");
    if (rc < 0 && err != 0) {
        printf(",\"error\":");
        json_print_string(strerror(err));
    }
    printf("}\n");
}

int main(int argc, char **argv) {
    bool json_mode = false;
    int argi = 1;
    if (argc > 1 && strcmp(argv[1], "--json") == 0) {
        json_mode = true;
        argi++;
    }

    if (argc <= argi) {
        usage(argv[0]);
        return 64;
    }

    pid_t pid = atoi(argv[argi]);
    if (pid <= 0 || !process_exists(pid)) {
        if (json_mode) {
            printf("{\"kind\":\"sb_api_validator_error\",\"schema_version\":1,\"error\":\"pid_missing\",\"pid\":%d}\n", pid);
        } else {
            fprintf(stderr, "PID %d doesn't exist\n", pid);
        }
        return 2;
    }
    argi++;

    if (argc <= argi) {
        errno = 0;
        int rc = sandbox_check(pid, NULL, SANDBOX_FILTER_NONE);
        int saved = errno;
        if (json_mode) {
            emit_status_json(pid, rc, saved);
        } else {
            printf("PID: %d\nSandbox: %s\n", pid, (rc == 1 || saved == EPERM) ? "YES" : "NO");
        }
        return rc;
    }

    if (strcmp(argv[argi], "--list-fds") == 0) {
        if (json_mode) {
            emit_fd_list_json(pid);
        } else {
            fprintf(stderr, "Use --json with --list-fds for structured output.\n");
        }
        return 0;
    }

    const char *op = argv[argi++];
    int filter = SANDBOX_FILTER_NONE;
    const char *value = NULL;
    const char *extra = NULL;

    if (argi < argc) {
        int parsed = parse_filter(argv[argi]);
        if (parsed < 0) {
            if (json_mode) {
                printf("{\"kind\":\"sb_api_validator_error\",\"schema_version\":1,\"error\":\"bad_filter\",\"filter\":");
                json_print_string(argv[argi]);
                printf("}\n");
            } else {
                fprintf(stderr, "Bad filter: %s\n", argv[argi]);
            }
            return 3;
        }
        filter = parsed;
        argi++;
    }

    if (argi < argc) {
        value = argv[argi++];
    }
    if (argi < argc) {
        extra = argv[argi++];
    }

    errno = 0;
    int rc = -1;
    switch (filter) {
        case SANDBOX_FILTER_NONE:
            rc = sandbox_check(pid, op, SANDBOX_FILTER_NONE);
            break;
        case SANDBOX_FILTER_NOTIFICATION: {
            int flags = extra ? atoi(extra) : 0;
            rc = sandbox_check(pid, op, filter, value, flags);
            break;
        }
        case SANDBOX_FILTER_AUDIT_TOKEN_ATTR: {
            int v1 = value ? atoi(value) : 0;
            long long v2 = extra ? atoll(extra) : 0;
            rc = sandbox_check(pid, op, filter, &v1, &v2);
            break;
        }
        case SANDBOX_FILTER_FILE_DESCRIPTOR: {
            long fd = value ? atol(value) : 0;
            rc = sandbox_check(pid, op, filter, (void *)fd);
            break;
        }
        default:
            rc = sandbox_check(pid, op, filter, value);
            break;
    }
    int saved = errno;

    if (json_mode) {
        emit_result_json(pid, op, filter, value, extra, rc, saved);
    } else {
        printf("Process: %d\nOperation: %s\n", pid, op);
        if (filter != SANDBOX_FILTER_NONE) {
            printf("Filter: %s", filter_name_for_id(filter));
            if (value) {
                printf(" = %s", value);
            }
            if (extra) {
                printf(" (extra: %s)", extra);
            }
            printf("\n");
        }
        if (rc == 0) {
            printf("[ALLOWED]\n");
        } else if (rc == 1 || saved == EPERM) {
            printf("[DENIED]\n");
        } else {
            printf("[ERROR] %s (%d)\n", strerror(saved), saved);
        }
    }

    return rc;
}
