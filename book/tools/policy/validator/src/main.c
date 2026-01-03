#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <libproc.h>

// Sandbox check flags (bitwise OR with filter type)
#define SANDBOX_CHECK_NO_REPORT    0x40000000 // No info to syslog
#define SANDBOX_CHECK_CANONICAL    0x20000000 // Path is canonicalized (no .. or symlinks)
#define SANDBOX_CHECK_NOFOLLOW     0x10000000 // Do not follow symlinks ??
#define SANDBOX_CHECK_SNOOP        0x08000000 // Existence/metadata only, not full read/write ?
#define SANDBOX_CHECK_PRIVILEGE    0x04000000 // Entitlement privileges ?
#define SANDBOX_CHECK_USER_INTENT  0x02000000 // Access was granted by user intent ?

enum sandbox_filter_type {
    SANDBOX_FILTER_NONE                     = 0,   // opcode: 0
    SANDBOX_FILTER_PATH                     = 1,   // opcode: 1
    SANDBOX_FILTER_GLOBAL_NAME              = 2,   // opcode: 6
    SANDBOX_FILTER_LOCAL_NAME               = 3,   // opcode: 7
    SANDBOX_FILTER_APPLEEVENT_DESTINATION   = 4,   // opcode: 25
    SANDBOX_FILTER_RIGHT_NAME               = 5,   // opcode: 27
    SANDBOX_FILTER_PREFERENCE_DOMAIN        = 6,   // opcode: 28
    SANDBOX_FILTER_KEXT_BUNDLE_ID           = 7,   // opcode: 33
    SANDBOX_FILTER_INFO_TYPE                = 8,   // opcode: 34
    SANDBOX_FILTER_NOTIFICATION             = 9,   // opcode: 35
    SANDBOX_FILTER_FILE_DESCRIPTOR          = 10,  // opcode: 240
    SANDBOX_FILTER_AUDIT_TOKEN_ATTR         = 11,  // opcode: 241
    SANDBOX_FILTER_XPC_SERVICE_NAME         = 12,  // opcode: 50
    SANDBOX_FILTER_IOKIT_CONNECTION         = 13,  // opcode: 19
    SANDBOX_FILTER_IOKIT_USER_CLIENT_CLASS  = 14,  // opcode: 65
    SANDBOX_FILTER_NVRAM_VARIABLE           = 15,  // opcode: 75
    SANDBOX_FILTER_SYSCTL_NAME              = 16,  // opcode: 45
    SANDBOX_FILTER_POSIX_IPC_NAME           = 17,  // opcode: 5
    SANDBOX_FILTER_MESSAGE_FILTER           = 18,  // opcode: 52
};



const char* filter_names[] = {
    "NONE", "PATH", "GLOBAL_NAME", "LOCAL_NAME", "APPLEEVENT_DESTINATION",
    "RIGHT_NAME", "PREFERENCE_DOMAIN", "KEXT_BUNDLE_ID", "INFO_TYPE",
    "NOTIFICATION", "FILE_DESCRIPTOR", "AUDIT_TOKEN_ATTR", "XPC_SERVICE_NAME",
    "IOKIT_CONNECTION", "IOKIT_USER_CLIENT_CLASS", "NVRAM_VARIABLE",
    "SYSCTL_NAME", "POSIX_IPC_NAME", "MESSAGE_FILTER"
};

#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m"

int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);

void show_filters() {
    printf("\nFilter types:\n");
    for (size_t i = 0; i < sizeof(filter_names) / sizeof(filter_names[0]); i++) {
        printf("  %2zu: %s\n", i, filter_names[i]);
    }
}

int process_exists(pid_t pid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    return (sysctl(mib, 4, &info, &size, NULL, 0) == 0 && size > 0);
}

void list_fds(pid_t pid) {
    printf(CYAN "\n=== File Descriptors (PID %d) ===\n" RESET, pid);
    
    int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bufsize <= 0) {
        fprintf(stderr, RED "Can't get FD list: %s\n" RESET, strerror(errno));
        return;
    }
    
    struct proc_fdinfo *fds = malloc(bufsize);
    if (!fds) {
        fprintf(stderr, RED "Out of memory\n" RESET);
        return;
    }
    
    int ret = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufsize);
    if (ret <= 0) {
        fprintf(stderr, RED "Failed to list FDs: %s\n" RESET, strerror(errno));
        free(fds);
        return;
    }
    
    int count = ret / sizeof(struct proc_fdinfo);
    printf("Total: %d\n\n", count);
    
    for (int i = 0; i < count; i++) {
        printf("FD %d: ", fds[i].proc_fd);
        
        switch (fds[i].proc_fdtype) {
            case PROX_FDTYPE_VNODE: {
                printf("VNODE");
                struct vnode_fdinfowithpath vinfo;
                if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDVNODEPATHINFO, 
                                   &vinfo, sizeof(vinfo)) > 0) {
                    printf(" -> %s", vinfo.pvip.vip_path);
                }
                break;
            }
            case PROX_FDTYPE_SOCKET: printf("SOCKET"); break;
            case PROX_FDTYPE_PIPE: printf("PIPE"); break;
            case PROX_FDTYPE_KQUEUE: printf("KQUEUE"); break;
            case PROX_FDTYPE_PSEM: printf("POSIX_SEM"); break;
            case PROX_FDTYPE_PSHM: printf("POSIX_SHM"); break;
            case PROX_FDTYPE_FSEVENTS: printf("FSEVENTS"); break;
            default: printf("UNKNOWN(%d)", fds[i].proc_fdtype); break;
        }
        printf("\n");
    }
    
    free(fds);
    printf("\n");
}

void usage() {
    fprintf(stderr, "Usage: %s <pid> <operation> [<filter_type> <value> [extra]]\n\n", getprogname());
    fprintf(stderr, "Special:\n");
    fprintf(stderr, "  %s <pid> --list-fds\n\n", getprogname());
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s 1337 --list-fds\n", getprogname());
    fprintf(stderr, "  %s 1337 file-read* PATH /etc/passwd\n", getprogname());
    fprintf(stderr, "  %s 1337 mach-lookup GLOBAL_NAME com.apple.foo\n", getprogname());
    fprintf(stderr, "  %s 1337 distributed-notification-post NOTIFICATION com.apple.foo 0\n", getprogname());
    show_filters();
    exit(1);
}

enum sandbox_filter_type parse_filter(const char* str) {
    char *end;
    long val = strtol(str, &end, 10);
    if (*end == '\0' && val >= 0 && val <= 18)
        return (enum sandbox_filter_type)val;
    
    for (size_t i = 0; i < sizeof(filter_names) / sizeof(filter_names[0]); i++) {
        if (strcasecmp(str, filter_names[i]) == 0)
            return i;
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) usage();

    pid_t pid = atoi(argv[1]);
    if (!process_exists(pid)) {
        fprintf(stderr, RED "PID %d doesn't exist\n" RESET, pid);
        exit(2);
    }
    
    /* If only PID is provided, perform a simple sandbox probe by calling
     * sandbox_check(pid, 0, 0). The result is interpreted as "sandboxed"
     * when the call is denied (rc == 1 or errno == EPERM). This enables
     * the simple CLI form: `sb_validator <pid>` which prints whether the
     * process appears to be sandboxed. */
    if (argc == 2) {
        int rc = sandbox_check(pid, 0, 0);
        int sandboxed = (rc == 1 || errno == EPERM);
        printf(BLUE "PID: %d" RESET "\n", pid);
        if (sandboxed) {
            printf("Sandbox: " GREEN "YES" RESET "\n");
        } else {
            printf("Sandbox: " RED "NO" RESET "\n");
        }
        return rc;
    }
    if (strcmp(argv[2], "--list-fds") == 0) {
        list_fds(pid);
        return 0;
    }

    const char *op = argv[2];
    enum sandbox_filter_type filter = SANDBOX_FILTER_NONE;
    const char *value = NULL;
    const char *extra = NULL;

    if (argc >= 4) {
        int type = parse_filter(argv[3]);
        if (type == -1) {
            fprintf(stderr, "Bad filter: %s\n", argv[3]);
            exit(3);
        }
        filter = (enum sandbox_filter_type)type;
    }

    if (argc >= 5) value = argv[4];
    if (argc >= 6) extra = argv[5];

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
            
            // Check if FD exists in target
            int bufsize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
            if (bufsize > 0) {
                struct proc_fdinfo *fds = malloc(bufsize);
                if (fds) {
                    int ret = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, bufsize);
                    if (ret > 0) {
                        int count = ret / sizeof(struct proc_fdinfo);
                        int found = 0;
                        for (int i = 0; i < count; i++) {
                            if (fds[i].proc_fd == fd) {
                                found = 1;
                                printf(BLUE "FD %ld exists (type: %d)\n" RESET, 
                                       fd, fds[i].proc_fdtype);
                                break;
                            }
                        }
                        if (!found) {
                            fprintf(stderr, YELLOW "FD %ld not found in PID %d\n" RESET, fd, pid);
                            fprintf(stderr, YELLOW "Run with --list-fds to see available FDs\n" RESET);
                        }
                    }
                    free(fds);
                }
            }
            
            rc = sandbox_check(pid, op, filter, (void*)fd);
            break;
        }

        default:
            rc = sandbox_check(pid, op, filter, value);
            break;
    }

    printf("Process: %d\n", pid);
    printf("Operation: %s\n", op);
    if (filter != SANDBOX_FILTER_NONE) {
        printf("Filter: %s", filter_names[filter]);
        if (value) printf(" = %s", value);
        if (extra) printf(" (extra: %s)", extra);
        printf("\n");
    }

    if (rc == 0) {
        printf(GREEN "[ALLOWED]\n" RESET);
    } else if (rc == 1 || errno == EPERM) {
        printf(RED "[DENIED]\n" RESET);
    } else {
        printf(RED "[ERROR] %s (%d)\n" RESET, strerror(errno), errno);
        
        if (errno == 9 && filter == SANDBOX_FILTER_FILE_DESCRIPTOR) {
            printf(YELLOW "Hint: Try %s %d --list-fds\n" RESET, getprogname(), pid);
        }
    }

    return rc;
}