#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_running = 1;
static const char *g_wait_mode = NULL;
static char g_wait_path[PATH_MAX] = {0};
static bool g_created_fifo = false;
static char g_fifo_dir[PATH_MAX] = {0};
static long long g_started_ms = 0;

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

static long long now_unix_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
}

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

static void emit_event(const char *kind, int pid, const char *extra_key, long long extra_value) {
    long long event_ms = now_unix_ms();
    printf("{\"kind\":");
    json_print_string(kind);
    printf(",\"schema_version\":1,\"pid\":%d,\"wait_mode\":", pid);
    json_print_string(g_wait_mode);
    printf(",\"wait_path\":");
    json_print_string(g_wait_path[0] ? g_wait_path : NULL);
    printf(",\"started_at_unix_ms\":%lld", g_started_ms);
    printf(",\"event_at_unix_ms\":%lld", event_ms);
    if (extra_key) {
        printf(",\"%s\":%lld", extra_key, extra_value);
    }
    printf("}\n");
    fflush(stdout);
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--wait fifo:auto|fifo:/path|exists:/path] [--max-seconds <n>]\n", prog);
}

static int parse_wait_spec(const char *spec) {
    if (!spec || !*spec) {
        return 0;
    }
    if (strncmp(spec, "fifo:", 5) == 0) {
        g_wait_mode = "fifo";
        const char *path = spec + 5;
        if (strcmp(path, "auto") == 0) {
            return 1;
        }
        snprintf(g_wait_path, sizeof(g_wait_path), "%s", path);
        return 2;
    }
    if (strncmp(spec, "exists:", 7) == 0) {
        g_wait_mode = "exists";
        snprintf(g_wait_path, sizeof(g_wait_path), "%s", spec + 7);
        return 2;
    }
    return -1;
}

static int create_fifo_auto(void) {
    const char *tmp = getenv("TMPDIR");
    if (!tmp || !*tmp) {
        tmp = "/tmp";
    }
    char template[PATH_MAX];
    snprintf(template, sizeof(template), "%s/pw-hold-open.XXXXXX", tmp);
    char *dir = mkdtemp(template);
    if (!dir) {
        return -1;
    }
    snprintf(g_fifo_dir, sizeof(g_fifo_dir), "%s", dir);
    snprintf(g_wait_path, sizeof(g_wait_path), "%s/wait.fifo", dir);
    if (mkfifo(g_wait_path, 0600) != 0 && errno != EEXIST) {
        return -1;
    }
    g_created_fifo = true;
    return 0;
}

static int create_fifo_path(void) {
    if (mkfifo(g_wait_path, 0600) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int wait_on_fifo(void) {
    int fd = open(g_wait_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    char buf[1];
    ssize_t nread = read(fd, buf, sizeof(buf));
    close(fd);
    return (nread >= 0) ? 0 : -1;
}

static int wait_on_exists(void) {
    struct stat st;
    while (g_running) {
        if (stat(g_wait_path, &st) == 0) {
            return 0;
        }
        usleep(50000);
    }
    return -1;
}

static void cleanup_fifo(void) {
    if (g_created_fifo) {
        unlink(g_wait_path);
        if (g_fifo_dir[0]) {
            rmdir(g_fifo_dir);
        }
    }
}

int main(int argc, char **argv) {
    const char *wait_spec = NULL;
    double max_seconds = 0.0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--wait") == 0 && i + 1 < argc) {
            wait_spec = argv[++i];
        } else if (strcmp(argv[i], "--max-seconds") == 0 && i + 1 < argc) {
            max_seconds = atof(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 64;
        }
    }

    int wait_mode_state = parse_wait_spec(wait_spec);
    if (wait_mode_state < 0) {
        fprintf(stderr, "Bad wait spec: %s\n", wait_spec ? wait_spec : "(null)");
        return 64;
    }

    if (g_wait_mode && strcmp(g_wait_mode, "fifo") == 0) {
        int rc = (wait_mode_state == 1) ? create_fifo_auto() : create_fifo_path();
        if (rc != 0) {
            perror("mkfifo");
            return 1;
        }
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    g_started_ms = now_unix_ms();
    emit_event("hold_open_ready", getpid(), NULL, 0);

    if (g_wait_mode) {
        int rc = 0;
        if (strcmp(g_wait_mode, "fifo") == 0) {
            rc = wait_on_fifo();
        } else if (strcmp(g_wait_mode, "exists") == 0) {
            rc = wait_on_exists();
        }
        if (rc == 0) {
            emit_event("hold_open_triggered", getpid(), "triggered_at_unix_ms", now_unix_ms());
        }
    }

    long long start_ms = now_unix_ms();
    while (g_running) {
        if (max_seconds > 0.0) {
            double elapsed = (now_unix_ms() - start_ms) / 1000.0;
            if (elapsed >= max_seconds) {
                break;
            }
        }
        sleep(1);
    }

    cleanup_fifo();
    emit_event("hold_open_exit", getpid(), "exit_at_unix_ms", now_unix_ms());
    return 0;
}
