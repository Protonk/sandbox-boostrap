/*
 * sandbox_check_probe: evaluate a single seatbelt decision via sandbox_check.
 *
 * This probe is intentionally minimal: it assumes a sandbox has already been
 * applied (for example by sandbox_runner or SBPL wrapper) and only performs
 * the check + emits an SBL_PROBE_DETAILS line to stdout.
 *
 * Usage:
 *   sandbox_check_probe <operation> <filter_type> <argument> [filter_name]
 *
 * Exits 0 on allow, 1 on deny/error.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int sandbox_check(pid_t pid, const char *operation, int type, ...);

/* Sandbox-check flags (bitwise OR with filter type). */
#define SANDBOX_CHECK_NO_REPORT 0x40000000

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <operation> <filter_type> <argument> [filter_name]\n", prog);
}

static void json_write_string(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; p && *p; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", out);
            break;
        case '"':
            fputs("\\\"", out);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        case '\f':
            fputs("\\f", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20) {
                fprintf(out, "\\u%04x", (unsigned int)*p);
            } else {
                fputc(*p, out);
            }
        }
    }
    fputc('"', out);
}

static void json_emit_kv_string(FILE *out, int *first, const char *k, const char *v) {
    if (!v) return;
    if (!*first) fputc(',', out);
    *first = 0;
    json_write_string(out, k);
    fputc(':', out);
    json_write_string(out, v);
}

static void json_emit_kv_int(FILE *out, int *first, const char *k, long v) {
    if (!*first) fputc(',', out);
    *first = 0;
    json_write_string(out, k);
    fprintf(out, ":%ld", v);
}

int main(int argc, char *argv[]) {
    if (argc < 4 || argc > 5) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    const char *operation = argv[1];
    const char *filter_str = argv[2];
    const char *argument = argv[3];
    const char *filter_name = argc == 5 ? argv[4] : NULL;

    char *end = NULL;
    long filter_type_long = strtol(filter_str, &end, 10);
    if (!end || *end != '\0' || filter_type_long < 0 || filter_type_long > 0x7fffffffL) {
        fprintf(stderr, "invalid filter_type: %s\n", filter_str);
        return 64; /* EX_USAGE */
    }
    int filter_type = (int)filter_type_long;

    errno = 0;
    int rc = 0;
    if (filter_type == 0) {
        rc = sandbox_check(getpid(), operation, filter_type);
    } else {
        int check_type = filter_type | SANDBOX_CHECK_NO_REPORT;
        rc = sandbox_check(getpid(), operation, check_type, argument);
    }
    int err = errno;

    const char *decision = (rc == 0) ? "allow" : "deny";

    int first = 1;
    fputs("SBL_PROBE_DETAILS ", stdout);
    fputc('{', stdout);
    json_emit_kv_string(stdout, &first, "operation", operation);
    json_emit_kv_int(stdout, &first, "filter_type", filter_type_long);
    json_emit_kv_string(stdout, &first, "argument", argument);
    if (filter_name && *filter_name) {
        json_emit_kv_string(stdout, &first, "filter_name", filter_name);
    }
    json_emit_kv_int(stdout, &first, "rc", rc);
    if (rc == -1) {
        json_emit_kv_int(stdout, &first, "errno", err);
        json_emit_kv_string(stdout, &first, "error", strerror(err));
    }
    json_emit_kv_string(stdout, &first, "decision", decision);
    fputs("}\n", stdout);
    fflush(stdout);

    return strcmp(decision, "allow") == 0 ? 0 : 1;
}
