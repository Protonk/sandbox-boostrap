#include "../../../api/runtime_tools/native/tool_markers.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecTask.h>
#include <limits.h>
#include <sys/wait.h>

/*
 * SBPL wrapper: apply an SBPL profile to the current process and exec a command.
 *
 * Mode A: SBPL text via sandbox_init.
 * Mode B: compiled blob via sandbox_apply on .sb.bin (uses libsandbox.1.dylib).
 *
 * Usage:
 *   wrapper --sbpl <profile.sb> -- <cmd> [args...]
 *   wrapper --blob <profile.sb.bin> -- <cmd> [args...]
 *   wrapper --compile <profile.sb> [--out <profile.sb.bin>]
 *   Optional: --preflight {off|enforce|force}
 */

static char *find_repo_root_from_argv0(const char *argv0) {
    if (!argv0) return NULL;
    if (!strchr(argv0, '/')) return NULL;

    char resolved[PATH_MAX];
    const char *binary_path = argv0;
    if (realpath(argv0, resolved)) {
        binary_path = resolved;
    }

    char dir[PATH_MAX];
    strncpy(dir, binary_path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *slash = strrchr(dir, '/');
    if (!slash) return NULL;
    if (slash == dir) {
        dir[1] = '\0';
    } else {
        *slash = '\0';
    }

    char candidate[PATH_MAX];
    for (int i = 0; i < 8; i++) {
        snprintf(candidate, sizeof(candidate), "%s/book/tools/preflight/preflight.py", dir);
        if (access(candidate, R_OK) == 0) {
            return strdup(dir);
        }
        if (strcmp(dir, "/") == 0) break;
        slash = strrchr(dir, '/');
        if (!slash) break;
        if (slash == dir) {
            dir[1] = '\0';
        } else {
            *slash = '\0';
        }
    }

    return NULL;
}

static int run_preflight_tool(
    const char *python_path,
    const char *preflight_script,
    const char *profile_path,
    char **out_record_json,
    char **out_error
) {
    if (out_record_json) *out_record_json = NULL;
    if (out_error) *out_error = NULL;

    int fds[2];
    if (pipe(fds) != 0) {
        if (out_error) *out_error = strdup("pipe_failed");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        if (out_error) *out_error = strdup("fork_failed");
        return -1;
    }

    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        dup2(fds[1], STDERR_FILENO);
        close(fds[0]);
        close(fds[1]);

        char *const argv_exec[] = {
            (char *)python_path,
            (char *)preflight_script,
            (char *)"scan",
            (char *)profile_path,
            (char *)"--jsonl",
            NULL,
        };
        if (python_path[0] == '/') {
            execv(python_path, argv_exec);
        }
        execvp(python_path, argv_exec);
        _exit(127);
    }

    close(fds[1]);
    char buf[65536];
    ssize_t used = 0;
    while (used < (ssize_t)sizeof(buf) - 1) {
        ssize_t n = read(fds[0], buf + used, (size_t)((ssize_t)sizeof(buf) - 1 - used));
        if (n <= 0) break;
        used += n;
    }
    close(fds[0]);
    buf[used] = '\0';

    int status = 0;
    waitpid(pid, &status, 0);
    int rc = -1;
    if (WIFEXITED(status)) {
        rc = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        rc = 128 + WTERMSIG(status);
    }

    /* Extract first JSON object line as the record payload (best-effort). */
    char *record = NULL;
    char *cursor = buf;
    while (cursor && *cursor) {
        char *line_end = strchr(cursor, '\n');
        if (line_end) *line_end = '\0';

        char *line = cursor;
        while (*line == ' ' || *line == '\t' || *line == '\r') line++;
        size_t line_len = strlen(line);
        while (line_len > 0 && (line[line_len - 1] == ' ' || line[line_len - 1] == '\t' || line[line_len - 1] == '\r')) {
            line[--line_len] = '\0';
        }
        if (line_len >= 2 && line[0] == '{' && line[line_len - 1] == '}') {
            record = strdup(line);
            break;
        }

        if (!line_end) break;
        cursor = line_end + 1;
    }

    if (!record && out_error && buf[0] != '\0') {
        /* Keep a short excerpt so failures are inspectable without large logs. */
        size_t n = strlen(buf);
        if (n > 200) n = 200;
        char *excerpt = (char *)malloc(n + 1);
        if (excerpt) {
            memcpy(excerpt, buf, n);
            excerpt[n] = '\0';
            *out_error = excerpt;
        } else {
            *out_error = strdup("preflight_output_truncated");
        }
    }
    if (out_record_json) *out_record_json = record;
    return rc;
}

static void emit_message_filter_entitlement_check_marker(const char *stage) {
    const char *entitlement = "com.apple.private.security.message-filter";

    SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    if (!task) {
        sbl_emit_entitlement_check_marker(stage, entitlement, -1, -1, -1, "error", "SecTaskCreateFromSelf returned NULL");
        return;
    }

    CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, entitlement, kCFStringEncodingUTF8);
    if (!key) {
        CFRelease(task);
        sbl_emit_entitlement_check_marker(stage, entitlement, -1, -1, -1, "error", "CFStringCreateWithCString failed");
        return;
    }

    CFErrorRef error = NULL;
    CFTypeRef value = SecTaskCopyValueForEntitlement(task, key, &error);
    if (error) {
        CFRelease(error);
        if (value) CFRelease(value);
        CFRelease(key);
        CFRelease(task);
        sbl_emit_entitlement_check_marker(stage, entitlement, -1, -1, -1, "error", "SecTaskCopyValueForEntitlement error");
        return;
    }

    if (!value) {
        sbl_emit_entitlement_check_marker(stage, entitlement, 0, 0, -1, "absent", NULL);
    } else if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
        int b = CFBooleanGetValue((CFBooleanRef)value) ? 1 : 0;
        sbl_emit_entitlement_check_marker(stage, entitlement, 0, 1, b, "bool", NULL);
    } else {
        sbl_emit_entitlement_check_marker(stage, entitlement, 0, 1, -1, "non_bool", NULL);
    }

    if (value) CFRelease(value);
    CFRelease(key);
    CFRelease(task);
}

static void usage(const char *prog) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s --sbpl <profile.sb> [--preflight off|enforce|force] -- <cmd> [args...]\n", prog);
    fprintf(stderr, "  %s --blob <profile.sb.bin> [--preflight off|enforce|force] -- <cmd> [args...]\n", prog);
    fprintf(stderr, "  %s --compile <profile.sb> [--out <profile.sb.bin>]\n", prog);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    /* parse args */
    const char *mode = NULL;
    const char *profile_path = NULL;
    const char *out_path = NULL;
    const char *preflight_policy_cli = NULL;
    int sep = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            sep = i;
            break;
        }
        if (strcmp(argv[i], "--sbpl") == 0 && i + 1 < argc) {
            mode = "sbpl";
            profile_path = argv[++i];
        }
        if (strcmp(argv[i], "--blob") == 0 && i + 1 < argc) {
            mode = "blob";
            profile_path = argv[++i];
        }
        if (strcmp(argv[i], "--compile") == 0 && i + 1 < argc) {
            mode = "compile";
            profile_path = argv[++i];
        }
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
        if (strcmp(argv[i], "--preflight") == 0 && i + 1 < argc) {
            preflight_policy_cli = argv[++i];
        }
    }

    if (!mode || !profile_path) {
        usage(argv[0]);
        return 64;
    }

    const char *preflight_policy = "enforce";
    const char *env_enabled = getenv("SANDBOX_LORE_PREFLIGHT");
    const char *env_force = getenv("SANDBOX_LORE_PREFLIGHT_FORCE");
    if (env_enabled && strcmp(env_enabled, "0") == 0) {
        preflight_policy = "off";
    }
    if (env_force && strcmp(env_force, "1") == 0) {
        preflight_policy = "force";
    }
    if (preflight_policy_cli) {
        if (strcmp(preflight_policy_cli, "off") == 0) {
            preflight_policy = "off";
        } else if (strcmp(preflight_policy_cli, "enforce") == 0) {
            preflight_policy = "enforce";
        } else if (strcmp(preflight_policy_cli, "force") == 0) {
            preflight_policy = "force";
        } else {
            fprintf(stderr, "invalid --preflight value: %s\n", preflight_policy_cli);
            return 64;
        }
    }

    if (strcmp(mode, "compile") != 0) {
        const char *python_path = (access("/usr/bin/python3", X_OK) == 0) ? "/usr/bin/python3" : "python3";
        char *repo_root = NULL;
        char script_path[PATH_MAX];
        char *record_json = NULL;
        char *preflight_error = NULL;
        int preflight_rc = -1;

        if (strcmp(preflight_policy, "off") == 0) {
            preflight_error = strdup("preflight_disabled");
        } else {
            repo_root = find_repo_root_from_argv0(argv[0]);
            if (!repo_root) {
                preflight_error = strdup("repo_root_not_found");
            } else {
                snprintf(script_path, sizeof(script_path), "%s/book/tools/preflight/preflight.py", repo_root);
                if (access(script_path, R_OK) != 0) {
                    preflight_error = strdup("preflight_script_missing");
                } else {
                    preflight_rc = run_preflight_tool(python_path, script_path, profile_path, &record_json, &preflight_error);
                }
            }
        }

        sbl_emit_sbpl_preflight_marker(mode, preflight_policy, profile_path, preflight_rc, record_json, preflight_error);
        if (repo_root) free(repo_root);
        if (record_json) free(record_json);
        if (preflight_error) free(preflight_error);

        if (strcmp(preflight_policy, "enforce") == 0 && preflight_rc == 2) {
            fprintf(stderr, "preflight blocked: known apply-gate signature\n");
            return 2;
        }

        emit_message_filter_entitlement_check_marker("pre_apply");
    }

    if (strcmp(mode, "compile") == 0) {
        sbl_compiled_profile_t *profile = sbl_sandbox_compile_file_with_markers(profile_path, 0, NULL);
        if (!profile) {
            fprintf(stderr, "sandbox_compile_file failed\n");
            return 1;
        }

        if (out_path) {
            FILE *out = fopen(out_path, "wb");
            if (!out) {
                perror("open out");
                sbl_sandbox_free_profile(profile);
                return 66;
            }
            if (fwrite(profile->bytecode, 1, profile->bytecode_length, out) != profile->bytecode_length) {
                perror("write out");
                fclose(out);
                sbl_sandbox_free_profile(profile);
                return 74;
            }
            fclose(out);
        }

        sbl_sandbox_free_profile(profile);
        return 0;
    }

    if (sep < 0 || sep == argc - 1) {
        usage(argv[0]);
        return 64;
    }

    if (strcmp(mode, "sbpl") == 0) {
        /* load SBPL text */
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
    } else if (strcmp(mode, "blob") == 0) {
        /* load blob */
        FILE *fp = fopen(profile_path, "rb");
        if (!fp) {
            perror("open blob");
            return 66;
        }
        fseek(fp, 0, SEEK_END);
        long len = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        unsigned char *blob = (unsigned char *)malloc((size_t)len);
        if (!blob) {
            fprintf(stderr, "oom\n");
            fclose(fp);
            return 70;
        }
        size_t nread = fread(blob, 1, (size_t)len, fp);
        fclose(fp);
        if (nread != (size_t)len) {
            fprintf(stderr, "short read on blob\n");
            free(blob);
            return 66;
        }

        void *h = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW | RTLD_LOCAL);
        if (!h) {
            fprintf(stderr, "dlopen libsandbox.1.dylib failed: %s\n", dlerror());
            free(blob);
            return 1;
        }

        typedef struct sandbox_profile {
            char *builtin;
            const unsigned char *data;
            size_t size;
        } sandbox_profile_t;

        int (*p_sandbox_apply)(sandbox_profile_t *) =
            (int (*)(sandbox_profile_t *))dlsym(h, "sandbox_apply");
        if (!p_sandbox_apply) {
            fprintf(stderr, "dlsym sandbox_apply failed: %s\n", dlerror());
            dlclose(h);
            free(blob);
            return 1;
        }

        sandbox_profile_t profile = {0};
        profile.builtin = NULL;
        profile.data = blob;
        profile.size = (size_t)len;

        sbl_apply_report_t report = sbl_sandbox_apply_with_markers((sbl_sandbox_apply_fn)p_sandbox_apply, &profile, profile_path);
        free(blob);
        if (report.rc != 0) {
            perror("sandbox_apply");
            dlclose(h);
            return 1;
        }
        dlclose(h);
    } else {
        usage(argv[0]);
        return 64;
    }

    /* exec command */
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
