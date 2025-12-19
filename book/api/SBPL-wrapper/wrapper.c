#include "../runtime/tool_markers.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecTask.h>

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
 */

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
    fprintf(stderr, "  %s --sbpl <profile.sb> -- <cmd> [args...]\n", prog);
    fprintf(stderr, "  %s --blob <profile.sb.bin> -- <cmd> [args...]\n", prog);
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
    }

    if (!mode || !profile_path) {
        usage(argv[0]);
        return 64;
    }

    if (strcmp(mode, "compile") != 0) {
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
