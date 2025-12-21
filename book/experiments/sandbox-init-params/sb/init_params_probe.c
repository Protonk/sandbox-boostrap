#include "../../../api/runtime_tools/native/tool_markers.h"

#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef void *(*sandbox_compile_string_fn)(const char *profile, void *params, char **errorbuf);
typedef void *(*sandbox_compile_named_fn)(const char *name, void *params, char **errorbuf);
typedef void *(*sandbox_compile_file_fn)(const char *path, void *params, char **errorbuf);
typedef int (*sandbox_apply_fn)(void *compiled, const char *container);
typedef void (*sandbox_free_profile_fn)(void *compiled);

enum probe_mode {
    MODE_STRING = 0,
    MODE_NAMED = 1,
    MODE_FILE = 2,
    MODE_FORCED = 3,
};

static void dump_qwords(const char *label, const uint64_t *ptr, size_t count) {
    printf("%s @ %p:", label, (const void *)ptr);
    for (size_t i = 0; i < count; i++) {
        printf(" [%zu]=0x%016" PRIx64, i, ptr[i]);
    }
    printf("\n");
}

static void write_json_string(FILE *f, const char *s) {
    fputc('"', f);
    if (s) {
        for (const char *p = s; *p; p++) {
            switch (*p) {
                case '\\': fputs("\\\\", f); break;
                case '"': fputs("\\\"", f); break;
                case '\n': fputs("\\n", f); break;
                case '\r': fputs("\\r", f); break;
                case '\t': fputs("\\t", f); break;
                default: fputc(*p, f); break;
            }
        }
    }
    fputc('"', f);
}

static char *read_file_to_string(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen profile_path");
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        perror("ftell");
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(f);
        return NULL;
    }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return NULL;
    }
    size_t read = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[read] = '\0';
    return buf;
}

int main(void) {
    const char *profile_inline = "(version 1)\n(allow default)";
    const char *container = getenv("INIT_PARAMS_PROBE_CONTAINER");
    const char *run_json = getenv("INIT_PARAMS_PROBE_RUN_JSON");
    const char *run_id = getenv("INIT_PARAMS_PROBE_RUN_ID");
    const char *mode_env = getenv("INIT_PARAMS_PROBE_MODE");
    const char *profile_env = getenv("INIT_PARAMS_PROBE_PROFILE");
    const char *force_handle0 = getenv("INIT_PARAMS_FORCE_HANDLE0");
    const char *mode_str = "string";
    enum probe_mode mode = MODE_STRING;
    if (mode_env && mode_env[0]) {
        if (strcmp(mode_env, "named") == 0) {
            mode = MODE_NAMED;
            mode_str = "named";
        } else if (strcmp(mode_env, "file") == 0) {
            mode = MODE_FILE;
            mode_str = "file";
        } else if (strcmp(mode_env, "forced") == 0) {
            mode = MODE_FORCED;
            mode_str = "forced";
        }
    }
    size_t container_len = 0;
    if (container && container[0]) {
        container_len = strlen(container);
    }
    if (!run_id || !run_id[0]) {
        if (mode == MODE_FORCED) {
            run_id = "init_params_probe_forced";
        } else if (mode == MODE_NAMED) {
            run_id = "init_params_probe_named";
        } else if (mode == MODE_FILE) {
            run_id = "init_params_probe_file";
        } else {
            run_id = "init_params_probe";
        }
    }
    FILE *run_json_file = NULL;
    if (run_json && *run_json) {
        run_json_file = fopen(run_json, "w");
        if (!run_json_file) {
            perror("fopen run_json");
        }
    }

    char *err = NULL;

    void *lib = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_LAZY);
    if (!lib) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    sandbox_compile_string_fn compile_string_fn = (sandbox_compile_string_fn)dlsym(lib, "sandbox_compile_string");
    sandbox_compile_named_fn compile_named_fn = (sandbox_compile_named_fn)dlsym(lib, "sandbox_compile_named");
    sandbox_compile_file_fn compile_file_fn = (sandbox_compile_file_fn)dlsym(lib, "sandbox_compile_file");
    sandbox_apply_fn apply_fn = (sandbox_apply_fn)dlsym(lib, "sandbox_apply");
    sandbox_free_profile_fn free_fn = (sandbox_free_profile_fn)dlsym(lib, "sandbox_free_profile");
    if (!compile_string_fn || !apply_fn) {
        fprintf(stderr, "dlsym failed (compile_string_fn=%p apply_fn=%p): %s\n", (void *)compile_string_fn, (void *)apply_fn, dlerror());
        return 1;
    }

    void *handle = NULL;
    const char *profile_field = "(version 1)\\n(allow default)";
    const char *profile_id = "";
    const char *profile_path = "";
    char *profile_from_file = NULL;

    if (mode == MODE_NAMED) {
        if (!profile_env || !profile_env[0]) {
            fprintf(stderr, "INIT_PARAMS_PROBE_PROFILE required for mode=named\n");
            return 1;
        }
        if (!compile_named_fn) {
            fprintf(stderr, "sandbox_compile_named not available\n");
            return 1;
        }
        profile_id = profile_env;
        handle = compile_named_fn(profile_env, NULL, &err);
        profile_field = "";
    } else if (mode == MODE_FILE) {
        if (!profile_env || !profile_env[0]) {
            fprintf(stderr, "INIT_PARAMS_PROBE_PROFILE required for mode=file\n");
            return 1;
        }
        if (!compile_file_fn) {
            fprintf(stderr, "sandbox_compile_file not available\n");
            return 1;
        }
        profile_path = profile_env;
        profile_from_file = read_file_to_string(profile_env);
        if (profile_from_file) {
            profile_field = profile_from_file;
        } else {
            profile_field = "";
        }
        handle = compile_file_fn(profile_env, NULL, &err);
    } else {
        handle = compile_string_fn(profile_inline, NULL, &err);
    }

    if (!handle) {
        fprintf(stderr, "sandbox_compile returned NULL\n");
        if (err) {
            fprintf(stderr, "error: %s\n", err);
            free(err);
        }
        if (run_json_file) {
            fclose(run_json_file);
        }
        return 1;
    }

    uint64_t *handle_q = (uint64_t *)handle;
    dump_qwords("handle", handle_q, 3);

    bool forced = false;
    uint64_t forced_handle[3] = {0, 0, 0};
    uint64_t packed_buf[2] = {0, 0};
    uint64_t *apply_handle = handle_q;
    if ((force_handle0 && force_handle0[0] == '1') || mode == MODE_FORCED) {
        forced = true;
        packed_buf[0] = handle_q[1];
        packed_buf[1] = handle_q[2];
        forced_handle[0] = (uint64_t)packed_buf;
        forced_handle[1] = 0;
        forced_handle[2] = 0;
        apply_handle = forced_handle;
        printf("forced handle[0]!=0 for branch coverage (apply sees forced copy)\n");
    }

    const void *blob_ptr = NULL;
    size_t blob_len = 0;

    if (apply_handle[0]) {
        uint64_t *buf = (uint64_t *)apply_handle[0];
        dump_qwords("sb_buffer", buf, 4);
        blob_ptr = (const void *)buf[0];
        blob_len = (size_t)buf[1];
    } else {
        blob_ptr = (const void *)apply_handle[1];
        blob_len = (size_t)apply_handle[2];
    }

    printf("compiled blob ptr=%p len=%zu\n", blob_ptr, blob_len);

    const char *out_path = getenv("INIT_PARAMS_PROBE_OUT");
    if (blob_ptr && blob_len && out_path && out_path[0]) {
        FILE *f = fopen(out_path, "wb");
        if (!f) {
            perror("fopen");
        } else {
            size_t written = fwrite(blob_ptr, 1, blob_len, f);
            fclose(f);
            printf("wrote %zu bytes to %s\n", written, out_path);
        }
    }

    const char *marker_profile = profile_env && profile_env[0] ? profile_env : "inline";
    errno = 0;
    int apply_rv = apply_fn((void *)apply_handle, container && container[0] ? container : NULL);
    int saved_errno = errno;
    sbl_emit_sbpl_apply_marker(
        "blob",
        "sandbox_apply",
        apply_rv,
        saved_errno,
        (saved_errno == 0) ? NULL : strerror(saved_errno),
        marker_profile
    );
    if (apply_rv == 0) {
        sbl_emit_sbpl_applied_marker("blob", "sandbox_apply", marker_profile);
    }
    printf("sandbox_apply returned %d (container=%s)\n", apply_rv, container && container[0] ? container : "NULL");

    int call_code = apply_handle[0] ? 1 : 0;

    if (run_json_file) {
        fprintf(run_json_file, "{\n");
        fprintf(run_json_file, "  \"world_id\": \"sonoma-14.4.1-23E224-arm64-dyld-2c0602c5\",\n");
        fprintf(run_json_file, "  \"run_id\": \"%s\",\n", run_id);
        fprintf(run_json_file, "  \"mode\": \"%s\",\n", mode_str);
        fprintf(run_json_file, "  \"profile\": ");
        write_json_string(run_json_file, profile_field);
        fprintf(run_json_file, ",\n");
        fprintf(run_json_file, "  \"profile_id\": ");
        write_json_string(run_json_file, profile_id);
        fprintf(run_json_file, ",\n");
        fprintf(run_json_file, "  \"profile_path\": ");
        write_json_string(run_json_file, profile_path);
        fprintf(run_json_file, ",\n");
        fprintf(run_json_file, "  \"container\": \"%s\",\n", container && container[0] ? container : "");
        fprintf(run_json_file, "  \"container_len\": %zu,\n", container_len);
        fprintf(run_json_file, "  \"handle_ptr_hex\": \"%p\",\n", apply_handle);
        fprintf(run_json_file, "  \"handle_words\": [%" PRIu64 ", %" PRIu64 ", %" PRIu64 "],\n", apply_handle[0], apply_handle[1], apply_handle[2]);
        fprintf(run_json_file, "  \"handle_words_hex\": [\"0x%016" PRIx64 "\", \"0x%016" PRIx64 "\", \"0x%016" PRIx64 "\"],\n",
                apply_handle[0], apply_handle[1], apply_handle[2]);
        fprintf(run_json_file, "  \"call_code\": %d,\n", call_code);
        fprintf(run_json_file, "  \"forced_handle0\": %s,\n", forced ? "true" : "false");
        fprintf(run_json_file, "  \"pointer_nonzero\": %s,\n", blob_ptr ? "true" : "false");
        fprintf(run_json_file, "  \"blob\": {\"ptr_hex\": \"%p\", \"len\": %zu, \"file\": \"%s\"},\n",
                blob_ptr, blob_len, out_path ? out_path : "");
        fprintf(run_json_file, "  \"apply_return\": %d\n", apply_rv);
        fprintf(run_json_file, "\n}\n");
        fclose(run_json_file);
        printf("wrote run json to %s\n", run_json);
    }

    if (free_fn) {
        free_fn(handle);
    }
    free(profile_from_file);
    if (err) {
        free(err);
    }
    dlclose(lib);
    return 0;
}
