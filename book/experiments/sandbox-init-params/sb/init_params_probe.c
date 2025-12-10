#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef void *(*sandbox_compile_string_fn)(const char *profile, void *params, char **errorbuf);
typedef int (*sandbox_apply_fn)(void *compiled, const char *container);
typedef void (*sandbox_free_profile_fn)(void *compiled);

static void dump_qwords(const char *label, const uint64_t *ptr, size_t count) {
    printf("%s @ %p:", label, (const void *)ptr);
    for (size_t i = 0; i < count; i++) {
        printf(" [%zu]=0x%016" PRIx64, i, ptr[i]);
    }
    printf("\n");
}

int main(void) {
    const char *profile = "(version 1)\n(allow default)";
    const char *profile_json = "(version 1)\\n(allow default)";
    const char *container = getenv("INIT_PARAMS_PROBE_CONTAINER");
    const char *run_json = getenv("INIT_PARAMS_PROBE_RUN_JSON");
    size_t container_len = 0;
    if (container && container[0]) {
        container_len = strlen(container);
    }
    char *err = NULL;

    void *lib = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_LAZY);
    if (!lib) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    sandbox_compile_string_fn compile_fn = (sandbox_compile_string_fn)dlsym(lib, "sandbox_compile_string");
    sandbox_apply_fn apply_fn = (sandbox_apply_fn)dlsym(lib, "sandbox_apply");
    sandbox_free_profile_fn free_fn = (sandbox_free_profile_fn)dlsym(lib, "sandbox_free_profile");
    if (!compile_fn || !apply_fn) {
        fprintf(stderr, "dlsym failed (compile_fn=%p apply_fn=%p): %s\n", (void *)compile_fn, (void *)apply_fn, dlerror());
        return 1;
    }

    void *handle = compile_fn(profile, NULL, &err);
    if (!handle) {
        fprintf(stderr, "sandbox_compile_string returned NULL\n");
        if (err) {
            fprintf(stderr, "error: %s\n", err);
            free(err);
        }
        return 1;
    }

    uint64_t *handle_q = (uint64_t *)handle;
    dump_qwords("handle", handle_q, 3);

    const void *blob_ptr = NULL;
    size_t blob_len = 0;

    if (handle_q[0]) {
        uint64_t *buf = (uint64_t *)handle_q[0];
        dump_qwords("sb_buffer", buf, 4);
        blob_ptr = (const void *)buf[0];
        blob_len = (size_t)buf[1];
    } else {
        blob_ptr = (const void *)handle_q[1];
        blob_len = (size_t)handle_q[2];
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

    int apply_rv = apply_fn(handle, container && container[0] ? container : NULL);
    printf("sandbox_apply returned %d (container=%s)\n", apply_rv, container && container[0] ? container : "NULL");

    int call_code = handle_q[0] ? 1 : 0;

    if (run_json && *run_json) {
        FILE *r = fopen(run_json, "w");
        if (!r) {
            perror("fopen run_json");
        } else {
            fprintf(r, "{\n");
            fprintf(r, "  \"world_id\": \"sonoma-14.4.1-23E224-arm64-dyld-2c0602c5\",\n");
            fprintf(r, "  \"profile\": \"%s\",\n", profile_json);
            fprintf(r, "  \"container\": \"%s\",\n", container && container[0] ? container : "");
            fprintf(r, "  \"container_len\": %zu,\n", container_len);
            fprintf(r, "  \"handle_ptr_hex\": \"%p\",\n", handle);
            fprintf(r, "  \"handle_words\": [%" PRIu64 ", %" PRIu64 ", %" PRIu64 "],\n", handle_q[0], handle_q[1], handle_q[2]);
            fprintf(r, "  \"handle_words_hex\": [\"0x%016" PRIx64 "\", \"0x%016" PRIx64 "\", \"0x%016" PRIx64 "\"],\n",
                    handle_q[0], handle_q[1], handle_q[2]);
            fprintf(r, "  \"call_code\": %d,\n", call_code);
            fprintf(r, "  \"blob\": {\"ptr_hex\": \"%p\", \"len\": %zu, \"file\": \"%s\"},\n",
                    blob_ptr, blob_len, out_path ? out_path : "");
            fprintf(r, "  \"apply_return\": %d\n", apply_rv);
            fprintf(r, "}\n");
            fclose(r);
            printf("wrote run json to %s\n", run_json);
        }
    }

    if (free_fn) {
        free_fn(handle);
    }
    if (err) {
        free(err);
    }
    dlclose(lib);
    return 0;
}
