#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ctype.h>
#if defined(__arm64e__)
#include <ptrauth.h>
#endif

static pthread_mutex_t g_trace_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_trace_fp = NULL;
static FILE *g_triage_fp = NULL;
static const char *g_trace_path = NULL;
static const char *g_trace_input = NULL;
static const char *g_triage_path = NULL;
static const char *g_trace_mode = NULL;
static uint64_t g_seq = 0;
static __thread int g_in_hook = 0;
static const char *k_target_symbol = "_sb_mutable_buffer_write";

typedef void (*sb_write_fn)(void *buf, uint64_t cursor, const void *data, uint64_t len);
static sb_write_fn g_original = NULL;

struct patch_report;

struct dyld_interpose_tuple {
    const void *replacement;
    const void *replacee;
};

__attribute__((weak_import))
extern void dyld_dynamic_interpose(const struct mach_header *mh,
                                   const struct dyld_interpose_tuple array[],
                                   size_t count);

static void trace_open(void) {
    if (g_trace_fp) {
        return;
    }
    if (!g_trace_path) {
        g_trace_path = getenv("SBPL_TRACE_OUT");
    }
    if (!g_trace_input) {
        g_trace_input = getenv("SBPL_TRACE_INPUT");
    }
    if (!g_trace_path) {
        return;
    }
    FILE *fp = fopen(g_trace_path, "a");
    if (!fp) {
        return;
    }
    setvbuf(fp, NULL, _IOLBF, 0);
    g_trace_fp = fp;
}

static void triage_open(void) {
    if (g_triage_fp) {
        return;
    }
    if (!g_triage_path) {
        g_triage_path = getenv("SBPL_TRACE_TRIAGE_OUT");
    }
    if (!g_triage_path) {
        return;
    }
    FILE *fp = fopen(g_triage_path, "w");
    if (!fp) {
        return;
    }
    setvbuf(fp, NULL, _IOLBF, 0);
    g_triage_fp = fp;
}

static void json_escape(FILE *fp, const char *s) {
    if (!s) {
        fputs("null", fp);
        return;
    }
    fputc('"', fp);
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            fputc('\\', fp);
            fputc(*p, fp);
        } else if (*p < 0x20) {
            fprintf(fp, "\\u%04x", *p);
        } else {
            fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

static void emit_hex(FILE *fp, const uint8_t *data, uint64_t len) {
    static const char *hex = "0123456789abcdef";
    for (uint64_t i = 0; i < len; i++) {
        unsigned char b = data[i];
        fputc(hex[b >> 4], fp);
        fputc(hex[b & 0x0f], fp);
    }
}

static int parse_u64(const char *value, uint64_t *out) {
    if (!value || !*value) {
        return 0;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 0);
    if (errno != 0 || end == value || (end && *end != '\0')) {
        return 0;
    }
    *out = (uint64_t)parsed;
    return 1;
}

static const char *sandbox_path(void) {
    const char *env = getenv("SBPL_SANDBOX_PATH");
    if (env && *env) {
        return env;
    }
    return "/usr/lib/libsandbox.1.dylib";
}

static void triage_emit(
    const char *arch,
    const char *target_symbol,
    uint64_t patch_stub_size,
    const char *patch_surface,
    const char *image_name,
    int image_index,
    int slide_known,
    intptr_t image_slide,
    int unslid_known,
    uint64_t unslid_addr,
    const char *uuid_expected,
    const char *uuid_loaded,
    int uuid_match_known,
    int uuid_match,
    const struct patch_report *patch,
    const char *mode,
    const char *sandbox_path_str,
    int sandbox_loaded,
    int sandbox_already_loaded,
    const char *sandbox_symbol,
    const struct mach_header *sandbox_base,
    int target_exported,
    const void *target_addr,
    const char *target_addr_source,
    int dyld_interpose_available,
    const char *hook_attempt,
    const char *hook_status,
    const char *hook_error
);

static void emit_record(void *buf, uint64_t cursor, const void *data, uint64_t len) {
    if (!g_trace_fp) {
        return;
    }
    uint64_t seq = ++g_seq;
    fprintf(g_trace_fp, "{\"seq\":%llu,", (unsigned long long)seq);
    fputs("\"input\":", g_trace_fp);
    json_escape(g_trace_fp, g_trace_input);
    fprintf(g_trace_fp, ",\"buf\":\"0x%llx\",", (unsigned long long)(uintptr_t)buf);
    fprintf(g_trace_fp, "\"cursor\":%llu,", (unsigned long long)cursor);
    fprintf(g_trace_fp, "\"len\":%llu,", (unsigned long long)len);
    fputs("\"bytes_hex\":\"", g_trace_fp);
    emit_hex(g_trace_fp, (const uint8_t *)data, len);
    fputs("\"}\n", g_trace_fp);
}

static void sbpl_trace_write_hook(void *buf, uint64_t cursor, const void *data, uint64_t len) {
    sb_write_fn real = g_original;
    if (g_in_hook) {
        if (real) {
            real(buf, cursor, data, len);
        }
        return;
    }

    g_in_hook = 1;
    trace_open();
    if (g_trace_fp) {
        pthread_mutex_lock(&g_trace_lock);
        emit_record(buf, cursor, data, len);
        pthread_mutex_unlock(&g_trace_lock);
    }
    if (real) {
        real(buf, cursor, data, len);
    }
    g_in_hook = 0;
}

#if defined(__arm64e__)
#define SBPL_ARCH "arm64e"
#elif defined(__arm64__) || defined(__aarch64__)
#define SBPL_ARCH "arm64"
#elif defined(__x86_64__)
#define SBPL_ARCH "x86_64"
#else
#error "Unsupported architecture for encoder write trace hook"
#endif

#if defined(__arm64e__)
static const void *sbpl_strip_ptr(const void *ptr) {
    return ptrauth_strip(ptr, ptrauth_key_function_pointer);
}

static const void *sbpl_sign_ptr(const void *ptr) {
    return ptrauth_sign_unauthenticated(ptr, ptrauth_key_function_pointer, 0);
}
#else
static const void *sbpl_strip_ptr(const void *ptr) {
    return ptr;
}

static const void *sbpl_sign_ptr(const void *ptr) {
    return ptr;
}
#endif

#if defined(__x86_64__)
#define SBPL_PATCH_SIZE 12
// movabs rax, imm64; jmp rax
struct jump_stub {
    uint8_t movabs_rax[2];
    uint64_t target;
    uint8_t jmp_rax[2];
};

static void fill_jump_stub(struct jump_stub *stub, const void *target) {
    stub->movabs_rax[0] = 0x48;
    stub->movabs_rax[1] = 0xB8;
    stub->target = (uint64_t)target;
    stub->jmp_rax[0] = 0xFF;
    stub->jmp_rax[1] = 0xE0;
}
#else
#define SBPL_PATCH_SIZE 16
// 16-byte absolute jump stub (ldr x17, #8; br x17; .quad target).
struct jump_stub {
    uint32_t ldr_x17;
    uint32_t br_x17;
    uint64_t target;
};

static void fill_jump_stub(struct jump_stub *stub, const void *target) {
    stub->ldr_x17 = 0x58000051;
    stub->br_x17 = 0xd61f0220;
    stub->target = (uint64_t)sbpl_strip_ptr(target);
}
#endif

_Static_assert(sizeof(struct jump_stub) == SBPL_PATCH_SIZE, "jump stub size mismatch");

struct patch_report {
    int attempted;
    int applied;
    int pre_bytes_ok;
    int post_bytes_ok;
    int mprotect_start_ok;
    int mprotect_end_ok;
    int mprotect_restore_ok;
    int mprotect_restore_end_ok;
    int vm_copy_attempted;
    int vm_copy_start_ok;
    int vm_copy_end_ok;
    int vm_copy_restore_ok;
    int vm_copy_restore_end_ok;
    int icache_target_called;
    int icache_trampoline_called;
    int region_info_ok;
    int region_protection;
    int region_max_protection;
    int region_inheritance;
    int region_is_submap;
    int region_depth;
    int region_share_mode;
    int region_user_tag;
    int region_max_write;
    uint64_t region_start;
    uint64_t region_size;
    uint64_t region_offset;
    const void *target_runtime_addr;
    const void *trampoline_addr;
    char error[256];
    char region_error[128];
    char region_protection_flags[4];
    char region_max_protection_flags[4];
    char pre_bytes_hex[SBPL_PATCH_SIZE * 2 + 1];
    char post_bytes_hex[SBPL_PATCH_SIZE * 2 + 1];
};

static void hex_encode(const uint8_t *data, size_t len, char *out, size_t out_len) {
    static const char *hex = "0123456789abcdef";
    if (!out || out_len == 0) {
        return;
    }
    size_t need = len * 2 + 1;
    if (out_len < need) {
        out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char b = data[i];
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
    out[len * 2] = '\0';
}

static int format_uuid(const uint8_t *uuid, char *out, size_t out_len) {
    if (!uuid || !out || out_len < 37) {
        return 0;
    }
    snprintf(
        out,
        out_len,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    );
    return 1;
}

static int read_uuid(const struct mach_header *base, char *out, size_t out_len) {
    if (!base || !out || out_len < 37) {
        return 0;
    }
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)base;
    if (hdr->magic != MH_MAGIC_64 && hdr->magic != MH_CIGAM_64) {
        return 0;
    }
    const uint8_t *cmd = (const uint8_t *)(hdr + 1);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cmd;
        if (lc->cmd == LC_UUID) {
            const struct uuid_command *uc = (const struct uuid_command *)cmd;
            return format_uuid(uc->uuid, out, out_len);
        }
        cmd += lc->cmdsize;
    }
    return 0;
}

static int uuid_equal(const char *a, const char *b) {
    if (!a || !b) {
        return 0;
    }
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static const char *mach_err_str(kern_return_t kr) {
    const char *msg = mach_error_string(kr);
    return msg ? msg : "unknown";
}

static void format_prot_flags(int prot, char out[4]) {
    if (!out) {
        return;
    }
    out[0] = (prot & VM_PROT_READ) ? 'r' : '-';
    out[1] = (prot & VM_PROT_WRITE) ? 'w' : '-';
    out[2] = (prot & VM_PROT_EXECUTE) ? 'x' : '-';
    out[3] = '\0';
}

static void record_region_info(mach_vm_address_t addr, struct patch_report *report) {
    if (!report) {
        return;
    }
    mach_vm_address_t region_addr = addr;
    mach_vm_size_t region_size = 0;
    uint32_t depth = 0;
    vm_region_submap_info_data_64_t info;
    while (1) {
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &region_addr, &region_size, &depth,
                                                  (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS) {
            snprintf(report->region_error, sizeof(report->region_error), "%s", mach_err_str(kr));
            report->region_info_ok = 0;
            return;
        }
        if (!info.is_submap) {
            break;
        }
        depth++;
    }
    report->region_info_ok = 1;
    report->region_start = region_addr;
    report->region_size = region_size;
    report->region_protection = info.protection;
    report->region_max_protection = info.max_protection;
    report->region_inheritance = info.inheritance;
    report->region_offset = (uint64_t)info.offset;
    report->region_is_submap = info.is_submap;
    report->region_depth = (int)depth;
    report->region_share_mode = info.share_mode;
    report->region_user_tag = info.user_tag;
    report->region_max_write = (info.max_protection & VM_PROT_WRITE) ? 1 : 0;
    format_prot_flags(info.protection, report->region_protection_flags);
    format_prot_flags(info.max_protection, report->region_max_protection_flags);
}

static void triage_emit(
    const char *arch,
    const char *target_symbol,
    uint64_t patch_stub_size,
    const char *patch_surface,
    const char *image_name,
    int image_index,
    int slide_known,
    intptr_t image_slide,
    int unslid_known,
    uint64_t unslid_addr,
    const char *uuid_expected,
    const char *uuid_loaded,
    int uuid_match_known,
    int uuid_match,
    const struct patch_report *patch,
    const char *mode,
    const char *sandbox_path_str,
    int sandbox_loaded,
    int sandbox_already_loaded,
    const char *sandbox_symbol,
    const struct mach_header *sandbox_base,
    int target_exported,
    const void *target_addr,
    const char *target_addr_source,
    int dyld_interpose_available,
    const char *hook_attempt,
    const char *hook_status,
    const char *hook_error
) {
    if (!g_triage_fp) {
        return;
    }
    fprintf(g_triage_fp, "{");
    fputs("\"arch\":", g_triage_fp);
    json_escape(g_triage_fp, arch);
    fputs(",\"target_symbol\":", g_triage_fp);
    json_escape(g_triage_fp, target_symbol);
    fprintf(g_triage_fp, ",\"patch_stub_size\":%llu", (unsigned long long)patch_stub_size);
    fputs(",\"patch_surface\":", g_triage_fp);
    json_escape(g_triage_fp, patch_surface);
    fputs(",\"image_name\":", g_triage_fp);
    json_escape(g_triage_fp, image_name);
    fputs(",\"image_index\":", g_triage_fp);
    if (image_index >= 0) {
        fprintf(g_triage_fp, "%d", image_index);
    } else {
        fputs("null", g_triage_fp);
    }
    fputs(",\"image_slide\":", g_triage_fp);
    if (slide_known) {
        fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)image_slide);
    } else {
        fputs("null", g_triage_fp);
    }
    fputs(",\"unslid_addr\":", g_triage_fp);
    if (unslid_known) {
        fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)unslid_addr);
    } else {
        fputs("null", g_triage_fp);
    }
    fputs(",\"uuid_expected\":", g_triage_fp);
    json_escape(g_triage_fp, uuid_expected);
    fputs(",\"uuid_loaded\":", g_triage_fp);
    json_escape(g_triage_fp, uuid_loaded);
    fputs(",\"uuid_match\":", g_triage_fp);
    if (uuid_match_known) {
        fputs(uuid_match ? "true" : "false", g_triage_fp);
    } else {
        fputs("null", g_triage_fp);
    }
    fputs(",\"target_runtime_addr\":", g_triage_fp);
    if (patch && patch->target_runtime_addr) {
        fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)(uintptr_t)patch->target_runtime_addr);
    } else {
        fputs("null", g_triage_fp);
    }
    if (patch) {
        fprintf(g_triage_fp, ",\"patch_attempted\":%s", patch->attempted ? "true" : "false");
        fprintf(g_triage_fp, ",\"patch_applied\":%s", patch->applied ? "true" : "false");
        fputs(",\"patch_error\":", g_triage_fp);
        json_escape(g_triage_fp, patch->error[0] ? patch->error : NULL);
        fputs(",\"patch_pre_bytes\":", g_triage_fp);
        if (patch->pre_bytes_ok) {
            json_escape(g_triage_fp, patch->pre_bytes_hex);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"patch_post_bytes\":", g_triage_fp);
        if (patch->post_bytes_ok) {
            json_escape(g_triage_fp, patch->post_bytes_hex);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"trampoline_addr\":", g_triage_fp);
        if (patch->trampoline_addr) {
            fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)(uintptr_t)patch->trampoline_addr);
        } else {
            fputs("null", g_triage_fp);
        }
        fprintf(g_triage_fp, ",\"mprotect_start_ok\":%s", patch->mprotect_start_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"mprotect_end_ok\":%s", patch->mprotect_end_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"mprotect_restore_ok\":%s", patch->mprotect_restore_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"mprotect_restore_end_ok\":%s", patch->mprotect_restore_end_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"vm_copy_attempted\":%s", patch->vm_copy_attempted ? "true" : "false");
        fprintf(g_triage_fp, ",\"vm_copy_start_ok\":%s", patch->vm_copy_start_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"vm_copy_end_ok\":%s", patch->vm_copy_end_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"vm_copy_restore_ok\":%s", patch->vm_copy_restore_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"vm_copy_restore_end_ok\":%s", patch->vm_copy_restore_end_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"icache_invalidate_target\":%s", patch->icache_target_called ? "true" : "false");
        fprintf(g_triage_fp, ",\"icache_invalidate_trampoline\":%s", patch->icache_trampoline_called ? "true" : "false");
        fputs(",\"region\":{", g_triage_fp);
        fprintf(g_triage_fp, "\"info_ok\":%s", patch->region_info_ok ? "true" : "false");
        fputs(",\"error\":", g_triage_fp);
        json_escape(g_triage_fp, patch->region_error[0] ? patch->region_error : NULL);
        fputs(",\"start\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)patch->region_start);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"size\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "%llu", (unsigned long long)patch->region_size);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"protection\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "%d", patch->region_protection);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"protection_flags\":", g_triage_fp);
        if (patch->region_info_ok) {
            json_escape(g_triage_fp, patch->region_protection_flags);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"max_protection\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "%d", patch->region_max_protection);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"max_protection_flags\":", g_triage_fp);
        if (patch->region_info_ok) {
            json_escape(g_triage_fp, patch->region_max_protection_flags);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"max_has_write\":", g_triage_fp);
        if (patch->region_info_ok) {
            fputs(patch->region_max_write ? "true" : "false", g_triage_fp);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"is_submap\":", g_triage_fp);
        if (patch->region_info_ok) {
            fputs(patch->region_is_submap ? "true" : "false", g_triage_fp);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"depth\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "%d", patch->region_depth);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"share_mode\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "%d", patch->region_share_mode);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"user_tag\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "%d", patch->region_user_tag);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"inheritance\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "%d", patch->region_inheritance);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"offset\":", g_triage_fp);
        if (patch->region_info_ok) {
            fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)patch->region_offset);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs("}", g_triage_fp);
    } else {
        fputs(",\"patch_attempted\":false", g_triage_fp);
    }
    fputs(",\"mode\":", g_triage_fp);
    json_escape(g_triage_fp, mode);
    fputs(",\"sandbox_path\":", g_triage_fp);
    json_escape(g_triage_fp, sandbox_path_str);
    fprintf(g_triage_fp, ",\"sandbox_loaded\":%s", sandbox_loaded ? "true" : "false");
    fprintf(g_triage_fp, ",\"sandbox_already_loaded\":%s", sandbox_already_loaded ? "true" : "false");
    fputs(",\"sandbox_symbol\":", g_triage_fp);
    json_escape(g_triage_fp, sandbox_symbol);
    fputs(",\"sandbox_base\":", g_triage_fp);
    if (sandbox_base) {
        fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)(uintptr_t)sandbox_base);
    } else {
        fputs("null", g_triage_fp);
    }
    fprintf(g_triage_fp, ",\"target_exported\":%s", target_exported ? "true" : "false");
    fputs(",\"target_addr\":", g_triage_fp);
    if (target_addr) {
        fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)(uintptr_t)target_addr);
    } else {
        fputs("null", g_triage_fp);
    }
    fputs(",\"target_addr_source\":", g_triage_fp);
    json_escape(g_triage_fp, target_addr_source);
    fprintf(g_triage_fp, ",\"dyld_dynamic_interpose\":%s", dyld_interpose_available ? "true" : "false");
    fputs(",\"hook_attempt\":", g_triage_fp);
    json_escape(g_triage_fp, hook_attempt);
    fputs(",\"hook_status\":", g_triage_fp);
    json_escape(g_triage_fp, hook_status);
    fputs(",\"hook_error\":", g_triage_fp);
    json_escape(g_triage_fp, hook_error);
    fputs("}\n", g_triage_fp);
}

static int install_patch(
    void *target,
    void *replacement,
    sb_write_fn *out_trampoline,
    struct patch_report *report,
    char *err,
    size_t err_len
) {
    if (report) {
        memset(report, 0, sizeof(*report));
        report->attempted = 1;
        report->target_runtime_addr = target;
    }
    if (!target || !replacement || !out_trampoline) {
        snprintf(err, err_len, "missing target or replacement");
        if (report) {
            snprintf(report->error, sizeof(report->error), "missing target or replacement");
        }
        return 0;
    }

    const size_t patch_size = SBPL_PATCH_SIZE;
    if (report) {
        uint8_t pre_bytes[SBPL_PATCH_SIZE];
        memcpy(pre_bytes, target, patch_size);
        hex_encode(pre_bytes, patch_size, report->pre_bytes_hex, sizeof(report->pre_bytes_hex));
        report->pre_bytes_ok = 1;
    }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) {
        snprintf(err, err_len, "page size unavailable");
        if (report) {
            snprintf(report->error, sizeof(report->error), "page size unavailable");
        }
        return 0;
    }
    uintptr_t page_start = (uintptr_t)target & ~((uintptr_t)page_size - 1);
    uintptr_t page_end = ((uintptr_t)target + patch_size - 1) & ~((uintptr_t)page_size - 1);
    if (report && !report->region_info_ok) {
        record_region_info((mach_vm_address_t)page_start, report);
    }
    int used_vm_copy_start = 0;
    int used_vm_copy_end = 0;
    if (mprotect((void *)page_start, (size_t)page_size, PROT_READ | PROT_WRITE) != 0) {
        kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_start, (mach_vm_size_t)page_size,
                                          FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
        if (report) {
            report->vm_copy_attempted = 1;
        }
        if (kr != KERN_SUCCESS) {
            snprintf(err, err_len, "mprotect failed: %s; vm_protect_copy failed: %s",
                     strerror(errno), mach_err_str(kr));
            if (report) {
                snprintf(report->error, sizeof(report->error), "mprotect failed: %s; vm_protect_copy failed: %s",
                         strerror(errno), mach_err_str(kr));
            }
            return 0;
        }
        used_vm_copy_start = 1;
        if (report) {
            report->vm_copy_start_ok = 1;
        }
    } else if (report) {
        report->mprotect_start_ok = 1;
    }
    if (page_end != page_start) {
        if (mprotect((void *)page_end, (size_t)page_size, PROT_READ | PROT_WRITE) != 0) {
            kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_end, (mach_vm_size_t)page_size,
                                              FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
            if (report) {
                report->vm_copy_attempted = 1;
            }
            if (kr != KERN_SUCCESS) {
                if (!used_vm_copy_start) {
                    mprotect((void *)page_start, (size_t)page_size, PROT_READ | PROT_EXEC);
                } else {
                    mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_start, (mach_vm_size_t)page_size,
                                    FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
                }
                snprintf(err, err_len, "mprotect end page failed: %s; vm_protect_copy failed: %s",
                         strerror(errno), mach_err_str(kr));
                if (report) {
                    snprintf(report->error, sizeof(report->error), "mprotect end page failed: %s; vm_protect_copy failed: %s",
                             strerror(errno), mach_err_str(kr));
                }
                return 0;
            }
            used_vm_copy_end = 1;
            if (report) {
                report->vm_copy_end_ok = 1;
            }
        } else if (report) {
            report->mprotect_end_ok = 1;
        }
    }

    size_t tramp_size = patch_size + sizeof(struct jump_stub);
    void *tramp = mmap(NULL, tramp_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (tramp == MAP_FAILED) {
        int saved_errno = errno;
        if (used_vm_copy_start) {
            mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_start, (mach_vm_size_t)page_size,
                            FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        } else {
            mprotect((void *)page_start, (size_t)page_size, PROT_READ | PROT_EXEC);
        }
        if (page_end != page_start) {
            if (used_vm_copy_end) {
                mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_end, (mach_vm_size_t)page_size,
                                FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
            } else {
                mprotect((void *)page_end, (size_t)page_size, PROT_READ | PROT_EXEC);
            }
        }
        snprintf(err, err_len, "mmap failed: %s", strerror(saved_errno));
        if (report) {
            snprintf(report->error, sizeof(report->error), "mmap failed: %s", strerror(saved_errno));
        }
        return 0;
    }

    memcpy(tramp, target, patch_size);
    struct jump_stub *back = (struct jump_stub *)((uint8_t *)tramp + patch_size);
    fill_jump_stub(back, (uint8_t *)target + patch_size);
    if (mprotect(tramp, tramp_size, PROT_READ | PROT_EXEC) != 0) {
        int saved_errno = errno;
        if (used_vm_copy_start) {
            mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_start, (mach_vm_size_t)page_size,
                            FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        } else {
            mprotect((void *)page_start, (size_t)page_size, PROT_READ | PROT_EXEC);
        }
        if (page_end != page_start) {
            if (used_vm_copy_end) {
                mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_end, (mach_vm_size_t)page_size,
                                FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
            } else {
                mprotect((void *)page_end, (size_t)page_size, PROT_READ | PROT_EXEC);
            }
        }
        snprintf(err, err_len, "mprotect trampoline failed: %s", strerror(saved_errno));
        if (report) {
            snprintf(report->error, sizeof(report->error), "mprotect trampoline failed: %s", strerror(saved_errno));
        }
        return 0;
    }
    sys_icache_invalidate(tramp, tramp_size);
    __builtin___clear_cache((char *)tramp, (char *)tramp + tramp_size);
    if (report) {
        report->icache_trampoline_called = 1;
        report->trampoline_addr = tramp;
    }

    struct jump_stub stub;
    fill_jump_stub(&stub, replacement);
    memcpy(target, &stub, patch_size);
    sys_icache_invalidate(target, patch_size);
    __builtin___clear_cache((char *)target, (char *)target + patch_size);
    if (report) {
        report->icache_target_called = 1;
        uint8_t post_bytes[SBPL_PATCH_SIZE];
        memcpy(post_bytes, target, patch_size);
        hex_encode(post_bytes, patch_size, report->post_bytes_hex, sizeof(report->post_bytes_hex));
        report->post_bytes_ok = 1;
    }

    if (used_vm_copy_start) {
        kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_start,
                                          (mach_vm_size_t)page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        if (kr == KERN_SUCCESS) {
            if (report) {
                report->vm_copy_restore_ok = 1;
            }
        } else {
            if (report) {
                report->vm_copy_attempted = 1;
            }
            if (mprotect((void *)page_start, (size_t)page_size, PROT_READ | PROT_EXEC) == 0) {
                if (report) {
                    report->mprotect_restore_ok = 1;
                }
            } else {
                snprintf(err, err_len, "vm_protect restore failed: %s; mprotect restore failed: %s",
                         mach_err_str(kr), strerror(errno));
                if (report) {
                    snprintf(report->error, sizeof(report->error), "vm_protect restore failed: %s; mprotect restore failed: %s",
                             mach_err_str(kr), strerror(errno));
                }
                return 0;
            }
        }
    } else {
        if (mprotect((void *)page_start, (size_t)page_size, PROT_READ | PROT_EXEC) == 0) {
            if (report) {
                report->mprotect_restore_ok = 1;
            }
        } else {
            int saved_errno = errno;
            if (report) {
                report->vm_copy_attempted = 1;
            }
            kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_start,
                                              (mach_vm_size_t)page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
            if (kr == KERN_SUCCESS) {
                if (report) {
                    report->vm_copy_restore_ok = 1;
                }
            } else {
                snprintf(err, err_len, "mprotect restore failed: %s; vm_protect restore failed: %s",
                         strerror(saved_errno), mach_err_str(kr));
                if (report) {
                    snprintf(report->error, sizeof(report->error), "mprotect restore failed: %s; vm_protect restore failed: %s",
                             strerror(saved_errno), mach_err_str(kr));
                }
                return 0;
            }
        }
    }
    if (page_end != page_start) {
        if (used_vm_copy_end) {
            kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_end,
                                              (mach_vm_size_t)page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
            if (kr == KERN_SUCCESS) {
                if (report) {
                    report->vm_copy_restore_end_ok = 1;
                }
            } else {
                if (report) {
                    report->vm_copy_attempted = 1;
                }
                if (mprotect((void *)page_end, (size_t)page_size, PROT_READ | PROT_EXEC) == 0) {
                    if (report) {
                        report->mprotect_restore_end_ok = 1;
                    }
                } else {
                    snprintf(err, err_len, "vm_protect restore end page failed: %s; mprotect restore end page failed: %s",
                             mach_err_str(kr), strerror(errno));
                    if (report) {
                        snprintf(report->error, sizeof(report->error), "vm_protect restore end page failed: %s; mprotect restore end page failed: %s",
                                 mach_err_str(kr), strerror(errno));
                    }
                    return 0;
                }
            }
        } else {
            if (mprotect((void *)page_end, (size_t)page_size, PROT_READ | PROT_EXEC) == 0) {
                if (report) {
                    report->mprotect_restore_end_ok = 1;
                }
            } else {
                int saved_errno = errno;
                if (report) {
                    report->vm_copy_attempted = 1;
                }
                kern_return_t kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t)page_end,
                                                  (mach_vm_size_t)page_size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
                if (kr == KERN_SUCCESS) {
                    if (report) {
                        report->vm_copy_restore_end_ok = 1;
                    }
                } else {
                    snprintf(err, err_len, "mprotect restore end page failed: %s; vm_protect restore end page failed: %s",
                             strerror(saved_errno), mach_err_str(kr));
                    if (report) {
                        snprintf(report->error, sizeof(report->error), "mprotect restore end page failed: %s; vm_protect restore end page failed: %s",
                                 strerror(saved_errno), mach_err_str(kr));
                    }
                    return 0;
                }
            }
        }
    }

    *out_trampoline = (sb_write_fn)sbpl_sign_ptr(tramp);
    if (report) {
        report->applied = 1;
    }
    return 1;
}

static int find_image_index(const struct mach_header *base, const char **image_name, intptr_t *slide) {
    if (!base) {
        return -1;
    }
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (hdr == base) {
            if (image_name) {
                *image_name = _dyld_get_image_name(i);
            }
            if (slide) {
                *slide = _dyld_get_image_vmaddr_slide(i);
            }
            return (int)i;
        }
    }
    return -1;
}

static void install_hook(void) {
    g_trace_mode = getenv("SBPL_TRACE_MODE");
    if (!g_trace_mode || !*g_trace_mode) {
        g_trace_mode = "triage";
    }

    const char *sandbox_path_str = sandbox_path();
    int sandbox_already_loaded = 0;
    void *handle = dlopen(sandbox_path_str, RTLD_LAZY | RTLD_NOLOAD);
    if (handle) {
        sandbox_already_loaded = 1;
    } else {
        handle = dlopen(sandbox_path_str, RTLD_LAZY);
    }

    const char *sandbox_symbol = NULL;
    const struct mach_header *sandbox_base = NULL;
    if (handle) {
        const char *symbols[] = {"sandbox_compile_file", "sandbox_compile_string", "sandbox_init"};
        for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
            void *sym = dlsym(handle, symbols[i]);
            if (sym) {
                Dl_info info;
                if (dladdr(sym, &info) && info.dli_fbase) {
                    sandbox_base = (const struct mach_header *)info.dli_fbase;
                    sandbox_symbol = symbols[i];
                    break;
                }
            }
        }
    }

    const char *image_name = NULL;
    intptr_t image_slide = 0;
    int image_index = -1;
    int slide_known = 0;
    if (sandbox_base) {
        image_index = find_image_index(sandbox_base, &image_name, &image_slide);
        if (image_index >= 0) {
            slide_known = 1;
        }
    }

    const char *uuid_expected = getenv("SBPL_WRITE_UUID_EXPECTED");
    char uuid_loaded[37] = {0};
    int uuid_loaded_ok = 0;
    int uuid_match_known = 0;
    int uuid_match = 0;
    if (sandbox_base) {
        uuid_loaded_ok = read_uuid(sandbox_base, uuid_loaded, sizeof(uuid_loaded));
    }
    if (uuid_expected && *uuid_expected && uuid_loaded_ok) {
        uuid_match_known = 1;
        uuid_match = uuid_equal(uuid_expected, uuid_loaded);
    } else if (uuid_expected && *uuid_expected) {
        uuid_match_known = 1;
        uuid_match = 0;
    }

    void *exported_target = NULL;
    int target_exported = 0;
    if (handle) {
        dlerror();
        exported_target = dlsym(handle, k_target_symbol);
        const char *err = dlerror();
        if (!err && exported_target) {
            target_exported = 1;
        }
    }

    void *target_addr = exported_target;
    const char *target_source = target_exported ? "dlsym" : NULL;
    const char *addr_env = getenv("SBPL_WRITE_ADDR");
    const char *unslid_env = getenv("SBPL_WRITE_UNSLID");
    const char *offset_env = getenv("SBPL_WRITE_OFFSET");
    uint64_t addr = 0;
    uint64_t unslid_addr = 0;
    int unslid_known = 0;
    int unslid_allowed = 1;
    const char *unslid_block_reason = NULL;
    if (parse_u64(unslid_env, &unslid_addr)) {
        unslid_known = 1;
    }
    if (uuid_expected && *uuid_expected) {
        if (!uuid_match_known || !uuid_match) {
            unslid_allowed = 0;
            unslid_block_reason = uuid_match_known ? "uuid_mismatch" : "uuid_unknown";
        }
    }
    if (parse_u64(addr_env, &addr)) {
        target_addr = (void *)(uintptr_t)addr;
        target_source = "env_addr";
    } else if (unslid_known) {
        if (!unslid_allowed) {
            target_addr = NULL;
        } else if (slide_known) {
            target_addr = (void *)(uintptr_t)(unslid_addr + (uint64_t)image_slide);
        } else {
            target_addr = NULL;
        }
        target_source = "unslid+slide";
    } else if (parse_u64(offset_env, &addr) && sandbox_base) {
        target_addr = (void *)((uintptr_t)sandbox_base + addr);
        target_source = "env_offset";
    }

    const int interpose_available = (dyld_dynamic_interpose != NULL);
    const char *hook_attempt = "none";
    const char *hook_status = "skipped";
    const char *hook_error = NULL;
    const char *patch_surface = NULL;
    struct patch_report patch = {0};

    if (strcmp(g_trace_mode, "dynamic") == 0) {
        hook_attempt = "dynamic";
        if (!interpose_available) {
            hook_status = "skipped";
            hook_error = "dyld_dynamic_interpose unavailable";
        } else if (!target_exported || !exported_target || !sandbox_base) {
            hook_status = "skipped";
            hook_error = "target not exported or base unavailable";
        } else {
            struct dyld_interpose_tuple tuple = { (const void *)sbpl_trace_write_hook, exported_target };
            dyld_dynamic_interpose(sandbox_base, &tuple, 1);
            g_original = (sb_write_fn)exported_target;
            hook_status = "ok";
        }
    } else if (strcmp(g_trace_mode, "patch") == 0) {
        hook_attempt = "patch";
        patch_surface = "entry_text";
        if (!target_addr) {
            hook_status = "skipped";
            if (unslid_known && !unslid_allowed && unslid_block_reason) {
                hook_error = unslid_block_reason;
            } else if (unslid_known && !slide_known) {
                hook_error = "image slide unavailable";
            } else {
                hook_error = "target address unavailable";
            }
        } else {
            patch.target_runtime_addr = target_addr;
            record_region_info((mach_vm_address_t)(uintptr_t)target_addr, &patch);
            if (patch.region_info_ok && !patch.region_max_write) {
                hook_status = "skipped_immutable";
                hook_error = "region_max_protection_no_write";
            } else {
                char err_buf[256] = {0};
                if (install_patch(target_addr, (void *)sbpl_trace_write_hook, &g_original, &patch, err_buf, sizeof(err_buf))) {
                    hook_status = "ok";
                } else {
                    hook_status = "failed";
                    hook_error = err_buf;
                }
            }
        }
    }

    triage_open();
    triage_emit(
        SBPL_ARCH,
        k_target_symbol,
        SBPL_PATCH_SIZE,
        patch_surface,
        image_name,
        image_index,
        slide_known,
        image_slide,
        unslid_known,
        unslid_addr,
        (uuid_expected && *uuid_expected) ? uuid_expected : NULL,
        uuid_loaded_ok ? uuid_loaded : NULL,
        uuid_match_known,
        uuid_match,
        (patch.attempted || patch.applied || patch.region_info_ok) ? &patch : NULL,
        g_trace_mode,
        sandbox_path_str,
        handle != NULL,
        sandbox_already_loaded,
        sandbox_symbol,
        sandbox_base,
        target_exported,
        target_addr,
        target_source,
        interpose_available,
        hook_attempt,
        hook_status,
        hook_error
    );
}

__attribute__((constructor)) static void sbpl_trace_init(void) {
    install_hook();
}
