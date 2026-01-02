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
#include <mach/exc.h>
#include <mach/arm/thread_status.h>
#include <mach/arm/exception.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ctype.h>
#include "mach_exc_server.h"
#include "mach_exc_user.h"
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
static const char *k_immutable_symbol = "_sb_mutable_buffer_make_immutable";
static mach_port_t g_hw_exception_port = MACH_PORT_NULL;
static int g_hw_server_running = 0;
static int g_hw_break_index = 0;
static int g_hw_break_index_secondary = 1;
static uint64_t g_hw_bcr_value = 0;
static uint64_t g_hw_target_addr = 0;
static uint64_t g_hw_target_addr_secondary = 0;
static mach_port_t g_hw_prev_port = MACH_PORT_NULL;
static exception_behavior_t g_hw_prev_behavior = 0;
static thread_state_flavor_t g_hw_prev_flavor = 0;
static int g_hw_prev_valid = 0;
static int g_hw_arm_running = 0;
static int g_hw_monitor_running = 0;

#define HW_RING_SIZE 4096
#define HW_CHUNK_SIZE 1024
#define HW_THREAD_MAX 128

struct hw_ring_entry {
    uint32_t ready;
    uint32_t len;
    uint32_t reported_len;
    uint32_t chunk_offset;
    uint64_t seq;
    void *buf;
    uint64_t cursor;
    uint8_t bytes[HW_CHUNK_SIZE];
};

static struct hw_ring_entry g_hw_ring[HW_RING_SIZE];
static volatile uint64_t g_hw_ring_write = 0;
static volatile uint64_t g_hw_ring_read = 0;
static volatile uint64_t g_hw_ring_dropped = 0;
static volatile uint64_t g_hw_capture_truncated = 0;
static volatile uint64_t g_hw_break_hits = 0;
static volatile uint64_t g_hw_step_hits = 0;
static volatile uint64_t g_hw_forwarded = 0;
static volatile uint64_t g_hw_unknown_break_hits = 0;
static volatile uint64_t g_hw_immutable_hits = 0;
static volatile uint64_t g_hw_immutable_buf = 0;
static volatile uint64_t g_hw_thread_overflow = 0;
static volatile uint64_t g_hw_arm_failures = 0;
static volatile uint64_t g_hw_rescans = 0;
static volatile uint64_t g_hw_threads_scanned = 0;
static volatile uint64_t g_hw_threads_armed = 0;
static int g_hw_flush_running = 0;

struct hw_thread_entry {
    mach_port_t thread;
    uint32_t step_active;
    uint32_t armed;
};

static struct hw_thread_entry g_hw_threads[HW_THREAD_MAX];

typedef void (*sb_write_fn)(void *buf, uint64_t cursor, const void *data, uint64_t len);
static sb_write_fn g_original = NULL;

struct patch_report;
struct hw_breakpoint_report;

static int hw_breakpoint_update_state(
    thread_t thread,
    uint64_t addr_primary,
    uint64_t addr_secondary,
    uint64_t bcr_value,
    int enable_primary,
    int enable_secondary,
    int single_step,
    char *err,
    size_t err_len
);

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
    const struct hw_breakpoint_report *hw,
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

static void emit_record_bytes(
    uint64_t seq,
    void *buf,
    uint64_t cursor,
    const uint8_t *data,
    uint64_t len,
    uint64_t reported_len,
    uint64_t chunk_offset,
    int include_chunk_fields
) {
    if (!g_trace_fp) {
        return;
    }
    fprintf(g_trace_fp, "{\"seq\":%llu,", (unsigned long long)seq);
    fputs("\"input\":", g_trace_fp);
    json_escape(g_trace_fp, g_trace_input);
    fprintf(g_trace_fp, ",\"buf\":\"0x%llx\",", (unsigned long long)(uintptr_t)buf);
    fprintf(g_trace_fp, "\"cursor\":%llu,", (unsigned long long)cursor);
    fprintf(g_trace_fp, "\"len\":%llu,", (unsigned long long)len);
    if (include_chunk_fields) {
        fprintf(g_trace_fp, "\"reported_len\":%llu,", (unsigned long long)reported_len);
        fprintf(g_trace_fp, "\"chunk_offset\":%llu,", (unsigned long long)chunk_offset);
    }
    fputs("\"bytes_hex\":\"", g_trace_fp);
    emit_hex(g_trace_fp, data, len);
    fputs("\"}\n", g_trace_fp);
}

static int hw_ring_push_chunk(
    void *buf,
    uint64_t cursor,
    const uint8_t *data,
    uint32_t len,
    uint32_t reported_len,
    uint32_t chunk_offset
) {
    uint64_t idx = __atomic_fetch_add(&g_hw_ring_write, 1, __ATOMIC_RELAXED);
    uint64_t read = __atomic_load_n(&g_hw_ring_read, __ATOMIC_ACQUIRE);
    if (idx - read >= HW_RING_SIZE) {
        __atomic_fetch_add(&g_hw_ring_dropped, 1, __ATOMIC_RELAXED);
        return 0;
    }
    struct hw_ring_entry *entry = &g_hw_ring[idx % HW_RING_SIZE];
    entry->ready = 0;
    entry->len = len;
    entry->reported_len = reported_len;
    entry->chunk_offset = chunk_offset;
    entry->seq = __atomic_add_fetch(&g_seq, 1, __ATOMIC_RELAXED);
    entry->buf = buf;
    entry->cursor = cursor;
    if (len > 0) {
        memcpy(entry->bytes, data, len);
    }
    __atomic_store_n(&entry->ready, 1, __ATOMIC_RELEASE);
    return 1;
}

static int hw_ring_enqueue(void *buf, uint64_t cursor, const uint8_t *data, uint64_t len) {
    if (!data && len > 0) {
        return 0;
    }
    if (len == 0) {
        return hw_ring_push_chunk(buf, cursor, data, 0, 0, 0);
    }
    uint64_t offset = 0;
    int pushed = 0;
    while (offset < len) {
        uint32_t chunk = (uint32_t)((len - offset) > HW_CHUNK_SIZE ? HW_CHUNK_SIZE : (len - offset));
        if (!hw_ring_push_chunk(buf, cursor + offset, data + offset, chunk, (uint32_t)len, (uint32_t)offset)) {
            break;
        }
        offset += chunk;
        pushed++;
    }
    if (offset < len) {
        __atomic_fetch_add(&g_hw_capture_truncated, 1, __ATOMIC_RELAXED);
    }
    return pushed;
}

static int hw_flush_ring(void) {
    int wrote = 0;
    while (1) {
        uint64_t read = __atomic_load_n(&g_hw_ring_read, __ATOMIC_ACQUIRE);
        uint64_t write = __atomic_load_n(&g_hw_ring_write, __ATOMIC_ACQUIRE);
        if (read >= write) {
            break;
        }
        struct hw_ring_entry *entry = &g_hw_ring[read % HW_RING_SIZE];
        if (!__atomic_load_n(&entry->ready, __ATOMIC_ACQUIRE)) {
            break;
        }
        trace_open();
        if (g_trace_fp) {
            pthread_mutex_lock(&g_trace_lock);
            emit_record_bytes(
                entry->seq,
                entry->buf,
                entry->cursor,
                entry->bytes,
                entry->len,
                entry->reported_len,
                entry->chunk_offset,
                1
            );
            pthread_mutex_unlock(&g_trace_lock);
        }
        entry->ready = 0;
        __atomic_store_n(&g_hw_ring_read, read + 1, __ATOMIC_RELEASE);
        wrote++;
    }
    return wrote;
}

static void *hw_flush_thread(void *arg) {
    (void)arg;
    while (__atomic_load_n(&g_hw_flush_running, __ATOMIC_ACQUIRE)) {
        if (hw_flush_ring() == 0) {
            usleep(1000);
        }
    }
    hw_flush_ring();
    return NULL;
}

static void hw_write_stats(void) {
    const char *path = getenv("SBPL_TRACE_STATS_OUT");
    if (!path || !*path) {
        return;
    }
    FILE *fp = fopen(path, "w");
    if (!fp) {
        return;
    }
    fprintf(fp, "{");
    fprintf(fp, "\"ring_dropped\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_ring_dropped, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"capture_truncated\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_capture_truncated, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"break_hits\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_break_hits, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"step_hits\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_step_hits, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"forwarded\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_forwarded, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"unknown_break_hits\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_unknown_break_hits, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"immutable_hits\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_immutable_hits, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"immutable_buf\":\"0x%llx\",", (unsigned long long)__atomic_load_n(&g_hw_immutable_buf, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"thread_overflow\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_thread_overflow, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"arm_failures\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_arm_failures, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"rescans\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_rescans, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"threads_scanned_total\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_threads_scanned, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"threads_armed_total\":%llu,", (unsigned long long)__atomic_load_n(&g_hw_threads_armed, __ATOMIC_ACQUIRE));
    fprintf(fp, "\"ring_size\":%u,", HW_RING_SIZE);
    fprintf(fp, "\"chunk_size\":%u", HW_CHUNK_SIZE);
    fprintf(fp, "}\n");
    fclose(fp);
}

static int hw_thread_index(mach_port_t thread, int create, int *created) {
    if (created) {
        *created = 0;
    }
    for (int i = 0; i < HW_THREAD_MAX; i++) {
        mach_port_t current = __atomic_load_n(&g_hw_threads[i].thread, __ATOMIC_ACQUIRE);
        if (current == thread) {
            return i;
        }
        if (current == MACH_PORT_NULL && create) {
            mach_port_t expected = MACH_PORT_NULL;
            if (__atomic_compare_exchange_n(
                    &g_hw_threads[i].thread,
                    &expected,
                    thread,
                    0,
                    __ATOMIC_ACQ_REL,
                    __ATOMIC_RELAXED)) {
                __atomic_store_n(&g_hw_threads[i].step_active, 0, __ATOMIC_RELEASE);
                __atomic_store_n(&g_hw_threads[i].armed, 0, __ATOMIC_RELEASE);
                if (created) {
                    *created = 1;
                }
                return i;
            }
        }
    }
    if (create) {
        __atomic_fetch_add(&g_hw_thread_overflow, 1, __ATOMIC_RELAXED);
    }
    return -1;
}

static int hw_thread_step_active(mach_port_t thread, int *known) {
    int idx = hw_thread_index(thread, 0, NULL);
    if (idx < 0) {
        if (known) {
            *known = 0;
        }
        return 0;
    }
    if (known) {
        *known = 1;
    }
    return (int)__atomic_load_n(&g_hw_threads[idx].step_active, __ATOMIC_ACQUIRE);
}

static void hw_thread_set_step_active(mach_port_t thread, int active) {
    int idx = hw_thread_index(thread, 1, NULL);
    if (idx < 0) {
        return;
    }
    __atomic_store_n(&g_hw_threads[idx].step_active, active ? 1u : 0u, __ATOMIC_RELEASE);
}

static void hw_thread_mark_armed(mach_port_t thread) {
    int idx = hw_thread_index(thread, 1, NULL);
    if (idx < 0) {
        return;
    }
    __atomic_store_n(&g_hw_threads[idx].armed, 1u, __ATOMIC_RELEASE);
}

static int hw_arm_thread(thread_t thread) {
#if defined(__arm64__) || defined(__aarch64__)
    if (!hw_breakpoint_update_state(
            thread,
            g_hw_target_addr,
            g_hw_target_addr_secondary,
            g_hw_bcr_value,
            1,
            g_hw_target_addr_secondary ? 1 : 0,
            0,
            NULL,
            0)) {
        __atomic_fetch_add(&g_hw_arm_failures, 1, __ATOMIC_RELAXED);
        return 0;
    }
    hw_thread_mark_armed(thread);
    return 1;
#else
    (void)thread;
    return 0;
#endif
}

static void hw_arm_all_threads(void) {
#if defined(__arm64__) || defined(__aarch64__)
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
    if (kr != KERN_SUCCESS) {
        __atomic_fetch_add(&g_hw_arm_failures, 1, __ATOMIC_RELAXED);
        return;
    }
    __atomic_fetch_add(&g_hw_threads_scanned, count, __ATOMIC_RELAXED);
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (hw_arm_thread(threads[i])) {
            __atomic_fetch_add(&g_hw_threads_armed, 1, __ATOMIC_RELAXED);
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_t));
#else
    (void)0;
#endif
}

static void hw_disable_all_threads(void) {
#if defined(__arm64__) || defined(__aarch64__)
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    kern_return_t kr = task_threads(mach_task_self(), &threads, &count);
    if (kr != KERN_SUCCESS) {
        return;
    }
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        hw_breakpoint_update_state(threads[i], 0, 0, g_hw_bcr_value, 0, 0, 0, NULL, 0);
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_t));
#else
    (void)0;
#endif
}

static void *hw_arm_monitor_thread(void *arg) {
    (void)arg;
    __atomic_store_n(&g_hw_monitor_running, 1, __ATOMIC_RELEASE);
    while (__atomic_load_n(&g_hw_arm_running, __ATOMIC_ACQUIRE)) {
        hw_arm_all_threads();
        __atomic_fetch_add(&g_hw_rescans, 1, __ATOMIC_RELAXED);
        usleep(10000);
    }
    __atomic_store_n(&g_hw_monitor_running, 0, __ATOMIC_RELEASE);
    return NULL;
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
        uint64_t seq = __atomic_add_fetch(&g_seq, 1, __ATOMIC_RELAXED);
        emit_record_bytes(seq, buf, cursor, (const uint8_t *)data, len, len, 0, 0);
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

#if defined(__DARWIN_UNIX03)
#define ARM_TS_X(ts, idx) ((ts).__x[(idx)])
#define ARM_TS_PC(ts) ((ts).__pc)
#define ARM_DBG_BVR(ds, idx) ((ds).__bvr[(idx)])
#define ARM_DBG_BCR(ds, idx) ((ds).__bcr[(idx)])
#define ARM_DBG_MDSCR(ds) ((ds).__mdscr_el1)
#else
#define ARM_TS_X(ts, idx) ((ts).x[(idx)])
#define ARM_TS_PC(ts) ((ts).pc)
#define ARM_DBG_BVR(ds, idx) ((ds).bvr[(idx)])
#define ARM_DBG_BCR(ds, idx) ((ds).bcr[(idx)])
#define ARM_DBG_MDSCR(ds) ((ds).mdscr_el1)
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

struct hw_breakpoint_report {
    int attempted;
    int port_ok;
    int handler_thread_ok;
    int exception_port_ok;
    int exception_scope_task;
    int debug_state_ok;
    int breakpoint_set_ok;
    int secondary_set_ok;
    int prev_handler_ok;
    int threads_scanned;
    int threads_armed;
    int breakpoint_index;
    int secondary_index;
    uint64_t bcr_value;
    uint64_t target_addr;
    uint64_t secondary_addr;
    uint64_t ring_dropped;
    uint64_t capture_truncated;
    uint64_t break_hits;
    uint64_t step_hits;
    uint64_t forwarded;
    uint64_t unknown_break_hits;
    uint64_t immutable_hits;
    uint64_t immutable_buf;
    uint64_t thread_overflow;
    uint64_t arm_failures;
    uint64_t rescans;
    uint64_t threads_scanned_total;
    uint64_t threads_armed_total;
    uint32_t ring_size;
    uint32_t chunk_size;
    int prev_behavior;
    int prev_flavor;
    char error[256];
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

static uint64_t hw_breakpoint_control(void) {
    // Best-effort AArch64 breakpoint control: enable + match in user/priv + full byte select.
    const uint64_t enable = 1u;
    const uint64_t priv = (0x3u << 1);
    const uint64_t bas = (0xFu << 5);
    return enable | priv | bas;
}

static int hw_breakpoint_update_state(
    thread_t thread,
    uint64_t addr_primary,
    uint64_t addr_secondary,
    uint64_t bcr_value,
    int enable_primary,
    int enable_secondary,
    int single_step,
    char *err,
    size_t err_len
) {
#if defined(__arm64__) || defined(__aarch64__)
    arm_debug_state64_t dbg;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, &count);
    if (kr != KERN_SUCCESS) {
        if (err && err_len > 0) {
            snprintf(err, err_len, "thread_get_state(ARM_DEBUG_STATE64) failed: %s", mach_err_str(kr));
        }
        return 0;
    }
    if (enable_primary) {
        ARM_DBG_BVR(dbg, g_hw_break_index) = addr_primary;
        ARM_DBG_BCR(dbg, g_hw_break_index) = bcr_value;
    } else {
        ARM_DBG_BCR(dbg, g_hw_break_index) = 0;
    }
    if (enable_secondary && addr_secondary) {
        ARM_DBG_BVR(dbg, g_hw_break_index_secondary) = addr_secondary;
        ARM_DBG_BCR(dbg, g_hw_break_index_secondary) = bcr_value;
    } else {
        ARM_DBG_BCR(dbg, g_hw_break_index_secondary) = 0;
    }
    if (single_step) {
        ARM_DBG_MDSCR(dbg) |= 0x1;
    } else {
        ARM_DBG_MDSCR(dbg) &= ~0x1ULL;
    }
    kr = thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, count);
    if (kr != KERN_SUCCESS) {
        if (err && err_len > 0) {
            snprintf(err, err_len, "thread_set_state(ARM_DEBUG_STATE64) failed: %s", mach_err_str(kr));
        }
        return 0;
    }
    return 1;
#else
    (void)thread;
    (void)addr_primary;
    (void)addr_secondary;
    (void)bcr_value;
    (void)enable_primary;
    (void)enable_secondary;
    (void)single_step;
    if (err && err_len > 0) {
        snprintf(err, err_len, "hardware breakpoints unavailable on this architecture");
    }
    return 0;
#endif
}

static void *hw_exception_server(void *arg) {
    mach_port_t port = (mach_port_t)(uintptr_t)arg;
    mach_msg_server(mach_exc_server, 2048, port, 0);
    return NULL;
}

static int install_hw_breakpoint(
    void *target,
    void *target_secondary,
    struct hw_breakpoint_report *report,
    char *err,
    size_t err_len
) {
    if (report) {
        memset(report, 0, sizeof(*report));
        report->attempted = 1;
        report->breakpoint_index = g_hw_break_index;
        report->secondary_index = g_hw_break_index_secondary;
        report->ring_size = HW_RING_SIZE;
        report->chunk_size = HW_CHUNK_SIZE;
        report->prev_behavior = -1;
        report->prev_flavor = -1;
    }
    memset(g_hw_threads, 0, sizeof(g_hw_threads));
    __atomic_store_n(&g_hw_ring_write, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_ring_read, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_ring_dropped, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_capture_truncated, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_break_hits, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_step_hits, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_forwarded, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_unknown_break_hits, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_immutable_hits, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_immutable_buf, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_thread_overflow, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_arm_failures, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_rescans, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_threads_scanned, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&g_hw_threads_armed, 0, __ATOMIC_RELAXED);
    if (!target) {
        snprintf(err, err_len, "target address unavailable");
        if (report) {
            snprintf(report->error, sizeof(report->error), "target address unavailable");
        }
        return 0;
    }
#if defined(__arm64__) || defined(__aarch64__)
    kern_return_t kr;
    if (g_hw_exception_port == MACH_PORT_NULL) {
        kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_hw_exception_port);
        if (kr != KERN_SUCCESS) {
            snprintf(err, err_len, "mach_port_allocate failed: %s", mach_err_str(kr));
            if (report) {
                snprintf(report->error, sizeof(report->error), "mach_port_allocate failed: %s", mach_err_str(kr));
            }
            return 0;
        }
        kr = mach_port_insert_right(mach_task_self(), g_hw_exception_port, g_hw_exception_port, MACH_MSG_TYPE_MAKE_SEND);
        if (kr != KERN_SUCCESS) {
            snprintf(err, err_len, "mach_port_insert_right failed: %s", mach_err_str(kr));
            if (report) {
                snprintf(report->error, sizeof(report->error), "mach_port_insert_right failed: %s", mach_err_str(kr));
            }
            return 0;
        }
        if (report) {
            report->port_ok = 1;
        }
    } else if (report) {
        report->port_ok = 1;
    }

    if (!g_hw_server_running) {
        pthread_t thr;
        int rc = pthread_create(&thr, NULL, hw_exception_server, (void *)(uintptr_t)g_hw_exception_port);
        if (rc != 0) {
            snprintf(err, err_len, "pthread_create failed: %s", strerror(rc));
            if (report) {
                snprintf(report->error, sizeof(report->error), "pthread_create failed: %s", strerror(rc));
            }
            return 0;
        }
        pthread_detach(thr);
        g_hw_server_running = 1;
        if (report) {
            report->handler_thread_ok = 1;
        }
    } else if (report) {
        report->handler_thread_ok = 1;
    }

    if (!__atomic_load_n(&g_hw_flush_running, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&g_hw_flush_running, 1, __ATOMIC_RELEASE);
        pthread_t flush_thr;
        int rc = pthread_create(&flush_thr, NULL, hw_flush_thread, NULL);
        if (rc != 0) {
            __atomic_store_n(&g_hw_flush_running, 0, __ATOMIC_RELEASE);
            snprintf(err, err_len, "pthread_create(flush) failed: %s", strerror(rc));
            if (report) {
                snprintf(report->error, sizeof(report->error), "pthread_create(flush) failed: %s", strerror(rc));
            }
            return 0;
        }
        pthread_detach(flush_thr);
    }

    exception_mask_t masks[1] = {0};
    mach_msg_type_number_t mask_count = 1;
    exception_handler_t handlers[1] = {MACH_PORT_NULL};
    exception_behavior_t behaviors[1] = {0};
    thread_state_flavor_t flavors[1] = {0};
    if (g_hw_prev_valid && g_hw_prev_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), g_hw_prev_port);
    }
    g_hw_prev_port = MACH_PORT_NULL;
    g_hw_prev_behavior = 0;
    g_hw_prev_flavor = 0;
    g_hw_prev_valid = 0;

    kr = task_swap_exception_ports(
        mach_task_self(),
        EXC_MASK_BREAKPOINT,
        g_hw_exception_port,
        EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64,
        masks,
        &mask_count,
        handlers,
        behaviors,
        flavors
    );
    if (kr != KERN_SUCCESS) {
        snprintf(err, err_len, "task_swap_exception_ports failed: %s", mach_err_str(kr));
        if (report) {
            snprintf(report->error, sizeof(report->error), "task_swap_exception_ports failed: %s", mach_err_str(kr));
        }
        return 0;
    }
    if (report) {
        report->exception_port_ok = 1;
        report->exception_scope_task = 1;
    }
    for (mach_msg_type_number_t i = 0; i < mask_count; i++) {
        if (masks[i] & EXC_MASK_BREAKPOINT) {
            g_hw_prev_port = handlers[i];
            g_hw_prev_behavior = behaviors[i];
            g_hw_prev_flavor = flavors[i];
            g_hw_prev_valid = (handlers[i] != MACH_PORT_NULL);
            if (report && g_hw_prev_valid) {
                report->prev_handler_ok = 1;
                report->prev_behavior = (int)g_hw_prev_behavior;
                report->prev_flavor = (int)g_hw_prev_flavor;
            }
        } else if (handlers[i] != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), handlers[i]);
        }
    }

    g_hw_bcr_value = hw_breakpoint_control();
    if (report) {
        report->bcr_value = g_hw_bcr_value;
    }
    g_hw_target_addr = (uint64_t)(uintptr_t)target;
    g_hw_target_addr_secondary = (uint64_t)(uintptr_t)target_secondary;
    if (report) {
        report->target_addr = g_hw_target_addr;
        report->secondary_addr = g_hw_target_addr_secondary;
    }
    hw_arm_all_threads();
    if (!__atomic_load_n(&g_hw_arm_running, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&g_hw_arm_running, 1, __ATOMIC_RELEASE);
        pthread_t arm_thr;
        int rc = pthread_create(&arm_thr, NULL, hw_arm_monitor_thread, NULL);
        if (rc != 0) {
            __atomic_store_n(&g_hw_arm_running, 0, __ATOMIC_RELEASE);
            snprintf(err, err_len, "pthread_create(arm_monitor) failed: %s", strerror(rc));
            if (report) {
                snprintf(report->error, sizeof(report->error), "pthread_create(arm_monitor) failed: %s", strerror(rc));
            }
            return 0;
        }
        pthread_detach(arm_thr);
    }
    if (report) {
        report->threads_scanned = (int)__atomic_load_n(&g_hw_threads_scanned, __ATOMIC_ACQUIRE);
        report->threads_armed = (int)__atomic_load_n(&g_hw_threads_armed, __ATOMIC_ACQUIRE);
        report->debug_state_ok = (report->threads_armed > 0);
        report->breakpoint_set_ok = (report->threads_armed > 0);
        report->secondary_set_ok = (g_hw_target_addr_secondary && report->threads_armed > 0) ? 1 : 0;
        report->ring_dropped = __atomic_load_n(&g_hw_ring_dropped, __ATOMIC_ACQUIRE);
        report->capture_truncated = __atomic_load_n(&g_hw_capture_truncated, __ATOMIC_ACQUIRE);
        report->break_hits = __atomic_load_n(&g_hw_break_hits, __ATOMIC_ACQUIRE);
        report->step_hits = __atomic_load_n(&g_hw_step_hits, __ATOMIC_ACQUIRE);
        report->forwarded = __atomic_load_n(&g_hw_forwarded, __ATOMIC_ACQUIRE);
        report->unknown_break_hits = __atomic_load_n(&g_hw_unknown_break_hits, __ATOMIC_ACQUIRE);
        report->immutable_hits = __atomic_load_n(&g_hw_immutable_hits, __ATOMIC_ACQUIRE);
        report->immutable_buf = __atomic_load_n(&g_hw_immutable_buf, __ATOMIC_ACQUIRE);
        report->thread_overflow = __atomic_load_n(&g_hw_thread_overflow, __ATOMIC_ACQUIRE);
        report->arm_failures = __atomic_load_n(&g_hw_arm_failures, __ATOMIC_ACQUIRE);
        report->rescans = __atomic_load_n(&g_hw_rescans, __ATOMIC_ACQUIRE);
        report->threads_scanned_total = __atomic_load_n(&g_hw_threads_scanned, __ATOMIC_ACQUIRE);
        report->threads_armed_total = __atomic_load_n(&g_hw_threads_armed, __ATOMIC_ACQUIRE);
    }
    return 1;
#else
    snprintf(err, err_len, "hardware breakpoints unsupported on this architecture");
    if (report) {
        snprintf(report->error, sizeof(report->error), "hardware breakpoints unsupported on this architecture");
    }
    return 0;
#endif
}

static int hw_read_thread_state(thread_t thread, arm_thread_state64_t *out) {
#if defined(__arm64__) || defined(__aarch64__)
    if (!out) {
        return 0;
    }
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t kr = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)out, &count);
    return (kr == KERN_SUCCESS);
#else
    (void)thread;
    (void)out;
    return 0;
#endif
}

static void hw_capture_from_state(const arm_thread_state64_t *ts) {
#if defined(__arm64__) || defined(__aarch64__)
    if (!ts) {
        return;
    }
    void *buf = (void *)(uintptr_t)ARM_TS_X((*ts), 0);
    uint64_t cursor = (uint64_t)ARM_TS_X((*ts), 1);
    const uint8_t *data = (const uint8_t *)(uintptr_t)ARM_TS_X((*ts), 2);
    uint64_t len = (uint64_t)ARM_TS_X((*ts), 3);
    hw_ring_enqueue(buf, cursor, data, len);
#else
    (void)ts;
#endif
}

static void hw_capture_immutable_from_state(const arm_thread_state64_t *ts) {
#if defined(__arm64__) || defined(__aarch64__)
    if (!ts) {
        return;
    }
    void *buf = (void *)(uintptr_t)ARM_TS_X((*ts), 0);
    __atomic_store_n(&g_hw_immutable_buf, (uint64_t)(uintptr_t)buf, __ATOMIC_RELEASE);
#else
    (void)ts;
#endif
}

static int hw_pc_matches(uint64_t pc, uint64_t target) {
    if (!target) {
        return 0;
    }
    if (pc == target) {
        return 1;
    }
    if (pc == target + 4) {
        return 1;
    }
    return 0;
}

static kern_return_t hw_forward_exception(
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt
) {
    if (!g_hw_prev_valid || g_hw_prev_port == MACH_PORT_NULL) {
        return KERN_FAILURE;
    }
    exception_behavior_t behavior = g_hw_prev_behavior;
    exception_behavior_t base = behavior & ~MACH_EXCEPTION_CODES;
    if (base != EXCEPTION_DEFAULT) {
        return KERN_FAILURE;
    }
    if (behavior & MACH_EXCEPTION_CODES) {
        return mach_exception_raise(g_hw_prev_port, thread, task, exception, code, codeCnt);
    }
    exception_data_type_t local_code[2] = {0, 0};
    mach_msg_type_number_t count = codeCnt;
    if (count > 2) {
        count = 2;
    }
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        local_code[i] = (exception_data_type_t)code[i];
    }
    return exception_raise(g_hw_prev_port, thread, task, exception, local_code, count);
}

kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt
) {
    (void)exception_port;
    (void)code;
    (void)codeCnt;
    if (exception != EXC_BREAKPOINT || codeCnt < 1) {
        __atomic_fetch_add(&g_hw_forwarded, 1, __ATOMIC_RELAXED);
        kern_return_t forward = hw_forward_exception(thread, task, exception, code, codeCnt);
        if (thread != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), thread);
        }
        if (task != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task);
        }
        return forward;
    }

    int created = 0;
    int idx = hw_thread_index(thread, 1, &created);
    if (idx < 0) {
        __atomic_fetch_add(&g_hw_forwarded, 1, __ATOMIC_RELAXED);
        kern_return_t forward = hw_forward_exception(thread, task, exception, code, codeCnt);
        if (thread != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), thread);
        }
        if (task != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task);
        }
        return forward;
    }

    uint64_t subcode = 0;
    if (codeCnt > 1) {
        subcode = (uint64_t)code[1];
    }
    int step_active = (int)__atomic_load_n(&g_hw_threads[idx].step_active, __ATOMIC_ACQUIRE);
    int is_break_hit = step_active ? 0 : 1;
    int is_step_hit = step_active ? 1 : 0;
    (void)subcode;

    int ok = 0;
    if (is_break_hit) {
        arm_thread_state64_t ts;
        int has_state = hw_read_thread_state(thread, &ts);
        if (!has_state) {
            __atomic_fetch_add(&g_hw_forwarded, 1, __ATOMIC_RELAXED);
            kern_return_t forward = hw_forward_exception(thread, task, exception, code, codeCnt);
            if (thread != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), thread);
            }
            if (task != MACH_PORT_NULL) {
                mach_port_deallocate(mach_task_self(), task);
            }
            return forward;
        }
        uint64_t pc = (uint64_t)ARM_TS_PC(ts);
        int matched_primary = hw_pc_matches(pc, g_hw_target_addr);
        int matched_secondary = hw_pc_matches(pc, g_hw_target_addr_secondary);
        if (matched_secondary && !matched_primary) {
            hw_capture_immutable_from_state(&ts);
            __atomic_fetch_add(&g_hw_immutable_hits, 1, __ATOMIC_RELAXED);
        } else if (matched_primary) {
            hw_capture_from_state(&ts);
            __atomic_fetch_add(&g_hw_break_hits, 1, __ATOMIC_RELAXED);
        } else {
            __atomic_fetch_add(&g_hw_unknown_break_hits, 1, __ATOMIC_RELAXED);
        }
        __atomic_store_n(&g_hw_threads[idx].step_active, 1, __ATOMIC_RELEASE);
        ok = hw_breakpoint_update_state(thread, 0, 0, g_hw_bcr_value, 0, 0, 1, NULL, 0);
    } else {
        __atomic_fetch_add(&g_hw_step_hits, 1, __ATOMIC_RELAXED);
        __atomic_store_n(&g_hw_threads[idx].step_active, 0, __ATOMIC_RELEASE);
        ok = hw_breakpoint_update_state(
            thread,
            g_hw_target_addr,
            g_hw_target_addr_secondary,
            g_hw_bcr_value,
            1,
            g_hw_target_addr_secondary ? 1 : 0,
            0,
            NULL,
            0);
    }

    if (thread != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), thread);
    }
    if (task != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), task);
    }
    return ok ? KERN_SUCCESS : KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt
) {
    (void)exception_port;
    (void)exception;
    (void)code;
    (void)codeCnt;
    (void)flavor;
    (void)old_state;
    (void)old_stateCnt;
    (void)new_state;
    (void)new_stateCnt;
    return KERN_NOT_SUPPORTED;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt
) {
    (void)exception_port;
    (void)thread;
    (void)task;
    (void)exception;
    (void)code;
    (void)codeCnt;
    (void)flavor;
    (void)old_state;
    (void)old_stateCnt;
    (void)new_state;
    (void)new_stateCnt;
    return KERN_NOT_SUPPORTED;
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
    const struct hw_breakpoint_report *hw,
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
    if (hw) {
        fputs(",\"hw_breakpoint\":{", g_triage_fp);
        fprintf(g_triage_fp, "\"attempted\":%s", hw->attempted ? "true" : "false");
        fprintf(g_triage_fp, ",\"port_ok\":%s", hw->port_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"handler_thread_ok\":%s", hw->handler_thread_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"exception_port_ok\":%s", hw->exception_port_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"exception_scope\":");
        if (hw->exception_scope_task) {
            json_escape(g_triage_fp, "task");
        } else {
            json_escape(g_triage_fp, "thread");
        }
        fprintf(g_triage_fp, ",\"debug_state_ok\":%s", hw->debug_state_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"breakpoint_set_ok\":%s", hw->breakpoint_set_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"prev_handler_ok\":%s", hw->prev_handler_ok ? "true" : "false");
        fprintf(g_triage_fp, ",\"threads_scanned\":%d", hw->threads_scanned);
        fprintf(g_triage_fp, ",\"threads_armed\":%d", hw->threads_armed);
        fprintf(g_triage_fp, ",\"threads_scanned_total\":%llu", (unsigned long long)hw->threads_scanned_total);
        fprintf(g_triage_fp, ",\"threads_armed_total\":%llu", (unsigned long long)hw->threads_armed_total);
        fprintf(g_triage_fp, ",\"breakpoint_index\":%d", hw->breakpoint_index);
        fprintf(g_triage_fp, ",\"secondary_index\":%d", hw->secondary_index);
        fputs(",\"bcr_value\":", g_triage_fp);
        if (hw->bcr_value) {
            fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)hw->bcr_value);
        } else {
            fputs("null", g_triage_fp);
        }
        fprintf(g_triage_fp, ",\"secondary_set_ok\":%s", hw->secondary_set_ok ? "true" : "false");
        fputs(",\"target_addr\":", g_triage_fp);
        if (hw->target_addr) {
            fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)hw->target_addr);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"secondary_addr\":", g_triage_fp);
        if (hw->secondary_addr) {
            fprintf(g_triage_fp, "\"0x%llx\"", (unsigned long long)hw->secondary_addr);
        } else {
            fputs("null", g_triage_fp);
        }
        fprintf(g_triage_fp, ",\"ring_size\":%u", hw->ring_size);
        fprintf(g_triage_fp, ",\"chunk_size\":%u", hw->chunk_size);
        fprintf(g_triage_fp, ",\"ring_dropped\":%llu", (unsigned long long)hw->ring_dropped);
        fprintf(g_triage_fp, ",\"capture_truncated\":%llu", (unsigned long long)hw->capture_truncated);
        fprintf(g_triage_fp, ",\"break_hits\":%llu", (unsigned long long)hw->break_hits);
        fprintf(g_triage_fp, ",\"step_hits\":%llu", (unsigned long long)hw->step_hits);
        fprintf(g_triage_fp, ",\"forwarded\":%llu", (unsigned long long)hw->forwarded);
        fprintf(g_triage_fp, ",\"unknown_break_hits\":%llu", (unsigned long long)hw->unknown_break_hits);
        fprintf(g_triage_fp, ",\"immutable_hits\":%llu", (unsigned long long)hw->immutable_hits);
        fprintf(g_triage_fp, ",\"immutable_buf\":\"0x%llx\"", (unsigned long long)hw->immutable_buf);
        fprintf(g_triage_fp, ",\"thread_overflow\":%llu", (unsigned long long)hw->thread_overflow);
        fprintf(g_triage_fp, ",\"arm_failures\":%llu", (unsigned long long)hw->arm_failures);
        fprintf(g_triage_fp, ",\"rescans\":%llu", (unsigned long long)hw->rescans);
        fputs(",\"prev_behavior\":", g_triage_fp);
        if (hw->prev_handler_ok) {
            fprintf(g_triage_fp, "%d", hw->prev_behavior);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"prev_flavor\":", g_triage_fp);
        if (hw->prev_handler_ok) {
            fprintf(g_triage_fp, "%d", hw->prev_flavor);
        } else {
            fputs("null", g_triage_fp);
        }
        fputs(",\"error\":", g_triage_fp);
        json_escape(g_triage_fp, hw->error[0] ? hw->error : NULL);
        fputs("}", g_triage_fp);
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

    void *immutable_target_addr = NULL;
    const char *immutable_addr_env = getenv("SBPL_WRITE_IMMUTABLE_ADDR");
    const char *immutable_unslid_env = getenv("SBPL_WRITE_IMMUTABLE_UNSLID");
    const char *immutable_offset_env = getenv("SBPL_WRITE_IMMUTABLE_OFFSET");
    uint64_t immutable_addr = 0;
    uint64_t immutable_unslid = 0;
    int immutable_unslid_known = 0;
    if (parse_u64(immutable_unslid_env, &immutable_unslid)) {
        immutable_unslid_known = 1;
    }
    if (parse_u64(immutable_addr_env, &immutable_addr)) {
        immutable_target_addr = (void *)(uintptr_t)immutable_addr;
    } else if (immutable_unslid_known) {
        if (unslid_allowed && slide_known) {
            immutable_target_addr = (void *)(uintptr_t)(immutable_unslid + (uint64_t)image_slide);
        }
    } else if (parse_u64(immutable_offset_env, &immutable_addr) && sandbox_base) {
        immutable_target_addr = (void *)((uintptr_t)sandbox_base + immutable_addr);
    }

    const int interpose_available = (dyld_dynamic_interpose != NULL);
    const char *hook_attempt = "none";
    const char *hook_status = "skipped";
    const char *hook_error = NULL;
    const char *patch_surface = NULL;
    struct patch_report patch = {0};
    struct hw_breakpoint_report hw = {0};

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
    } else if (strcmp(g_trace_mode, "hw_breakpoint") == 0) {
        hook_attempt = "hw_breakpoint";
        patch_surface = "hw_breakpoint";
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
            char err_buf[256] = {0};
            if (install_hw_breakpoint(target_addr, immutable_target_addr, &hw, err_buf, sizeof(err_buf))) {
                hook_status = "ok";
            } else {
                hook_status = "failed";
                hook_error = err_buf;
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
        (hw.attempted || hw.port_ok || hw.handler_thread_ok) ? &hw : NULL,
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

__attribute__((destructor)) static void sbpl_trace_shutdown(void) {
#if defined(__arm64__) || defined(__aarch64__)
    __atomic_store_n(&g_hw_arm_running, 0, __ATOMIC_RELEASE);
#endif
    __atomic_store_n(&g_hw_flush_running, 0, __ATOMIC_RELEASE);
    hw_disable_all_threads();
    hw_write_stats();
    if (g_hw_prev_valid && g_hw_prev_port != MACH_PORT_NULL) {
        task_set_exception_ports(
            mach_task_self(),
            EXC_MASK_BREAKPOINT,
            g_hw_prev_port,
            g_hw_prev_behavior,
            g_hw_prev_flavor
        );
        mach_port_deallocate(mach_task_self(), g_hw_prev_port);
        g_hw_prev_port = MACH_PORT_NULL;
        g_hw_prev_valid = 0;
    }
    if (g_hw_exception_port != MACH_PORT_NULL) {
        mach_port_mod_refs(mach_task_self(), g_hw_exception_port, MACH_PORT_RIGHT_SEND, -1);
        mach_port_mod_refs(mach_task_self(), g_hw_exception_port, MACH_PORT_RIGHT_RECEIVE, -1);
        g_hw_exception_port = MACH_PORT_NULL;
    }
    hw_flush_ring();
}
