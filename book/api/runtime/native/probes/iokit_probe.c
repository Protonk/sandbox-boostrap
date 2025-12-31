/*
 * iokit_probe: attempt to open an IOKit service matching a registry entry class,
 * then issue a minimal post-open user-client call to exercise the call path.
 *
 * This is used as an unsandboxed baseline for runtime discriminator matrices.
 * It prints a single JSON object to stdout:
 *   {"found":<bool>,"open_kr":<int|null>,"call_kr":<int|null>,"call_selector":<int|null>,"surface_create_ok":<bool|null>,"surface_create_signal":<int|null>}
 *
 * Exit codes:
 * - 0: service found, IOServiceOpen succeeded, and the post-open call succeeded
 * - 1: service found but IOServiceOpen failed or the post-open call failed
 * - 2: no matching service found (unobservable in this process context)
 *
 * Usage: iokit_probe <registry_entry_class>
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFSerialize.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOReturn.h>
#include <IOSurface/IOSurface.h>
#include <dlfcn.h>
#include <mach/error.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern kern_return_t mach_msg_overwrite_trap(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify,
    mach_msg_header_t *rcv_msg,
    mach_msg_size_t rcv_limit) __attribute__((weak_import));

extern kern_return_t mach_msg_trap(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify) __attribute__((weak_import));

extern kern_return_t mach_msg2_trap(
    mach_msg_header_t *msg,
    uint64_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify,
    uint64_t priority,
    mach_msg_size_t rcv_trailer_size) __attribute__((weak_import));

#define SBL_IKIT_CAPTURE_ENV "SANDBOX_LORE_IKIT_CAPTURE_CALLS"
#define SBL_IKIT_CALL_KIND_ENV "SANDBOX_LORE_IKIT_CALL_KIND"
#define SBL_IKIT_CALL_IN_SCALARS_ENV "SANDBOX_LORE_IKIT_CALL_IN_SCALARS"
#define SBL_IKIT_CALL_IN_STRUCT_BYTES_ENV "SANDBOX_LORE_IKIT_CALL_IN_STRUCT_BYTES"
#define SBL_IKIT_CALL_OUT_SCALARS_ENV "SANDBOX_LORE_IKIT_CALL_OUT_SCALARS"
#define SBL_IKIT_CALL_OUT_STRUCT_BYTES_ENV "SANDBOX_LORE_IKIT_CALL_OUT_STRUCT_BYTES"
#define SBL_IKIT_SYNTH_CALL_ENV "SANDBOX_LORE_IKIT_SYNTH_CALL"
#define SBL_IKIT_REPLAY_ENV "SANDBOX_LORE_IKIT_REPLAY"
#define SBL_IKIT_REPLAY_SPEC_ENV "SANDBOX_LORE_IKIT_REPLAY_SPEC"
#define SBL_IKIT_SWEEP_ENV "SANDBOX_LORE_IKIT_SWEEP"
#define SBL_IKIT_SWEEP_MENU_ENV "SANDBOX_LORE_IKIT_SWEEP_MENU"
#define SBL_IKIT_MACH_CAPTURE_ENV "SANDBOX_LORE_IKIT_MACH_CAPTURE"
#define SBL_IKIT_METHOD0_ENV "SANDBOX_LORE_IKIT_METHOD0"
#define SBL_IKIT_METHOD0_BINARY_ENV "SANDBOX_LORE_IKIT_METHOD0_BINARY"
#define SBL_IKIT_METHOD0_PAYLOAD_IN_ENV "SANDBOX_LORE_IKIT_METHOD0_PAYLOAD_IN"
#define SBL_IKIT_METHOD0_PAYLOAD_OUT_ENV "SANDBOX_LORE_IKIT_METHOD0_PAYLOAD_OUT"

typedef struct {
    int seen;
    int non_invalid_seen;
    char kind[64];
    char non_invalid_kind[64];
    uint32_t selector;
    uint32_t non_invalid_selector;
    uint32_t input_scalar_count;
    uint32_t non_invalid_input_scalar_count;
    size_t input_struct_bytes;
    size_t non_invalid_input_struct_bytes;
    uint32_t output_scalar_count;
    uint32_t non_invalid_output_scalar_count;
    size_t output_struct_bytes;
    size_t non_invalid_output_struct_bytes;
    kern_return_t kr;
    kern_return_t non_invalid_kr;
} sbl_iokit_capture_t;

typedef struct {
    int valid;
    char kind[64];
    uint32_t selector;
    uint32_t input_scalar_count;
    size_t input_struct_bytes;
    uint32_t output_scalar_count;
    size_t output_struct_bytes;
    kern_return_t kr;
} sbl_iokit_call_tuple_t;

typedef struct {
    uint32_t input_scalar_count;
    size_t input_struct_bytes;
    uint32_t output_scalar_count;
    size_t output_struct_bytes;
} sbl_iokit_call_shape_t;

static const sbl_iokit_call_shape_t k_sweep_shapes[] = {
    {0, 0, 0, 0},
    {0, 16, 0, 16},
    {0, 64, 0, 64},
    {1, 0, 1, 0},
    {1, 16, 1, 16},
};

typedef struct {
    int enabled;
    mach_port_t port;
    size_t count;
    struct {
        int32_t msg_id;
        mach_msg_size_t size;
        uint32_t hash;
        kern_return_t kr;
    } entries[32];
} sbl_mach_capture_t;

#define SBL_DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct {          \
        const void *replacement;                   \
        const void *replacee;                      \
    } _interpose_##_replacee                       \
        __attribute__((section("__DATA,__interpose"))) = { \
            (const void *)(unsigned long)&_replacement,    \
            (const void *)(unsigned long)&_replacee        \
        };

typedef kern_return_t (*sbl_mach_msg_fn)(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify);

typedef kern_return_t (*sbl_mach_msg_overwrite_trap_fn)(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify,
    mach_msg_header_t *rcv_msg,
    mach_msg_size_t rcv_limit);

typedef kern_return_t (*sbl_mach_msg_trap_fn)(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify);

typedef kern_return_t (*sbl_mach_msg2_trap_fn)(
    mach_msg_header_t *msg,
    uint64_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify,
    uint64_t priority,
    mach_msg_size_t rcv_trailer_size);

static sbl_iokit_capture_t g_capture;
static int g_capture_active = 0;
static sbl_mach_capture_t g_mach_capture;
static sbl_mach_msg_fn sbl_real_mach_msg = NULL;
static sbl_mach_msg_overwrite_trap_fn sbl_real_mach_msg_overwrite_trap = NULL;
static sbl_mach_msg_trap_fn sbl_real_mach_msg_trap = NULL;
static sbl_mach_msg2_trap_fn sbl_real_mach_msg2_trap = NULL;

static void sbl_capture_reset(void) {
    memset(&g_capture, 0, sizeof(g_capture));
}

static CFDictionaryRef sbl_build_iosurface_create_props(void) {
    int width = 1;
    int height = 1;
    int bytes_per_elem = 4;
    int bytes_per_row = width * bytes_per_elem;
    int alloc_size = bytes_per_row * height;
    uint32_t pixel_format = 0x42475241; /* 'BGRA' */
    CFNumberRef width_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &width);
    CFNumberRef height_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &height);
    CFNumberRef bpe_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytes_per_elem);
    CFNumberRef bpr_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytes_per_row);
    CFNumberRef alloc_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &alloc_size);
    CFNumberRef pixel_format_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &pixel_format);
    if (!width_num || !height_num || !bpe_num || !bpr_num || !alloc_num || !pixel_format_num) {
        if (width_num) CFRelease(width_num);
        if (height_num) CFRelease(height_num);
        if (bpe_num) CFRelease(bpe_num);
        if (bpr_num) CFRelease(bpr_num);
        if (alloc_num) CFRelease(alloc_num);
        if (pixel_format_num) CFRelease(pixel_format_num);
        return NULL;
    }
    const void *keys[] = {
        kIOSurfaceWidth,
        kIOSurfaceHeight,
        kIOSurfaceBytesPerElement,
        kIOSurfaceBytesPerRow,
        kIOSurfacePixelFormat,
        kIOSurfaceAllocSize,
    };
    const void *vals[] = {
        width_num,
        height_num,
        bpe_num,
        bpr_num,
        pixel_format_num,
        alloc_num,
    };
    CFDictionaryRef props = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        vals,
        6,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    CFRelease(width_num);
    CFRelease(height_num);
    CFRelease(bpe_num);
    CFRelease(bpr_num);
    CFRelease(alloc_num);
    CFRelease(pixel_format_num);
    if (!props) {
        return NULL;
    }
    return props;
}

static CFDataRef sbl_build_iosurface_plist(
    const char **format_out,
    const char **source_out,
    CFOptionFlags serialize_flags
) {
    CFDictionaryRef props = sbl_build_iosurface_create_props();
    if (!props) {
        return NULL;
    }
    if (source_out) {
        *source_out = "create_props";
    }
    CFDataRef data = IOCFSerialize(props, serialize_flags);
    if (data && format_out) {
        *format_out = (serialize_flags & kIOCFSerializeToBinary) ? "iocf_binary" : "iocf_xml";
    }
    CFRelease(props);
    return data;
}

static CFDataRef sbl_load_payload_file(const char *path) {
    if (!path || !*path) {
        return NULL;
    }
    FILE *fh = fopen(path, "rb");
    if (!fh) {
        return NULL;
    }
    if (fseek(fh, 0, SEEK_END) != 0) {
        fclose(fh);
        return NULL;
    }
    long size = ftell(fh);
    if (size <= 0) {
        fclose(fh);
        return NULL;
    }
    if (fseek(fh, 0, SEEK_SET) != 0) {
        fclose(fh);
        return NULL;
    }
    uint8_t *buf = (uint8_t *)calloc(1, (size_t)size);
    if (!buf) {
        fclose(fh);
        return NULL;
    }
    size_t read_len = fread(buf, 1, (size_t)size, fh);
    fclose(fh);
    if (read_len != (size_t)size) {
        free(buf);
        return NULL;
    }
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, buf, (CFIndex)read_len);
    free(buf);
    return data;
}

static void sbl_write_payload_file(const char *path, const uint8_t *data, size_t len) {
    if (!path || !*path || !data || len == 0) {
        return;
    }
    FILE *fh = fopen(path, "wb");
    if (!fh) {
        return;
    }
    (void)fwrite(data, 1, len, fh);
    fclose(fh);
}

static uint8_t *sbl_copy_payload_with_nul(
    const uint8_t *data,
    size_t len,
    size_t *out_len,
    bool *nul_appended_out
) {
    if (!data || len == 0) {
        return NULL;
    }
    bool needs_nul = data[len - 1] != 0;
    size_t final_len = len + (needs_nul ? 1 : 0);
    uint8_t *buf = (uint8_t *)calloc(1, final_len);
    if (!buf) {
        return NULL;
    }
    memcpy(buf, data, len);
    if (needs_nul) {
        buf[len] = 0;
    }
    if (out_len) {
        *out_len = final_len;
    }
    if (nul_appended_out) {
        *nul_appended_out = needs_nul;
    }
    return buf;
}

static uint32_t sbl_hash_bytes(const uint8_t *data, size_t len) {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

static void sbl_mach_capture_record(const mach_msg_header_t *msg, mach_msg_size_t size, kern_return_t kr) {
    if (!g_mach_capture.enabled || !msg) {
        return;
    }
    if (g_mach_capture.count >= (sizeof(g_mach_capture.entries) / sizeof(g_mach_capture.entries[0]))) {
        return;
    }
    size_t idx = g_mach_capture.count++;
    size_t hash_len = size > 256 ? 256 : size;
    uint32_t hash = sbl_hash_bytes((const uint8_t *)msg, hash_len);
    g_mach_capture.entries[idx].msg_id = msg->msgh_id;
    g_mach_capture.entries[idx].size = size;
    g_mach_capture.entries[idx].hash = hash;
    g_mach_capture.entries[idx].kr = kr;
}

static sbl_mach_msg_fn sbl_load_mach_msg(void) {
    if (sbl_real_mach_msg) {
        return sbl_real_mach_msg;
    }
    sbl_real_mach_msg = (sbl_mach_msg_fn)dlsym(RTLD_NEXT, "mach_msg");
    return sbl_real_mach_msg;
}

static sbl_mach_msg_overwrite_trap_fn sbl_load_mach_msg_overwrite_trap(void) {
    if (sbl_real_mach_msg_overwrite_trap) {
        return sbl_real_mach_msg_overwrite_trap;
    }
    sbl_real_mach_msg_overwrite_trap = (sbl_mach_msg_overwrite_trap_fn)dlsym(RTLD_NEXT, "mach_msg_overwrite_trap");
    return sbl_real_mach_msg_overwrite_trap;
}

static sbl_mach_msg_trap_fn sbl_load_mach_msg_trap(void) {
    if (sbl_real_mach_msg_trap) {
        return sbl_real_mach_msg_trap;
    }
    sbl_real_mach_msg_trap = (sbl_mach_msg_trap_fn)dlsym(RTLD_NEXT, "mach_msg_trap");
    return sbl_real_mach_msg_trap;
}

static sbl_mach_msg2_trap_fn sbl_load_mach_msg2_trap(void) {
    if (sbl_real_mach_msg2_trap) {
        return sbl_real_mach_msg2_trap;
    }
    sbl_real_mach_msg2_trap = (sbl_mach_msg2_trap_fn)dlsym(RTLD_NEXT, "mach_msg2_trap");
    return sbl_real_mach_msg2_trap;
}

kern_return_t sbl_interpose_mach_msg(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify
) {
    sbl_mach_msg_fn fn = sbl_load_mach_msg();
    if (!fn) {
        return KERN_FAILURE;
    }
    kern_return_t kr = fn(msg, option, send_size, rcv_size, rcv_name, timeout, notify);
    if (g_mach_capture.enabled && msg && (option & MACH_SEND_MSG) && msg->msgh_remote_port == g_mach_capture.port) {
        mach_msg_size_t size = send_size ? send_size : msg->msgh_size;
        sbl_mach_capture_record(msg, size, kr);
    }
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_mach_msg, mach_msg)

kern_return_t sbl_interpose_mach_msg_overwrite_trap(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify,
    mach_msg_header_t *rcv_msg,
    mach_msg_size_t rcv_limit
) {
    sbl_mach_msg_overwrite_trap_fn fn = sbl_load_mach_msg_overwrite_trap();
    if (!fn) {
        return KERN_FAILURE;
    }
    kern_return_t kr = fn(msg, option, send_size, rcv_size, rcv_name, timeout, notify, rcv_msg, rcv_limit);
    if (g_mach_capture.enabled && msg && (option & MACH_SEND_MSG) && msg->msgh_remote_port == g_mach_capture.port) {
        mach_msg_size_t size = send_size ? send_size : msg->msgh_size;
        sbl_mach_capture_record(msg, size, kr);
    }
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_mach_msg_overwrite_trap, mach_msg_overwrite_trap)

kern_return_t sbl_interpose_mach_msg_trap(
    mach_msg_header_t *msg,
    mach_msg_option_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify
) {
    sbl_mach_msg_trap_fn fn = sbl_load_mach_msg_trap();
    if (!fn) {
        return KERN_FAILURE;
    }
    kern_return_t kr = fn(msg, option, send_size, rcv_size, rcv_name, timeout, notify);
    if (g_mach_capture.enabled && msg && (option & MACH_SEND_MSG) && msg->msgh_remote_port == g_mach_capture.port) {
        mach_msg_size_t size = send_size ? send_size : msg->msgh_size;
        sbl_mach_capture_record(msg, size, kr);
    }
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_mach_msg_trap, mach_msg_trap)

kern_return_t sbl_interpose_mach_msg2_trap(
    mach_msg_header_t *msg,
    uint64_t option,
    mach_msg_size_t send_size,
    mach_msg_size_t rcv_size,
    mach_port_t rcv_name,
    mach_msg_timeout_t timeout,
    mach_port_t notify,
    uint64_t priority,
    mach_msg_size_t rcv_trailer_size
) {
    sbl_mach_msg2_trap_fn fn = sbl_load_mach_msg2_trap();
    if (!fn) {
        return KERN_FAILURE;
    }
    kern_return_t kr = fn(msg, option, send_size, rcv_size, rcv_name, timeout, notify, priority, rcv_trailer_size);
    if (g_mach_capture.enabled && msg && (option & MACH_SEND_MSG) && msg->msgh_remote_port == g_mach_capture.port) {
        mach_msg_size_t size = send_size ? send_size : msg->msgh_size;
        sbl_mach_capture_record(msg, size, kr);
    }
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_mach_msg2_trap, mach_msg2_trap)

static const char *normalize_call_kind(const char *kind);

static void sbl_tuple_reset(sbl_iokit_call_tuple_t *tuple) {
    if (!tuple) {
        return;
    }
    memset(tuple, 0, sizeof(*tuple));
}

static void sbl_capture_copy_kind(char *dst, size_t dst_len, const char *kind) {
    if (!dst || dst_len == 0) {
        return;
    }
    if (!kind) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_len, "%s", kind);
}

static void sbl_capture_record(
    const char *kind,
    uint32_t selector,
    uint32_t input_scalar_count,
    size_t input_struct_bytes,
    uint32_t output_scalar_count,
    size_t output_struct_bytes,
    kern_return_t kr
) {
    if (!g_capture_active) {
        return;
    }
    if (!g_capture.seen) {
        g_capture.seen = 1;
        sbl_capture_copy_kind(g_capture.kind, sizeof(g_capture.kind), kind);
        g_capture.selector = selector;
        g_capture.input_scalar_count = input_scalar_count;
        g_capture.input_struct_bytes = input_struct_bytes;
        g_capture.output_scalar_count = output_scalar_count;
        g_capture.output_struct_bytes = output_struct_bytes;
        g_capture.kr = kr;
    }
    if (!g_capture.non_invalid_seen && kr != kIOReturnBadArgument) {
        g_capture.non_invalid_seen = 1;
        sbl_capture_copy_kind(g_capture.non_invalid_kind, sizeof(g_capture.non_invalid_kind), kind);
        g_capture.non_invalid_selector = selector;
        g_capture.non_invalid_input_scalar_count = input_scalar_count;
        g_capture.non_invalid_input_struct_bytes = input_struct_bytes;
        g_capture.non_invalid_output_scalar_count = output_scalar_count;
        g_capture.non_invalid_output_struct_bytes = output_struct_bytes;
        g_capture.non_invalid_kr = kr;
    }
}

static void sbl_tuple_set(
    sbl_iokit_call_tuple_t *tuple,
    const char *kind,
    uint32_t selector,
    uint32_t input_scalar_count,
    size_t input_struct_bytes,
    uint32_t output_scalar_count,
    size_t output_struct_bytes,
    kern_return_t kr
) {
    if (!tuple) {
        return;
    }
    sbl_tuple_reset(tuple);
    tuple->valid = 1;
    sbl_capture_copy_kind(tuple->kind, sizeof(tuple->kind), kind);
    tuple->selector = selector;
    tuple->input_scalar_count = input_scalar_count;
    tuple->input_struct_bytes = input_struct_bytes;
    tuple->output_scalar_count = output_scalar_count;
    tuple->output_struct_bytes = output_struct_bytes;
    tuple->kr = kr;
}

static void sbl_format_replay_spec(const sbl_iokit_call_tuple_t *tuple, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return;
    }
    if (!tuple || !tuple->valid) {
        buf[0] = '\0';
        return;
    }
    snprintf(
        buf,
        buf_len,
        "%s:%u:%u:%zu:%u:%zu",
        tuple->kind,
        tuple->selector,
        tuple->input_scalar_count,
        tuple->input_struct_bytes,
        tuple->output_scalar_count,
        tuple->output_struct_bytes
    );
}

static int sbl_parse_replay_spec(const char *spec, sbl_iokit_call_tuple_t *tuple) {
    if (!spec || !*spec || !tuple) {
        return 0;
    }
    char buf[256];
    snprintf(buf, sizeof(buf), "%s", spec);
    char *save = NULL;
    char *kind = strtok_r(buf, ":", &save);
    char *selector_str = strtok_r(NULL, ":", &save);
    char *in_scalars_str = strtok_r(NULL, ":", &save);
    char *in_struct_str = strtok_r(NULL, ":", &save);
    char *out_scalars_str = strtok_r(NULL, ":", &save);
    char *out_struct_str = strtok_r(NULL, ":", &save);
    if (!kind || !selector_str || !in_scalars_str || !in_struct_str || !out_scalars_str || !out_struct_str) {
        return 0;
    }
    char *end = NULL;
    unsigned long selector = strtoul(selector_str, &end, 10);
    if (!end || *end != '\0') {
        return 0;
    }
    unsigned long in_scalars = strtoul(in_scalars_str, &end, 10);
    if (!end || *end != '\0') {
        return 0;
    }
    unsigned long in_struct = strtoul(in_struct_str, &end, 10);
    if (!end || *end != '\0') {
        return 0;
    }
    unsigned long out_scalars = strtoul(out_scalars_str, &end, 10);
    if (!end || *end != '\0') {
        return 0;
    }
    unsigned long out_struct = strtoul(out_struct_str, &end, 10);
    if (!end || *end != '\0') {
        return 0;
    }
    sbl_tuple_reset(tuple);
    tuple->valid = 1;
    sbl_capture_copy_kind(tuple->kind, sizeof(tuple->kind), normalize_call_kind(kind));
    tuple->selector = (uint32_t)selector;
    tuple->input_scalar_count = (uint32_t)in_scalars;
    tuple->input_struct_bytes = (size_t)in_struct;
    tuple->output_scalar_count = (uint32_t)out_scalars;
    tuple->output_struct_bytes = (size_t)out_struct;
    tuple->kr = KERN_FAILURE;
    return 1;
}

typedef kern_return_t (*sbl_IOConnectCallMethod_fn)(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *input,
    uint32_t inputCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    uint64_t *output,
    uint32_t *outputCnt,
    void *outputStruct,
    size_t *outputStructCnt);

static sbl_IOConnectCallMethod_fn sbl_load_IOConnectCallMethod(void) {
    static sbl_IOConnectCallMethod_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_IOConnectCallMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallMethod");
    return fn;
}

static sbl_IOConnectCallMethod_fn sbl_load_IOConnectCallMethod_default(void) {
    static sbl_IOConnectCallMethod_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_IOConnectCallMethod_fn)dlsym(RTLD_DEFAULT, "IOConnectCallMethod");
    return fn;
}

kern_return_t sbl_interpose_IOConnectCallMethod(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *input,
    uint32_t inputCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    uint64_t *output,
    uint32_t *outputCnt,
    void *outputStruct,
    size_t *outputStructCnt
) {
    sbl_IOConnectCallMethod_fn fn = sbl_load_IOConnectCallMethod();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(
        connection,
        selector,
        input,
        inputCnt,
        inputStruct,
        inputStructCnt,
        output,
        outputCnt,
        outputStruct,
        outputStructCnt
    );
    uint32_t out_scalars = outputCnt ? *outputCnt : 0;
    size_t out_struct = outputStructCnt ? *outputStructCnt : 0;
    sbl_capture_record("IOConnectCallMethod", selector, inputCnt, inputStructCnt, out_scalars, out_struct, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_IOConnectCallMethod, IOConnectCallMethod);

typedef kern_return_t (*sbl_IOConnectCallScalarMethod_fn)(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *input,
    uint32_t inputCnt,
    uint64_t *output,
    uint32_t *outputCnt);

static sbl_IOConnectCallScalarMethod_fn sbl_load_IOConnectCallScalarMethod(void) {
    static sbl_IOConnectCallScalarMethod_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_IOConnectCallScalarMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallScalarMethod");
    return fn;
}

kern_return_t sbl_interpose_IOConnectCallScalarMethod(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *input,
    uint32_t inputCnt,
    uint64_t *output,
    uint32_t *outputCnt
) {
    sbl_IOConnectCallScalarMethod_fn fn = sbl_load_IOConnectCallScalarMethod();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, input, inputCnt, output, outputCnt);
    uint32_t out_scalars = outputCnt ? *outputCnt : 0;
    sbl_capture_record("IOConnectCallScalarMethod", selector, inputCnt, 0, out_scalars, 0, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_IOConnectCallScalarMethod, IOConnectCallScalarMethod);

typedef kern_return_t (*sbl_IOConnectCallStructMethod_fn)(
    io_connect_t connection,
    uint32_t selector,
    const void *inputStruct,
    size_t inputStructCnt,
    void *outputStruct,
    size_t *outputStructCnt);

static sbl_IOConnectCallStructMethod_fn sbl_load_IOConnectCallStructMethod(void) {
    static sbl_IOConnectCallStructMethod_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_IOConnectCallStructMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallStructMethod");
    return fn;
}

kern_return_t sbl_interpose_IOConnectCallStructMethod(
    io_connect_t connection,
    uint32_t selector,
    const void *inputStruct,
    size_t inputStructCnt,
    void *outputStruct,
    size_t *outputStructCnt
) {
    sbl_IOConnectCallStructMethod_fn fn = sbl_load_IOConnectCallStructMethod();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, inputStruct, inputStructCnt, outputStruct, outputStructCnt);
    size_t out_struct = outputStructCnt ? *outputStructCnt : 0;
    sbl_capture_record("IOConnectCallStructMethod", selector, 0, inputStructCnt, 0, out_struct, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_IOConnectCallStructMethod, IOConnectCallStructMethod);

typedef kern_return_t (*sbl_IOConnectCallAsyncScalarMethod_fn)(
    io_connect_t connection,
    uint32_t selector,
    mach_port_t wake_port,
    uint64_t *reference,
    uint32_t referenceCnt,
    const uint64_t *input,
    uint32_t inputCnt,
    uint64_t *output,
    uint32_t *outputCnt);

static sbl_IOConnectCallAsyncScalarMethod_fn sbl_load_IOConnectCallAsyncScalarMethod(void) {
    static sbl_IOConnectCallAsyncScalarMethod_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_IOConnectCallAsyncScalarMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallAsyncScalarMethod");
    return fn;
}

kern_return_t sbl_interpose_IOConnectCallAsyncScalarMethod(
    io_connect_t connection,
    uint32_t selector,
    mach_port_t wake_port,
    uint64_t *reference,
    uint32_t referenceCnt,
    const uint64_t *input,
    uint32_t inputCnt,
    uint64_t *output,
    uint32_t *outputCnt
) {
    sbl_IOConnectCallAsyncScalarMethod_fn fn = sbl_load_IOConnectCallAsyncScalarMethod();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, wake_port, reference, referenceCnt, input, inputCnt, output, outputCnt);
    uint32_t out_scalars = outputCnt ? *outputCnt : 0;
    sbl_capture_record("IOConnectCallAsyncScalarMethod", selector, inputCnt, 0, out_scalars, 0, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_IOConnectCallAsyncScalarMethod, IOConnectCallAsyncScalarMethod);

typedef kern_return_t (*sbl_IOConnectCallAsyncStructMethod_fn)(
    io_connect_t connection,
    uint32_t selector,
    mach_port_t wake_port,
    uint64_t *reference,
    uint32_t referenceCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    void *outputStruct,
    size_t *outputStructCnt);

static sbl_IOConnectCallAsyncStructMethod_fn sbl_load_IOConnectCallAsyncStructMethod(void) {
    static sbl_IOConnectCallAsyncStructMethod_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_IOConnectCallAsyncStructMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallAsyncStructMethod");
    return fn;
}

kern_return_t sbl_interpose_IOConnectCallAsyncStructMethod(
    io_connect_t connection,
    uint32_t selector,
    mach_port_t wake_port,
    uint64_t *reference,
    uint32_t referenceCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    void *outputStruct,
    size_t *outputStructCnt
) {
    sbl_IOConnectCallAsyncStructMethod_fn fn = sbl_load_IOConnectCallAsyncStructMethod();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, wake_port, reference, referenceCnt, inputStruct, inputStructCnt, outputStruct, outputStructCnt);
    size_t out_struct = outputStructCnt ? *outputStructCnt : 0;
    sbl_capture_record("IOConnectCallAsyncStructMethod", selector, 0, inputStructCnt, 0, out_struct, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(sbl_interpose_IOConnectCallAsyncStructMethod, IOConnectCallAsyncStructMethod);

typedef kern_return_t (*sbl_io_connect_method_scalarI_scalarO_fn)(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_scalar_inband_t output,
    mach_msg_type_number_t *outputCnt);

static sbl_io_connect_method_scalarI_scalarO_fn sbl_load_io_connect_method_scalarI_scalarO(void) {
    static sbl_io_connect_method_scalarI_scalarO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_scalarI_scalarO_fn)dlsym(RTLD_NEXT, "io_connect_method_scalarI_scalarO");
    return fn;
}

kern_return_t io_connect_method_scalarI_scalarO(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_scalar_inband_t output,
    mach_msg_type_number_t *outputCnt
) {
    sbl_io_connect_method_scalarI_scalarO_fn fn = sbl_load_io_connect_method_scalarI_scalarO();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, input, inputCnt, output, outputCnt);
    uint32_t out_scalars = outputCnt ? *outputCnt : 0;
    sbl_capture_record("io_connect_method_scalarI_scalarO", (uint32_t)selector, (uint32_t)inputCnt, 0, out_scalars, 0, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_connect_method_scalarI_scalarO, io_connect_method_scalarI_scalarO);

typedef kern_return_t (*sbl_io_connect_method_scalarI_structureO_fn)(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

static sbl_io_connect_method_scalarI_structureO_fn sbl_load_io_connect_method_scalarI_structureO(void) {
    static sbl_io_connect_method_scalarI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_scalarI_structureO_fn)dlsym(RTLD_NEXT, "io_connect_method_scalarI_structureO");
    return fn;
}

kern_return_t io_connect_method_scalarI_structureO(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt
) {
    sbl_io_connect_method_scalarI_structureO_fn fn = sbl_load_io_connect_method_scalarI_structureO();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, input, inputCnt, output, outputCnt);
    size_t out_struct = outputCnt ? (size_t)*outputCnt : 0;
    sbl_capture_record("io_connect_method_scalarI_structureO", (uint32_t)selector, (uint32_t)inputCnt, 0, 0, out_struct, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_connect_method_scalarI_structureO, io_connect_method_scalarI_structureO);

typedef kern_return_t (*sbl_io_connect_method_scalarI_structureI_fn)(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t inputStruct,
    mach_msg_type_number_t inputStructCnt);

static sbl_io_connect_method_scalarI_structureI_fn sbl_load_io_connect_method_scalarI_structureI(void) {
    static sbl_io_connect_method_scalarI_structureI_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_scalarI_structureI_fn)dlsym(RTLD_NEXT, "io_connect_method_scalarI_structureI");
    return fn;
}

kern_return_t io_connect_method_scalarI_structureI(
    mach_port_t connection,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t inputStruct,
    mach_msg_type_number_t inputStructCnt
) {
    sbl_io_connect_method_scalarI_structureI_fn fn = sbl_load_io_connect_method_scalarI_structureI();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, input, inputCnt, inputStruct, inputStructCnt);
    sbl_capture_record("io_connect_method_scalarI_structureI", (uint32_t)selector, (uint32_t)inputCnt, (size_t)inputStructCnt, 0, 0, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_connect_method_scalarI_structureI, io_connect_method_scalarI_structureI);

typedef kern_return_t (*sbl_io_connect_method_structureI_structureO_fn)(
    mach_port_t connection,
    int selector,
    io_struct_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

static sbl_io_connect_method_structureI_structureO_fn sbl_load_io_connect_method_structureI_structureO(void) {
    static sbl_io_connect_method_structureI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_connect_method_structureI_structureO_fn)dlsym(RTLD_NEXT, "io_connect_method_structureI_structureO");
    return fn;
}

kern_return_t io_connect_method_structureI_structureO(
    mach_port_t connection,
    int selector,
    io_struct_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt
) {
    sbl_io_connect_method_structureI_structureO_fn fn = sbl_load_io_connect_method_structureI_structureO();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, selector, input, inputCnt, output, outputCnt);
    size_t out_struct = outputCnt ? (size_t)*outputCnt : 0;
    sbl_capture_record("io_connect_method_structureI_structureO", (uint32_t)selector, 0, (size_t)inputCnt, 0, out_struct, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_connect_method_structureI_structureO, io_connect_method_structureI_structureO);

typedef kern_return_t (*sbl_io_async_method_scalarI_scalarO_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_scalar_inband_t output,
    mach_msg_type_number_t *outputCnt);

static sbl_io_async_method_scalarI_scalarO_fn sbl_load_io_async_method_scalarI_scalarO(void) {
    static sbl_io_async_method_scalarI_scalarO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_scalarI_scalarO_fn)dlsym(RTLD_NEXT, "io_async_method_scalarI_scalarO");
    return fn;
}

kern_return_t io_async_method_scalarI_scalarO(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_scalar_inband_t output,
    mach_msg_type_number_t *outputCnt
) {
    sbl_io_async_method_scalarI_scalarO_fn fn = sbl_load_io_async_method_scalarI_scalarO();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, wake_port, reference, referenceCnt, selector, input, inputCnt, output, outputCnt);
    uint32_t out_scalars = outputCnt ? *outputCnt : 0;
    sbl_capture_record("io_async_method_scalarI_scalarO", (uint32_t)selector, (uint32_t)inputCnt, 0, out_scalars, 0, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_async_method_scalarI_scalarO, io_async_method_scalarI_scalarO);

typedef kern_return_t (*sbl_io_async_method_scalarI_structureO_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

static sbl_io_async_method_scalarI_structureO_fn sbl_load_io_async_method_scalarI_structureO(void) {
    static sbl_io_async_method_scalarI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_scalarI_structureO_fn)dlsym(RTLD_NEXT, "io_async_method_scalarI_structureO");
    return fn;
}

kern_return_t io_async_method_scalarI_structureO(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt
) {
    sbl_io_async_method_scalarI_structureO_fn fn = sbl_load_io_async_method_scalarI_structureO();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, wake_port, reference, referenceCnt, selector, input, inputCnt, output, outputCnt);
    size_t out_struct = outputCnt ? (size_t)*outputCnt : 0;
    sbl_capture_record("io_async_method_scalarI_structureO", (uint32_t)selector, (uint32_t)inputCnt, 0, 0, out_struct, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_async_method_scalarI_structureO, io_async_method_scalarI_structureO);

typedef kern_return_t (*sbl_io_async_method_scalarI_structureI_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t inputStruct,
    mach_msg_type_number_t inputStructCnt);

static sbl_io_async_method_scalarI_structureI_fn sbl_load_io_async_method_scalarI_structureI(void) {
    static sbl_io_async_method_scalarI_structureI_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_scalarI_structureI_fn)dlsym(RTLD_NEXT, "io_async_method_scalarI_structureI");
    return fn;
}

kern_return_t io_async_method_scalarI_structureI(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_scalar_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t inputStruct,
    mach_msg_type_number_t inputStructCnt
) {
    sbl_io_async_method_scalarI_structureI_fn fn = sbl_load_io_async_method_scalarI_structureI();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, wake_port, reference, referenceCnt, selector, input, inputCnt, inputStruct, inputStructCnt);
    sbl_capture_record("io_async_method_scalarI_structureI", (uint32_t)selector, (uint32_t)inputCnt, (size_t)inputStructCnt, 0, 0, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_async_method_scalarI_structureI, io_async_method_scalarI_structureI);

typedef kern_return_t (*sbl_io_async_method_structureI_structureO_fn)(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_struct_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt);

static sbl_io_async_method_structureI_structureO_fn sbl_load_io_async_method_structureI_structureO(void) {
    static sbl_io_async_method_structureI_structureO_fn fn = NULL;
    static int attempted = 0;
    if (attempted) return fn;
    attempted = 1;
    fn = (sbl_io_async_method_structureI_structureO_fn)dlsym(RTLD_NEXT, "io_async_method_structureI_structureO");
    return fn;
}

kern_return_t io_async_method_structureI_structureO(
    mach_port_t connection,
    mach_port_t wake_port,
    io_async_ref_t reference,
    mach_msg_type_number_t referenceCnt,
    int selector,
    io_struct_inband_t input,
    mach_msg_type_number_t inputCnt,
    io_struct_inband_t output,
    mach_msg_type_number_t *outputCnt
) {
    sbl_io_async_method_structureI_structureO_fn fn = sbl_load_io_async_method_structureI_structureO();
    if (!fn) {
        return kIOReturnUnsupported;
    }
    kern_return_t kr = fn(connection, wake_port, reference, referenceCnt, selector, input, inputCnt, output, outputCnt);
    size_t out_struct = outputCnt ? (size_t)*outputCnt : 0;
    sbl_capture_record("io_async_method_structureI_structureO", (uint32_t)selector, 0, (size_t)inputCnt, 0, out_struct, kr);
    return kr;
}

SBL_DYLD_INTERPOSE(io_async_method_structureI_structureO, io_async_method_structureI_structureO);

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <registry_entry_class>\n", prog);
}

static size_t parse_selector_list(const char *env, uint32_t *out, size_t max_count) {
    if (!env || !out || max_count == 0) {
        return 0;
    }
    size_t count = 0;
    const char *p = env;
    while (*p && count < max_count) {
        while (*p == ' ' || *p == '\t' || *p == ',' || *p == ';') {
            p++;
        }
        if (!*p) {
            break;
        }
        char *end = NULL;
        unsigned long value = strtoul(p, &end, 10);
        if (end == p) {
            break;
        }
        out[count++] = (uint32_t)value;
        p = end;
    }
    return count;
}

static int parse_env_u32(const char *name, uint32_t *out) {
    if (!name || !out) {
        return 0;
    }
    const char *env = getenv(name);
    if (!env || !*env) {
        return 0;
    }
    char *end = NULL;
    unsigned long value = strtoul(env, &end, 10);
    if (!end || end == env || *end != '\0') {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

static int parse_env_size(const char *name, size_t *out) {
    if (!name || !out) {
        return 0;
    }
    const char *env = getenv(name);
    if (!env || !*env) {
        return 0;
    }
    char *end = NULL;
    unsigned long value = strtoul(env, &end, 10);
    if (!end || end == env || *end != '\0') {
        return 0;
    }
    *out = (size_t)value;
    return 1;
}

static void sbl_json_append(char **buf, size_t *len, size_t *cap, const char *fmt, ...) {
    if (!buf || !len || !cap || !fmt) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    va_list args_copy;
    va_copy(args_copy, args);
    int needed = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);
    if (needed < 0) {
        va_end(args);
        return;
    }
    size_t required = *len + (size_t)needed + 1;
    if (*cap < required) {
        size_t new_cap = *cap ? *cap : 256;
        while (new_cap < required) {
            new_cap *= 2;
        }
        char *next = (char *)realloc(*buf, new_cap);
        if (!next) {
            va_end(args);
            return;
        }
        *buf = next;
        *cap = new_cap;
    }
    vsnprintf(*buf + *len, *cap - *len, fmt, args);
    va_end(args);
    *len += (size_t)needed;
}

static const char *json_string_or_null(char *buf, size_t buf_len, const char *value, int has_value) {
    if (!has_value || !value || !*value) {
        return "null";
    }
    snprintf(buf, buf_len, "\"%s\"", value);
    return buf;
}

static const char *json_uint_or_null(char *buf, size_t buf_len, unsigned long value, int has_value) {
    if (!has_value) {
        return "null";
    }
    snprintf(buf, buf_len, "%lu", value);
    return buf;
}

static const char *json_int_or_null(char *buf, size_t buf_len, long value, int has_value) {
    if (!has_value) {
        return "null";
    }
    snprintf(buf, buf_len, "%ld", value);
    return buf;
}

static const char *normalize_call_kind(const char *kind) {
    if (!kind || !*kind) {
        return "IOConnectCallMethod";
    }
    if (strcmp(kind, "IOConnectCallMethod") == 0) {
        return "IOConnectCallMethod";
    }
    if (strcmp(kind, "IOConnectCallScalarMethod") == 0) {
        return "IOConnectCallScalarMethod";
    }
    if (strcmp(kind, "IOConnectCallStructMethod") == 0) {
        return "IOConnectCallStructMethod";
    }
    if (strcmp(kind, "IOConnectCallAsyncScalarMethod") == 0) {
        return "IOConnectCallAsyncScalarMethod";
    }
    if (strcmp(kind, "IOConnectCallAsyncStructMethod") == 0) {
        return "IOConnectCallAsyncStructMethod";
    }
    if (strcmp(kind, "io_connect_method_scalarI_scalarO") == 0) {
        return "io_connect_method_scalarI_scalarO";
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureO") == 0) {
        return "io_connect_method_scalarI_structureO";
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureI") == 0) {
        return "io_connect_method_scalarI_structureI";
    }
    if (strcmp(kind, "io_connect_method_structureI_structureO") == 0) {
        return "io_connect_method_structureI_structureO";
    }
    if (strcmp(kind, "io_async_method_scalarI_scalarO") == 0) {
        return "io_async_method_scalarI_scalarO";
    }
    if (strcmp(kind, "io_async_method_scalarI_structureO") == 0) {
        return "io_async_method_scalarI_structureO";
    }
    if (strcmp(kind, "io_async_method_scalarI_structureI") == 0) {
        return "io_async_method_scalarI_structureI";
    }
    if (strcmp(kind, "io_async_method_structureI_structureO") == 0) {
        return "io_async_method_structureI_structureO";
    }
    return "IOConnectCallMethod";
}

static kern_return_t call_by_kind(
    const char *kind,
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *input_scalars,
    uint32_t input_scalar_count,
    const void *input_struct,
    size_t input_struct_bytes,
    uint64_t *output_scalars,
    uint32_t *output_scalar_count,
    void *output_struct,
    size_t *output_struct_bytes
) {
    if (!kind || strcmp(kind, "IOConnectCallMethod") == 0) {
        return IOConnectCallMethod(
            connection,
            selector,
            input_scalar_count ? input_scalars : NULL,
            input_scalar_count,
            input_struct_bytes ? input_struct : NULL,
            input_struct_bytes,
            output_scalar_count && *output_scalar_count ? output_scalars : NULL,
            output_scalar_count,
            output_struct_bytes && *output_struct_bytes ? output_struct : NULL,
            output_struct_bytes
        );
    }
    if (strcmp(kind, "IOConnectCallScalarMethod") == 0) {
        return IOConnectCallScalarMethod(
            connection,
            selector,
            input_scalar_count ? input_scalars : NULL,
            input_scalar_count,
            output_scalar_count && *output_scalar_count ? output_scalars : NULL,
            output_scalar_count
        );
    }
    if (strcmp(kind, "IOConnectCallStructMethod") == 0) {
        return IOConnectCallStructMethod(
            connection,
            selector,
            input_struct_bytes ? input_struct : NULL,
            input_struct_bytes,
            output_struct_bytes && *output_struct_bytes ? output_struct : NULL,
            output_struct_bytes
        );
    }
    if (strcmp(kind, "IOConnectCallAsyncScalarMethod") == 0) {
        uint64_t async_ref[8] = {0};
        return IOConnectCallAsyncScalarMethod(
            connection,
            selector,
            MACH_PORT_NULL,
            async_ref,
            0,
            input_scalar_count ? input_scalars : NULL,
            input_scalar_count,
            output_scalar_count && *output_scalar_count ? output_scalars : NULL,
            output_scalar_count
        );
    }
    if (strcmp(kind, "IOConnectCallAsyncStructMethod") == 0) {
        uint64_t async_ref[8] = {0};
        return IOConnectCallAsyncStructMethod(
            connection,
            selector,
            MACH_PORT_NULL,
            async_ref,
            0,
            input_struct_bytes ? input_struct : NULL,
            input_struct_bytes,
            output_struct_bytes && *output_struct_bytes ? output_struct : NULL,
            output_struct_bytes
        );
    }
    if (strcmp(kind, "io_connect_method_scalarI_scalarO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_scalar_inband_t out_scalars = {0};
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_scalar_count) {
            out_cnt = (mach_msg_type_number_t)(*output_scalar_count > 16 ? 16 : *output_scalar_count);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        kern_return_t kr = io_connect_method_scalarI_scalarO(
            connection,
            (int)selector,
            in_scalars,
            in_cnt,
            out_scalars,
            &out_cnt
        );
        if (output_scalar_count) {
            *output_scalar_count = (uint32_t)out_cnt;
        }
        if (output_scalars) {
            for (mach_msg_type_number_t i = 0; i < out_cnt; i++) {
                output_scalars[i] = out_scalars[i];
            }
        }
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t out_struct;
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        kern_return_t kr = io_connect_method_scalarI_structureO(
            connection,
            (int)selector,
            in_scalars,
            in_cnt,
            out_struct,
            &out_cnt
        );
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_connect_method_scalarI_structureI") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t in_struct;
        memset(in_struct, 0, sizeof(in_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t struct_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        if (input_struct && struct_cnt > 0) {
            memcpy(in_struct, input_struct, struct_cnt);
        }
        kern_return_t kr = io_connect_method_scalarI_structureI(
            connection,
            (int)selector,
            in_scalars,
            in_cnt,
            in_struct,
            struct_cnt
        );
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_connect_method_structureI_structureO") == 0) {
        io_struct_inband_t in_struct;
        io_struct_inband_t out_struct;
        memset(in_struct, 0, sizeof(in_struct));
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        if (input_struct && in_cnt > 0) {
            memcpy(in_struct, input_struct, in_cnt);
        }
        kern_return_t kr = io_connect_method_structureI_structureO(
            connection,
            (int)selector,
            in_struct,
            in_cnt,
            out_struct,
            &out_cnt
        );
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_scalarI_scalarO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_scalar_inband_t out_scalars = {0};
        io_async_ref_t async_ref = {0};
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_scalar_count) {
            out_cnt = (mach_msg_type_number_t)(*output_scalar_count > 16 ? 16 : *output_scalar_count);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        kern_return_t kr = io_async_method_scalarI_scalarO(
            connection,
            MACH_PORT_NULL,
            async_ref,
            0,
            (int)selector,
            in_scalars,
            in_cnt,
            out_scalars,
            &out_cnt
        );
        if (output_scalar_count) {
            *output_scalar_count = (uint32_t)out_cnt;
        }
        if (output_scalars) {
            for (mach_msg_type_number_t i = 0; i < out_cnt; i++) {
                output_scalars[i] = out_scalars[i];
            }
        }
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_scalarI_structureO") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t out_struct;
        io_async_ref_t async_ref = {0};
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        kern_return_t kr = io_async_method_scalarI_structureO(
            connection,
            MACH_PORT_NULL,
            async_ref,
            0,
            (int)selector,
            in_scalars,
            in_cnt,
            out_struct,
            &out_cnt
        );
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_scalarI_structureI") == 0) {
        io_scalar_inband_t in_scalars = {0};
        io_struct_inband_t in_struct;
        io_async_ref_t async_ref = {0};
        memset(in_struct, 0, sizeof(in_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_scalar_count > 16 ? 16 : input_scalar_count);
        mach_msg_type_number_t struct_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        for (mach_msg_type_number_t i = 0; i < in_cnt; i++) {
            in_scalars[i] = input_scalars ? input_scalars[i] : 0;
        }
        if (input_struct && struct_cnt > 0) {
            memcpy(in_struct, input_struct, struct_cnt);
        }
        kern_return_t kr = io_async_method_scalarI_structureI(
            connection,
            MACH_PORT_NULL,
            async_ref,
            0,
            (int)selector,
            in_scalars,
            in_cnt,
            in_struct,
            struct_cnt
        );
        if (output_struct_bytes) {
            *output_struct_bytes = 0;
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    if (strcmp(kind, "io_async_method_structureI_structureO") == 0) {
        io_struct_inband_t in_struct;
        io_struct_inband_t out_struct;
        io_async_ref_t async_ref = {0};
        memset(in_struct, 0, sizeof(in_struct));
        memset(out_struct, 0, sizeof(out_struct));
        mach_msg_type_number_t in_cnt = (mach_msg_type_number_t)(input_struct_bytes > sizeof(in_struct) ? sizeof(in_struct) : input_struct_bytes);
        mach_msg_type_number_t out_cnt = 0;
        if (output_struct_bytes) {
            out_cnt = (mach_msg_type_number_t)(*output_struct_bytes > sizeof(out_struct) ? sizeof(out_struct) : *output_struct_bytes);
        }
        if (input_struct && in_cnt > 0) {
            memcpy(in_struct, input_struct, in_cnt);
        }
        kern_return_t kr = io_async_method_structureI_structureO(
            connection,
            MACH_PORT_NULL,
            async_ref,
            0,
            (int)selector,
            in_struct,
            in_cnt,
            out_struct,
            &out_cnt
        );
        if (output_struct_bytes) {
            *output_struct_bytes = (size_t)out_cnt;
        }
        if (output_struct && out_cnt > 0) {
            memcpy(output_struct, out_struct, out_cnt);
        }
        if (output_scalar_count) {
            *output_scalar_count = 0;
        }
        return kr;
    }
    return kIOReturnUnsupported;
}

static bool attempt_surface_create(int *signal_out, bool capture_calls) {
    int width = 1;
    int height = 1;
    int bytes_per_elem = 4;
    if (signal_out) {
        *signal_out = 0;
    }
    if (capture_calls) {
        g_capture_active = 1;
        CFNumberRef width_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &width);
        CFNumberRef height_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &height);
        CFNumberRef bpe_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytes_per_elem);
        if (!width_num || !height_num || !bpe_num) {
            if (width_num) CFRelease(width_num);
            if (height_num) CFRelease(height_num);
            if (bpe_num) CFRelease(bpe_num);
            g_capture_active = 0;
            return false;
        }
        const void *keys[] = {kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement};
        const void *vals[] = {width_num, height_num, bpe_num};
        CFDictionaryRef props = CFDictionaryCreate(
            kCFAllocatorDefault, keys, vals, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFRelease(width_num);
        CFRelease(height_num);
        CFRelease(bpe_num);
        if (!props) {
            g_capture_active = 0;
            return false;
        }
        IOSurfaceRef surface = IOSurfaceCreate(props);
        CFRelease(props);
        g_capture_active = 0;
        if (surface) {
            CFRelease(surface);
            return true;
        }
        return false;
    }
    pid_t pid = fork();
    if (pid == 0) {
        CFNumberRef width_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &width);
        CFNumberRef height_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &height);
        CFNumberRef bpe_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytes_per_elem);
        if (!width_num || !height_num || !bpe_num) {
            if (width_num) CFRelease(width_num);
            if (height_num) CFRelease(height_num);
            if (bpe_num) CFRelease(bpe_num);
            _exit(1);
        }
        const void *keys[] = {kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement};
        const void *vals[] = {width_num, height_num, bpe_num};
        CFDictionaryRef props = CFDictionaryCreate(
            kCFAllocatorDefault, keys, vals, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFRelease(width_num);
        CFRelease(height_num);
        CFRelease(bpe_num);
        if (!props) {
            _exit(1);
        }
        IOSurfaceRef surface = IOSurfaceCreate(props);
        CFRelease(props);
        if (surface) {
            CFRelease(surface);
            _exit(0);
        }
        _exit(1);
    }
    if (pid < 0) {
        return false;
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }
    if (WIFSIGNALED(status)) {
        if (signal_out) {
            *signal_out = WTERMSIG(status);
        }
        return false;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status) == 0;
    }
    return false;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 64; /* EX_USAGE */
    }

    sbl_capture_reset();
    bool capture_calls = false;
    const char *capture_env = getenv(SBL_IKIT_CAPTURE_ENV);
    if (capture_env && capture_env[0] != '\0' && capture_env[0] != '0') {
        capture_calls = true;
    }

    const char *class_name = argv[1];
    CFMutableDictionaryRef matching = IOServiceMatching(class_name);
    if (!matching) {
        printf("{\"found\":false,\"open_kr\":null,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":null,\"surface_create_signal\":null}\n");
        return 2;
    }

    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);
    if (service == IO_OBJECT_NULL) {
        printf("{\"found\":false,\"open_kr\":null,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":null,\"surface_create_signal\":null}\n");
        return 2;
    }

    io_connect_t conn = IO_OBJECT_NULL;
    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &conn);
    kern_return_t call_kr = KERN_FAILURE;
    const char *call_kr_string = NULL;
    bool call_attempted = false;
    bool call_succeeded = false;
    uint32_t call_selector = 0;
    uint32_t call_input_scalar_count = 0;
    size_t call_input_struct_bytes = 0;
    uint32_t call_output_scalar_count = 0;
    size_t call_output_struct_bytes = 0;
    bool synthetic_call_attempted = false;
    bool synthetic_call_used_dlsym = false;
    bool synthetic_call_capture_forced = false;
    const char *synthetic_call_kind = "IOConnectCallMethod";
    uint32_t synthetic_call_selector = 0;
    uint32_t synthetic_call_input_scalar_count = 0;
    size_t synthetic_call_input_struct_bytes = 0;
    uint32_t synthetic_call_output_scalar_count = 0;
    size_t synthetic_call_output_struct_bytes = 0;
    kern_return_t synthetic_call_kr = KERN_FAILURE;
    const char *synthetic_call_kr_string = NULL;
    bool surface_ok = false;
    int surface_signal = 0;
    bool do_sweep = true;
    bool sweep_requested = false;
    bool sweep_enabled = false;
    bool sweep_found_non_invalid = false;
    bool sweep_missing_non_invalid = false;
    bool mach_capture_enabled = false;
    bool method0_enabled = false;
    bool method0_binary = false;
    CFOptionFlags method0_serialize_flags = 0;
    bool method0_sweep = false;
    bool method0_attempted = false;
    bool method0_payload_ok = false;
    const char *method0_plist_format = NULL;
    const char *method0_payload_source = NULL;
    bool method0_payload_nul_appended = false;
    const char *method0_payload_in_path = NULL;
    const char *method0_payload_out_path = NULL;
    size_t method0_input_bytes = 0;
    size_t method0_output_capacity = 0x2000;
    size_t method0_output_bytes = 0;
    uint32_t method0_output_id = 0;
    bool method0_output_id_valid = false;
    size_t sweep_result_count = 0;
    char *sweep_results_json = NULL;
    size_t sweep_results_len = 0;
    size_t sweep_results_cap = 0;
    char sweep_first_spec_buf[256];
    sweep_first_spec_buf[0] = '\0';
    bool replay_enabled = false;
    bool replay_attempted = false;
    bool replay_missing_capture = false;
    const char *replay_status = NULL;
    const char *replay_source = NULL;
    sbl_iokit_call_tuple_t replay_tuple;
    sbl_tuple_reset(&replay_tuple);
    sbl_iokit_call_tuple_t capture_tuple;
    sbl_tuple_reset(&capture_tuple);
    const char *capture_source = NULL;
    const char *call_kind_env = getenv(SBL_IKIT_CALL_KIND_ENV);
    const char *call_kind = normalize_call_kind(call_kind_env);
    const char *call_kind_used = call_kind;
    const uint32_t default_selectors[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const uint32_t *selectors = default_selectors;
    size_t selector_count = sizeof(default_selectors) / sizeof(default_selectors[0]);
    uint32_t selector_buf[128];
    uint32_t sweep_selector_buf[160];
    const uint32_t *sweep_selectors = NULL;
    size_t sweep_selector_count = 0;
    const char *selector_env = getenv("SANDBOX_LORE_IKIT_SELECTOR_LIST");
    if (selector_env && selector_env[0] != '\0') {
        size_t parsed = parse_selector_list(selector_env, selector_buf, sizeof(selector_buf) / sizeof(selector_buf[0]));
        if (parsed > 0) {
            selectors = selector_buf;
            selector_count = parsed;
        }
    }
    const char *sweep_env = getenv(SBL_IKIT_SWEEP_ENV);
    if (sweep_env && sweep_env[0] != '\0' && sweep_env[0] != '0') {
        sweep_requested = true;
    }
    const char *sweep_menu_env = getenv(SBL_IKIT_SWEEP_MENU_ENV);
    if (!sweep_requested && sweep_menu_env && sweep_menu_env[0] != '\0' && sweep_menu_env[0] != '0') {
        sweep_requested = true;
    }
    const char *mach_capture_env = getenv(SBL_IKIT_MACH_CAPTURE_ENV);
    if (mach_capture_env && mach_capture_env[0] != '\0' && mach_capture_env[0] != '0') {
        mach_capture_enabled = true;
    }
    const char *method0_env = getenv(SBL_IKIT_METHOD0_ENV);
    if (method0_env && method0_env[0] != '\0' && method0_env[0] != '0') {
        method0_enabled = true;
    }
    const char *method0_binary_env = getenv(SBL_IKIT_METHOD0_BINARY_ENV);
    if (method0_binary_env && method0_binary_env[0] != '\0' && method0_binary_env[0] != '0') {
        method0_binary = true;
    }
    method0_serialize_flags = method0_binary ? kIOCFSerializeToBinary : 0;
    method0_payload_in_path = getenv(SBL_IKIT_METHOD0_PAYLOAD_IN_ENV);
    method0_payload_out_path = getenv(SBL_IKIT_METHOD0_PAYLOAD_OUT_ENV);
    const char *skip_sweep_env = getenv("SBL_IKIT_SKIP_SWEEP");
    if (skip_sweep_env && skip_sweep_env[0] != '\0' && skip_sweep_env[0] != '0') {
        do_sweep = false;
    }
    if (capture_calls) {
        do_sweep = false;
    }
    const char *replay_env = getenv(SBL_IKIT_REPLAY_ENV);
    if (replay_env && replay_env[0] != '\0' && replay_env[0] != '0') {
        replay_enabled = true;
        do_sweep = false;
    }
    bool synthetic_call_enabled = false;
    const char *synthetic_env = getenv(SBL_IKIT_SYNTH_CALL_ENV);
    if (synthetic_env && synthetic_env[0] != '\0' && synthetic_env[0] != '0') {
        synthetic_call_enabled = true;
        do_sweep = false;
    }
    if (method0_enabled && sweep_requested) {
        method0_sweep = true;
    }
    if (method0_enabled && !method0_sweep) {
        do_sweep = false;
    }
    if (sweep_requested && !capture_calls && !replay_enabled && !synthetic_call_enabled) {
        sweep_enabled = true;
        do_sweep = false;
    }
    uint32_t input_scalar_override = 0;
    size_t input_struct_override = 0;
    uint32_t output_scalar_override = 0;
    size_t output_struct_override = 0;
    bool call_shape_override = false;
    call_shape_override |= parse_env_u32(SBL_IKIT_CALL_IN_SCALARS_ENV, &input_scalar_override);
    call_shape_override |= parse_env_size(SBL_IKIT_CALL_IN_STRUCT_BYTES_ENV, &input_struct_override);
    call_shape_override |= parse_env_u32(SBL_IKIT_CALL_OUT_SCALARS_ENV, &output_scalar_override);
    call_shape_override |= parse_env_size(SBL_IKIT_CALL_OUT_STRUCT_BYTES_ENV, &output_struct_override);
    if (sweep_enabled) {
        if (selector_env && selector_env[0] != '\0') {
            size_t parsed = parse_selector_list(
                selector_env, sweep_selector_buf, sizeof(sweep_selector_buf) / sizeof(sweep_selector_buf[0]));
            if (parsed > 0) {
                sweep_selectors = sweep_selector_buf;
                sweep_selector_count = parsed;
            }
        }
        if (sweep_selector_count == 0) {
            if (method0_sweep) {
                for (uint32_t i = 0; i <= 25 && sweep_selector_count < (sizeof(sweep_selector_buf) / sizeof(sweep_selector_buf[0])); i++) {
                    sweep_selector_buf[sweep_selector_count++] = i;
                }
            } else {
                for (uint32_t i = 0; i <= 64 && sweep_selector_count < (sizeof(sweep_selector_buf) / sizeof(sweep_selector_buf[0])); i++) {
                    sweep_selector_buf[sweep_selector_count++] = i;
                }
                const uint32_t extras[] = {257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 513};
                size_t extras_count = sizeof(extras) / sizeof(extras[0]);
                for (size_t i = 0; i < extras_count && sweep_selector_count < (sizeof(sweep_selector_buf) / sizeof(sweep_selector_buf[0])); i++) {
                    sweep_selector_buf[sweep_selector_count++] = extras[i];
                }
            }
            sweep_selectors = sweep_selector_buf;
        }
    }
    const char *replay_spec_env = getenv(SBL_IKIT_REPLAY_SPEC_ENV);
    if (replay_enabled) {
        if (!sbl_parse_replay_spec(replay_spec_env, &replay_tuple)) {
            replay_missing_capture = true;
            replay_status = "replay_missing_capture";
        } else {
            replay_source = "spec";
        }
    }
    if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
        if (mach_capture_enabled) {
            memset(&g_mach_capture, 0, sizeof(g_mach_capture));
            g_mach_capture.enabled = 1;
            g_mach_capture.port = conn;
        }
        if (replay_enabled && replay_missing_capture) {
            /* Skip replay when we do not have a tuple; surface as probe-stage failure. */
        } else if (replay_enabled && replay_tuple.valid) {
            uint64_t *input_scalars = NULL;
            uint64_t *output_scalars = NULL;
            uint8_t *input_struct = NULL;
            uint8_t *output_struct = NULL;
            uint32_t output_scalar_count = replay_tuple.output_scalar_count;
            size_t output_struct_bytes = replay_tuple.output_struct_bytes;
            CFDataRef replay_payload = NULL;
            uint8_t *payload_buf = NULL;
            size_t payload_len = 0;
            bool payload_nul_appended = false;
            if (method0_enabled && strcmp(replay_tuple.kind, "IOConnectCallStructMethod") == 0) {
                if (method0_payload_in_path && method0_payload_in_path[0] != '\0') {
                    replay_payload = sbl_load_payload_file(method0_payload_in_path);
                    if (replay_payload) {
                        method0_payload_source = "file";
                        method0_plist_format = "file";
                    }
                }
                if (!replay_payload) {
                    method0_payload_source = NULL;
                    replay_payload = sbl_build_iosurface_plist(
                        &method0_plist_format,
                        &method0_payload_source,
                        method0_serialize_flags
                    );
                }
                if (replay_payload) {
                    const uint8_t *payload_bytes = CFDataGetBytePtr(replay_payload);
                    size_t payload_raw_len = (size_t)CFDataGetLength(replay_payload);
                    payload_buf = sbl_copy_payload_with_nul(
                        payload_bytes,
                        payload_raw_len,
                        &payload_len,
                        &payload_nul_appended
                    );
                    if (!payload_buf) {
                        replay_status = "replay_missing_payload";
                        replay_missing_capture = true;
                    } else {
                        method0_payload_ok = true;
                        method0_attempted = true;
                        method0_payload_nul_appended = payload_nul_appended;
                        method0_input_bytes = payload_len;
                        if (method0_payload_out_path && method0_payload_out_path[0] != '\0') {
                            sbl_write_payload_file(method0_payload_out_path, payload_buf, payload_len);
                        }
                        replay_tuple.input_struct_bytes = payload_len;
                        output_struct_bytes = method0_output_capacity;
                        replay_tuple.output_struct_bytes = output_struct_bytes;
                    }
                } else {
                    replay_status = "replay_missing_payload";
                    replay_missing_capture = true;
                }
            }
            if (replay_enabled && replay_missing_capture) {
                if (replay_payload) {
                    CFRelease(replay_payload);
                }
                if (payload_buf) {
                    free(payload_buf);
                }
            } else {
                if (replay_tuple.input_scalar_count > 0) {
                    input_scalars = (uint64_t *)calloc(replay_tuple.input_scalar_count, sizeof(uint64_t));
                }
                if (output_scalar_count > 0) {
                    output_scalars = (uint64_t *)calloc(output_scalar_count, sizeof(uint64_t));
                }
                if (replay_tuple.input_struct_bytes > 0) {
                    input_struct = (uint8_t *)calloc(1, replay_tuple.input_struct_bytes);
                    if (input_struct && payload_buf && payload_len > 0) {
                        size_t copy_len = payload_len > replay_tuple.input_struct_bytes ? replay_tuple.input_struct_bytes : payload_len;
                        memcpy(input_struct, payload_buf, copy_len);
                    }
                }
                if (output_struct_bytes > 0) {
                    output_struct = (uint8_t *)calloc(1, output_struct_bytes);
                }
                replay_attempted = true;
                replay_status = "replay_attempted";
                replay_tuple.kr = call_by_kind(
                    replay_tuple.kind,
                    conn,
                    replay_tuple.selector,
                    input_scalars,
                    replay_tuple.input_scalar_count,
                    input_struct,
                    replay_tuple.input_struct_bytes,
                    output_scalars,
                    &output_scalar_count,
                    output_struct,
                    &output_struct_bytes
                );
                replay_tuple.output_scalar_count = output_scalar_count;
                replay_tuple.output_struct_bytes = output_struct_bytes;
                if (method0_enabled && method0_payload_ok && output_struct_bytes > 0) {
                    method0_output_bytes = output_struct_bytes;
                    if (output_struct && output_struct_bytes >= 0x14) {
                        uint32_t id_value = 0;
                        memcpy(&id_value, output_struct + 0x10, sizeof(id_value));
                        method0_output_id = id_value;
                        method0_output_id_valid = true;
                    }
                }
                if (input_scalars) free(input_scalars);
                if (output_scalars) free(output_scalars);
                if (input_struct) free(input_struct);
                if (output_struct) free(output_struct);
                if (payload_buf) {
                    free(payload_buf);
                }
                if (replay_payload) {
                    CFRelease(replay_payload);
                }
            }
        }
        if (method0_enabled && !replay_enabled) {
            CFDataRef payload = NULL;
            uint8_t *payload_buf = NULL;
            size_t payload_len = 0;
            bool payload_nul_appended = false;
            if (method0_payload_in_path && method0_payload_in_path[0] != '\0') {
                payload = sbl_load_payload_file(method0_payload_in_path);
                if (payload) {
                    method0_payload_source = "file";
                    method0_plist_format = "file";
                }
            }
            if (!payload) {
                method0_payload_source = NULL;
                payload = sbl_build_iosurface_plist(
                    &method0_plist_format,
                    &method0_payload_source,
                    method0_serialize_flags
                );
            }
            if (payload) {
                const uint8_t *payload_bytes = CFDataGetBytePtr(payload);
                size_t payload_raw_len = (size_t)CFDataGetLength(payload);
                payload_buf = sbl_copy_payload_with_nul(
                    payload_bytes,
                    payload_raw_len,
                    &payload_len,
                    &payload_nul_appended
                );
            }
            if (payload_buf) {
                method0_payload_ok = true;
                method0_payload_nul_appended = payload_nul_appended;
                method0_input_bytes = payload_len;
                if (method0_payload_out_path && method0_payload_out_path[0] != '\0') {
                    sbl_write_payload_file(method0_payload_out_path, payload_buf, method0_input_bytes);
                }
                size_t output_struct_bytes = method0_output_capacity;
                uint8_t *output_struct = NULL;
                if (output_struct_bytes > 0) {
                    output_struct = (uint8_t *)calloc(1, output_struct_bytes);
                }
                call_kind_used = "IOConnectCallStructMethod";
                call_selector = 0;
                call_input_scalar_count = 0;
                call_input_struct_bytes = method0_input_bytes;
                call_output_scalar_count = 0;
                call_output_struct_bytes = output_struct_bytes;
                call_attempted = true;
                method0_attempted = true;
                call_kr = call_by_kind(
                    call_kind_used,
                    conn,
                    call_selector,
                    NULL,
                    0,
                    payload_buf,
                    method0_input_bytes,
                    NULL,
                    NULL,
                    output_struct,
                    &output_struct_bytes
                );
                call_kr_string = mach_error_string(call_kr);
                call_succeeded = (call_kr == KERN_SUCCESS);
                call_output_struct_bytes = output_struct_bytes;
                method0_output_bytes = output_struct_bytes;
                if (output_struct && output_struct_bytes >= 0x14) {
                    uint32_t id_value = 0;
                    memcpy(&id_value, output_struct + 0x10, sizeof(id_value));
                    method0_output_id = id_value;
                    method0_output_id_valid = true;
                }
                if (output_struct) {
                    free(output_struct);
                }
            }
            if (payload) {
                CFRelease(payload);
            }
            if (payload_buf) {
                free(payload_buf);
            }
        }
        if (synthetic_call_enabled) {
            uint32_t input_scalar_count = 1;
            uint32_t output_scalar_capacity = 0;
            size_t input_struct_bytes = 16;
            size_t output_struct_bytes = 16;
            if (call_shape_override) {
                input_scalar_count = input_scalar_override;
                input_struct_bytes = input_struct_override;
                output_scalar_capacity = output_scalar_override;
                output_struct_bytes = output_struct_override;
            }
            synthetic_call_selector = selector_count ? selectors[0] : 0;
            synthetic_call_input_scalar_count = input_scalar_count;
            synthetic_call_input_struct_bytes = input_struct_bytes;
            synthetic_call_output_scalar_count = output_scalar_capacity;
            synthetic_call_output_struct_bytes = output_struct_bytes;

            uint64_t *input_scalars = NULL;
            uint64_t *output_scalars = NULL;
            uint8_t *input_struct = NULL;
            uint8_t *output_struct = NULL;
            if (input_scalar_count > 0) {
                input_scalars = (uint64_t *)calloc(input_scalar_count, sizeof(uint64_t));
                if (!input_scalars) {
                    input_scalar_count = 0;
                    synthetic_call_input_scalar_count = 0;
                }
            }
            if (output_scalar_capacity > 0) {
                output_scalars = (uint64_t *)calloc(output_scalar_capacity, sizeof(uint64_t));
                if (!output_scalars) {
                    output_scalar_capacity = 0;
                    synthetic_call_output_scalar_count = 0;
                }
            }
            if (input_struct_bytes > 0) {
                input_struct = (uint8_t *)calloc(1, input_struct_bytes);
                if (!input_struct) {
                    input_struct_bytes = 0;
                    synthetic_call_input_struct_bytes = 0;
                }
            }
            if (output_struct_bytes > 0) {
                output_struct = (uint8_t *)calloc(1, output_struct_bytes);
                if (!output_struct) {
                    output_struct_bytes = 0;
                    synthetic_call_output_struct_bytes = 0;
                }
            }

            sbl_IOConnectCallMethod_fn fn = sbl_load_IOConnectCallMethod_default();
            if (fn) {
                synthetic_call_used_dlsym = true;
                synthetic_call_attempted = true;
                synthetic_call_kr = fn(
                    conn,
                    synthetic_call_selector,
                    input_scalar_count ? input_scalars : NULL,
                    input_scalar_count,
                    input_struct_bytes ? input_struct : NULL,
                    input_struct_bytes,
                    output_scalar_capacity ? output_scalars : NULL,
                    &synthetic_call_output_scalar_count,
                    output_struct_bytes ? output_struct : NULL,
                    &synthetic_call_output_struct_bytes
                );
                synthetic_call_kr_string = mach_error_string(synthetic_call_kr);
            } else {
                synthetic_call_attempted = true;
                synthetic_call_kr = kIOReturnUnsupported;
                synthetic_call_kr_string = "IOConnectCallMethod missing";
            }

            if (capture_calls) {
                g_capture_active = 1;
                (void)sbl_interpose_IOConnectCallMethod(
                    conn,
                    synthetic_call_selector,
                    input_scalar_count ? input_scalars : NULL,
                    input_scalar_count,
                    input_struct_bytes ? input_struct : NULL,
                    input_struct_bytes,
                    output_scalar_capacity ? output_scalars : NULL,
                    &synthetic_call_output_scalar_count,
                    output_struct_bytes ? output_struct : NULL,
                    &synthetic_call_output_struct_bytes
                );
                g_capture_active = 0;
                synthetic_call_capture_forced = true;
            }

            if (input_scalars) free(input_scalars);
            if (output_scalars) free(output_scalars);
            if (input_struct) free(input_struct);
            if (output_struct) free(output_struct);
        }
        if (sweep_enabled) {
            if (!sweep_selectors || sweep_selector_count == 0) {
                sweep_missing_non_invalid = true;
            } else if (method0_sweep) {
                CFDataRef payload = NULL;
                uint8_t *payload_buf = NULL;
                size_t payload_len = 0;
                bool payload_nul_appended = false;
                if (method0_payload_in_path && method0_payload_in_path[0] != '\0') {
                    payload = sbl_load_payload_file(method0_payload_in_path);
                    if (payload) {
                        method0_payload_source = "file";
                        method0_plist_format = "file";
                    }
                }
                if (!payload) {
                    method0_payload_source = NULL;
                    payload = sbl_build_iosurface_plist(
                        &method0_plist_format,
                        &method0_payload_source,
                        method0_serialize_flags
                    );
                }
                if (payload) {
                    const uint8_t *payload_bytes = CFDataGetBytePtr(payload);
                    size_t payload_raw_len = (size_t)CFDataGetLength(payload);
                    payload_buf = sbl_copy_payload_with_nul(
                        payload_bytes,
                        payload_raw_len,
                        &payload_len,
                        &payload_nul_appended
                    );
                }
                if (!payload_buf) {
                    sweep_missing_non_invalid = true;
                } else {
                    method0_payload_ok = true;
                    method0_attempted = true;
                    method0_payload_nul_appended = payload_nul_appended;
                    method0_input_bytes = payload_len;
                    if (method0_payload_out_path && method0_payload_out_path[0] != '\0') {
                        sbl_write_payload_file(method0_payload_out_path, payload_buf, payload_len);
                    }
                    sbl_json_append(&sweep_results_json, &sweep_results_len, &sweep_results_cap, "[");
                    bool sweep_stop = false;
                    for (size_t si = 0; si < sweep_selector_count && !sweep_stop; si++) {
                        uint32_t input_scalar_count = 0;
                        size_t input_struct_bytes = payload_len;
                        uint32_t output_scalar_capacity = 0;
                        size_t output_struct_bytes = method0_output_capacity;
                        uint8_t *output_struct = NULL;
                        if (output_struct_bytes > 0) {
                            output_struct = (uint8_t *)calloc(1, output_struct_bytes);
                            if (!output_struct) {
                                output_struct_bytes = 0;
                            }
                        }
                        uint32_t output_scalar_count = output_scalar_capacity;
                        size_t output_struct_count = output_struct_bytes;
                        call_kind_used = "IOConnectCallStructMethod";
                        kern_return_t sweep_kr = call_by_kind(
                            call_kind_used,
                            conn,
                            sweep_selectors[si],
                            NULL,
                            0,
                            payload_buf,
                            payload_len,
                            NULL,
                            &output_scalar_count,
                            output_struct,
                            &output_struct_count
                        );
                        const char *sweep_kr_string = mach_error_string(sweep_kr);
                        char sweep_kr_string_json[128];
                        const char *sweep_kr_string_out = json_string_or_null(
                            sweep_kr_string_json, sizeof(sweep_kr_string_json), sweep_kr_string, sweep_kr_string != NULL);
                        if (sweep_result_count > 0) {
                            sbl_json_append(&sweep_results_json, &sweep_results_len, &sweep_results_cap, ",");
                        }
                        sbl_json_append(
                            &sweep_results_json,
                            &sweep_results_len,
                            &sweep_results_cap,
                            "{\"selector\":%u,\"call_kind\":\"%s\",\"input_scalar_count\":%u,"
                            "\"input_struct_bytes\":%zu,\"output_scalar_count\":%u,\"output_struct_bytes\":%zu,"
                            "\"kr\":%d,\"kr_string\":%s}",
                            sweep_selectors[si],
                            call_kind_used,
                            input_scalar_count,
                            input_struct_bytes,
                            output_scalar_capacity,
                            output_struct_bytes,
                            sweep_kr,
                            sweep_kr_string_out
                        );
                        sweep_result_count++;
                        if (!sweep_found_non_invalid && sweep_kr != kIOReturnBadArgument) {
                            sweep_found_non_invalid = true;
                            sbl_tuple_set(
                                &capture_tuple,
                                call_kind_used,
                                sweep_selectors[si],
                                input_scalar_count,
                                input_struct_bytes,
                                output_scalar_capacity,
                                output_struct_bytes,
                                sweep_kr
                            );
                            capture_source = "sweep_first_non_invalid";
                            call_attempted = true;
                            call_selector = sweep_selectors[si];
                            call_input_scalar_count = input_scalar_count;
                            call_input_struct_bytes = input_struct_bytes;
                            call_output_scalar_count = output_scalar_count;
                            call_output_struct_bytes = output_struct_count;
                            call_kr = sweep_kr;
                            call_kr_string = sweep_kr_string;
                            if (output_struct && output_struct_count >= 0x14) {
                                uint32_t id_value = 0;
                                memcpy(&id_value, output_struct + 0x10, sizeof(id_value));
                                method0_output_id = id_value;
                                method0_output_id_valid = true;
                            }
                            method0_output_bytes = output_struct_count;
                            sbl_format_replay_spec(&capture_tuple, sweep_first_spec_buf, sizeof(sweep_first_spec_buf));
                            sweep_stop = true;
                        } else {
                            call_attempted = true;
                            call_selector = sweep_selectors[si];
                            call_input_scalar_count = input_scalar_count;
                            call_input_struct_bytes = input_struct_bytes;
                            call_output_scalar_count = output_scalar_count;
                            call_output_struct_bytes = output_struct_count;
                            call_kr = sweep_kr;
                            call_kr_string = sweep_kr_string;
                        }
                        if (output_struct) {
                            free(output_struct);
                        }
                    }
                    sbl_json_append(&sweep_results_json, &sweep_results_len, &sweep_results_cap, "]");
                    if (!sweep_found_non_invalid) {
                        sweep_missing_non_invalid = true;
                    }
                }
                if (payload) {
                    CFRelease(payload);
                }
                if (payload_buf) {
                    free(payload_buf);
                }
            } else {
                const sbl_iokit_call_shape_t *shapes = k_sweep_shapes;
                size_t shape_count = sizeof(k_sweep_shapes) / sizeof(k_sweep_shapes[0]);
                sbl_json_append(&sweep_results_json, &sweep_results_len, &sweep_results_cap, "[");
                bool sweep_stop = false;
                for (size_t si = 0; si < sweep_selector_count && !sweep_stop; si++) {
                    for (size_t sj = 0; sj < shape_count && !sweep_stop; sj++) {
                        uint32_t input_scalar_count = shapes[sj].input_scalar_count;
                        size_t input_struct_bytes = shapes[sj].input_struct_bytes;
                        uint32_t output_scalar_capacity = shapes[sj].output_scalar_count;
                        size_t output_struct_bytes = shapes[sj].output_struct_bytes;
                        uint64_t *input_scalars = NULL;
                        uint64_t *output_scalars = NULL;
                        uint8_t *input_struct = NULL;
                        uint8_t *output_struct = NULL;
                        if (input_scalar_count > 0) {
                            input_scalars = (uint64_t *)calloc(input_scalar_count, sizeof(uint64_t));
                            if (!input_scalars) {
                                input_scalar_count = 0;
                            }
                        }
                        if (output_scalar_capacity > 0) {
                            output_scalars = (uint64_t *)calloc(output_scalar_capacity, sizeof(uint64_t));
                            if (!output_scalars) {
                                output_scalar_capacity = 0;
                            }
                        }
                        if (input_struct_bytes > 0) {
                            input_struct = (uint8_t *)calloc(1, input_struct_bytes);
                            if (!input_struct) {
                                input_struct_bytes = 0;
                            }
                        }
                        if (output_struct_bytes > 0) {
                            output_struct = (uint8_t *)calloc(1, output_struct_bytes);
                            if (!output_struct) {
                                output_struct_bytes = 0;
                            }
                        }
                        uint32_t output_scalar_count = output_scalar_capacity;
                        size_t output_struct_count = output_struct_bytes;
                        call_kind_used = call_kind;
                        kern_return_t sweep_kr = call_by_kind(
                            call_kind,
                            conn,
                            sweep_selectors[si],
                            input_scalars,
                            input_scalar_count,
                            input_struct,
                            input_struct_bytes,
                            output_scalars,
                            &output_scalar_count,
                            output_struct,
                            &output_struct_count
                        );
                        const char *sweep_kr_string = mach_error_string(sweep_kr);
                        char sweep_kr_string_json[128];
                        const char *sweep_kr_string_out = json_string_or_null(
                            sweep_kr_string_json, sizeof(sweep_kr_string_json), sweep_kr_string, sweep_kr_string != NULL);
                        if (sweep_result_count > 0) {
                            sbl_json_append(&sweep_results_json, &sweep_results_len, &sweep_results_cap, ",");
                        }
                        sbl_json_append(
                            &sweep_results_json,
                            &sweep_results_len,
                            &sweep_results_cap,
                            "{\"selector\":%u,\"call_kind\":\"%s\",\"input_scalar_count\":%u,"
                            "\"input_struct_bytes\":%zu,\"output_scalar_count\":%u,\"output_struct_bytes\":%zu,"
                            "\"kr\":%d,\"kr_string\":%s}",
                            sweep_selectors[si],
                            call_kind_used,
                            input_scalar_count,
                            input_struct_bytes,
                            output_scalar_capacity,
                            output_struct_bytes,
                            sweep_kr,
                            sweep_kr_string_out
                        );
                        sweep_result_count++;
                        if (!sweep_found_non_invalid && sweep_kr != kIOReturnBadArgument) {
                            sweep_found_non_invalid = true;
                            sbl_tuple_set(
                                &capture_tuple,
                                call_kind_used,
                                sweep_selectors[si],
                                input_scalar_count,
                                input_struct_bytes,
                                output_scalar_capacity,
                                output_struct_bytes,
                                sweep_kr
                            );
                            capture_source = "sweep_first_non_invalid";
                            call_attempted = true;
                            call_selector = sweep_selectors[si];
                            call_input_scalar_count = input_scalar_count;
                            call_input_struct_bytes = input_struct_bytes;
                            call_output_scalar_count = output_scalar_count;
                            call_output_struct_bytes = output_struct_count;
                            call_kr = sweep_kr;
                            call_kr_string = sweep_kr_string;
                            sbl_format_replay_spec(&capture_tuple, sweep_first_spec_buf, sizeof(sweep_first_spec_buf));
                            sweep_stop = true;
                        } else {
                            call_attempted = true;
                            call_selector = sweep_selectors[si];
                            call_input_scalar_count = input_scalar_count;
                            call_input_struct_bytes = input_struct_bytes;
                            call_output_scalar_count = output_scalar_count;
                            call_output_struct_bytes = output_struct_count;
                            call_kr = sweep_kr;
                            call_kr_string = sweep_kr_string;
                        }
                        if (input_scalars) free(input_scalars);
                        if (output_scalars) free(output_scalars);
                        if (input_struct) free(input_struct);
                        if (output_struct) free(output_struct);
                    }
                }
                sbl_json_append(&sweep_results_json, &sweep_results_len, &sweep_results_cap, "]");
                if (!sweep_found_non_invalid) {
                    sweep_missing_non_invalid = true;
                }
            }
        } else if (do_sweep) {
            uint32_t input_scalar_count = 0;
            uint32_t output_scalar_capacity = 0;
            size_t input_struct_bytes = 0;
            size_t output_struct_bytes = 0;
            if (call_shape_override) {
                input_scalar_count = input_scalar_override;
                input_struct_bytes = input_struct_override;
                output_scalar_capacity = output_scalar_override;
                output_struct_bytes = output_struct_override;
            } else if (selectors != default_selectors) {
                input_scalar_count = 1;
                input_struct_bytes = 16;
                output_struct_bytes = 16;
            }
            uint64_t *input_scalars = NULL;
            uint64_t *output_scalars = NULL;
            uint8_t *input_struct = NULL;
            uint8_t *output_struct = NULL;
            if (input_scalar_count > 0) {
                input_scalars = (uint64_t *)calloc(input_scalar_count, sizeof(uint64_t));
                if (!input_scalars) {
                    input_scalar_count = 0;
                }
            }
            if (output_scalar_capacity > 0) {
                output_scalars = (uint64_t *)calloc(output_scalar_capacity, sizeof(uint64_t));
                if (!output_scalars) {
                    output_scalar_capacity = 0;
                }
            }
            if (input_struct_bytes > 0) {
                input_struct = (uint8_t *)calloc(1, input_struct_bytes);
                if (!input_struct) {
                    input_struct_bytes = 0;
                }
            }
            if (output_struct_bytes > 0) {
                output_struct = (uint8_t *)calloc(1, output_struct_bytes);
                if (!output_struct) {
                    output_struct_bytes = 0;
                }
            }
            bool saw_non_invalid = false;
            uint32_t non_invalid_selector = 0;
            int non_invalid_kr = 0;
            const char *non_invalid_kr_string = NULL;
            uint32_t non_invalid_output_scalar_count = 0;
            size_t non_invalid_output_struct_bytes = 0;
            for (size_t i = 0; i < selector_count; i++) {
                call_output_scalar_count = output_scalar_capacity;
                call_output_struct_bytes = output_struct_bytes;
                call_attempted = true;
                call_selector = selectors[i];
                call_input_scalar_count = input_scalar_count;
                call_input_struct_bytes = input_struct_bytes;
                call_kind_used = call_kind;
                call_kr = call_by_kind(
                    call_kind,
                    conn,
                    selectors[i],
                    input_scalars,
                    input_scalar_count,
                    input_struct,
                    input_struct_bytes,
                    output_scalars,
                    &call_output_scalar_count,
                    output_struct,
                    &call_output_struct_bytes
                );
                call_kr_string = mach_error_string(call_kr);
                if (!saw_non_invalid && call_kr != kIOReturnBadArgument) {
                    saw_non_invalid = true;
                    non_invalid_selector = selectors[i];
                    non_invalid_kr = call_kr;
                    non_invalid_kr_string = call_kr_string;
                    non_invalid_output_scalar_count = call_output_scalar_count;
                    non_invalid_output_struct_bytes = call_output_struct_bytes;
                }
                if (call_kr == KERN_SUCCESS) {
                    call_succeeded = true;
                    break;
                }
            }
            if (saw_non_invalid && !call_succeeded) {
                call_selector = non_invalid_selector;
                call_kr = non_invalid_kr;
                call_kr_string = non_invalid_kr_string;
                call_output_scalar_count = non_invalid_output_scalar_count;
                call_output_struct_bytes = non_invalid_output_struct_bytes;
            }
            if (input_scalars) free(input_scalars);
            if (output_scalars) free(output_scalars);
            if (input_struct) free(input_struct);
            if (output_struct) free(output_struct);
        }
        if (call_attempted && !capture_tuple.valid) {
            sbl_tuple_set(
                &capture_tuple,
                call_kind_used,
                call_selector,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_kr
            );
            capture_source = "post_open_call";
        } else if (!capture_tuple.valid && g_capture.seen) {
            sbl_tuple_set(
                &capture_tuple,
                g_capture.kind,
                g_capture.selector,
                g_capture.input_scalar_count,
                g_capture.input_struct_bytes,
                g_capture.output_scalar_count,
                g_capture.output_struct_bytes,
                g_capture.kr
            );
            capture_source = "interpose_capture";
        } else if (!capture_tuple.valid && synthetic_call_attempted) {
            sbl_tuple_set(
                &capture_tuple,
                synthetic_call_kind,
                synthetic_call_selector,
                synthetic_call_input_scalar_count,
                synthetic_call_input_struct_bytes,
                synthetic_call_output_scalar_count,
                synthetic_call_output_struct_bytes,
                synthetic_call_kr
            );
            capture_source = "synthetic_call";
        }
        surface_ok = attempt_surface_create(&surface_signal, capture_calls);
        IOServiceClose(conn);
    }
    IOObjectRelease(service);

    const char *capture_enabled_json = capture_calls ? "true" : "false";
    const char *capture_seen_json = g_capture.seen ? "true" : "false";
    const char *capture_non_invalid_seen_json = g_capture.non_invalid_seen ? "true" : "false";
    const char *capture_kr_string = g_capture.seen ? mach_error_string(g_capture.kr) : NULL;
    const char *capture_non_invalid_kr_string = g_capture.non_invalid_seen ? mach_error_string(g_capture.non_invalid_kr) : NULL;
    char capture_kind_json[96];
    char capture_non_invalid_kind_json[96];
    char capture_selector_json[32];
    char capture_non_invalid_selector_json[32];
    char capture_input_scalar_json[32];
    char capture_non_invalid_input_scalar_json[32];
    char capture_input_struct_json[32];
    char capture_non_invalid_input_struct_json[32];
    char capture_output_scalar_json[32];
    char capture_non_invalid_output_scalar_json[32];
    char capture_output_struct_json[32];
    char capture_non_invalid_output_struct_json[32];
    char capture_kr_json[32];
    char capture_non_invalid_kr_json[32];
    char capture_kr_string_json[128];
    char capture_non_invalid_kr_string_json[128];
    const char *capture_kind_out = json_string_or_null(capture_kind_json, sizeof(capture_kind_json), g_capture.kind, g_capture.seen);
    const char *capture_non_invalid_kind_out = json_string_or_null(
        capture_non_invalid_kind_json, sizeof(capture_non_invalid_kind_json), g_capture.non_invalid_kind, g_capture.non_invalid_seen);
    const char *capture_selector_out = json_uint_or_null(
        capture_selector_json, sizeof(capture_selector_json), g_capture.selector, g_capture.seen);
    const char *capture_non_invalid_selector_out = json_uint_or_null(
        capture_non_invalid_selector_json, sizeof(capture_non_invalid_selector_json), g_capture.non_invalid_selector, g_capture.non_invalid_seen);
    const char *capture_input_scalar_out = json_uint_or_null(
        capture_input_scalar_json, sizeof(capture_input_scalar_json), g_capture.input_scalar_count, g_capture.seen);
    const char *capture_non_invalid_input_scalar_out = json_uint_or_null(
        capture_non_invalid_input_scalar_json,
        sizeof(capture_non_invalid_input_scalar_json),
        g_capture.non_invalid_input_scalar_count,
        g_capture.non_invalid_seen);
    const char *capture_input_struct_out = json_uint_or_null(
        capture_input_struct_json, sizeof(capture_input_struct_json), g_capture.input_struct_bytes, g_capture.seen);
    const char *capture_non_invalid_input_struct_out = json_uint_or_null(
        capture_non_invalid_input_struct_json,
        sizeof(capture_non_invalid_input_struct_json),
        g_capture.non_invalid_input_struct_bytes,
        g_capture.non_invalid_seen);
    const char *capture_output_scalar_out = json_uint_or_null(
        capture_output_scalar_json, sizeof(capture_output_scalar_json), g_capture.output_scalar_count, g_capture.seen);
    const char *capture_non_invalid_output_scalar_out = json_uint_or_null(
        capture_non_invalid_output_scalar_json,
        sizeof(capture_non_invalid_output_scalar_json),
        g_capture.non_invalid_output_scalar_count,
        g_capture.non_invalid_seen);
    const char *capture_output_struct_out = json_uint_or_null(
        capture_output_struct_json, sizeof(capture_output_struct_json), g_capture.output_struct_bytes, g_capture.seen);
    const char *capture_non_invalid_output_struct_out = json_uint_or_null(
        capture_non_invalid_output_struct_json,
        sizeof(capture_non_invalid_output_struct_json),
        g_capture.non_invalid_output_struct_bytes,
        g_capture.non_invalid_seen);
    const char *capture_kr_out = json_int_or_null(
        capture_kr_json, sizeof(capture_kr_json), g_capture.kr, g_capture.seen);
    const char *capture_non_invalid_kr_out = json_int_or_null(
        capture_non_invalid_kr_json,
        sizeof(capture_non_invalid_kr_json),
        g_capture.non_invalid_kr,
        g_capture.non_invalid_seen);
    const char *capture_kr_string_out = json_string_or_null(
        capture_kr_string_json, sizeof(capture_kr_string_json), capture_kr_string, g_capture.seen);
    const char *capture_non_invalid_kr_string_out = json_string_or_null(
        capture_non_invalid_kr_string_json,
        sizeof(capture_non_invalid_kr_string_json),
        capture_non_invalid_kr_string,
        g_capture.non_invalid_seen);
    char capture_fields[1024];
    snprintf(
        capture_fields,
        sizeof(capture_fields),
        ",\"capture_enabled\":%s,\"capture_seen\":%s,\"capture_kind\":%s,\"capture_selector\":%s,"
        "\"capture_input_scalar_count\":%s,\"capture_input_struct_bytes\":%s,\"capture_output_scalar_count\":%s,"
        "\"capture_output_struct_bytes\":%s,\"capture_kr\":%s,\"capture_kr_string\":%s,"
        "\"capture_non_invalid_seen\":%s,\"capture_non_invalid_kind\":%s,\"capture_non_invalid_selector\":%s,"
        "\"capture_non_invalid_input_scalar_count\":%s,\"capture_non_invalid_input_struct_bytes\":%s,"
        "\"capture_non_invalid_output_scalar_count\":%s,\"capture_non_invalid_output_struct_bytes\":%s,"
        "\"capture_non_invalid_kr\":%s,\"capture_non_invalid_kr_string\":%s",
        capture_enabled_json,
        capture_seen_json,
        capture_kind_out,
        capture_selector_out,
        capture_input_scalar_out,
        capture_input_struct_out,
        capture_output_scalar_out,
        capture_output_struct_out,
        capture_kr_out,
        capture_kr_string_out,
        capture_non_invalid_seen_json,
        capture_non_invalid_kind_out,
        capture_non_invalid_selector_out,
        capture_non_invalid_input_scalar_out,
        capture_non_invalid_input_struct_out,
        capture_non_invalid_output_scalar_out,
        capture_non_invalid_output_struct_out,
        capture_non_invalid_kr_out,
        capture_non_invalid_kr_string_out);
    const char *synthetic_attempted_json = synthetic_call_attempted ? "true" : "false";
    const char *synthetic_used_dlsym_json = synthetic_call_used_dlsym ? "true" : "false";
    const char *synthetic_capture_forced_json = synthetic_call_capture_forced ? "true" : "false";
    char synthetic_kind_json[64];
    char synthetic_selector_json[32];
    char synthetic_input_scalar_json[32];
    char synthetic_input_struct_json[32];
    char synthetic_output_scalar_json[32];
    char synthetic_output_struct_json[32];
    char synthetic_kr_json[32];
    char synthetic_kr_string_json[128];
    const char *synthetic_kind_out = json_string_or_null(
        synthetic_kind_json, sizeof(synthetic_kind_json), synthetic_call_kind, synthetic_call_attempted);
    const char *synthetic_selector_out = json_uint_or_null(
        synthetic_selector_json, sizeof(synthetic_selector_json), synthetic_call_selector, synthetic_call_attempted);
    const char *synthetic_input_scalar_out = json_uint_or_null(
        synthetic_input_scalar_json,
        sizeof(synthetic_input_scalar_json),
        synthetic_call_input_scalar_count,
        synthetic_call_attempted);
    const char *synthetic_input_struct_out = json_uint_or_null(
        synthetic_input_struct_json,
        sizeof(synthetic_input_struct_json),
        synthetic_call_input_struct_bytes,
        synthetic_call_attempted);
    const char *synthetic_output_scalar_out = json_uint_or_null(
        synthetic_output_scalar_json,
        sizeof(synthetic_output_scalar_json),
        synthetic_call_output_scalar_count,
        synthetic_call_attempted);
    const char *synthetic_output_struct_out = json_uint_or_null(
        synthetic_output_struct_json,
        sizeof(synthetic_output_struct_json),
        synthetic_call_output_struct_bytes,
        synthetic_call_attempted);
    const char *synthetic_kr_out = json_int_or_null(
        synthetic_kr_json, sizeof(synthetic_kr_json), synthetic_call_kr, synthetic_call_attempted);
    const char *synthetic_kr_string_out = json_string_or_null(
        synthetic_kr_string_json, sizeof(synthetic_kr_string_json), synthetic_call_kr_string, synthetic_call_attempted);
    char synthetic_fields[512];
    snprintf(
        synthetic_fields,
        sizeof(synthetic_fields),
        ",\"synthetic_call_attempted\":%s,\"synthetic_call_used_dlsym\":%s,\"synthetic_call_capture_forced\":%s,"
        "\"synthetic_call_kind\":%s,\"synthetic_call_selector\":%s,\"synthetic_call_input_scalar_count\":%s,"
        "\"synthetic_call_input_struct_bytes\":%s,\"synthetic_call_output_scalar_count\":%s,"
        "\"synthetic_call_output_struct_bytes\":%s,\"synthetic_call_kr\":%s,\"synthetic_call_kr_string\":%s",
        synthetic_attempted_json,
        synthetic_used_dlsym_json,
        synthetic_capture_forced_json,
        synthetic_kind_out,
        synthetic_selector_out,
        synthetic_input_scalar_out,
        synthetic_input_struct_out,
        synthetic_output_scalar_out,
        synthetic_output_struct_out,
        synthetic_kr_out,
        synthetic_kr_string_out);

    const char *capture_source_out = capture_source ? capture_source : "none";
    const char *capture_source_json = capture_tuple.valid ? capture_source_out : "none";
    char capture_first_kind_json[96];
    char capture_first_selector_json[32];
    char capture_first_input_scalar_json[32];
    char capture_first_input_struct_json[32];
    char capture_first_output_scalar_json[32];
    char capture_first_output_struct_json[32];
    char capture_first_kr_json[32];
    char capture_first_kr_string_json[128];
    char capture_first_spec_json[256];
    char capture_first_spec_buf[256];
    sbl_format_replay_spec(&capture_tuple, capture_first_spec_buf, sizeof(capture_first_spec_buf));
    const char *capture_first_kind_out = json_string_or_null(
        capture_first_kind_json, sizeof(capture_first_kind_json), capture_tuple.kind, capture_tuple.valid);
    const char *capture_first_selector_out = json_uint_or_null(
        capture_first_selector_json, sizeof(capture_first_selector_json), capture_tuple.selector, capture_tuple.valid);
    const char *capture_first_input_scalar_out = json_uint_or_null(
        capture_first_input_scalar_json,
        sizeof(capture_first_input_scalar_json),
        capture_tuple.input_scalar_count,
        capture_tuple.valid);
    const char *capture_first_input_struct_out = json_uint_or_null(
        capture_first_input_struct_json,
        sizeof(capture_first_input_struct_json),
        capture_tuple.input_struct_bytes,
        capture_tuple.valid);
    const char *capture_first_output_scalar_out = json_uint_or_null(
        capture_first_output_scalar_json,
        sizeof(capture_first_output_scalar_json),
        capture_tuple.output_scalar_count,
        capture_tuple.valid);
    const char *capture_first_output_struct_out = json_uint_or_null(
        capture_first_output_struct_json,
        sizeof(capture_first_output_struct_json),
        capture_tuple.output_struct_bytes,
        capture_tuple.valid);
    const char *capture_first_kr_out = json_int_or_null(
        capture_first_kr_json, sizeof(capture_first_kr_json), capture_tuple.kr, capture_tuple.valid);
    const char *capture_first_kr_string_out = json_string_or_null(
        capture_first_kr_string_json,
        sizeof(capture_first_kr_string_json),
        capture_tuple.valid ? mach_error_string(capture_tuple.kr) : NULL,
        capture_tuple.valid);
    const char *capture_first_spec_out = json_string_or_null(
        capture_first_spec_json,
        sizeof(capture_first_spec_json),
        capture_first_spec_buf,
        capture_tuple.valid && capture_first_spec_buf[0] != '\0');
    char capture_first_fields[512];
    snprintf(
        capture_first_fields,
        sizeof(capture_first_fields),
        ",\"capture_first_source\":\"%s\",\"capture_first_kind\":%s,\"capture_first_selector\":%s,"
        "\"capture_first_input_scalar_count\":%s,\"capture_first_input_struct_bytes\":%s,"
        "\"capture_first_output_scalar_count\":%s,\"capture_first_output_struct_bytes\":%s,"
        "\"capture_first_kr\":%s,\"capture_first_kr_string\":%s,\"capture_first_spec\":%s",
        capture_source_json,
        capture_first_kind_out,
        capture_first_selector_out,
        capture_first_input_scalar_out,
        capture_first_input_struct_out,
        capture_first_output_scalar_out,
        capture_first_output_struct_out,
        capture_first_kr_out,
        capture_first_kr_string_out,
        capture_first_spec_out);

    const char *replay_enabled_json = replay_enabled ? "true" : "false";
    const char *replay_attempted_json = replay_attempted ? "true" : "false";
    char replay_kind_json[96];
    char replay_selector_json[32];
    char replay_input_scalar_json[32];
    char replay_input_struct_json[32];
    char replay_output_scalar_json[32];
    char replay_output_struct_json[32];
    char replay_kr_json[32];
    char replay_kr_string_json[128];
    const char *replay_kind_out = json_string_or_null(
        replay_kind_json, sizeof(replay_kind_json), replay_tuple.kind, replay_tuple.valid);
    const char *replay_selector_out = json_uint_or_null(
        replay_selector_json, sizeof(replay_selector_json), replay_tuple.selector, replay_tuple.valid);
    const char *replay_input_scalar_out = json_uint_or_null(
        replay_input_scalar_json,
        sizeof(replay_input_scalar_json),
        replay_tuple.input_scalar_count,
        replay_tuple.valid);
    const char *replay_input_struct_out = json_uint_or_null(
        replay_input_struct_json,
        sizeof(replay_input_struct_json),
        replay_tuple.input_struct_bytes,
        replay_tuple.valid);
    const char *replay_output_scalar_out = json_uint_or_null(
        replay_output_scalar_json,
        sizeof(replay_output_scalar_json),
        replay_tuple.output_scalar_count,
        replay_tuple.valid);
    const char *replay_output_struct_out = json_uint_or_null(
        replay_output_struct_json,
        sizeof(replay_output_struct_json),
        replay_tuple.output_struct_bytes,
        replay_tuple.valid);
    const char *replay_kr_out = json_int_or_null(
        replay_kr_json, sizeof(replay_kr_json), replay_tuple.kr, replay_attempted);
    const char *replay_kr_string_out = json_string_or_null(
        replay_kr_string_json,
        sizeof(replay_kr_string_json),
        replay_attempted ? mach_error_string(replay_tuple.kr) : NULL,
        replay_attempted);
    const char *replay_status_out = replay_status ? replay_status : (replay_enabled ? "replay_ready" : "replay_disabled");
    const char *replay_source_out = replay_source ? replay_source : (replay_enabled ? "unknown" : "none");
    char replay_fields[512];
    snprintf(
        replay_fields,
        sizeof(replay_fields),
        ",\"replay_enabled\":%s,\"replay_attempted\":%s,\"replay_status\":\"%s\",\"replay_source\":\"%s\","
        "\"replay_kind\":%s,\"replay_selector\":%s,\"replay_input_scalar_count\":%s,\"replay_input_struct_bytes\":%s,"
        "\"replay_output_scalar_count\":%s,\"replay_output_struct_bytes\":%s,\"replay_kr\":%s,\"replay_kr_string\":%s",
        replay_enabled_json,
        replay_attempted_json,
        replay_status_out,
        replay_source_out,
        replay_kind_out,
        replay_selector_out,
        replay_input_scalar_out,
        replay_input_struct_out,
        replay_output_scalar_out,
        replay_output_struct_out,
        replay_kr_out,
        replay_kr_string_out);
    const char *method0_enabled_json = method0_enabled ? "true" : "false";
    const char *method0_attempted_json = method0_attempted ? "true" : "false";
    const char *method0_payload_ok_json = method0_payload_ok ? "true" : "false";
    const char *method0_payload_nul_out = method0_attempted ? (method0_payload_nul_appended ? "true" : "false") : "null";
    char method0_format_json[64];
    char method0_source_json[64];
    char method0_input_bytes_json[32];
    char method0_output_cap_json[32];
    char method0_output_bytes_json[32];
    char method0_output_id_json[32];
    const char *method0_format_out = json_string_or_null(
        method0_format_json,
        sizeof(method0_format_json),
        method0_plist_format,
        method0_plist_format != NULL);
    const char *method0_source_out = json_string_or_null(
        method0_source_json,
        sizeof(method0_source_json),
        method0_payload_source,
        method0_payload_source != NULL);
    const char *method0_input_bytes_out = json_uint_or_null(
        method0_input_bytes_json,
        sizeof(method0_input_bytes_json),
        method0_input_bytes,
        method0_attempted);
    const char *method0_output_cap_out = json_uint_or_null(
        method0_output_cap_json,
        sizeof(method0_output_cap_json),
        method0_output_capacity,
        method0_attempted);
    const char *method0_output_bytes_out = json_uint_or_null(
        method0_output_bytes_json,
        sizeof(method0_output_bytes_json),
        method0_output_bytes,
        method0_attempted);
    const char *method0_output_id_out = json_uint_or_null(
        method0_output_id_json,
        sizeof(method0_output_id_json),
        method0_output_id,
        method0_output_id_valid);
    char method0_fields[512];
    snprintf(
        method0_fields,
        sizeof(method0_fields),
        ",\"method0_enabled\":%s,\"method0_attempted\":%s,\"method0_payload_ok\":%s,"
        "\"method0_payload_nul_appended\":%s,\"method0_plist_format\":%s,\"method0_payload_source\":%s,"
        "\"method0_input_bytes\":%s,"
        "\"method0_output_capacity\":%s,"
        "\"method0_output_bytes\":%s,\"method0_output_id_u32_0x10\":%s",
        method0_enabled_json,
        method0_attempted_json,
        method0_payload_ok_json,
        method0_payload_nul_out,
        method0_format_out,
        method0_source_out,
        method0_input_bytes_out,
        method0_output_cap_out,
        method0_output_bytes_out,
        method0_output_id_out);
    char *sweep_fields = NULL;
    size_t sweep_fields_len = 0;
    size_t sweep_fields_cap = 0;
    if (sweep_enabled) {
        char sweep_first_spec_json[256];
        const char *sweep_first_spec_out = json_string_or_null(
            sweep_first_spec_json,
            sizeof(sweep_first_spec_json),
            sweep_first_spec_buf,
            sweep_found_non_invalid && sweep_first_spec_buf[0] != '\0');
        const char *sweep_results_out = sweep_results_json ? sweep_results_json : "[]";
        sbl_json_append(
            &sweep_fields,
            &sweep_fields_len,
            &sweep_fields_cap,
            ",\"sweep_enabled\":true,\"sweep_result_count\":%zu,\"sweep_results\":%s,"
            "\"first_non_invalid_spec\":%s,\"first_non_invalid_missing\":%s",
            sweep_result_count,
            sweep_results_out,
            sweep_first_spec_out,
            sweep_missing_non_invalid ? "true" : "false");
    }
    char *mach_capture_fields = NULL;
    size_t mach_capture_fields_len = 0;
    size_t mach_capture_fields_cap = 0;
    char *mach_capture_json = NULL;
    size_t mach_capture_json_len = 0;
    size_t mach_capture_json_cap = 0;
    if (mach_capture_enabled) {
        sbl_json_append(&mach_capture_json, &mach_capture_json_len, &mach_capture_json_cap, "[");
        for (size_t i = 0; i < g_mach_capture.count; i++) {
            if (i > 0) {
                sbl_json_append(&mach_capture_json, &mach_capture_json_len, &mach_capture_json_cap, ",");
            }
            sbl_json_append(
                &mach_capture_json,
                &mach_capture_json_len,
                &mach_capture_json_cap,
                "{\"msg_id\":%d,\"size\":%u,\"hash\":%u,\"kr\":%d}",
                g_mach_capture.entries[i].msg_id,
                (unsigned int)g_mach_capture.entries[i].size,
                g_mach_capture.entries[i].hash,
                g_mach_capture.entries[i].kr
            );
        }
        sbl_json_append(&mach_capture_json, &mach_capture_json_len, &mach_capture_json_cap, "]");
        sbl_json_append(
            &mach_capture_fields,
            &mach_capture_fields_len,
            &mach_capture_fields_cap,
            ",\"mach_msg_capture_enabled\":true,\"mach_msg_capture_count\":%zu,\"mach_msg_capture\":%s",
            g_mach_capture.count,
            mach_capture_json ? mach_capture_json : "[]");
    }

    if (call_attempted) {
        const char *call_kr_string_value = call_kr_string ? call_kr_string : "unknown";
        if (surface_signal) {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"%s\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s%s%s%s%s%s%s}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_kind_used,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false",
                surface_signal,
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s%s%s%s%s%s%s}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false",
                surface_signal,
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
        } else {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"%s\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":null%s%s%s%s%s%s%s}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_kind_used,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false",
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":null%s%s%s%s%s%s%s}\n",
                kr,
                call_kr,
                call_kr_string_value,
                call_selector,
                call_input_scalar_count,
                call_input_struct_bytes,
                call_output_scalar_count,
                call_output_struct_bytes,
                call_succeeded ? "true" : "false",
                surface_ok ? "true" : "false",
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
        }
    } else {
        if (surface_signal) {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"%s\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s%s%s%s%s%s%s}\n",
                kr,
                call_kind_used,
                surface_ok ? "true" : "false",
                surface_signal,
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s%s%s%s%s%s%s}\n",
                kr,
                surface_ok ? "true" : "false",
                surface_signal,
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
        } else {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"%s\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":null%s%s%s%s%s%s%s}\n",
                kr,
                call_kind_used,
                surface_ok ? "true" : "false",
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":null%s%s%s%s%s%s%s}\n",
                kr,
                surface_ok ? "true" : "false",
                capture_fields,
                synthetic_fields,
                capture_first_fields,
                replay_fields,
                method0_fields,
                sweep_fields ? sweep_fields : "",
                mach_capture_fields ? mach_capture_fields : "");
        }
    }
    if (sweep_fields) {
        free(sweep_fields);
    }
    if (sweep_results_json) {
        free(sweep_results_json);
    }
    if (mach_capture_fields) {
        free(mach_capture_fields);
    }
    if (mach_capture_json) {
        free(mach_capture_json);
    }
    if (replay_enabled && replay_missing_capture) {
        return 1;
    }
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    if (call_attempted && call_kr != KERN_SUCCESS && !surface_ok) {
        return 1;
    }
    return 0;
}
