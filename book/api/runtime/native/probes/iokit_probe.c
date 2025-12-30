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
#include <IOKit/IOKitLib.h>
#include <IOKit/IOReturn.h>
#include <IOSurface/IOSurface.h>
#include <dlfcn.h>
#include <mach/error.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define SBL_IKIT_CAPTURE_ENV "SANDBOX_LORE_IKIT_CAPTURE_CALLS"
#define SBL_IKIT_CALL_KIND_ENV "SANDBOX_LORE_IKIT_CALL_KIND"
#define SBL_IKIT_CALL_IN_SCALARS_ENV "SANDBOX_LORE_IKIT_CALL_IN_SCALARS"
#define SBL_IKIT_CALL_IN_STRUCT_BYTES_ENV "SANDBOX_LORE_IKIT_CALL_IN_STRUCT_BYTES"
#define SBL_IKIT_CALL_OUT_SCALARS_ENV "SANDBOX_LORE_IKIT_CALL_OUT_SCALARS"
#define SBL_IKIT_CALL_OUT_STRUCT_BYTES_ENV "SANDBOX_LORE_IKIT_CALL_OUT_STRUCT_BYTES"

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

static sbl_iokit_capture_t g_capture;
static int g_capture_active = 0;

static void sbl_capture_reset(void) {
    memset(&g_capture, 0, sizeof(g_capture));
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

#define SBL_DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void *replacement; \
        const void *replacee; \
    } _sbl_interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(unsigned long)&_replacement, \
        (const void *)(unsigned long)&_replacee \
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
    bool surface_ok = false;
    int surface_signal = 0;
    bool do_sweep = true;
    const char *call_kind_env = getenv(SBL_IKIT_CALL_KIND_ENV);
    const char *call_kind = normalize_call_kind(call_kind_env);
    const char *call_kind_used = call_kind;
    const uint32_t default_selectors[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    const uint32_t *selectors = default_selectors;
    size_t selector_count = sizeof(default_selectors) / sizeof(default_selectors[0]);
    uint32_t selector_buf[128];
    const char *selector_env = getenv("SANDBOX_LORE_IKIT_SELECTOR_LIST");
    if (selector_env && selector_env[0] != '\0') {
        size_t parsed = parse_selector_list(selector_env, selector_buf, sizeof(selector_buf) / sizeof(selector_buf[0]));
        if (parsed > 0) {
            selectors = selector_buf;
            selector_count = parsed;
        }
    }
    const char *skip_sweep_env = getenv("SBL_IKIT_SKIP_SWEEP");
    if (skip_sweep_env && skip_sweep_env[0] != '\0' && skip_sweep_env[0] != '0') {
        do_sweep = false;
    }
    if (capture_calls) {
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
    if (kr == KERN_SUCCESS && conn != IO_OBJECT_NULL) {
        if (do_sweep) {
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

    if (call_attempted) {
        const char *call_kr_string_value = call_kr_string ? call_kr_string : "unknown";
        if (surface_signal) {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"%s\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s}\n",
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
                capture_fields);
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s}\n",
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
                capture_fields);
        } else {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_kind\":\"%s\",\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":null%s}\n",
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
                capture_fields);
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":%d,\"call_kr_string\":\"%s\",\"call_selector\":%u,\"call_input_scalar_count\":%u,\"call_input_struct_bytes\":%zu,\"call_output_scalar_count\":%u,\"call_output_struct_bytes\":%zu,\"call_succeeded\":%s,\"surface_create_ok\":%s,\"surface_create_signal\":null%s}\n",
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
                capture_fields);
        }
    } else {
        if (surface_signal) {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"%s\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s}\n",
                kr,
                call_kind_used,
                surface_ok ? "true" : "false",
                surface_signal,
                capture_fields);
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":%d%s}\n",
                kr,
                surface_ok ? "true" : "false",
                surface_signal,
                capture_fields);
        } else {
            printf(
                "SBL_PROBE_DETAILS {\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_kind\":\"%s\",\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":null%s}\n",
                kr,
                call_kind_used,
                surface_ok ? "true" : "false",
                capture_fields);
            printf(
                "{\"found\":true,\"open_kr\":%d,\"call_kr\":null,\"call_kr_string\":null,\"call_selector\":null,\"call_input_scalar_count\":null,\"call_input_struct_bytes\":null,\"call_output_scalar_count\":null,\"call_output_struct_bytes\":null,\"surface_create_ok\":%s,\"surface_create_signal\":null%s}\n",
                kr,
                surface_ok ? "true" : "false",
                capture_fields);
        }
    }
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    if (call_attempted && call_kr != KERN_SUCCESS && !surface_ok) {
        return 1;
    }
    return 0;
}
