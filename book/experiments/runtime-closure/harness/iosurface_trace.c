/*
 * iosurface_trace: minimal IOSurfaceCreate caller used with the interposer
 * to observe IOConnectCallMethod selector + argument shapes.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOSurface/IOSurface.h>
#include <dlfcn.h>
#include <mach/error.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct dyld_interpose_tuple {
    const void *replacement;
    const void *replacee;
};

typedef void (*dyld_dynamic_interpose_fn)(const struct mach_header *mh, const struct dyld_interpose_tuple *array, size_t count);

typedef kern_return_t (*IOConnectCallMethodFn)(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *inputScalar,
    uint32_t inputScalarCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    uint64_t *outputScalar,
    uint32_t *outputScalarCnt,
    void *outputStruct,
    size_t *outputStructCnt);

typedef kern_return_t (*IOConnectCallAsyncMethodFn)(
    io_connect_t connection,
    uint32_t selector,
    mach_port_t wakePort,
    uint64_t *reference,
    uint32_t referenceCnt,
    const uint64_t *inputScalar,
    uint32_t inputScalarCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    uint64_t *outputScalar,
    uint32_t *outputScalarCnt,
    void *outputStruct,
    size_t *outputStructCnt);

typedef kern_return_t (*IOConnectCallScalarMethodFn)(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *inputScalar,
    uint32_t inputScalarCnt,
    uint64_t *outputScalar,
    uint32_t *outputScalarCnt);

typedef kern_return_t (*IOConnectCallStructMethodFn)(
    io_connect_t connection,
    uint32_t selector,
    const void *inputStruct,
    size_t inputStructCnt,
    void *outputStruct,
    size_t *outputStructCnt);

static IOConnectCallMethodFn g_original_call = NULL;
static IOConnectCallAsyncMethodFn g_original_async = NULL;
static IOConnectCallScalarMethodFn g_original_scalar = NULL;
static IOConnectCallStructMethodFn g_original_struct = NULL;

static kern_return_t hooked_IOConnectCallMethod(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *inputScalar,
    uint32_t inputScalarCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    uint64_t *outputScalar,
    uint32_t *outputScalarCnt,
    void *outputStruct,
    size_t *outputStructCnt) {
    uint32_t output_scalar_before = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_before = outputStructCnt ? *outputStructCnt : 0;
    kern_return_t kr = g_original_call
        ? g_original_call(
              connection,
              selector,
              inputScalar,
              inputScalarCnt,
              inputStruct,
              inputStructCnt,
              outputScalar,
              outputScalarCnt,
              outputStruct,
              outputStructCnt)
        : KERN_FAILURE;
    uint32_t output_scalar_after = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_after = outputStructCnt ? *outputStructCnt : 0;
    const char *kr_str = mach_error_string(kr);
    fprintf(
        stderr,
        "SBL_IKIT_CALL {\"api\":\"IOConnectCallMethod\",\"selector\":%u,\"input_scalar_count\":%u,"
        "\"input_struct_bytes\":%zu,\"output_scalar_count_before\":%u,\"output_struct_bytes_before\":%zu,"
        "\"output_scalar_count_after\":%u,\"output_struct_bytes_after\":%zu,\"kr\":%d,\"kr_string\":\"%s\"}\n",
        selector,
        inputScalarCnt,
        inputStructCnt,
        output_scalar_before,
        output_struct_before,
        output_scalar_after,
        output_struct_after,
        kr,
        kr_str ? kr_str : "unknown");
    return kr;
}

static kern_return_t hooked_IOConnectCallAsyncMethod(
    io_connect_t connection,
    uint32_t selector,
    mach_port_t wakePort,
    uint64_t *reference,
    uint32_t referenceCnt,
    const uint64_t *inputScalar,
    uint32_t inputScalarCnt,
    const void *inputStruct,
    size_t inputStructCnt,
    uint64_t *outputScalar,
    uint32_t *outputScalarCnt,
    void *outputStruct,
    size_t *outputStructCnt) {
    uint32_t output_scalar_before = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_before = outputStructCnt ? *outputStructCnt : 0;
    kern_return_t kr = g_original_async
        ? g_original_async(
              connection,
              selector,
              wakePort,
              reference,
              referenceCnt,
              inputScalar,
              inputScalarCnt,
              inputStruct,
              inputStructCnt,
              outputScalar,
              outputScalarCnt,
              outputStruct,
              outputStructCnt)
        : KERN_FAILURE;
    uint32_t output_scalar_after = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_after = outputStructCnt ? *outputStructCnt : 0;
    const char *kr_str = mach_error_string(kr);
    fprintf(
        stderr,
        "SBL_IKIT_CALL {\"api\":\"IOConnectCallAsyncMethod\",\"selector\":%u,\"input_scalar_count\":%u,"
        "\"input_struct_bytes\":%zu,\"output_scalar_count_before\":%u,\"output_struct_bytes_before\":%zu,"
        "\"output_scalar_count_after\":%u,\"output_struct_bytes_after\":%zu,\"kr\":%d,\"kr_string\":\"%s\"}\n",
        selector,
        inputScalarCnt,
        inputStructCnt,
        output_scalar_before,
        output_struct_before,
        output_scalar_after,
        output_struct_after,
        kr,
        kr_str ? kr_str : "unknown");
    return kr;
}

static kern_return_t hooked_IOConnectCallScalarMethod(
    io_connect_t connection,
    uint32_t selector,
    const uint64_t *inputScalar,
    uint32_t inputScalarCnt,
    uint64_t *outputScalar,
    uint32_t *outputScalarCnt) {
    uint32_t output_scalar_before = outputScalarCnt ? *outputScalarCnt : 0;
    kern_return_t kr = g_original_scalar
        ? g_original_scalar(
              connection,
              selector,
              inputScalar,
              inputScalarCnt,
              outputScalar,
              outputScalarCnt)
        : KERN_FAILURE;
    uint32_t output_scalar_after = outputScalarCnt ? *outputScalarCnt : 0;
    const char *kr_str = mach_error_string(kr);
    fprintf(
        stderr,
        "SBL_IKIT_CALL {\"api\":\"IOConnectCallScalarMethod\",\"selector\":%u,\"input_scalar_count\":%u,"
        "\"input_struct_bytes\":0,\"output_scalar_count_before\":%u,\"output_struct_bytes_before\":0,"
        "\"output_scalar_count_after\":%u,\"output_struct_bytes_after\":0,\"kr\":%d,\"kr_string\":\"%s\"}\n",
        selector,
        inputScalarCnt,
        output_scalar_before,
        output_scalar_after,
        kr,
        kr_str ? kr_str : "unknown");
    return kr;
}

static kern_return_t hooked_IOConnectCallStructMethod(
    io_connect_t connection,
    uint32_t selector,
    const void *inputStruct,
    size_t inputStructCnt,
    void *outputStruct,
    size_t *outputStructCnt) {
    size_t output_struct_before = outputStructCnt ? *outputStructCnt : 0;
    kern_return_t kr = g_original_struct
        ? g_original_struct(
              connection,
              selector,
              inputStruct,
              inputStructCnt,
              outputStruct,
              outputStructCnt)
        : KERN_FAILURE;
    size_t output_struct_after = outputStructCnt ? *outputStructCnt : 0;
    const char *kr_str = mach_error_string(kr);
    fprintf(
        stderr,
        "SBL_IKIT_CALL {\"api\":\"IOConnectCallStructMethod\",\"selector\":%u,\"input_scalar_count\":0,"
        "\"input_struct_bytes\":%zu,\"output_scalar_count_before\":0,\"output_struct_bytes_before\":%zu,"
        "\"output_scalar_count_after\":0,\"output_struct_bytes_after\":%zu,\"kr\":%d,\"kr_string\":\"%s\"}\n",
        selector,
        inputStructCnt,
        output_struct_before,
        output_struct_after,
        kr,
        kr_str ? kr_str : "unknown");
    return kr;
}

static void install_interpose(void) {
    dyld_dynamic_interpose_fn interpose = (dyld_dynamic_interpose_fn)dlsym(RTLD_DEFAULT, "dyld_dynamic_interpose");
    if (!interpose) {
        fprintf(stderr, "SBL_IKIT_INTERPOSE {\"status\":\"unavailable\"}\n");
        return;
    }
    Dl_info info;
    if (!dladdr((void *)IOSurfaceCreate, &info) || !info.dli_fbase) {
        fprintf(stderr, "SBL_IKIT_INTERPOSE {\"status\":\"missing_target\"}\n");
        return;
    }
    g_original_call = (IOConnectCallMethodFn)IOConnectCallMethod;
    g_original_async = (IOConnectCallAsyncMethodFn)IOConnectCallAsyncMethod;
    g_original_scalar = (IOConnectCallScalarMethodFn)IOConnectCallScalarMethod;
    g_original_struct = (IOConnectCallStructMethodFn)IOConnectCallStructMethod;
    struct dyld_interpose_tuple tuples[] = {
        { (const void *)hooked_IOConnectCallMethod, (const void *)IOConnectCallMethod },
        { (const void *)hooked_IOConnectCallAsyncMethod, (const void *)IOConnectCallAsyncMethod },
        { (const void *)hooked_IOConnectCallScalarMethod, (const void *)IOConnectCallScalarMethod },
        { (const void *)hooked_IOConnectCallStructMethod, (const void *)IOConnectCallStructMethod },
    };
    interpose((const struct mach_header *)info.dli_fbase, tuples, sizeof(tuples) / sizeof(tuples[0]));
    fprintf(stderr, "SBL_IKIT_INTERPOSE {\"status\":\"installed\"}\n");
}

int main(void) {
    install_interpose();
    int width = 1;
    int height = 1;
    int bytes_per_elem = 4;
    CFNumberRef width_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &width);
    CFNumberRef height_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &height);
    CFNumberRef bpe_num = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bytes_per_elem);
    if (!width_num || !height_num || !bpe_num) {
        if (width_num) CFRelease(width_num);
        if (height_num) CFRelease(height_num);
        if (bpe_num) CFRelease(bpe_num);
        printf("{\"surface_create_ok\":false}\n");
        return 1;
    }
    const void *keys[] = {kIOSurfaceWidth, kIOSurfaceHeight, kIOSurfaceBytesPerElement};
    const void *vals[] = {width_num, height_num, bpe_num};
    CFDictionaryRef props = CFDictionaryCreate(
        kCFAllocatorDefault, keys, vals, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(width_num);
    CFRelease(height_num);
    CFRelease(bpe_num);
    if (!props) {
        printf("{\"surface_create_ok\":false}\n");
        return 1;
    }
    IOSurfaceRef surface = IOSurfaceCreate(props);
    CFRelease(props);
    if (surface) {
        CFRelease(surface);
        printf("{\"surface_create_ok\":true}\n");
        return 0;
    }
    printf("{\"surface_create_ok\":false}\n");
    return 1;
}
