/*
 * iokit_call_interpose: dyld interposer for IOConnectCallMethod and
 * IOConnectCallAsyncMethod used to capture selector + argument shapes.
 *
 * This is used to observe IOSurfaceCreate call shapes so we can build
 * message-filter allowlists with iokit-method-number.
 */
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <mach/error.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct {      \
        const void *replacement;               \
        const void *replacee;                  \
    } _interpose_##_replacee                    \
        __attribute__((section("__DATA,__interpose"))) = { \
            (const void *)(unsigned long)&_replacement,   \
            (const void *)(unsigned long)&_replacee       \
        }

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

static IOConnectCallMethodFn real_IOConnectCallMethod = NULL;
static IOConnectCallAsyncMethodFn real_IOConnectCallAsyncMethod = NULL;
static __thread int g_in_hook = 0;

static IOConnectCallMethodFn load_IOConnectCallMethod(void) {
    if (!real_IOConnectCallMethod) {
        real_IOConnectCallMethod = (IOConnectCallMethodFn)dlsym(RTLD_NEXT, "IOConnectCallMethod");
    }
    return real_IOConnectCallMethod;
}

static IOConnectCallAsyncMethodFn load_IOConnectCallAsyncMethod(void) {
    if (!real_IOConnectCallAsyncMethod) {
        real_IOConnectCallAsyncMethod = (IOConnectCallAsyncMethodFn)dlsym(RTLD_NEXT, "IOConnectCallAsyncMethod");
    }
    return real_IOConnectCallAsyncMethod;
}

static void emit_trace(
    const char *api,
    uint32_t selector,
    uint32_t input_scalar_count,
    size_t input_struct_bytes,
    uint32_t output_scalar_count_before,
    size_t output_struct_bytes_before,
    uint32_t output_scalar_count_after,
    size_t output_struct_bytes_after,
    kern_return_t kr) {
    const char *kr_str = mach_error_string(kr);
    fprintf(
        stderr,
        "SBL_IKIT_CALL {\"api\":\"%s\",\"selector\":%u,\"input_scalar_count\":%u,\"input_struct_bytes\":%zu,"
        "\"output_scalar_count_before\":%u,\"output_struct_bytes_before\":%zu,"
        "\"output_scalar_count_after\":%u,\"output_struct_bytes_after\":%zu,"
        "\"kr\":%d,\"kr_string\":\"%s\"}\n",
        api,
        selector,
        input_scalar_count,
        input_struct_bytes,
        output_scalar_count_before,
        output_struct_bytes_before,
        output_scalar_count_after,
        output_struct_bytes_after,
        kr,
        kr_str ? kr_str : "unknown");
}

kern_return_t hooked_IOConnectCallMethod(
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
    IOConnectCallMethodFn real_call = load_IOConnectCallMethod();
    if (!real_call) {
        return KERN_FAILURE;
    }
    if (g_in_hook) {
        return real_call(
            connection,
            selector,
            inputScalar,
            inputScalarCnt,
            inputStruct,
            inputStructCnt,
            outputScalar,
            outputScalarCnt,
            outputStruct,
            outputStructCnt);
    }
    g_in_hook = 1;
    uint32_t output_scalar_before = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_before = outputStructCnt ? *outputStructCnt : 0;
    kern_return_t kr = real_call(
        connection,
        selector,
        inputScalar,
        inputScalarCnt,
        inputStruct,
        inputStructCnt,
        outputScalar,
        outputScalarCnt,
        outputStruct,
        outputStructCnt);
    uint32_t output_scalar_after = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_after = outputStructCnt ? *outputStructCnt : 0;
    emit_trace(
        "IOConnectCallMethod",
        selector,
        inputScalarCnt,
        inputStructCnt,
        output_scalar_before,
        output_struct_before,
        output_scalar_after,
        output_struct_after,
        kr);
    g_in_hook = 0;
    return kr;
}

kern_return_t hooked_IOConnectCallAsyncMethod(
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
    IOConnectCallAsyncMethodFn real_call = load_IOConnectCallAsyncMethod();
    if (!real_call) {
        return KERN_FAILURE;
    }
    if (g_in_hook) {
        return real_call(
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
            outputStructCnt);
    }
    g_in_hook = 1;
    uint32_t output_scalar_before = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_before = outputStructCnt ? *outputStructCnt : 0;
    kern_return_t kr = real_call(
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
        outputStructCnt);
    uint32_t output_scalar_after = outputScalarCnt ? *outputScalarCnt : 0;
    size_t output_struct_after = outputStructCnt ? *outputStructCnt : 0;
    emit_trace(
        "IOConnectCallAsyncMethod",
        selector,
        inputScalarCnt,
        inputStructCnt,
        output_scalar_before,
        output_struct_before,
        output_scalar_after,
        output_struct_after,
        kr);
    g_in_hook = 0;
    return kr;
}

DYLD_INTERPOSE(hooked_IOConnectCallMethod, IOConnectCallMethod);
DYLD_INTERPOSE(hooked_IOConnectCallAsyncMethod, IOConnectCallAsyncMethod);
