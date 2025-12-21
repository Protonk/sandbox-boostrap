#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static pthread_mutex_t g_trace_lock = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_trace_fp = NULL;
static const char *g_trace_path = NULL;
static const char *g_trace_input = NULL;
static uint64_t g_seq = 0;
static __thread int g_in_hook = 0;

typedef void (*sb_write_fn)(void *buf, uint64_t cursor, const void *data, uint64_t len);
extern void _sb_mutable_buffer_write(void *buf, uint64_t cursor, const void *data, uint64_t len);

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

static sb_write_fn resolve_real(void) {
    void *sym = dlsym(RTLD_NEXT, "_sb_mutable_buffer_write");
    return (sb_write_fn)sym;
}

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

void sb_mutable_buffer_write_interpose(void *buf, uint64_t cursor, const void *data, uint64_t len) {
    sb_write_fn real = resolve_real();
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

__attribute__((used)) static struct {
    const void *replacement;
    const void *original;
} g_interposes[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)sb_mutable_buffer_write_interpose, (const void *)_sb_mutable_buffer_write }
};
