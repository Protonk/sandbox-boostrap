#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void json_escape_and_write(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; p && *p; p++) {
        switch (*p) {
        case '\\':
            fputs("\\\\", out);
            break;
        case '"':
            fputs("\\\"", out);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        case '\f':
            fputs("\\f", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20) {
                fprintf(out, "\\u%04x", (unsigned int)*p);
            } else {
                fputc(*p, out);
            }
        }
    }
    fputc('"', out);
}

static const char *cfstring_to_utf8(CFStringRef str, char *buf, size_t buf_len) {
    if (!str || !buf || buf_len == 0) {
        return NULL;
    }
    if (CFStringGetCString(str, buf, (CFIndex)buf_len, kCFStringEncodingUTF8)) {
        return buf;
    }
    return NULL;
}

static void json_write_cf_type(FILE *out, CFTypeRef value) {
    if (!value) {
        fputs("null", out);
        return;
    }
    CFTypeID type_id = CFGetTypeID(value);
    if (type_id == CFBooleanGetTypeID()) {
        fputs(CFBooleanGetValue((CFBooleanRef)value) ? "true" : "false", out);
        return;
    }
    if (type_id == CFStringGetTypeID()) {
        char tmp[4096];
        const char *s = cfstring_to_utf8((CFStringRef)value, tmp, sizeof(tmp));
        if (!s) {
            fputs("null", out);
            return;
        }
        json_escape_and_write(out, s);
        return;
    }
    if (type_id == CFNumberGetTypeID()) {
        long long as_ll = 0;
        if (CFNumberGetValue((CFNumberRef)value, kCFNumberLongLongType, &as_ll)) {
            fprintf(out, "%lld", as_ll);
            return;
        }
        fputs("null", out);
        return;
    }

    // Unknown / unhandled CF types: record a minimal tag instead of attempting a conversion.
    char type_buf[64];
    snprintf(type_buf, sizeof(type_buf), "cf_type_id:%lu", (unsigned long)type_id);
    json_escape_and_write(out, type_buf);
}

int main(void) {
    const char *keys[] = {
        "com.apple.private.security.message-filter",
        "com.apple.private.security.message-filter-manager",
    };

    SecTaskRef task = SecTaskCreateFromSelf(NULL);
    if (!task) {
        fputs("{\"error\":\"SecTaskCreateFromSelf_failed\"}\n", stdout);
        return 1;
    }

    CFStringRef signing_id = SecTaskCopySigningIdentifier(task, NULL);

    FILE *out = stdout;
    fputs("{", out);
    fputs("\"schema_version\":\"1.0\"", out);
    fprintf(out, ",\"pid\":%ld", (long)getpid());

    if (signing_id) {
        char signing_buf[4096];
        const char *s = cfstring_to_utf8(signing_id, signing_buf, sizeof(signing_buf));
        if (s) {
            fputs(",\"signing_identifier\":", out);
            json_escape_and_write(out, s);
        }
    }

    fputs(",\"entitlements\":{", out);
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *key = keys[i];
        if (i > 0) {
            fputc(',', out);
        }
        json_escape_and_write(out, key);
        fputc(':', out);

        CFStringRef key_cf = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
        if (!key_cf) {
            fputs("null", out);
            continue;
        }
        CFTypeRef value = SecTaskCopyValueForEntitlement(task, key_cf, NULL);
        CFRelease(key_cf);

        json_write_cf_type(out, value);
        if (value) {
            CFRelease(value);
        }
    }
    fputs("}", out);

    fputs("}\n", out);
    fflush(out);

    if (signing_id) {
        CFRelease(signing_id);
    }
    CFRelease(task);
    return 0;
}

