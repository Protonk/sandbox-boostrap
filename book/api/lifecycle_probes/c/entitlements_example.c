#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Tiny helper to print CFString values as UTF-8 C strings.
static void print_cfstring(const char *label, CFStringRef str) {
    if (!str) {
        printf("%s: <none>\n", label);
        return;
    }
    char buffer[256];
    if (CFStringGetCString(str, buffer, sizeof(buffer), kCFStringEncodingUTF8)) {
        printf("%s: %s\n", label, buffer);
    } else {
        printf("%s: <unprintable CFString>\n", label);
    }
}

static void json_print_string(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') {
            putchar('\\');
            putchar(c);
        } else if (c == '\n') {
            fputs("\\n", stdout);
        } else if (c == '\r') {
            fputs("\\r", stdout);
        } else if (c == '\t') {
            fputs("\\t", stdout);
        } else if (c < 0x20) {
            printf("\\u%04x", c);
        } else {
            putchar(c);
        }
    }
    putchar('"');
}

static void cfstring_to_cstr(CFStringRef str, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (!str) {
        return;
    }
    if (!CFStringGetCString(str, out, (CFIndex)out_len, kCFStringEncodingUTF8)) {
        strncpy(out, "<unprintable CFString>", out_len - 1);
        out[out_len - 1] = '\0';
    }
}

int main(int argc, char **argv) {
    bool json_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json_mode = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "usage: %s [--json]\n", argv[0]);
            return 64;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 64;
        }
    }

    long path_max = proc_pidpath(getpid(), NULL, 0);
    size_t buf_len = (path_max > 0 && path_max < 4096) ? (size_t)path_max : 4096;
    char exec_path[4096];
    if (proc_pidpath(getpid(), exec_path, buf_len) <= 0) {
        strncpy(exec_path, "<unknown>", buf_len - 1);
    }

    // Seatbelt and SBPL can test entitlements/signing metadata via filters
    // like (entitlement-is-present ...) or (signing-identifier ...).
    // Those predicates are evaluated against the code signature, not against
    // anything this process does at runtime (see book/substrate/Appendix.md).

    SecCodeRef self_code = NULL;
    OSStatus status = SecCodeCopySelf(kSecCSDefaultFlags, &self_code);
    if (status != errSecSuccess) {
        fprintf(stderr, "SecCodeCopySelf failed: %d\n", (int)status);
        return 1;
    }

    CFDictionaryRef signing_info = NULL;
    status = SecCodeCopySigningInformation(self_code, kSecCSSigningInformation, &signing_info);
    if (status != errSecSuccess || !signing_info) {
        fprintf(stderr, "SecCodeCopySigningInformation failed: %d\n", (int)status);
        CFRelease(self_code);
        return 1;
    }

    // Print the signing identifier if present; SBPL can filter on this string.
    CFStringRef identifier = (CFStringRef)CFDictionaryGetValue(signing_info, kSecCodeInfoIdentifier);
    char identifier_c[256];
    cfstring_to_cstr(identifier, identifier_c, sizeof(identifier_c));

    // Entitlements are embedded in the code signature. At runtime the sandbox
    // sees them as metadata inputs; the binary is identical whether or not it
    // was signed with a specific entitlement payload.
    CFDictionaryRef entitlements = (CFDictionaryRef)CFDictionaryGetValue(signing_info, kSecCodeInfoEntitlementsDict);
    bool entitlements_present = entitlements != NULL;

    if (json_mode) {
        printf("{\"pid\":%d,\"executable\":", getpid());
        json_print_string(exec_path);
        printf(",\"signing_identifier\":");
        json_print_string(identifier_c[0] ? identifier_c : "<none>");
        printf(",\"entitlements_present\":%s}\n", entitlements_present ? "true" : "false");
        CFRelease(signing_info);
        CFRelease(self_code);
        return 0;
    }

    printf("Seatbelt entitlement probe\n");
    printf("PID: %d\n", getpid());
    printf("Executable: %s\n\n", exec_path);
    print_cfstring("Signing identifier", identifier);

    if (!entitlements_present) {
        printf("Entitlements present: no (run a signed build to compare)\n");
    } else {
        printf("Entitlements present: yes\n");
        CFErrorRef error = NULL;
        CFDataRef plist_data = CFPropertyListCreateData(
            kCFAllocatorDefault, entitlements, kCFPropertyListXMLFormat_v1_0, 0, &error);
        if (!plist_data) {
            char desc[256] = "<unknown>";
            if (error) {
                CFStringRef err_str = CFErrorCopyDescription(error);
                if (err_str) {
                    CFStringGetCString(err_str, desc, sizeof(desc), kCFStringEncodingUTF8);
                    CFRelease(err_str);
                }
            }
            fprintf(stderr, "Failed to serialize entitlements: %s\n", desc);
        } else {
            printf("Entitlements (XML plist):\n");
            fwrite(CFDataGetBytePtr(plist_data), 1, CFDataGetLength(plist_data), stdout);
            printf("\n");
            CFRelease(plist_data);
        }
        if (error) {
            CFRelease(error);
        }
    }

    // Clean up CoreFoundation objects.
    CFRelease(signing_info);
    CFRelease(self_code);

    printf("\nRe-run this binary with different signatures/entitlements to see how\n");
    printf("the metadata changes even though the compiled code stays identical.\n");
    printf("Seatbelt filters in the platform/App Sandbox profiles use that metadata\n");
    printf("as inputs when evaluating operations.\n");
    return 0;
}
