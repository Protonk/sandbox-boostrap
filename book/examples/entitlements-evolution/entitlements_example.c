#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <stdio.h>
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

int main(void) {
    char exec_path[PROC_PIDPATHINFO_MAX] = {0};
    if (proc_pidpath(getpid(), exec_path, sizeof(exec_path)) <= 0) {
        strncpy(exec_path, "<unknown>", sizeof(exec_path) - 1);
    }

    printf("Seatbelt entitlement probe\n");
    printf("PID: %d\n", getpid());
    printf("Executable: %s\n\n", exec_path);

    // Seatbelt and SBPL can test entitlements/signing metadata via filters
    // like (entitlement-is-present ...) or (signing-identifier ...).
    // Those predicates are evaluated against the code signature, not against
    // anything this process does at runtime (see substrate/Appendix.md).

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
    print_cfstring("Signing identifier", identifier);

    // Entitlements are embedded in the code signature. At runtime the sandbox
    // sees them as metadata inputs; the binary is identical whether or not it
    // was signed with a specific entitlement payload.
    CFDictionaryRef entitlements = (CFDictionaryRef)CFDictionaryGetValue(signing_info, kSecCodeInfoEntitlementsDict);
    if (!entitlements) {
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
