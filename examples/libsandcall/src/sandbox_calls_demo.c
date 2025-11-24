#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Private libsandbox interfaces (not declared in public headers)
struct sandbox_profile {
  uint32_t profile_type;
  uint32_t reserved;
  const void *bytecode;
  size_t bytecode_length;
};

extern struct sandbox_profile *sandbox_compile_string(const char *profile,
                                                      uint64_t flags,
                                                      char **errorbuf);
extern void sandbox_free_profile(struct sandbox_profile *profile);
extern int sandbox_apply(struct sandbox_profile *profile);

static void hex_preview(const void *data, size_t len) {
  const unsigned char *b = (const unsigned char *)data;
  size_t preview = len < 32 ? len : 32;
  printf("  first %zu bytes:", preview);
  for (size_t i = 0; i < preview; ++i) {
    if (i % 8 == 0) printf(" ");
    printf("%02x", b[i]);
  }
  printf("\n");
}

int main(void) {
  const char *profile_src =
      "(version 1)\n"
      "(deny default)\n"
      "(allow process*)\n"
      "(allow file-read* (subpath \"/System\"))\n";

  char *error = NULL;
  struct sandbox_profile *p = sandbox_compile_string(profile_src, 0, &error);
  if (p == NULL) {
    fprintf(stderr, "[-] sandbox_compile_string failed: %s\n",
            error ? error : "unknown error");
    free(error);
    return 1;
  }

  printf("[+] compiled inline SBPL\n");
  printf("  profile_type: %" PRIu32 "\n", p->profile_type);
  printf("  bytecode length: %zu bytes\n", p->bytecode_length);
  hex_preview(p->bytecode, p->bytecode_length);

  // Demonstrate that sandbox_apply is present but may be blocked by SIP/entitlements.
  int rv = sandbox_apply(p);
  if (rv != 0) {
    printf("[!] sandbox_apply returned %d (errno=%d: %s)\n", rv, errno,
           strerror(errno));
    printf("    On modern macOS this is expected without the right entitlements.\n");
  } else {
    printf("[+] sandbox_apply succeeded (sandbox now active for this process)\n");
  }

  sandbox_free_profile(p);
  free(error);
  return 0;
}
