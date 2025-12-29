/*
 * compile_profile.c — libsandbox SBPL compiler probe (Sonoma baseline)
 *
 * Purpose
 * - Minimal reference implementation for “SBPL file -> compiled blob bytes”
 *   using libsandbox’s private compiler entry point `sandbox_compile_file`.
 * - This is *structural tooling*, not a semantic policy interpreter.
 *
 * Preferred surface
 * - Most callers should use the Python API: `book.api.profile.compile`.
 * - This C program exists as a sanity probe and a second implementation of the
 *   same private interface for debugging.
 *
 * Baseline scoping
 * - This repo is host-bound. All assumptions here are scoped to:
 *   `book/world/sonoma-14.4.1-23E224-arm64/world.json`.
 *
 * Build/run
 * - `make -C book/api/profile/c`
 * - `book/api/profile/c/build/compile_profile <in.sb> <out.sb.bin>`
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Private libsandbox interfaces.
//
// `struct sandbox_profile` and the `sandbox_compile_*` APIs are not public macOS
// SDK APIs. They are private entry points used by Apple’s tooling and are
// expected to be stable only within the constraints of this repo’s pinned host
// baseline.
struct sandbox_profile {
  uint32_t profile_type;
  uint32_t reserved;
  const void *bytecode;
  size_t bytecode_length;
};

extern struct sandbox_profile *sandbox_compile_file(const char *path,
                                                    void *params,
                                                    char **errorbuf);
extern void sandbox_free_profile(struct sandbox_profile *profile);

static int write_bytes(const char *path, const void *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    fprintf(stderr, "[-] fopen %s failed: %s\n", path, strerror(errno));
    return -1;
  }
  if (fwrite(data, 1, len, f) != len) {
    fprintf(stderr, "[-] fwrite %s failed: %s\n", path, strerror(errno));
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

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

int main(int argc, char *argv[]) {
  const char *in = "demo.sb";
  const char *out = "demo.sb.bin";

  if (argc == 2 && strcmp(argv[1], "--help") == 0) {
    fprintf(stderr,
            "usage: %s [in.sb] [out.sb.bin]\n"
            "  default in: %s\n"
            "  default out: %s\n\n"
            "Compiles SBPL using libsandbox’s TinyScheme front end and writes the\n"
            "compiled policy blob.\n",
            argv[0], in, out);
    return 1;
  }

  if (argc >= 2) in = argv[1];
  if (argc >= 3) out = argv[2];

  char *error = NULL;
  // `error` is a `char **` out-parameter; on failure libsandbox may set it to a
  // malloc-owned string. We free it with `free(3)` below.
  struct sandbox_profile *p = sandbox_compile_file(in, NULL, &error);
  if (p == NULL) {
    fprintf(stderr, "[-] sandbox_compile_file failed: %s\n",
            error ? error : "unknown error");
    free(error);
    return 1;
  }

  printf("[+] compiled %s\n", in);
  printf("  profile_type: %" PRIu32 "\n", p->profile_type);
  printf("  bytecode length: %zu bytes\n", p->bytecode_length);
  hex_preview(p->bytecode, p->bytecode_length);

  if (write_bytes(out, p->bytecode, p->bytecode_length) == 0) {
    printf("[+] wrote compiled profile to %s\n", out);
  }

  // Ownership: always free the profile struct after copying/writing out bytes.
  sandbox_free_profile(p);
  free(error);
  return 0;
}
