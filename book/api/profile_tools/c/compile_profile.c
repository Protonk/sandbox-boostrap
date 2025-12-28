#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Private libsandbox interfaces for the fixed baseline recorded in:
// book/world/sonoma-14.4.1-23E224-arm64/world.json.
//
// This file is a minimal reference implementation for "SBPL file -> compiled
// blob" using libsandbox’s private compiler entry points. The canonical Python
// binding lives in `book/api/profile_tools/compile.py`.
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

  sandbox_free_profile(p);
  free(error);
  return 0;
}
