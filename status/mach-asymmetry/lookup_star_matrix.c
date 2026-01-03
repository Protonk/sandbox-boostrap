#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum sandbox_filter_type { SANDBOX_FILTER_GLOBAL_NAME = 2 };

extern int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                       const char *const parameters[], char **errorbuf);
extern void sandbox_free_error(char *errorbuf);

static int apply_profile(const char *profile) {
  const char *params[] = { NULL };
  char *err = NULL;
  int rc = sandbox_init_with_parameters(profile, 0x0000, params, &err);
  if (rc != 0) {
    fprintf(stderr, "sandbox_init_with_parameters failed rc=%d err=%s\n",
            rc, err ? err : "(null)");
    if (err) sandbox_free_error(err);
    return rc;
  }
  if (err) sandbox_free_error(err);
  return 0;
}

static void check_name(const char *name) {
  errno = 0;
  int rc = sandbox_check(getpid(), "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME, name);
  printf("mach-lookup name=\"%s\" rc=%d errno=%d\n", name, rc, errno);
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s <exact|prefix>\n", prog);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage(argv[0]);
    return 64;
  }

  const char *mode = argv[1];
  const char *aa = "com.sandboxlore.rendezvous";
  char bb[256];
  char star[256];

  snprintf(bb, sizeof(bb), "%s.%d", aa, (int)getpid());
  snprintf(star, sizeof(star), "%s*", aa);

  char profile[512];
  if (strcmp(mode, "exact") == 0) {
    snprintf(profile, sizeof(profile),
             "(version 1)\n"
             "(allow default)\n"
             "(deny mach-lookup)\n"
             "(allow mach-lookup (global-name \"%s\"))\n",
             star);
  } else if (strcmp(mode, "prefix") == 0) {
    snprintf(profile, sizeof(profile),
             "(version 1)\n"
             "(allow default)\n"
             "(deny mach-lookup)\n"
             "(allow mach-lookup (global-name-prefix \"%s\"))\n",
             aa);
  } else {
    usage(argv[0]);
    return 64;
  }

  if (apply_profile(profile) != 0) {
    return 2;
  }

  printf("mode=%s pid=%d\n", mode, (int)getpid());
  printf("AA=%s\n", aa);
  printf("AA_star=%s\n", star);
  printf("BB=%s\n", bb);
  check_name(aa);
  check_name(star);
  check_name(bb);

  return 0;
}
