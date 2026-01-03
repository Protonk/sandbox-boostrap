#include <errno.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum sandbox_filter_type {
  SANDBOX_FILTER_NONE = 0,
  SANDBOX_FILTER_PATH = 1,
  SANDBOX_FILTER_GLOBAL_NAME = 2,
  SANDBOX_FILTER_LOCAL_NAME = 3,
  SANDBOX_FILTER_APPLEEVENT_DESTINATION = 4,
  SANDBOX_FILTER_RIGHT_NAME = 5,
  SANDBOX_FILTER_PREFERENCE_DOMAIN = 6,
  SANDBOX_FILTER_KEXT_BUNDLE_ID = 7,
  SANDBOX_FILTER_INFO_TYPE = 8,
  SANDBOX_FILTER_NOTIFICATION = 9
};

extern int sandbox_check(pid_t pid, const char *operation, enum sandbox_filter_type type, ...);
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                       const char *const parameters[], char **errorbuf);
extern void sandbox_free_error(char *errorbuf);

static int apply_profile(const char *profile) {
  const char *params[] = { NULL };
  char *err = NULL;
  int rc = sandbox_init_with_parameters(profile, /* SANDBOX_STRING */ 0x0000, params, &err);
  if (rc != 0) {
    fprintf(stderr, "sandbox_init_with_parameters failed rc=%d err=%s\n", rc, err ? err : "(null)");
    if (err) sandbox_free_error(err);
    return rc;
  }
  if (err) sandbox_free_error(err);
  return 0;
}

static void do_check(const char *op, const char *name) {
  errno = 0;
  int rc = sandbox_check(getpid(), op, SANDBOX_FILTER_GLOBAL_NAME, name);
  int e = errno;
  printf("sandbox_check op=%s name=\"%s\" rc=%d errno=%d (%s)\n", op, name, rc, e, strerror(e));
}

static void do_bootstrap_lookup(const char *name) {
  mach_port_t bootstrap = MACH_PORT_NULL;
  if (task_get_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, &bootstrap) != KERN_SUCCESS) {
    fprintf(stderr, "task_get_special_port failed\n");
    return;
  }
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t kr = bootstrap_look_up(bootstrap, name, &port);
  if (kr == KERN_SUCCESS) {
    mach_port_deallocate(mach_task_self(), port);
  }
  const char *present = "null";
  if (kr == KERN_SUCCESS) {
    present = "true";
  } else if (kr == BOOTSTRAP_UNKNOWN_SERVICE) {
    present = "false";
  }
  printf("bootstrap_look_up name=\"%s\" kr=%d service_present=%s\n", name, kr, present);
}

static int run_equiv(void) {
  const char *aa = "com.sandboxlore.secondopinion.equiv";
  char bb[256];
  snprintf(bb, sizeof(bb), "%s.%d", aa, (int)getpid());

  char profile[512];
  snprintf(profile, sizeof(profile),
           "(version 1)\n"
           "(deny default)\n"
           "(allow mach-register (global-name \"%s\"))\n"
           "(allow mach-lookup (global-name \"%s\"))\n",
           aa, aa);

  int rc = apply_profile(profile);
  if (rc != 0) {
    return rc;
  }

  printf("mode=equiv pid=%d\n", (int)getpid());
  printf("AA=%s\n", aa);
  printf("BB=%s\n", bb);
  do_check("mach-register", aa);
  do_check("mach-register", bb);
  do_check("mach-lookup", aa);
  do_check("mach-lookup", bb);
  return 0;
}

static int run_lookup(void) {
  char aa[256];
  snprintf(aa, sizeof(aa), "com.sandboxlore.secondopinion.lookup.%d", (int)getpid());

  char profile[512];
  snprintf(profile, sizeof(profile),
           "(version 1)\n"
           "(deny default)\n"
           "(allow mach-lookup (global-name \"%s\"))\n",
           aa);

  int rc = apply_profile(profile);
  if (rc != 0) {
    return rc;
  }

  printf("mode=lookup pid=%d\n", (int)getpid());
  printf("AA=%s\n", aa);
  do_check("mach-lookup", aa);
  do_bootstrap_lookup(aa);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <equiv|lookup>\n", argv[0]);
    return 64;
  }
  if (strcmp(argv[1], "equiv") == 0) {
    return run_equiv();
  }
  if (strcmp(argv[1], "lookup") == 0) {
    return run_lookup();
  }
  fprintf(stderr, "unknown mode: %s\n", argv[1]);
  return 64;
}
