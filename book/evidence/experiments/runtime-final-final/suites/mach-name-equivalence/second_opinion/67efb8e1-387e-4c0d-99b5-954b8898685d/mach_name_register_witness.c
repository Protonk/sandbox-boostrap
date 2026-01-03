#include <errno.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                       const char *const parameters[], char **errorbuf);
extern void sandbox_free_error(char *errorbuf);

static int apply_profile_for(const char *aa) {
  char profile[512];
  snprintf(profile, sizeof(profile),
           "(version 1)\n"
           "(deny default)\n"
           "(allow mach-bootstrap)\n"
           "(allow mach-task-special-port-get)\n"
           "(allow mach-register (global-name \"%s\"))\n",
           aa);

  const char *params[] = { NULL };
  char *err = NULL;
  int rc = sandbox_init_with_parameters(profile, /* SANDBOX_STRING */ 0x0000, params, &err);
  if (rc != 0) {
    fprintf(stderr, "sandbox_init_with_parameters failed rc=%d err=%s\n",
            rc, err ? err : "(null)");
    if (err) sandbox_free_error(err);
    return rc;
  }
  if (err) sandbox_free_error(err);
  return 0;
}

static void print_kr(const char *label, kern_return_t kr) {
  const char *msg = bootstrap_strerror(kr);
  printf("%s kr=%d (%s)\n", label, kr, msg ? msg : "(null)");
}

static void do_register(const char *name) {
  name_t service_name = {0};
  if (strlen(name) >= sizeof(service_name)) {
    fprintf(stderr, "name too long: %s\n", name);
    return;
  }
  snprintf(service_name, sizeof(service_name), "%s", name);

  mach_port_t port = MACH_PORT_NULL;
  kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (kr != KERN_SUCCESS) {
    print_kr("mach_port_allocate", kr);
    return;
  }

  kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  if (kr != KERN_SUCCESS) {
    print_kr("mach_port_insert_right", kr);
    mach_port_deallocate(mach_task_self(), port);
    return;
  }

  kr = bootstrap_register(bootstrap_port, service_name, port);
  printf("bootstrap_register name=\"%s\" ", name);
  print_kr("", kr);

  mach_port_deallocate(mach_task_self(), port);
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s <sandbox|nosandbox>\n", prog);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    usage(argv[0]);
    return 64;
  }

  const char *mode = argv[1];
  const char *aa = "com.sandboxlore.registerwitness";
  char bb[256];
  snprintf(bb, sizeof(bb), "%s.%d", aa, (int)getpid());

  if (strcmp(mode, "sandbox") == 0) {
    int rc = apply_profile_for(aa);
    if (rc != 0) {
      return rc;
    }
  } else if (strcmp(mode, "nosandbox") != 0) {
    usage(argv[0]);
    return 64;
  }

  printf("mode=%s pid=%d\n", mode, (int)getpid());
  printf("AA=%s\n", aa);
  printf("BB=%s\n", bb);

  do_register(aa);
  do_register(bb);

  return 0;
}
