// sandbox_spawn.c
// Required subprocess workload: spawn /usr/bin/id and require exit 0.

#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

int main(void) {
  pid_t pid = 0;
  char *argv[] = {"/usr/bin/id", NULL};
  int rc = posix_spawn(&pid, "/usr/bin/id", NULL, NULL, argv, environ);
  if (rc != 0) {
    fprintf(stderr, "[required] posix_spawn(/usr/bin/id) FAILED: %s\n", strerror(rc));
    return 1;
  }
  int status = 0;
  if (waitpid(pid, &status, 0) < 0) {
    fprintf(stderr, "[required] waitpid FAILED: %s\n", strerror(errno));
    return 1;
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    fprintf(stderr, "[required] /usr/bin/id OK\n");
    return 0;
  }
  fprintf(stderr, "[required] /usr/bin/id FAILED: status=%d\n", status);
  return 1;
}
