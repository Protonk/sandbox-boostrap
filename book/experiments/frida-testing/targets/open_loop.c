#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *path = (argc > 1) ? argv[1] : "/etc/hosts";
  for (;;) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "open(%s) -> -1 errno=%d (%s)\n", path, errno, strerror(errno));
    } else {
      close(fd);
    }
    usleep(200 * 1000);
  }
}
