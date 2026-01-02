// sandbox_target.c
// A small deterministic workload to exercise Seatbelt rule generation.
//
// Required operations:
//   - read /etc/hosts
//   - sysctlbyname("kern.ostype")
//   - getpwuid(getuid())
//   - mkdir("./out") and write "./out/hello.txt"
//
// Optional (noise) operations:
//   - attempt TCP connect to 127.0.0.1:2000 (ignored if fails)
//
// Exit code:
//   - 0 only if all required operations succeeded.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>

static int required_ok = 1;

static void require_(int cond, const char* what) {
  if (!cond) {
    required_ok = 0;
    fprintf(stderr, "[required] %s FAILED: %s\n", what, strerror(errno));
  } else {
    fprintf(stderr, "[required] %s OK\n", what);
  }
}

static void optional_(int cond, const char* what) {
  if (!cond) {
    fprintf(stderr, "[optional] %s failed (ignored): %s\n", what, strerror(errno));
  } else {
    fprintf(stderr, "[optional] %s OK\n", what);
  }
}

int main(void) {
  // Required: read /etc/hosts
  int fd = open("/etc/hosts", O_RDONLY);
  require_(fd >= 0, "open(/etc/hosts)");
  if (fd >= 0) {
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    require_(n >= 0, "read(/etc/hosts)");
    close(fd);
  }

  // Required: sysctlbyname kern.ostype
  char ostype[256];
  size_t ostype_len = sizeof(ostype);
  int rc = sysctlbyname("kern.ostype", ostype, &ostype_len, NULL, 0);
  require_(rc == 0, "sysctlbyname(kern.ostype)");

  // Required: getpwuid -> often triggers service lookups
  errno = 0;
  struct passwd* pw = getpwuid(getuid());
  require_(pw != NULL, "getpwuid(getuid())");
  if (pw != NULL) {
    fprintf(stderr, "[required] username=%s\n", pw->pw_name);
  }

  // Required: mkdir ./out
  rc = mkdir("out", 0700);
  if (rc != 0 && errno == EEXIST) rc = 0;
  require_(rc == 0, "mkdir(out)");

  // Required: write ./out/hello.txt
  int ofd = open("out/hello.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
  require_(ofd >= 0, "open(out/hello.txt for write)");
  if (ofd >= 0) {
    const char* msg = "hello from sandbox_target\n";
    ssize_t wn = write(ofd, msg, strlen(msg));
    require_(wn == (ssize_t)strlen(msg), "write(out/hello.txt)");
    close(ofd);
  }

  // Optional noise: local connect attempt (ignored if denied/refused)
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s >= 0) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2000);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    rc = connect(s, (struct sockaddr*)&addr, sizeof(addr));
    optional_(rc == 0, "connect(127.0.0.1:2000)");
    close(s);
  } else {
    optional_(0, "socket(AF_INET,SOCK_STREAM)");
  }

  return required_ok ? 0 : 1;
}
