#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

// Network operations surface as sandbox operations like `network-outbound`
// with filters on socket domain/type/remote (book/substrate/Appendix.md). This demo
// performs a few socket types so you can map process-side calls to sandbox
// vocabulary when reasoning about profiles.

static void try_tcp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("TCP socket creation failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    printf("TCP connect to %s:%d -> rc=%d errno=%d (%s)\n", ip, port, rc, errno, strerror(errno));
    close(fd);
}

static void try_udp(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("UDP socket creation failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    const char payload[] = "sandbox network demo";
    ssize_t sent = sendto(fd, payload, sizeof(payload), 0, (struct sockaddr *)&addr, sizeof(addr));
    printf("UDP send to %s:%d -> bytes=%zd errno=%d (%s)\n", ip, port, sent, errno, strerror(errno));
    close(fd);
}

static void try_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("AF_UNIX socket creation failed: errno=%d (%s)\n", errno, strerror(errno));
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    printf("AF_UNIX connect to %s -> rc=%d errno=%d (%s)\n", path, rc, errno, strerror(errno));
    close(fd);
}

int main(void) {
    printf("Network filter probes (PID %d)\n\n", getpid());
    printf("Each call maps to `network-outbound` with filters like socket-domain/type/remote.\n");

    try_tcp("127.0.0.1", 80);     // likely ECONNREFUSED unless a server is listening
    try_udp("127.0.0.1", 5353);   // mDNS port; sendto may succeed silently
    try_unix("/var/run/syslog");  // illustrates AF_UNIX addressing

    printf("\nIf you apply a sandbox profile later, watch how rules on domain/type/remote\n");
    printf("affect these calls without changing the process-side code.\n");
    return 0;
}
