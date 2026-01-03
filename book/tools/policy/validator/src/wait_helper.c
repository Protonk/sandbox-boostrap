#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

volatile sig_atomic_t running = 1;

void handle_sigint(int sig) {
    running = 0;
}

int main() {
    printf("PID: %d\n", getpid());
    printf("Press Ctrl+C to exit.\n");
    int fd3 = open("/tmp/test1.txt", O_RDWR | O_CREAT, 0644);  // FD 3 for testing Filter ID 10
    signal(SIGINT, handle_sigint);
    
    while (running) {
        sleep(1);
    }
    
    printf("\nExiting...\n");
    
    return 0;
}
