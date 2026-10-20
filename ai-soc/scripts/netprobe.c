#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 64;
    int family = strchr(argv[1], ':') == NULL ? AF_INET : AF_INET6;
    int fd = syscall(SYS_socket, family, SOCK_STREAM, 0);
    if (fd < 0) return 65;
    int result = -1;
    if (family == AF_INET) {
        struct sockaddr_in address = {.sin_family = AF_INET,
                                      .sin_port = htons((unsigned short)atoi(argv[2]))};
        if (inet_pton(family, argv[1], &address.sin_addr) != 1) return 66;
        result = syscall(SYS_connect, fd, &address, sizeof(address));
    } else {
        struct sockaddr_in6 address = {.sin6_family = AF_INET6,
                                       .sin6_port = htons((unsigned short)atoi(argv[2]))};
        if (inet_pton(family, argv[1], &address.sin6_addr) != 1) return 66;
        result = syscall(SYS_connect, fd, &address, sizeof(address));
    }
    int error = errno;
    close(fd);
    if (result == 0) {
        puts("unexpectedly connected");
        return 0;
    }
    printf("direct syscall denied errno=%d\n", error);
    return 10;
}
