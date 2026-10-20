#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);

static connect_fn real_connect = NULL;

__attribute__((constructor)) static void initialize_connect(void) {
    real_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");
}

int connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (real_connect == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (address == NULL || address->sa_family == AF_UNIX) {
        return real_connect(fd, address, length);
    }
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        if (ntohl(ipv4->sin_addr.s_addr) == INADDR_LOOPBACK) {
            return real_connect(fd, address, length);
        }
    }
    if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        struct in_addr mapped_ipv4;
        memcpy(&mapped_ipv4, &ipv6->sin6_addr.s6_addr[12], sizeof(mapped_ipv4));
        if (IN6_IS_ADDR_LOOPBACK(&ipv6->sin6_addr)
            || (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)
                && ntohl(mapped_ipv4.s_addr) == INADDR_LOOPBACK)) {
            return real_connect(fd, address, length);
        }
    }
    errno = ENETUNREACH;
    return -1;
}
