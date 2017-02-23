#include "libc.h"
#include <unistd.h>

int transmit_all(int fd, const char *buf, const size_t size) {
    size_t sent = 0;
    size_t sent_now = 0;
    int ret;

    if (!buf) 
        return 1;

    if (!size)
        return 2;

    while (sent < size) {
        sent_now = write(fd, buf + sent, size - sent);
        if (sent_now <= 0) {
            return 3;
        }
        sent += sent_now;
    }

    return 0;
}
