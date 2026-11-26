/* board.c -- a board under tests/probes/bare.cho, so that the object built for `aarch64-none-elf` can be run.
 *
 * The object is the package as a kernel links it: no libc, the heap between two symbols, four foreign functions for
 * the drivers. Here those four are a TCP connection, the kernel's random numbers and a file of keys, and the result
 * is an AArch64 Linux process (`scripts/bare_run.py` runs it under qemu and logs in with a real client). This file
 * stands for hardware and is not part of the package.
 *
 *   BOARD_PORT   the port to accept one connection on, at 127.0.0.1
 *   BOARD_KEYS   a file of 96 bytes: the host key's seed, its public key, and the one key that may log in
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

/* The heap of the link script: 8 MiB between the two symbols the bare runtime reads. */
__asm__(".bss\n.balign 4096\n.global __cancho_heap_start\n__cancho_heap_start:\n.skip 8388608\n"
        ".global __cancho_heap_end\n__cancho_heap_end:\n.text\n");

static int conn = -1;
static int keys = -1;

static void say(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    if (write(1, s, n) < 0) _exit(70);
}

__attribute__((constructor)) static void board_up(void) {
    const char *port = getenv("BOARD_PORT");
    const char *path = getenv("BOARD_KEYS");
    if (!port || !path) { say("board: BOARD_PORT and BOARD_KEYS\n"); _exit(64); }
    keys = open(path, O_RDONLY);
    int l = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)atoi(port));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (keys < 0 || l < 0 || bind(l, (struct sockaddr *)&a, sizeof a) < 0 || listen(l, 1) < 0) { say("board: cannot start\n"); _exit(69); }
    say("listening\n");
    conn = accept(l, 0, 0);
    if (conn < 0) _exit(69);
    setsockopt(conn, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    close(l);
}

/* What arrived, at least one byte. The end of the connection ends the process: a kernel's TCP would say so. */
long board_receive(unsigned char *into, long n) {
    long got = read(conn, into, (size_t)n);
    if (got <= 0) _exit(got == 0 ? 0 : 71);
    return got;
}

long board_send(const unsigned char *data, long n) {
    long sent = write(conn, data, (size_t)n);
    if (sent < 0) _exit(72);
    return sent;
}

long board_random(unsigned char *into, long n) {
    if (getrandom(into, (size_t)n, 0) != n) _exit(73);
    return n;
}

/* The next 32 bytes of the key file. */
long board_key(unsigned char *into, long n) {
    if (read(keys, into, (size_t)n) != n) _exit(74);
    return n;
}
