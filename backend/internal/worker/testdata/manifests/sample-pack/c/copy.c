/* Deliberately vulnerable sample for the worker-sast fixture tests. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(const char *name) {
    char buf[16];
    strcpy(buf, name);
    printf(buf);
}

int sum(void) {
    int values[4] = {1, 2, 3, 4};
    int total = 0;
    for (int i = 0; i <= 4; i++) {
        total += values[i];
    }
    return total;
}

char *leak(size_t n) {
    char *p = malloc(n);
    char *q = malloc(n);
    if (p == NULL) {
        return NULL;
    }
    sprintf(p, "%s", "sample");
    return p;
}

int main(int argc, char **argv) {
    char line[64];
    if (argc > 1) {
        greet(argv[1]);
    }
    gets(line);
    system(line);
    return sum();
}
