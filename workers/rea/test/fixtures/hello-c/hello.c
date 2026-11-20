/* Test fixture for pathos-rea (not shipped). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* AWS's documented example key: the analyser must redact it. */
static const char *aws_key = "AKIAIOSFODNN7EXAMPLE";
static const char *endpoint = "https://api.example.com/v1/health";

static int checksum(const char *s) {
	int c = 0;
	for (size_t i = 0; i < strlen(s); i++) {
		c += s[i];
	}
	return c;
}

static void greet(const char *name) {
	printf("hello, %s (%d)\n", name, checksum(name));
}

int main(int argc, char **argv) {
	greet(argc > 1 ? argv[1] : "world");
	if (getenv("PATHOS_FIXTURE_DEBUG") != NULL) {
		puts(endpoint);
		puts(aws_key);
	}
	return 0;
}
