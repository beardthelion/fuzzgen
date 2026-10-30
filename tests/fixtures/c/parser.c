#include <stdint.h>
#include <stddef.h>

int parse(const uint8_t *buf, size_t len) { return (int)len; }

void reset(void) {}

int parse_weird(double x) { return (int)x; }
