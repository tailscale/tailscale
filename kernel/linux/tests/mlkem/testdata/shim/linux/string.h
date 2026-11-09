#include <string.h>
static inline void memzero_explicit(void *p, size_t n) { explicit_bzero(p, n); }
