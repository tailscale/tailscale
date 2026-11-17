#include <stdlib.h>
#define GFP_KERNEL 0
static inline void *kmalloc(size_t n, int flags) { return malloc(n); }
static inline void kfree_sensitive(void *p) { free(p); }
