#include <stdlib.h>
#include <sys/random.h>
static inline void get_random_bytes(void *p, size_t n)
{
	if (getrandom(p, n, 0) != (ssize_t)n)
		abort();
}
