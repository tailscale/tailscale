#include <linux/types.h>
static inline unsigned long crypto_memneq(const void *a, const void *b, size_t n)
{
	const u8 *x = a, *y = b;
	unsigned long r = 0;
	while (n--)
		r |= *x++ ^ *y++;
	return r;
}
