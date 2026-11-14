#include <linux/types.h>
static inline u64 rol64(u64 w, unsigned int s) { return w << s | w >> ((64 - s) & 63); }
