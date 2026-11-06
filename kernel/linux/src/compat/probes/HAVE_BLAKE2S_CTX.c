// SPDX-License-Identifier: GPL-2.0
// Probe for struct blake2s_ctx and the (key, in, out) blake2s() argument order.
#include <crypto/blake2s.h>

static void __maybe_unused probe(const u8 *in, u8 *out)
{
	struct blake2s_ctx ctx;

	blake2s_init(&ctx, BLAKE2S_HASH_SIZE);
	blake2s(NULL, 0, in, 1, out, BLAKE2S_HASH_SIZE);
}
