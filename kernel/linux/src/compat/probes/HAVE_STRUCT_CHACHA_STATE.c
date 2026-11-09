// SPDX-License-Identifier: GPL-2.0
// Probe for struct chacha_state (6.17), which replaced passing ChaCha's
// state as a u32 array.
#include <crypto/chacha.h>

static void __maybe_unused probe(struct chacha_state *state, u8 *dst)
{
	chacha20_crypt(state, dst, dst, 1);
}
