// SPDX-License-Identifier: GPL-2.0
// Probe for skb_frags_readable() (6.12, for devmem TCP).
#include <linux/skbuff.h>

static bool __maybe_unused probe(const struct sk_buff *skb)
{
	return skb_frags_readable(skb);
}
