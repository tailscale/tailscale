// SPDX-License-Identifier: GPL-2.0
// Probe for <linux/skbuff_ref.h> (6.11), where skb_frag_ref moved.
#include <linux/skbuff_ref.h>

static void __maybe_unused probe(struct sk_buff *skb)
{
	skb_frag_ref(skb, 0);
}
