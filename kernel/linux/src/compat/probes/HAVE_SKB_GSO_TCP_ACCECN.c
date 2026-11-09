// SPDX-License-Identifier: GPL-2.0
// Probe for SKB_GSO_TCP_ACCECN, for GSO packets of AccECN TCP flows.
#include <linux/skbuff.h>

static int __maybe_unused probe(void)
{
	return SKB_GSO_TCP_ACCECN;
}
