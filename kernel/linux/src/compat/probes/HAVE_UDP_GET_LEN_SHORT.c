// SPDX-License-Identifier: GPL-2.0
// Probe for udp_get_len_short() (7.4).
#include <linux/udp.h>

static unsigned int __maybe_unused probe(const struct udphdr *uh)
{
	return udp_get_len_short(uh);
}
