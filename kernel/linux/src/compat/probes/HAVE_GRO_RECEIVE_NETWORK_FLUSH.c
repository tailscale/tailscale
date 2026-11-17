// SPDX-License-Identifier: GPL-2.0
// Probe for gro_receive_network_flush() (6.10). Before it, inet_gro_receive
// and ipv6_gro_receive set NAPI_GRO_CB(p)->flush for network header changes.
#include <net/gro.h>

static int __maybe_unused probe(const void *th, const void *th2,
				struct sk_buff *p)
{
	return gro_receive_network_flush(th, th2, p);
}
