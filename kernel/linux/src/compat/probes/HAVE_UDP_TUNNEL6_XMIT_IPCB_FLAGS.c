// SPDX-License-Identifier: GPL-2.0
// Probe for the ip6cb_flags argument to udp_tunnel6_xmit_skb().
#include <net/udp_tunnel.h>

static void __maybe_unused probe(struct dst_entry *dst, struct sock *sk,
				  struct sk_buff *skb, struct net_device *dev,
				  struct in6_addr *a)
{
	udp_tunnel6_xmit_skb(dst, sk, skb, dev, a, a, 0, 0, 0, 0, 0, false, 0);
}
