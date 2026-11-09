// SPDX-License-Identifier: GPL-2.0
// Probe for the ipcb_flags argument to udp_tunnel_xmit_skb().
#include <net/udp_tunnel.h>

static void __maybe_unused probe(struct rtable *rt, struct sock *sk,
				  struct sk_buff *skb)
{
	udp_tunnel_xmit_skb(rt, sk, skb, 0, 0, 0, 0, 0, 0, 0, false, false, 0);
}
