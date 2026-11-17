// SPDX-License-Identifier: GPL-2.0
// Probe for setup_udp_tunnel_sock() taking a struct sock (7.4).
#include <net/udp_tunnel.h>

static void __maybe_unused probe(struct net *net, struct sock *sk,
				  struct udp_tunnel_sock_cfg *cfg)
{
	setup_udp_tunnel_sock(net, sk, cfg);
}
