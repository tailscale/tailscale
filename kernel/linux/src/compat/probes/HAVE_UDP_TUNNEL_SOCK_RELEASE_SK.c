// SPDX-License-Identifier: GPL-2.0
// Probe for udp_tunnel_sock_release() taking a struct sock (7.4).
#include <net/udp_tunnel.h>

static void __maybe_unused probe(struct sock *sk)
{
	udp_tunnel_sock_release(sk);
}
