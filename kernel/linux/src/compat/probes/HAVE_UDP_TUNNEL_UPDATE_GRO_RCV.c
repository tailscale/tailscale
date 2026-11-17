// SPDX-License-Identifier: GPL-2.0
// Probe for udp_tunnel_update_gro_rcv() (6.15), with which
// setup_udp_tunnel_sock may make a socket's gro_receive a static call.
#include <net/udp_tunnel.h>

static void __maybe_unused probe(struct sock *sk)
{
	udp_tunnel_update_gro_rcv(sk, false);
}
