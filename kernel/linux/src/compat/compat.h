/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compatibility shims that let the fork, which tracks the newest upstream
 * WireGuard, build against older kernels. Kbuild force-includes this file
 * before every source file.
 *
 * Each shim is keyed on a HAVE_* macro from generated/autoconf.h, which
 * scripts/probe.sh produces by compile-testing src/compat/probes/HAVE_*.c
 * against the target kernel. Shims that wrap a kernel function under its
 * own name include the kernel header first, so the macro doesn't rewrite
 * the kernel's own declaration.
 */

#ifndef _TSWG_COMPAT_H
#define _TSWG_COMPAT_H

#include "generated/autoconf.h"

#include <linux/kconfig.h>
#include <linux/types.h>

#ifndef HAVE_UDP_GET_LEN_SHORT
#include <linux/udp.h>
static inline unsigned int udp_get_len_short(const struct udphdr *uh)
{
	return ntohs(uh->len);
}
#endif

#if !defined(HAVE_SETUP_UDP_TUNNEL_SOCK_SK) ||		\
	!defined(HAVE_UDP_TUNNEL_SOCK_RELEASE_SK) ||	\
	!defined(HAVE_UDP_TUNNEL_XMIT_IPCB_FLAGS) ||	\
	!defined(HAVE_UDP_TUNNEL6_XMIT_IPCB_FLAGS)
#include <net/udp_tunnel.h>
#endif

#ifndef HAVE_SETUP_UDP_TUNNEL_SOCK_SK
#define setup_udp_tunnel_sock(net, sk, cfg) \
	setup_udp_tunnel_sock(net, (sk)->sk_socket, cfg)
#endif

#ifndef HAVE_UDP_TUNNEL_SOCK_RELEASE_SK
#define udp_tunnel_sock_release(sk) udp_tunnel_sock_release((sk)->sk_socket)
#endif

/* The fork always passes 0 for the (ip|ip6)cb_flags argument. */
#ifndef HAVE_UDP_TUNNEL_XMIT_IPCB_FLAGS
#define udp_tunnel_xmit_skb(rt, sk, skb, src, dst, tos, ttl, df, sport,	\
			    dport, xnet, nocheck, ipcb_flags)		\
	udp_tunnel_xmit_skb(rt, sk, skb, src, dst, tos, ttl, df, sport,	\
			    dport, xnet, nocheck)
#endif

#ifndef HAVE_UDP_TUNNEL6_XMIT_IPCB_FLAGS
#define udp_tunnel6_xmit_skb(dst, sk, skb, dev, saddr, daddr, prio, ttl, \
			     label, sport, dport, nocheck, ip6cb_flags)	 \
	udp_tunnel6_xmit_skb(dst, sk, skb, dev, saddr, daddr, prio, ttl, \
			     label, sport, dport, nocheck)
#endif

#ifndef HAVE_BLAKE2S_CTX
#include <crypto/blake2s.h>
#define blake2s_ctx blake2s_state
static inline void tswg_blake2s(const u8 *key, size_t keylen,
				const u8 *in, size_t inlen,
				u8 *out, size_t outlen)
{
	blake2s(out, in, key, outlen, inlen, keylen);
}
#define blake2s tswg_blake2s
#endif

#ifndef HAVE_WQ_PERCPU
/* Before WQ_PERCPU existed, workqueues without WQ_UNBOUND were per-CPU. */
#define WQ_PERCPU 0
#endif

#ifndef HAVE_NETIF_THREADED_ENABLE
#include <linux/netdevice.h>
/*
 * Older upstream WireGuard didn't enable threaded NAPI, so neither do we on
 * kernels that predate netif_threaded_enable().
 */
static inline void netif_threaded_enable(struct net_device *dev)
{
}
#endif

#ifndef HAVE_RTNL_NEWLINK_PARAMS
#include <net/rtnetlink.h>
/*
 * A minimal stand-in so wg_newlink can keep its upstream signature; see the
 * old-style wrapper in device.c.
 */
struct rtnl_newlink_params {
	struct net *src_net;
};
#endif

#ifndef HAVE_RTNL_NEWLINK_LINK_NET
static inline struct net *rtnl_newlink_link_net(struct rtnl_newlink_params *p)
{
	return p->src_net;
}
#endif

#ifndef HAVE_SOCKADDR_INET
#include <linux/in6.h>
struct sockaddr_inet {
	unsigned short	sa_family;
	char		sa_data[sizeof(struct sockaddr_in6) -
				sizeof(unsigned short)];
};
#endif

#include <linux/slab.h>
#ifndef kmalloc_obj
#define kmalloc_obj(P) kmalloc(sizeof(P), GFP_KERNEL)
#endif
#ifndef kzalloc_obj
#define kzalloc_obj(P) kzalloc(sizeof(P), GFP_KERNEL)
#endif
#ifndef kzalloc_objs
#define kzalloc_objs(P, COUNT) kcalloc(COUNT, sizeof(P), GFP_KERNEL)
#endif
#ifndef kvmalloc_obj
#define kvmalloc_obj(P) kvmalloc(sizeof(P), GFP_KERNEL)
#endif
#ifndef kvzalloc_objs
#define kvzalloc_objs(P, COUNT) kvcalloc(COUNT, sizeof(P), GFP_KERNEL)
#endif

#include <linux/timer.h>
#ifndef timer_container_of
#define timer_container_of(var, callback_timer, timer_fieldname) \
	from_timer(var, callback_timer, timer_fieldname)
#endif

#endif /* _TSWG_COMPAT_H */
