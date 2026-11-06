// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "device.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"
#include "tswg.h"

#include <uapi/linux/tswg.h>

#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <net/udp_tunnel.h>
#include <net/ipv6.h>

static int send4(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache)
{
	struct flowi4 fl = {
		.saddr = endpoint->src4.s_addr,
		.daddr = endpoint->addr4.sin_addr.s_addr,
		.fl4_dport = endpoint->addr4.sin_port,
		.flowi4_mark = wg->fwmark,
		.flowi4_proto = IPPROTO_UDP
	};
	struct rtable *rt = NULL;
	struct sock *sock;
	int ret = 0;

	skb_mark_not_on_list(skb);
	skb->dev = wg->dev;
	skb->mark = wg->fwmark;

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock4);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	fl.fl4_sport = inet_sk(sock)->inet_sport;

	if (cache)
		rt = dst_cache_get_ip4(cache, &fl.saddr);

	if (!rt) {
		security_sk_classify_flow(sock, flowi4_to_flowi_common(&fl));
		if (unlikely(!inet_confirm_addr(sock_net(sock), NULL, 0,
						fl.saddr, RT_SCOPE_HOST))) {
			endpoint->src4.s_addr = 0;
			endpoint->src_if4 = 0;
			fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
		}
		rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		if (unlikely(endpoint->src_if4 && ((IS_ERR(rt) &&
			     PTR_ERR(rt) == -EINVAL) || (!IS_ERR(rt) &&
			     rt->dst.dev->ifindex != endpoint->src_if4)))) {
			endpoint->src4.s_addr = 0;
			endpoint->src_if4 = 0;
			fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
			if (!IS_ERR(rt))
				ip_rt_put(rt);
			rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		}
		if (IS_ERR(rt)) {
			ret = PTR_ERR(rt);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		}
		if (cache)
			dst_cache_set_ip4(cache, &rt->dst, fl.saddr);
	}

	skb->ignore_df = 1;
	udp_tunnel_xmit_skb(rt, sock, skb, fl.saddr, fl.daddr, ds,
			    ip4_dst_hoplimit(&rt->dst), 0, fl.fl4_sport,
			    fl.fl4_dport, false, false, 0);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock_bh();
	return ret;
}

static int send6(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct flowi6 fl = {
		.saddr = endpoint->src6,
		.daddr = endpoint->addr6.sin6_addr,
		.fl6_dport = endpoint->addr6.sin6_port,
		.flowi6_mark = wg->fwmark,
		.flowi6_oif = endpoint->addr6.sin6_scope_id,
		.flowi6_proto = IPPROTO_UDP
		/* TODO: addr->sin6_flowinfo */
	};
	struct dst_entry *dst = NULL;
	struct sock *sock;
	int ret = 0;

	skb_mark_not_on_list(skb);
	skb->dev = wg->dev;
	skb->mark = wg->fwmark;

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock6);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	fl.fl6_sport = inet_sk(sock)->inet_sport;

	if (cache)
		dst = dst_cache_get_ip6(cache, &fl.saddr);

	if (!dst) {
		security_sk_classify_flow(sock, flowi6_to_flowi_common(&fl));
		if (unlikely(!ipv6_addr_any(&fl.saddr) &&
			     !ipv6_chk_addr(sock_net(sock), &fl.saddr, NULL, 0))) {
			endpoint->src6 = fl.saddr = in6addr_any;
			if (cache)
				dst_cache_reset(cache);
		}
		dst = ip6_dst_lookup_flow(sock_net(sock), sock, &fl, NULL);
		if (IS_ERR(dst)) {
			ret = PTR_ERR(dst);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		}
		if (cache)
			dst_cache_set_ip6(cache, dst, &fl.saddr);
	}

	skb->ignore_df = 1;
	udp_tunnel6_xmit_skb(dst, sock, skb, skb->dev, &fl.saddr, &fl.daddr, ds,
			     ip6_dst_hoplimit(dst), 0, fl.fl6_sport,
			     fl.fl6_dport, false, 0);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock_bh();
	return ret;
#else
	kfree_skb(skb);
	return -EAFNOSUPPORT;
#endif
}

int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb, u8 ds)
{
	size_t skb_len = skb->len;
	int ret = -EAFNOSUPPORT;

	read_lock_bh(&peer->endpoint_lock);
	if (peer->endpoint.addr.sa_family == AF_INET)
		ret = send4(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache);
	else if (peer->endpoint.addr.sa_family == AF_INET6)
		ret = send6(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache);
	else
		dev_kfree_skb(skb);
	if (likely(!ret))
		peer->tx_bytes += skb_len;
	read_unlock_bh(&peer->endpoint_lock);

	return ret;
}

int wg_socket_send_buffer_to_peer(struct wg_peer *peer, void *buffer,
				  size_t len, u8 ds)
{
	struct sk_buff *skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);

	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);
	skb_put_data(skb, buffer, len);
	return wg_socket_send_skb_to_peer(peer, skb, ds);
}

int wg_socket_send_buffer_as_reply_to_skb(struct wg_device *wg,
					  struct sk_buff *in_skb, void *buffer,
					  size_t len)
{
	int ret = 0;
	struct sk_buff *skb;
	struct endpoint endpoint;

	if (unlikely(!in_skb))
		return -EINVAL;
	ret = wg_socket_endpoint_from_skb(&endpoint, in_skb);
	if (unlikely(ret < 0))
		return ret;

	skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);
	skb_put_data(skb, buffer, len);

	if (endpoint.addr.sa_family == AF_INET)
		ret = send4(wg, skb, &endpoint, 0, NULL);
	else if (endpoint.addr.sa_family == AF_INET6)
		ret = send6(wg, skb, &endpoint, 0, NULL);
	/* No other possibilities if the endpoint is valid, which it is,
	 * as we checked above.
	 */

	return ret;
}

int wg_socket_endpoint_from_skb(struct endpoint *endpoint,
				const struct sk_buff *skb)
{
	memset(endpoint, 0, sizeof(*endpoint));
	if (skb->protocol == htons(ETH_P_IP)) {
		endpoint->addr4.sin_family = AF_INET;
		endpoint->addr4.sin_port = udp_hdr(skb)->source;
		endpoint->addr4.sin_addr.s_addr = ip_hdr(skb)->saddr;
		endpoint->src4.s_addr = ip_hdr(skb)->daddr;
		endpoint->src_if4 = skb->skb_iif;
	} else if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6)) {
		endpoint->addr6.sin6_family = AF_INET6;
		endpoint->addr6.sin6_port = udp_hdr(skb)->source;
		endpoint->addr6.sin6_addr = ipv6_hdr(skb)->saddr;
		endpoint->addr6.sin6_scope_id = ipv6_iface_scope_id(
			&ipv6_hdr(skb)->saddr, skb->skb_iif);
		endpoint->src6 = ipv6_hdr(skb)->daddr;
	} else {
		return -EINVAL;
	}
	return 0;
}

static bool endpoint_eq(const struct endpoint *a, const struct endpoint *b)
{
	return (a->addr.sa_family == AF_INET && b->addr.sa_family == AF_INET &&
		a->addr4.sin_port == b->addr4.sin_port &&
		a->addr4.sin_addr.s_addr == b->addr4.sin_addr.s_addr &&
		a->src4.s_addr == b->src4.s_addr && a->src_if4 == b->src_if4) ||
	       (a->addr.sa_family == AF_INET6 &&
		b->addr.sa_family == AF_INET6 &&
		a->addr6.sin6_port == b->addr6.sin6_port &&
		ipv6_addr_equal(&a->addr6.sin6_addr, &b->addr6.sin6_addr) &&
		a->addr6.sin6_scope_id == b->addr6.sin6_scope_id &&
		ipv6_addr_equal(&a->src6, &b->src6)) ||
	       unlikely(!a->addr.sa_family && !b->addr.sa_family);
}

void wg_socket_set_peer_endpoint(struct wg_peer *peer,
				 const struct endpoint *endpoint)
{
	/* First we check unlocked, in order to optimize, since it's pretty rare
	 * that an endpoint will change. If we happen to be mid-write, and two
	 * CPUs wind up writing the same thing or something slightly different,
	 * it doesn't really matter much either.
	 */
	if (endpoint_eq(endpoint, &peer->endpoint))
		return;
	write_lock_bh(&peer->endpoint_lock);
	if (endpoint->addr.sa_family == AF_INET) {
		peer->endpoint.addr4 = endpoint->addr4;
		peer->endpoint.src4 = endpoint->src4;
		peer->endpoint.src_if4 = endpoint->src_if4;
	} else if (IS_ENABLED(CONFIG_IPV6) && endpoint->addr.sa_family == AF_INET6) {
		peer->endpoint.addr6 = endpoint->addr6;
		peer->endpoint.src6 = endpoint->src6;
	} else {
		goto out;
	}
	dst_cache_reset(&peer->endpoint_cache);
out:
	write_unlock_bh(&peer->endpoint_lock);
}

void wg_socket_set_peer_endpoint_from_skb(struct wg_peer *peer,
					  const struct sk_buff *skb)
{
	struct endpoint endpoint;

	if (!tswg_peer_may_roam(peer)) /* TSWG */
		return;
	if (!wg_socket_endpoint_from_skb(&endpoint, skb))
		wg_socket_set_peer_endpoint(peer, &endpoint);
}

void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer)
{
	write_lock_bh(&peer->endpoint_lock);
	memset(&peer->endpoint.src6, 0, sizeof(peer->endpoint.src6));
	dst_cache_reset_now(&peer->endpoint_cache);
	write_unlock_bh(&peer->endpoint_lock);
}

/*
 * TSWG: tswg_is_wg_message reports whether the UDP payload of skb looks like
 * a WireGuard message: a little-endian 32-bit type of 1 through 4. Nothing
 * else Tailscale sends on the socket matches: disco starts with "TS", STUN
 * with 0x00 or 0x01 followed by a nonzero byte, and Geneve-encapsulated peer
 * relay traffic with 0x00.
 */
static bool tswg_is_wg_message(struct sk_buff *skb)
{
	u8 buf[4];
	const u8 *h;

	h = skb_header_pointer(skb, skb_transport_offset(skb) + sizeof(struct udphdr),
			       sizeof(buf), buf);
	if (!h)
		return false;
	return h[0] >= MESSAGE_HANDSHAKE_INITIATION && h[0] <= MESSAGE_DATA &&
	       !h[1] && !h[2] && !h[3];
}

static int wg_receive(struct sock *sk, struct sk_buff *skb)
{
	struct wg_device *wg;

	if (unlikely(!sk))
		goto err;
	/* TSWG: leave everything but WireGuard messages on user sockets. */
	if (!sk->sk_kern_sock && !tswg_is_wg_message(skb))
		return 1;
	wg = sk->sk_user_data;
	if (unlikely(!wg))
		goto err;
	/* TSWG: user sockets outlive the device being up. */
	if (!sk->sk_kern_sock && unlikely(!netif_running(wg->dev)))
		goto err;
	skb_mark_not_on_list(skb);
	wg_packet_receive(wg, skb);
	return 0;

err:
	kfree_skb(skb);
	return 0;
}

static void sock_free(struct sock *sock)
{
	if (unlikely(!sock))
		return;
	/* TSWG: user sockets belong to userspace; just drop our reference. */
	if (!sock->sk_kern_sock) {
		sock_put(sock);
		return;
	}
	sk_clear_memalloc(sock);
	udp_tunnel_sock_release(sock);
}

static int tswg_socket_activate_user(struct wg_device *wg);

static void set_sock_opts(struct socket *sock)
{
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_sndbuf = INT_MAX;
	sk_set_memalloc(sock->sk);
}

int wg_socket_init(struct wg_device *wg, u16 port)
{
	struct net *net;
	int ret;
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = wg,
		.encap_type = 1,
		.encap_rcv = wg_receive
	};
	struct socket *new4 = NULL, *new6 = NULL;
	struct udp_port_cfg port4 = {
		.family = AF_INET,
		.local_ip.s_addr = htonl(INADDR_ANY),
		.local_udp_port = htons(port),
		.use_udp_checksums = true
	};
#if IS_ENABLED(CONFIG_IPV6)
	int retries = 0;
	struct udp_port_cfg port6 = {
		.family = AF_INET6,
		.local_ip6 = IN6ADDR_ANY_INIT,
		.use_udp6_tx_checksums = true,
		.use_udp6_rx_checksums = true,
		.ipv6_v6only = true
	};
#endif

	/* TSWG: use the user's sockets, if any, instead of creating our own. */
	ret = tswg_socket_activate_user(wg);
	if (ret != -ENOENT)
		return ret;

	rcu_read_lock();
	net = rcu_dereference(wg->creating_net);
	net = net ? maybe_get_net(net) : NULL;
	rcu_read_unlock();
	if (unlikely(!net))
		return -ENONET;

#if IS_ENABLED(CONFIG_IPV6)
retry:
#endif

	ret = udp_sock_create(net, &port4, &new4);
	if (ret < 0) {
		pr_err("%s: Could not create IPv4 socket\n", wg->dev->name);
		goto out;
	}
	set_sock_opts(new4);
	setup_udp_tunnel_sock(net, new4->sk, &cfg);

#if IS_ENABLED(CONFIG_IPV6)
	if (ipv6_mod_enabled()) {
		port6.local_udp_port = inet_sk(new4->sk)->inet_sport;
		ret = udp_sock_create(net, &port6, &new6);
		if (ret < 0) {
			udp_tunnel_sock_release(new4->sk);
			if (ret == -EADDRINUSE && !port && retries++ < 100)
				goto retry;
			pr_err("%s: Could not create IPv6 socket\n",
			       wg->dev->name);
			goto out;
		}
		set_sock_opts(new6);
		setup_udp_tunnel_sock(net, new6->sk, &cfg);
	}
#endif

	wg_socket_reinit(wg, new4->sk, new6 ? new6->sk : NULL);
	ret = 0;
out:
	put_net(net);
	return ret;
}

void wg_socket_reinit(struct wg_device *wg, struct sock *new4,
		      struct sock *new6)
{
	struct sock *old4, *old6;

	mutex_lock(&wg->socket_update_lock);
	old4 = rcu_dereference_protected(wg->sock4,
				lockdep_is_held(&wg->socket_update_lock));
	old6 = rcu_dereference_protected(wg->sock6,
				lockdep_is_held(&wg->socket_update_lock));
	rcu_assign_pointer(wg->sock4, new4);
	rcu_assign_pointer(wg->sock6, new6);
	if (new4)
		wg->incoming_port = ntohs(inet_sk(new4)->inet_sport);
	mutex_unlock(&wg->socket_update_lock);
	synchronize_net();
	sock_free(old4);
	sock_free(old6);
}

/*
 * TSWG: user-supplied sockets.
 *
 * tailscaled shares one UDP socket (per address family) between the kernel,
 * which handles WireGuard messages, and itself, for disco, STUN and so on,
 * so that NAT mappings discovered by disco are the ones WireGuard uses. It
 * passes the socket's fd over netlink; we hook the socket's UDP encap_rcv
 * (as L2TP does for user-supplied sockets) and leave non-WireGuard
 * datagrams on its receive queue.
 *
 * The device keeps a reference to each user socket in tswg_user_sock4/6,
 * independent of whether the device is up. While it's up, the same sockets
 * are also the device's active sock4/sock6, each holding its own reference.
 * When the process closes a socket, UDP calls tswg_user_sock_destroy and we
 * drop it, so the socket's lifetime is that of the user's file descriptor.
 *
 * tswg_user_sock_lock serializes attaching and detaching user sockets
 * across all devices, including detaching from the socket's destroy hook,
 * which runs without any of our locks held. Lock order: device_update_lock,
 * then tswg_user_sock_lock, then socket_update_lock.
 */

static DEFINE_MUTEX(tswg_user_sock_lock);

/*
 * tswg_detach_user_sock_locked removes the user socket sk from wg, restores
 * it to a plain UDP socket, and drops wg's references to it.
 */
static void tswg_detach_user_sock_locked(struct wg_device *wg, struct sock *sk)
{
	struct udp_sock *up = udp_sk(sk);
	bool active = false;

	lockdep_assert_held(&tswg_user_sock_lock);

	if (wg->tswg_user_sock4 == sk)
		wg->tswg_user_sock4 = NULL;
	if (wg->tswg_user_sock6 == sk)
		wg->tswg_user_sock6 = NULL;

	mutex_lock(&wg->socket_update_lock);
	if (rcu_access_pointer(wg->sock4) == sk) {
		RCU_INIT_POINTER(wg->sock4, NULL);
		active = true;
	}
	if (rcu_access_pointer(wg->sock6) == sk) {
		RCU_INIT_POINTER(wg->sock6, NULL);
		active = true;
	}
	mutex_unlock(&wg->socket_update_lock);

	/*
	 * Undo setup_udp_tunnel_sock. We leave the socket's encap static key
	 * reference (ENCAP_ENABLED) alone, since UDP drops it when the socket
	 * is destroyed, and multicast loopback disabled, since we don't know
	 * its old value.
	 */
	lock_sock(sk);
	WRITE_ONCE(up->encap_rcv, NULL);
	WRITE_ONCE(up->encap_destroy, NULL);
	WRITE_ONCE(up->encap_type, 0);
	rcu_assign_sk_user_data(sk, NULL);
	inet_dec_convert_csum(sk);
	release_sock(sk);

	/* Wait for in-flight receives and sends before dropping references. */
	synchronize_net();
	if (active)
		sock_put(sk);
	sock_put(sk);
}

/* tswg_user_sock_destroy is the UDP encap_destroy hook for user sockets. */
static void tswg_user_sock_destroy(struct sock *sk)
{
	struct wg_device *wg;

	mutex_lock(&tswg_user_sock_lock);
	rcu_read_lock();
	wg = rcu_dereference_sk_user_data(sk);
	rcu_read_unlock();
	if (wg) {
		pr_debug("%s: User socket closed\n", wg->dev->name);
		tswg_detach_user_sock_locked(wg, sk);
	}
	mutex_unlock(&tswg_user_sock_lock);
}

/*
 * tswg_socket_activate_user makes wg's user sockets its active sockets. It
 * returns -ENOENT if wg has no user sockets.
 */
static int tswg_socket_activate_user(struct wg_device *wg)
{
	struct sock *s4, *s6;

	mutex_lock(&tswg_user_sock_lock);
	s4 = wg->tswg_user_sock4;
	s6 = wg->tswg_user_sock6;
	if (!s4 && !s6) {
		mutex_unlock(&tswg_user_sock_lock);
		return -ENOENT;
	}
	if (s4)
		sock_hold(s4);
	if (s6)
		sock_hold(s6);
	wg_socket_reinit(wg, s4, s6);
	if (!s4)
		wg->incoming_port = ntohs(inet_sk(s6)->inet_sport);
	mutex_unlock(&tswg_user_sock_lock);
	return 0;
}

/*
 * tswg_socket_set_user attaches the UDP socket with file descriptor fd in
 * the calling process as wg's socket for family (AF_INET or AF_INET6),
 * replacing any previous one. If fd is negative, it detaches the current
 * one instead. If the device is up, it then switches to the new socket(s),
 * or back to its own sockets if no user sockets are left.
 *
 * It must be called with rtnl and wg->device_update_lock held, from the
 * netlink request's process context.
 */
int tswg_socket_set_user(struct wg_device *wg, int family, int fd,
			 struct netlink_ext_ack *extack)
{
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = wg,
		.encap_type = 1,
		.encap_rcv = wg_receive,
		.encap_destroy = tswg_user_sock_destroy,
	};
	struct sock **slot, *old, *sk = NULL;
	struct socket *sock;
	int ret;

	if (fd >= 0) {
		sock = sockfd_lookup(fd, &ret);
		if (!sock) {
			NL_SET_ERR_MSG(extack, "invalid socket file descriptor");
			return ret;
		}
		sk = sock->sk;
		ret = -EINVAL;
		if (sk->sk_type != SOCK_DGRAM || sk->sk_protocol != IPPROTO_UDP ||
		    sk->sk_family != family) {
			NL_SET_ERR_MSG(extack, "not a UDP socket of the expected address family");
			goto err_put;
		}
		if (family == AF_INET6 && !sk->sk_ipv6only) {
			NL_SET_ERR_MSG(extack, "IPv6 socket must be IPV6_V6ONLY");
			goto err_put;
		}
		if (!inet_sk(sk)->inet_sport) {
			NL_SET_ERR_MSG(extack, "socket is not bound");
			goto err_put;
		}

		lock_sock(sk);
		if (rcu_access_pointer(sk->sk_user_data) == wg) {
			/* Already ours; nothing to do. */
			release_sock(sk);
			sockfd_put(sock);
			return 0;
		}
		if (rcu_access_pointer(sk->sk_user_data) || udp_sk(sk)->encap_type) {
			release_sock(sk);
			ret = -EBUSY;
			NL_SET_ERR_MSG(extack, "socket is already in use by a tunnel");
			goto err_put;
		}
		/* Like WireGuard's own sockets, since we send from atomic context. */
		sk->sk_allocation = GFP_ATOMIC;
		setup_udp_tunnel_sock(sock_net(sk), sk, &cfg);
		release_sock(sk);
		sock_hold(sk);
		sockfd_put(sock);
	}

	mutex_lock(&tswg_user_sock_lock);
	slot = family == AF_INET ? &wg->tswg_user_sock4 : &wg->tswg_user_sock6;
	old = *slot;
	*slot = sk;
	if (old)
		tswg_detach_user_sock_locked(wg, old);
	if (sk && (family == AF_INET || !wg->tswg_user_sock4))
		wg->incoming_port = ntohs(inet_sk(sk)->inet_sport);
	mutex_unlock(&tswg_user_sock_lock);

	if (!netif_running(wg->dev))
		return 0;
	/* This activates the user sockets, or creates our own if none are left. */
	return wg_socket_init(wg, wg->incoming_port);

err_put:
	sockfd_put(sock);
	return ret;
}

/* tswg_socket_has_user reports whether wg has any user sockets. */
bool tswg_socket_has_user(struct wg_device *wg)
{
	bool ret;

	mutex_lock(&tswg_user_sock_lock);
	ret = wg->tswg_user_sock4 || wg->tswg_user_sock6;
	mutex_unlock(&tswg_user_sock_lock);
	return ret;
}

/* tswg_socket_flags returns wg's TSWGDEVICE_F_USER_SOCK* flags. */
u32 tswg_socket_flags(struct wg_device *wg)
{
	u32 flags = 0;

	mutex_lock(&tswg_user_sock_lock);
	if (wg->tswg_user_sock4)
		flags |= TSWGDEVICE_F_USER_SOCK4;
	if (wg->tswg_user_sock6)
		flags |= TSWGDEVICE_F_USER_SOCK6;
	mutex_unlock(&tswg_user_sock_lock);
	return flags;
}

/* tswg_socket_detach_all_user detaches all of wg's user sockets. */
void tswg_socket_detach_all_user(struct wg_device *wg)
{
	mutex_lock(&tswg_user_sock_lock);
	if (wg->tswg_user_sock4)
		tswg_detach_user_sock_locked(wg, wg->tswg_user_sock4);
	if (wg->tswg_user_sock6)
		tswg_detach_user_sock_locked(wg, wg->tswg_user_sock6);
	mutex_unlock(&tswg_user_sock_lock);
}
