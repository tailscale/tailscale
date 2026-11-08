/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_PEER_H
#define _WG_PEER_H

#include "device.h"
#include "noise.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <net/dst_cache.h>

struct wg_device;

struct endpoint {
	union {
		struct sockaddr_inet addr;     /* Large enough for both address families */
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	union {
		struct {
			struct in_addr src4;
			/* Essentially the same as addr6->scope_id */
			int src_if4;
		};
		struct in6_addr src6;
	};
};

struct wg_peer {
	struct wg_device *device;
	struct prev_queue tx_queue, rx_queue;
	struct sk_buff_head staged_packet_queue;
	int serial_work_cpu;
	bool is_dead;
	struct noise_keypairs keypairs;
	struct endpoint endpoint;
	struct dst_cache endpoint_cache;
	rwlock_t endpoint_lock;
	struct noise_handshake handshake;
	atomic64_t last_sent_handshake;
	struct work_struct transmit_handshake_work, clear_peer_work, transmit_packet_work;
	struct cookie latest_cookie;
	struct hlist_node pubkey_hash;
	u64 rx_bytes, tx_bytes;
	struct timer_list timer_retransmit_handshake, timer_send_keepalive;
	struct timer_list timer_new_handshake, timer_zero_key_material;
	struct timer_list timer_persistent_keepalive;
	unsigned int timer_handshake_attempts;
	u16 persistent_keepalive_interval;
	bool timer_need_another_keepalive;
	bool sent_lastminute_handshake;
	struct timespec64 walltime_last_handshake;
	struct kref refcount;
	struct rcu_head rcu;
	struct list_head peer_list;
	struct list_head allowedips_list;
	struct napi_struct napi;
	u64 internal_id;

	/*
	 * TSWG: if set, don't learn the endpoint from incoming packets once
	 * one is set; userspace (disco) picks the path. Read locklessly.
	 */
	bool tswg_no_roam;
	/* TSWG: whoever holds it sends the peer's tx_queue; see tswg_tx_kick */
	spinlock_t tswg_tx_lock;
	bool tswg_tx_more; /* tx_queue may have more to send */
	/* TSWG: bytes received since jiffy tswg_rx_jiffy; see tswg_rx_inline_ok */
	unsigned long tswg_rx_jiffy;
	unsigned int tswg_rx_bytes;
	unsigned long tswg_rx_parallel_until; /* jiffies; see tswg_rx_path */
	unsigned long tswg_rx_steer_until; /* jiffies; see tswg_rx_path */
	atomic_t tswg_steered; /* packets on their way through tswg_steer */
	int tswg_rx_mode; /* enum tswg_rx_mode of the last packet received */
	int tswg_home; /* CPU its steered packets go to; see tswg_peer_home */

	/* TSWG: jiffies of the last TX and RX activity events; see tswg.h. */
	unsigned long tswg_tx_event, tswg_rx_event;
};

/*
 * TSWG: tswg_peer_may_roam reports whether an authenticated packet from a
 * new address may update peer's endpoint.
 */
static inline bool tswg_peer_may_roam(const struct wg_peer *peer)
{
	return !READ_ONCE(peer->tswg_no_roam) ||
	       !READ_ONCE(peer->endpoint.addr.sa_family);
}

struct wg_peer *wg_peer_create(struct wg_device *wg,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

struct wg_peer *__must_check wg_peer_get_maybe_zero(struct wg_peer *peer);
static inline struct wg_peer *wg_peer_get(struct wg_peer *peer)
{
	kref_get(&peer->refcount);
	return peer;
}
void wg_peer_put(struct wg_peer *peer);
void wg_peer_remove(struct wg_peer *peer);
void wg_peer_remove_all(struct wg_device *wg);

int wg_peer_init(void);
void wg_peer_uninit(void);

#endif /* _WG_PEER_H */
