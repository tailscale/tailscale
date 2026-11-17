/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_DEVICE_H
#define _WG_DEVICE_H

#include "noise.h"
#include "allowedips.h"
#include "peerlookup.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/ptr_ring.h>
#include <net/gro_cells.h> /* TSWG */
#include <linux/llist.h> /* TSWG */
#include <linux/smp.h> /* TSWG */

struct wg_device;

struct multicore_worker {
	void *ptr;
	struct work_struct work;
	bool tswg_busy; /* TSWG: worker is draining the ring; see tswg_crypt_kick */
	struct page_frag tswg_frag; /* TSWG: encrypt worker's output pages */
	/* TSWG: output pages for inline encryption on this CPU, with BHs off */
	struct page_frag tswg_inline_frag;
	/* TSWG: lone packets this CPU saw in jiffy tswg_rate_jiffy; see tswg_inline_ok */
	unsigned long tswg_rate_jiffy;
	unsigned int tswg_rate_count;
};

/*
 * TSWG: tswg_steer is a CPU's queue of received packets that other CPUs
 * handed it (see tswg_steer in receive.c), and the NAPI that takes them.
 */
struct tswg_steer {
	struct llist_head in; /* added by other CPUs, newest first */
	struct sk_buff_head todo; /* taken from in, oldest first; this CPU's */
	struct napi_struct napi;
	call_single_data_t csd; /* schedules napi on this CPU */
};

int tswg_steer_init(struct wg_device *wg);
void tswg_steer_uninit(struct wg_device *wg);

struct crypt_queue {
	struct ptr_ring ring;
	struct multicore_worker __percpu *worker;
	int last_cpu;
	/* TSWG: the workers' CPUs; see tswg_crypt_recruit_cpu */
	atomic_t tswg_active; /* workers draining now */
	unsigned int tswg_peak; /* most draining at once, this window */
	unsigned int tswg_width; /* CPUs to recruit from */
	unsigned int tswg_next; /* the next of them to recruit */
	unsigned long tswg_width_jiffy; /* when tswg_width was last set */
};

struct prev_queue {
	struct sk_buff *head, *tail, *peeked;
	struct { struct sk_buff *next, *prev; } empty; // Match first 2 members of struct sk_buff.
	atomic_t count;
};

struct wg_device {
	struct net_device *dev;
	struct crypt_queue encrypt_queue, decrypt_queue, handshake_queue;
	struct gro_cells tswg_gro_cells; /* TSWG: see tswg_receive_now */
	struct tswg_steer __percpu *tswg_steer; /* TSWG: see tswg_steer */
	struct sock __rcu *sock4, *sock6;
	struct net __rcu *creating_net;
	struct noise_static_identity static_identity;
	struct workqueue_struct *packet_crypt_wq,*handshake_receive_wq, *handshake_send_wq;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable *peer_hashtable;
	struct index_hashtable *index_hashtable;
	struct allowedips peer_allowedips;
	struct mutex device_update_lock, socket_update_lock;
	struct list_head device_list, peer_list;
	atomic_t handshake_queue_len;
	unsigned int num_peers, device_update_gen;
	u32 fwmark;
	u16 incoming_port;

	/* TSWG: user-supplied sockets, protected by tswg_user_sock_lock. */
	struct sock *tswg_user_sock4, *tswg_user_sock6;
};

int wg_device_init(void);
void wg_device_uninit(void);

#endif /* _WG_DEVICE_H */
