/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _WG_QUEUEING_H
#define _WG_QUEUEING_H

#include "peer.h"
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip_tunnels.h>

struct wg_device;
struct wg_peer;
struct multicore_worker;
struct crypt_queue;
struct prev_queue;
struct sk_buff;

/* queueing.c APIs: */
int wg_packet_queue_init(struct crypt_queue *queue, work_func_t function,
			 unsigned int len);
void wg_packet_queue_free(struct crypt_queue *queue, bool purge);
struct multicore_worker __percpu *
wg_packet_percpu_multicore_worker_alloc(work_func_t function, void *ptr);

/* receive.c APIs: */
void wg_packet_receive(struct wg_device *wg, struct sk_buff *skb);
void wg_packet_handshake_receive_worker(struct work_struct *work);
/* NAPI poll function: */
int wg_packet_rx_poll(struct napi_struct *napi, int budget);
/* Workqueue worker: */
void wg_packet_decrypt_worker(struct work_struct *work);

/* send.c APIs: */
void wg_packet_send_queued_handshake_initiation(struct wg_peer *peer,
						bool is_retry);
void wg_packet_send_handshake_response(struct wg_peer *peer, bool retry);
void wg_packet_send_handshake_cookie(struct wg_device *wg,
				     struct sk_buff *initiating_skb,
				     __le32 sender_index);
void wg_packet_send_keepalive(struct wg_peer *peer);
void wg_packet_purge_staged_packets(struct wg_peer *peer);
void wg_packet_send_staged_packets(struct wg_peer *peer);
/* Workqueue workers: */
void wg_packet_handshake_send_worker(struct work_struct *work);
void wg_packet_tx_worker(struct work_struct *work);
void wg_packet_encrypt_worker(struct work_struct *work);

enum packet_state {
	PACKET_STATE_UNCRYPTED,
	PACKET_STATE_CRYPTED,
	PACKET_STATE_DEAD
};

struct packet_cb {
	u64 nonce;
	struct noise_keypair *keypair;
	atomic_t state;
	u32 mtu;
	u8 ds;
	u16 tswg_count; /* TSWG: packets in this peer queue entry */
	/*
	 * TSWG: on the first packet of a list being encrypted, the encrypted
	 * packets to send (see tswg_encrypt_list); NULL until then.
	 */
	struct sk_buff *tswg_out;
};

#define PACKET_CB(skb) ((struct packet_cb *)((skb)->cb))
#define PACKET_PEER(skb) (PACKET_CB(skb)->keypair->entry.peer)

static inline bool wg_check_packet_protocol(struct sk_buff *skb)
{
	__be16 real_protocol = ip_tunnel_parse_protocol(skb);
	return real_protocol && skb->protocol == real_protocol;
}

static inline void wg_reset_packet(struct sk_buff *skb, bool encapsulating)
{
	u8 l4_hash = skb->l4_hash;
	u8 sw_hash = skb->sw_hash;
	u32 hash = skb->hash;
	u8 tstamp_type = skb->tstamp_type;
	skb_scrub_packet(skb, true);
	memset(&skb->headers, 0, sizeof(skb->headers));
	if (encapsulating) {
		skb->l4_hash = l4_hash;
		skb->sw_hash = sw_hash;
		skb->hash = hash;
		skb->tstamp_type = tstamp_type;
	}
	skb->queue_mapping = 0;
	skb->nohdr = 0;
	skb->peeked = 0;
	skb->mac_len = 0;
	skb->dev = NULL;
#ifdef CONFIG_NET_SCHED
	skb->tc_index = 0;
#endif
	skb_reset_redirect(skb);
	skb->hdr_len = skb_headroom(skb);
	skb_reset_mac_header(skb);
	skb_reset_network_header(skb);
	skb_reset_transport_header(skb);
	skb_probe_transport_header(skb);
	skb_reset_inner_headers(skb);
}

static inline int wg_cpumask_choose_online(int *stored_cpu, unsigned int id)
{
	unsigned int cpu = *stored_cpu;

	while (unlikely(cpu >= nr_cpu_ids || !cpu_online(cpu)))
		cpu = *stored_cpu = cpumask_nth(id % num_online_cpus(), cpu_online_mask);

	return cpu;
}

/* This function is racy, in the sense that it's called while last_cpu is
 * unlocked, so it could return the same CPU twice. Adding locking or using
 * atomic sequence numbers is slower though, and the consequences of racing are
 * harmless, so live with it.
 */
static inline int wg_cpumask_next_online(int *last_cpu)
{
	int cpu = cpumask_next(READ_ONCE(*last_cpu), cpu_online_mask);
	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(cpu_online_mask);
	WRITE_ONCE(*last_cpu, cpu);
	return cpu;
}

/*
 * TSWG: demand-driven crypt worker kicks. Upstream queues the next CPU's
 * crypt worker for every packet, round robin, which usually means waking
 * it with an IPI (a VM exit, in a VM); profiling showed that to be the main
 * cost on the receive path's single softirq CPU. All of a queue's workers
 * drain the same ring, so a packet needs no kick at all while some worker
 * is already draining it, unless the backlog shows that the busy workers
 * aren't keeping up, in which case we recruit another CPU's worker.
 *
 * tswg_busy pairs with the ring: the producer adds to the ring and then
 * reads tswg_busy, and a worker clears tswg_busy and then checks the ring,
 * each with a full barrier in between, so either the producer sees the
 * worker busy (and the worker sees the packet), or the producer kicks.
 */

/*
 * TSWG_PACKET_BACKLOG and TSWG_BATCH_BACKLOG are how many ring entries may
 * wait before another worker is recruited, when the entries are single
 * packets, and when they're batches (a GSO packet's worth: encrypt entries
 * are lists of packets, and decrypt entries can be packets merged by GRO).
 */
#define TSWG_PACKET_BACKLOG 16
#define TSWG_BATCH_BACKLOG 1

/*
 * tswg_crypt_backlog returns about how many entries are in the ring. It
 * reads indices that other CPUs write, so it's only an estimate.
 */
static inline unsigned int tswg_crypt_backlog(struct ptr_ring *r)
{
	int n = READ_ONCE(r->producer) - READ_ONCE(r->consumer_head);

	return n < 0 ? n + r->size : n;
}

/* tswg_worker_active reports whether w is draining or about to drain. */
static inline bool tswg_worker_active(struct multicore_worker *w)
{
	return READ_ONCE(w->tswg_busy) || work_pending(&w->work);
}

/*
 * tswg_crypt_kick makes sure some worker will consume what was just added
 * to queue's ring, recruiting another one if more than backlog entries
 * are waiting. It prefers workers on other CPUs than the caller's: for
 * decryption, the caller is the CPU taking packets from the NIC, and a
 * worker there is starved by that softirq work, holding up every packet
 * behind it in the peer's in-order queue.
 */
static inline void tswg_crypt_kick(struct crypt_queue *queue,
				   struct workqueue_struct *wq,
				   unsigned int backlog)
{
	struct multicore_worker *w;
	int cpu = READ_ONCE(queue->last_cpu);

	smp_mb(); /* ring produce before reading tswg_busy; see above */
	if (likely(cpu >= 0 && cpu < nr_cpu_ids && cpu_online(cpu) &&
		   cpu != raw_smp_processor_id())) {
		w = per_cpu_ptr(queue->worker, cpu);
		if (!tswg_worker_active(w)) {
			queue_work_on(cpu, wq, &w->work);
			return;
		}
		if (tswg_crypt_backlog(&queue->ring) <= backlog)
			return;
	}
	cpu = wg_cpumask_next_online(&queue->last_cpu);
	if (cpu == raw_smp_processor_id() && num_online_cpus() > 1)
		cpu = wg_cpumask_next_online(&queue->last_cpu);
	w = per_cpu_ptr(queue->worker, cpu);
	if (!tswg_worker_active(w))
		queue_work_on(cpu, wq, &w->work);
}

/*
 * tswg_crypt_worker_idle is called by a crypt worker that found its ring
 * empty. It returns whether the worker may return, or must keep draining
 * because something was added since.
 */
static inline bool tswg_crypt_worker_idle(struct multicore_worker *w,
					  struct crypt_queue *queue)
{
	WRITE_ONCE(w->tswg_busy, false);
	smp_mb(); /* clear tswg_busy before checking the ring; see above */
	if (likely(__ptr_ring_empty(&queue->ring)))
		return true;
	WRITE_ONCE(w->tswg_busy, true);
	return false;
}

/*
 * TSWG: inline crypto. Handing a packet to a crypt worker on another CPU
 * costs an IPI, and, if that CPU is idle, waking it, which in a VM means a
 * VM exit and the host scheduling the vCPU: idle round trip times were
 * 1.5-2x wireguard-go's in VMs, though 0.6x with idle=poll. So when the
 * workers are idle, a lone packet is encrypted or decrypted where it is,
 * on its way through the stack. It still goes on the peer's in-order
 * queue first, so ordering doesn't depend on being idle; being idle just
 * keeps bulk traffic on the workers, in parallel, and off the CPUs taking
 * the NIC's interrupts.
 *
 * tswg_crypt_idle reports whether queue's workers look idle: nothing waits
 * in the ring, and the worker last kicked isn't busy. It's a hint.
 * tswg_inline_crypto (module parameter inline_crypto) turns it all off.
 */
extern bool tswg_inline_crypto;

static inline bool tswg_crypt_idle(struct crypt_queue *queue)
{
	int cpu = READ_ONCE(queue->last_cpu);

	if (!__ptr_ring_empty(&queue->ring))
		return false;
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return true;
	return !tswg_worker_active(per_cpu_ptr(queue->worker, cpu));
}

/*
 * TSWG: tswg_queue_work_on is queue_work_on, skipping the call when the work
 * is already pending (queued but not yet started, so it will see whatever
 * was just enqueued). That check is a read; queue_work_on's own check is
 * an atomic test-and-set on a cache line that the worker's CPU writes.
 */
static inline void tswg_queue_work_on(int cpu, struct workqueue_struct *wq,
				      struct work_struct *work)
{
	if (work_pending(work))
		return;
	queue_work_on(cpu, wq, work);
}

void wg_prev_queue_init(struct prev_queue *queue);

/* Multi producer */
bool wg_prev_queue_enqueue(struct prev_queue *queue, struct sk_buff *skb);

/* Single consumer */
struct sk_buff *wg_prev_queue_dequeue(struct prev_queue *queue);

/* Single consumer */
static inline struct sk_buff *wg_prev_queue_peek(struct prev_queue *queue)
{
	if (queue->peeked)
		return queue->peeked;
	queue->peeked = wg_prev_queue_dequeue(queue);
	return queue->peeked;
}

/* Single consumer */
static inline void wg_prev_queue_drop_peeked(struct prev_queue *queue)
{
	queue->peeked = NULL;
}

/*
 * TSWG: tswg_inline_ok reports whether to do the crypto for a lone packet
 * inline (see tswg_crypt_idle), counting it in this CPU's rate. An empty
 * ring isn't enough: under load, workers drain a stream of small packets
 * (TCP ACKs) fast enough that the ring is often empty, and inlining them
 * put that work on the CPUs taking the NIC's interrupts, which cost a
 * subnet router 8% of its throughput. So past TSWG_INLINE_BURST lone
 * packets in a jiffy, this CPU leaves them to the workers. BHs must be off.
 */
#define TSWG_INLINE_BURST 8

static inline bool tswg_inline_ok(struct crypt_queue *queue)
{
	struct multicore_worker *w = this_cpu_ptr(queue->worker);
	unsigned long now = jiffies;

	if (!READ_ONCE(tswg_inline_crypto))
		return false;
	if (w->tswg_rate_jiffy != now) {
		w->tswg_rate_jiffy = now;
		w->tswg_rate_count = 0;
	}
	if (++w->tswg_rate_count > TSWG_INLINE_BURST)
		return false;
	return tswg_crypt_idle(queue);
}

/*
 * TSWG: tswg_enqueue_per_peer is the peer queue half of
 * wg_queue_enqueue_per_device_and_peer, for inline crypto.
 */
static inline int tswg_enqueue_per_peer(struct prev_queue *peer_queue,
					struct sk_buff *skb)
{
	atomic_set_release(&PACKET_CB(skb)->state, PACKET_STATE_UNCRYPTED);
	if (unlikely(!wg_prev_queue_enqueue(peer_queue, skb)))
		return -ENOSPC;
	return 0;
}

static inline int wg_queue_enqueue_per_device_and_peer(
	struct crypt_queue *device_queue, struct prev_queue *peer_queue,
	struct sk_buff *skb, struct workqueue_struct *wq,
	unsigned int backlog)
{
	atomic_set_release(&PACKET_CB(skb)->state, PACKET_STATE_UNCRYPTED);
	/* We first queue this up for the peer ingestion, but the consumer
	 * will wait for the state to change to CRYPTED or DEAD before.
	 */
	if (unlikely(!wg_prev_queue_enqueue(peer_queue, skb)))
		return -ENOSPC;

	/* Then we queue it up in the device queue, which consumes the
	 * packet as soon as it can.
	 */
	if (unlikely(ptr_ring_produce_bh(&device_queue->ring, skb)))
		return -EPIPE;
	tswg_crypt_kick(device_queue, wq, backlog); /* TSWG */
	return 0;
}

static inline void wg_queue_enqueue_per_peer_tx(struct sk_buff *skb, enum packet_state state)
{
	/* We take a reference, because as soon as we call atomic_set, the
	 * peer can be freed from below us.
	 */
	struct wg_peer *peer = wg_peer_get(PACKET_PEER(skb));

	atomic_set_release(&PACKET_CB(skb)->state, state);
	/*
	 * TSWG: upstream runs a peer's tx worker on one CPU chosen by the
	 * peer's ID (serial_work_cpu). When that's also the CPU handling the
	 * NIC's interrupts, softirq work starves the worker, and encrypted
	 * packets waited up to 20ms to be sent, behind the in-order queue's
	 * head. Queue it here instead, on a CPU running our own crypto work
	 * (and already awake, so without an IPI). The workqueue still runs
	 * it on one CPU at a time.
	 */
	tswg_queue_work_on(raw_smp_processor_id(),
			   peer->device->packet_crypt_wq, &peer->transmit_packet_work);
	wg_peer_put(peer);
}

static inline void wg_queue_enqueue_per_peer_rx(struct sk_buff *skb, enum packet_state state)
{
	/* We take a reference, because as soon as we call atomic_set, the
	 * peer can be freed from below us.
	 */
	struct wg_peer *peer = wg_peer_get(PACKET_PEER(skb));

	atomic_set_release(&PACKET_CB(skb)->state, state);
	napi_schedule(&peer->napi);
	wg_peer_put(peer);
}

#ifdef DEBUG
bool wg_packet_counter_selftest(void);
#endif

#endif /* _WG_QUEUEING_H */
