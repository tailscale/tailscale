// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/sock.h>

static void wg_packet_send_handshake_initiation(struct wg_peer *peer)
{
	struct message_handshake_initiation packet;

	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      REKEY_TIMEOUT))
		return; /* This function is rate limited. */

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake initiation to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	if (wg_noise_handshake_create_initiation(&packet, &peer->handshake)) {
		wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		wg_timers_any_authenticated_packet_traversal(peer);
		wg_timers_any_authenticated_packet_sent(peer);
		atomic64_set(&peer->last_sent_handshake,
			     ktime_get_coarse_boottime_ns());
		wg_socket_send_buffer_to_peer(peer, &packet, sizeof(packet),
					      HANDSHAKE_DSCP);
		wg_timers_handshake_initiated(peer);
	}
}

void wg_packet_handshake_send_worker(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer,
					    transmit_handshake_work);

	wg_packet_send_handshake_initiation(peer);
	wg_peer_put(peer);
}

void wg_packet_send_queued_handshake_initiation(struct wg_peer *peer,
						bool is_retry)
{
	if (!is_retry)
		peer->timer_handshake_attempts = 0;

	rcu_read_lock_bh();
	/* We check last_sent_handshake here in addition to the actual function
	 * we're queueing up, so that we don't queue things if not strictly
	 * necessary:
	 */
	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      REKEY_TIMEOUT) ||
			unlikely(READ_ONCE(peer->is_dead)))
		goto out;

	wg_peer_get(peer);
	/* Queues up calling packet_send_queued_handshakes(peer), where we do a
	 * peer_put(peer) after:
	 */
	if (!queue_work(peer->device->handshake_send_wq,
			&peer->transmit_handshake_work))
		/* If the work was already queued, we want to drop the
		 * extra reference:
		 */
		wg_peer_put(peer);
out:
	rcu_read_unlock_bh();
}

void wg_packet_send_handshake_response(struct wg_peer *peer)
{
	struct message_handshake_response packet;

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake response to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	if (wg_noise_handshake_create_response(&packet, &peer->handshake)) {
		wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		if (wg_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			wg_timers_session_derived(peer);
			wg_timers_any_authenticated_packet_traversal(peer);
			wg_timers_any_authenticated_packet_sent(peer);
			atomic64_set(&peer->last_sent_handshake,
				     ktime_get_coarse_boottime_ns());
			wg_socket_send_buffer_to_peer(peer, &packet,
						      sizeof(packet),
						      HANDSHAKE_DSCP);
		}
	}
}

void wg_packet_send_handshake_cookie(struct wg_device *wg,
				     struct sk_buff *initiating_skb,
				     __le32 sender_index)
{
	struct message_handshake_cookie packet;

	net_dbg_skb_ratelimited("%s: Sending cookie response for denied handshake message for %pISpfsc\n",
				wg->dev->name, initiating_skb);
	wg_cookie_message_create(&packet, initiating_skb, sender_index,
				 &wg->cookie_checker);
	wg_socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet,
					      sizeof(packet));
}

static void keep_key_fresh(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	bool send;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	send = keypair && READ_ONCE(keypair->sending.is_valid) &&
	       (atomic64_read(&keypair->sending_counter) > REKEY_AFTER_MESSAGES ||
		(keypair->i_am_the_initiator &&
		 wg_birthdate_has_expired(keypair->sending.birthdate, REKEY_AFTER_TIME)));
	rcu_read_unlock_bh();

	if (unlikely(send))
		wg_packet_send_queued_handshake_initiation(peer, false);
}

static unsigned int calculate_skb_padding(struct sk_buff *skb)
{
	unsigned int padded_size, last_unit = skb->len;

	if (unlikely(!PACKET_CB(skb)->mtu))
		return ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE) - last_unit;

	/* We do this modulo business with the MTU, just in case the networking
	 * layer gives us a packet that's bigger than the MTU. In that case, we
	 * wouldn't want the final subtraction to overflow in the case of the
	 * padded_size being clamped. Fortunately, that's very rarely the case,
	 * so we optimize for that not happening.
	 */
	if (unlikely(last_unit > PACKET_CB(skb)->mtu))
		last_unit %= PACKET_CB(skb)->mtu;

	padded_size = min(PACKET_CB(skb)->mtu,
			  ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE));
	return padded_size - last_unit;
}

/*
 * TSWG: encryption into new pages, sent as UDP GSO.
 *
 * Upstream encrypts each packet in place, which first means making it
 * linear and writable (skb_cow_data), usually a copy, and then sends each
 * through the UDP/IP stack and the device on its own. Instead, we copy each
 * packet (computing its checksum on the way, if it's still to be done) into
 * pages of our own, encrypt it there, and gather the encrypted packets of
 * a list, which mostly came from one GSO packet on the WireGuard device and
 * so are all the same size but perhaps the last (WireGuard pads to 16
 * bytes), into UDP GSO (SKB_GSO_UDP_L4) packets whose payload is those
 * pages. Segmenting such a packet needs no copying (just page references),
 * and a device that does UDP segmentation offload (USO) takes it whole.
 *
 * TSWG_GSO_MAX_SEGS and TSWG_GSO_MAX_BYTES bound a GSO packet; the IP and
 * UDP length fields are 16 bits.
 */
#define TSWG_GSO_MAX_SEGS 64
#define TSWG_GSO_MAX_BYTES (65535 - sizeof(struct ipv6hdr) - sizeof(struct udphdr))

/*
 * tswg_copy_plaintext copies skb to the linear buffer to, finishing its
 * checksum if that's still to be done, as skb_checksum_help would.
 */
static bool tswg_copy_plaintext(struct sk_buff *skb, u8 *to)
{
	int start;
	__wsum csum;

	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return !skb_copy_bits(skb, 0, to, skb->len);
	if (unlikely(skb_csum_is_sctp(skb)))
		return !skb_csum_hwoffload_help(skb, 0) &&
		       !skb_copy_bits(skb, 0, to, skb->len);
	start = skb_checksum_start_offset(skb);
	if (unlikely(start < 0 ||
		     start + skb->csum_offset + sizeof(__sum16) > skb->len))
		return false;
	if (unlikely(skb_copy_bits(skb, 0, to, start)))
		return false;
	csum = skb_copy_and_csum_bits(skb, start, to + start, skb->len - start);
	*(__sum16 *)(to + start + skb->csum_offset) =
		csum_fold(csum) ?: CSUM_MANGLED_0;
	return true;
}

/*
 * tswg_encrypt_into encrypts skb as a data message of msg_len bytes,
 * appended to out's page frags. out must have a free frag slot.
 */
static bool tswg_encrypt_into(struct sk_buff *out, struct sk_buff *skb,
			      unsigned int msg_len,
			      struct noise_keypair *keypair,
			      struct page_frag *pfrag)
{
	unsigned int plaintext_len = msg_len - message_data_len(0);
	int i = skb_shinfo(out)->nr_frags;
	struct message_data *header;
	u8 *plaintext;

	if (unlikely(!skb_page_frag_refill(msg_len, pfrag, GFP_ATOMIC)))
		return false;
	header = page_address(pfrag->page) + pfrag->offset;
	plaintext = (u8 *)(header + 1);
	if (unlikely(!tswg_copy_plaintext(skb, plaintext)))
		return false;
	memset(plaintext + skb->len, 0, plaintext_len - skb->len);
	header->header.type = cpu_to_le32(MESSAGE_DATA);
	header->key_idx = keypair->remote_index;
	header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
	chacha20poly1305_encrypt(plaintext, plaintext, plaintext_len, NULL, 0,
				 PACKET_CB(skb)->nonce, keypair->sending.key);

	if (skb_can_coalesce(out, i, pfrag->page, pfrag->offset)) {
		skb_frag_size_add(&skb_shinfo(out)->frags[i - 1], msg_len);
	} else {
		get_page(pfrag->page);
		skb_fill_page_desc(out, i, pfrag->page, pfrag->offset, msg_len);
	}
	pfrag->offset += msg_len;
	out->len += msg_len;
	out->data_len += msg_len;
	out->truesize += msg_len;
	return true;
}

/* tswg_finish_out makes out a GSO packet, if it has more than one segment. */
static void tswg_finish_out(struct sk_buff *out, unsigned int mss,
			    unsigned int segs)
{
	if (segs < 2)
		return;
	skb_shinfo(out)->gso_size = mss;
	skb_shinfo(out)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(out)->gso_segs = segs;
}

/*
 * tswg_encrypt_list encrypts the list of packets at first into
 * PACKET_CB(first)->tswg_out, a list of packets to send, and frees them,
 * but for first itself (which stays on the peer's queue).
 */
static bool tswg_encrypt_list(struct sk_buff *first, struct page_frag *pfrag)
{
	struct noise_keypair *keypair = PACKET_CB(first)->keypair;
	struct sk_buff **tail = &PACKET_CB(first)->tswg_out;
	unsigned int mss = 0, segs = 0;
	struct sk_buff *skb, *out = NULL;
	bool ok = true;

	for (skb = first; skb; skb = skb->next) {
		unsigned int msg_len = message_data_len(skb->len +
						       calculate_skb_padding(skb));

		/* Only the last segment of a GSO packet may be shorter. */
		if (out && (msg_len > mss || out->len != mss * segs ||
			    msg_len == message_data_len(0) ||
			    mss == message_data_len(0) ||
			    segs >= TSWG_GSO_MAX_SEGS ||
			    out->len + msg_len > TSWG_GSO_MAX_BYTES ||
			    skb_shinfo(out)->nr_frags >= MAX_SKB_FRAGS ||
			    PACKET_CB(skb)->ds != PACKET_CB(out)->ds)) {
			tswg_finish_out(out, mss, segs);
			out = NULL;
		}
		if (!out) {
			out = alloc_skb(SKB_HEADER_LEN, GFP_ATOMIC);
			if (unlikely(!out)) {
				ok = false;
				break;
			}
			skb_reserve(out, SKB_HEADER_LEN);
			/* Keep the inner flow's hash, as upstream does. */
			out->hash = skb_get_hash(skb);
			out->l4_hash = skb->l4_hash;
			out->sw_hash = skb->sw_hash;
			PACKET_CB(out)->ds = PACKET_CB(skb)->ds;
			*tail = out;
			tail = &out->next;
			mss = msg_len;
			segs = 0;
		}
		if (unlikely(!tswg_encrypt_into(out, skb, msg_len, keypair,
						pfrag))) {
			ok = false;
			break;
		}
		segs++;
	}
	if (out)
		tswg_finish_out(out, mss, segs);

	/*
	 * The packets may belong to the inner socket (for TCP, for its small
	 * queues accounting), which we'd rather release now than once first
	 * is sent; wireguard-go has the same effect, since the TUN device
	 * frees a packet once read.
	 */
	skb = first->next;
	first->next = NULL;
	skb_orphan(first);
	while (skb) {
		struct sk_buff *next = skb->next;

		skb_mark_not_on_list(skb);
		consume_skb(skb);
		skb = next;
	}
	return ok;
}

void wg_packet_send_keepalive(struct wg_peer *peer)
{
	struct sk_buff *skb;

	if (skb_queue_empty_lockless(&peer->staged_packet_queue)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH,
				GFP_ATOMIC);
		if (unlikely(!skb))
			return;
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = peer->device->dev;
		PACKET_CB(skb)->mtu = skb->dev->mtu;
		skb_queue_tail(&peer->staged_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %llu (%pISpfsc)\n",
				    peer->device->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
	}

	wg_packet_send_staged_packets(peer);
}

static void wg_packet_create_data_done(struct wg_peer *peer, struct sk_buff *first)
{
	struct sk_buff *skb, *next;
	bool is_keepalive, data_sent = false;

	wg_timers_any_authenticated_packet_traversal(peer);
	wg_timers_any_authenticated_packet_sent(peer);
	/* TSWG: send the encrypted packets; see tswg_encrypt_list. */
	skb = PACKET_CB(first)->tswg_out;
	PACKET_CB(first)->tswg_out = NULL;
	consume_skb(first);
	for (; skb; skb = next) {
		next = skb->next;
		skb_mark_not_on_list(skb);
		is_keepalive = skb->len == message_data_len(0);
		if (likely(!wg_socket_send_skb_to_peer(peer, skb,
				PACKET_CB(skb)->ds) && !is_keepalive))
			data_sent = true;
	}

	if (likely(data_sent))
		wg_timers_data_sent(peer);

	keep_key_fresh(peer);
}

void wg_packet_tx_worker(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer, transmit_packet_work);
	struct noise_keypair *keypair;
	enum packet_state state;
	struct sk_buff *first;

	while ((first = wg_prev_queue_peek(&peer->tx_queue)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(first)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		wg_prev_queue_drop_peeked(&peer->tx_queue);
		keypair = PACKET_CB(first)->keypair;

		if (likely(state == PACKET_STATE_CRYPTED)) {
			wg_packet_create_data_done(peer, first);
		} else {
			kfree_skb_list(PACKET_CB(first)->tswg_out); /* TSWG */
			kfree_skb_list(first);
		}

		wg_noise_keypair_put(keypair, false);
		wg_peer_put(peer);
		if (need_resched())
			cond_resched();
	}
}

void wg_packet_encrypt_worker(struct work_struct *work)
{
	struct multicore_worker *w = container_of(work, struct multicore_worker,
						  work);
	struct crypt_queue *queue = w->ptr;
	struct sk_buff *first;

	WRITE_ONCE(w->tswg_busy, true); /* TSWG */
again:
	while ((first = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state = PACKET_STATE_CRYPTED;

		/* TSWG: see tswg_encrypt_list. */
		if (unlikely(!tswg_encrypt_list(first, &w->tswg_frag)))
			state = PACKET_STATE_DEAD;
		wg_queue_enqueue_per_peer_tx(first, state);
		if (need_resched())
			cond_resched();
	}
	if (!tswg_crypt_worker_idle(w, queue)) /* TSWG */
		goto again;
}

static void wg_packet_create_data(struct wg_peer *peer, struct sk_buff *first)
{
	struct wg_device *wg = peer->device;
	int ret = -EINVAL;

	rcu_read_lock_bh();
	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	ret = wg_queue_enqueue_per_device_and_peer(&wg->encrypt_queue, &peer->tx_queue, first,
						   wg->packet_crypt_wq,
						   TSWG_BATCH_BACKLOG);
	if (unlikely(ret == -EPIPE))
		wg_queue_enqueue_per_peer_tx(first, PACKET_STATE_DEAD);
err:
	rcu_read_unlock_bh();
	if (likely(!ret || ret == -EPIPE))
		return;
	wg_noise_keypair_put(PACKET_CB(first)->keypair, false);
	wg_peer_put(peer);
	kfree_skb_list(first);
}

void wg_packet_purge_staged_packets(struct wg_peer *peer)
{
	spin_lock_bh(&peer->staged_packet_queue.lock);
	DEV_STATS_ADD(peer->device->dev, tx_dropped,
		      peer->staged_packet_queue.qlen);
	__skb_queue_purge(&peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
}

void wg_packet_send_staged_packets(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	struct sk_buff_head packets;
	struct sk_buff *skb;

	/* Steal the current queue into our local one. */
	__skb_queue_head_init(&packets);
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice_init(&peer->staged_packet_queue, &packets);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	if (unlikely(skb_queue_empty(&packets)))
		return;

	/* First we make sure we have a valid reference to a valid key. */
	rcu_read_lock_bh();
	keypair = wg_noise_keypair_get(
		rcu_dereference_bh(peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	if (unlikely(!keypair))
		goto out_nokey;
	if (unlikely(!READ_ONCE(keypair->sending.is_valid)))
		goto out_nokey;
	if (unlikely(wg_birthdate_has_expired(keypair->sending.birthdate,
					      REJECT_AFTER_TIME)))
		goto out_invalid;

	/* After we know we have a somewhat valid key, we now try to assign
	 * nonces to all of the packets in the queue. If we can't assign nonces
	 * for all of them, we just consider it a failure and wait for the next
	 * handshake.
	 */
	skb_queue_walk(&packets, skb) {
		/* 0 for no outer TOS: no leak. TODO: at some later point, we
		 * might consider using flowi->tos as outer instead.
		 */
		PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0, ip_hdr(skb), skb);
		PACKET_CB(skb)->nonce =
				atomic64_inc_return(&keypair->sending_counter) - 1;
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
	}

	packets.prev->next = NULL;
	wg_peer_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	PACKET_CB(packets.next)->tswg_out = NULL; /* TSWG */
	wg_packet_create_data(peer, packets.next);
	return;

out_invalid:
	WRITE_ONCE(keypair->sending.is_valid, false);
out_nokey:
	wg_noise_keypair_put(keypair, false);

	/* We orphan the packets if we're waiting on a handshake, so that they
	 * don't block a socket's pool.
	 */
	skb_queue_walk(&packets, skb)
		skb_orphan(skb);
	/* Then we put them back on the top of the queue. We're not too
	 * concerned about accidentally getting things a little out of order if
	 * packets are being added really fast, because this queue is for before
	 * packets can even be sent and it's small anyway.
	 */
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	/* If we're exiting because there's something wrong with the key, it
	 * means we should initiate a new handshake.
	 */
	wg_packet_send_queued_handshake_initiation(peer, false);
}
