// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include "device.h"
#include "peer.h"
#include "timers.h"
#include "messages.h"
#include "cookie.h"
#include "socket.h"
#include "tswg.h"
#include "tswg_aead.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/ip_tunnels.h>
#include <linux/hash.h> /* TSWG */
#include <linux/kernel_stat.h> /* TSWG */
#include <linux/llist.h> /* TSWG */
#include <linux/tick.h> /* TSWG */

/* Must be called with bh disabled. */
static void update_rx_stats(struct wg_peer *peer, size_t len)
{
	dev_sw_netstats_rx_add(peer->device->dev, len);
	peer->rx_bytes += len;
	tswg_note_activity(peer, &peer->tswg_rx_event, TSWGEVENT_F_RX); /* TSWG */
}

#define SKB_TYPE_LE32(skb) (((struct message_header *)(skb)->data)->type)

/*
 * TSWG: tswg_skb_type is SKB_TYPE_LE32 without TSWG_MESSAGE_RETRY, for
 * handshake messages, which may have it; see validate_header_len.
 */
static __le32 tswg_skb_type(struct sk_buff *skb)
{
	__le32 type = SKB_TYPE_LE32(skb);

	if (type == cpu_to_le32(MESSAGE_DATA))
		return type;
	return type & ~cpu_to_le32(TSWG_MESSAGE_RETRY);
}

static size_t validate_header_len(struct sk_buff *skb)
{
	if (unlikely(skb->len < sizeof(struct message_header)))
		return 0;
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_DATA) &&
	    skb->len >= MESSAGE_MINIMUM_LENGTH)
		return sizeof(struct message_data);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION) &&
	    skb->len == sizeof(struct message_handshake_initiation))
		return sizeof(struct message_handshake_initiation);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE) &&
	    skb->len == sizeof(struct message_handshake_response))
		return sizeof(struct message_handshake_response);
	/* TSWG: hybrid handshake messages, perhaps with the retry bit. */
	if (tswg_skb_type(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION) &&
	    skb->len == sizeof(struct message_handshake_initiation_hybrid))
		return sizeof(struct message_handshake_initiation_hybrid);
	if (tswg_skb_type(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE) &&
	    skb->len == sizeof(struct message_handshake_response_hybrid))
		return sizeof(struct message_handshake_response_hybrid);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE) &&
	    skb->len == sizeof(struct message_handshake_cookie))
		return sizeof(struct message_handshake_cookie);
	return 0;
}

static int prepare_skb_header(struct sk_buff *skb, struct wg_device *wg)
{
	size_t data_offset, data_len, header_len;
	struct udphdr *udp;

	if (unlikely(!wg_check_packet_protocol(skb) ||
		     skb_transport_header(skb) < skb->head ||
		     (skb_transport_header(skb) + sizeof(struct udphdr)) >
			     skb_tail_pointer(skb)))
		return -EINVAL; /* Bogus IP header */
	udp = udp_hdr(skb);
	data_offset = (u8 *)udp - skb->data;
	if (unlikely(data_offset > U16_MAX ||
		     data_offset + sizeof(struct udphdr) > skb->len))
		/* Packet has offset at impossible location or isn't big enough
		 * to have UDP fields.
		 */
		return -EINVAL;
	data_len = udp_get_len_short(udp);
	if (unlikely(data_len < sizeof(struct udphdr) ||
		     data_len > skb->len - data_offset))
		/* UDP packet is reporting too small of a size or lying about
		 * its size.
		 */
		return -EINVAL;
	data_len -= sizeof(struct udphdr);
	data_offset = (u8 *)udp + sizeof(struct udphdr) - skb->data;
	if (unlikely(!pskb_may_pull(skb,
				data_offset + sizeof(struct message_header)) ||
		     pskb_trim(skb, data_len + data_offset) < 0))
		return -EINVAL;
	skb_pull(skb, data_offset);
	if (unlikely(skb->len != data_len))
		/* Final len does not agree with calculated len */
		return -EINVAL;
	header_len = validate_header_len(skb);
	if (unlikely(!header_len))
		return -EINVAL;
	__skb_push(skb, data_offset);
	if (unlikely(!pskb_may_pull(skb, data_offset + header_len)))
		return -EINVAL;
	__skb_pull(skb, data_offset);
	return 0;
}

/*
 * TSWG: tswg_classic_initiation and tswg_classic_response copy a hybrid
 * handshake message's fields but encrypted_kem into the classic message
 * dst, for noise.c; see wg_noise_handshake_*.
 */
static void tswg_classic_initiation(struct message_handshake_initiation *dst,
				    const struct message_handshake_initiation_hybrid *src)
{
	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION);
	dst->sender_index = src->sender_index;
	memcpy(dst->unencrypted_ephemeral, src->unencrypted_ephemeral,
	       sizeof(dst->unencrypted_ephemeral));
	memcpy(dst->encrypted_static, src->encrypted_static,
	       sizeof(dst->encrypted_static));
	memcpy(dst->encrypted_timestamp, src->encrypted_timestamp,
	       sizeof(dst->encrypted_timestamp));
	dst->macs = src->macs;
}

static void tswg_classic_response(struct message_handshake_response *dst,
				  const struct message_handshake_response_hybrid *src)
{
	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE);
	dst->sender_index = src->sender_index;
	dst->receiver_index = src->receiver_index;
	memcpy(dst->unencrypted_ephemeral, src->unencrypted_ephemeral,
	       sizeof(dst->unencrypted_ephemeral));
	memcpy(dst->encrypted_nothing, src->encrypted_nothing,
	       sizeof(dst->encrypted_nothing));
	dst->macs = src->macs;
}

static void wg_receive_handshake_packet(struct wg_device *wg,
					struct sk_buff *skb)
{
	/* TSWG: hybrid handshake messages, converted; see above. */
	struct message_handshake_initiation classic_initiation;
	struct message_handshake_response classic_response;
	const u8 *kem = NULL;
	bool retry;
	enum cookie_mac_state mac_state;
	struct wg_peer *peer = NULL;
	/* This is global, so that our load calculation applies to the whole
	 * system. We don't care about races with it at all.
	 */
	static u64 last_under_load;
	bool packet_needs_cookie;
	bool under_load;

	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE)) {
		net_dbg_skb_ratelimited("%s: Receiving cookie response from %pISpfsc\n",
					wg->dev->name, skb);
		wg_cookie_message_consume(
			(struct message_handshake_cookie *)skb->data, wg);
		return;
	}

	under_load = atomic_read(&wg->handshake_queue_len) >=
			MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	if (under_load) {
		last_under_load = ktime_get_coarse_boottime_ns();
	} else if (last_under_load) {
		under_load = !wg_birthdate_has_expired(last_under_load, 1);
		if (!under_load)
			last_under_load = 0;
	}
	mac_state = wg_cookie_validate_packet(&wg->cookie_checker, skb,
					      under_load);
	if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) ||
	    (!under_load && mac_state == VALID_MAC_BUT_NO_COOKIE)) {
		packet_needs_cookie = false;
	} else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE) {
		packet_needs_cookie = true;
	} else {
		net_dbg_skb_ratelimited("%s: Invalid MAC of handshake, dropping packet from %pISpfsc\n",
					wg->dev->name, skb);
		return;
	}

	retry = SKB_TYPE_LE32(skb) & cpu_to_le32(TSWG_MESSAGE_RETRY);
	switch (tswg_skb_type(skb)) {
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION): {
		struct message_handshake_initiation *message =
			(struct message_handshake_initiation *)skb->data;

		if (skb->len == sizeof(struct message_handshake_initiation_hybrid)) {
			struct message_handshake_initiation_hybrid *hyb =
				(void *)skb->data;

			tswg_classic_initiation(&classic_initiation, hyb);
			message = &classic_initiation;
			kem = hyb->encrypted_kem;
		}
		if (packet_needs_cookie) {
			wg_packet_send_handshake_cookie(wg, skb,
							message->sender_index);
			return;
		}
		peer = wg_noise_handshake_consume_initiation(message, kem, wg);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("%s: Invalid handshake initiation from %pISpfsc\n",
						wg->dev->name, skb);
			return;
		}
		wg_socket_set_peer_endpoint_from_skb(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake initiation from peer %llu (%pISpfsc)\n",
				    wg->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		wg_packet_send_handshake_response(peer, retry);
		break;
	}
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE): {
		struct message_handshake_response *message =
			(struct message_handshake_response *)skb->data;

		if (skb->len == sizeof(struct message_handshake_response_hybrid)) {
			struct message_handshake_response_hybrid *hyb =
				(void *)skb->data;

			tswg_classic_response(&classic_response, hyb);
			message = &classic_response;
			kem = hyb->encrypted_kem;
		}
		if (packet_needs_cookie) {
			wg_packet_send_handshake_cookie(wg, skb,
							message->sender_index);
			return;
		}
		peer = wg_noise_handshake_consume_response(message, kem, wg);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("%s: Invalid handshake response from %pISpfsc\n",
						wg->dev->name, skb);
			return;
		}
		wg_socket_set_peer_endpoint_from_skb(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake response from peer %llu (%pISpfsc)\n",
				    wg->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		if (wg_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			wg_timers_session_derived(peer);
			wg_timers_handshake_complete(peer);
			/* Calling this function will either send any existing
			 * packets in the queue and not send a keepalive, which
			 * is the best case, Or, if there's nothing in the
			 * queue, it will send a keepalive, in order to give
			 * immediate confirmation of the session.
			 */
			wg_packet_send_keepalive(peer);
		}
		break;
	}
	}

	if (unlikely(!peer)) {
		WARN(1, "Somehow a wrong type of packet wound up in the handshake queue!\n");
		return;
	}

	local_bh_disable();
	update_rx_stats(peer, skb->len);
	local_bh_enable();

	wg_timers_any_authenticated_packet_received(peer);
	wg_timers_any_authenticated_packet_traversal(peer);
	wg_peer_put(peer);
}

void wg_packet_handshake_receive_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct multicore_worker, work)->ptr;
	struct wg_device *wg = container_of(queue, struct wg_device, handshake_queue);
	struct sk_buff *skb;

	while ((skb = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		wg_receive_handshake_packet(wg, skb);
		dev_kfree_skb(skb);
		atomic_dec(&wg->handshake_queue_len);
		cond_resched();
	}
}

static void keep_key_fresh(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	bool send;

	if (peer->sent_lastminute_handshake)
		return;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	send = keypair && READ_ONCE(keypair->sending.is_valid) &&
	       keypair->i_am_the_initiator &&
	       wg_birthdate_has_expired(keypair->sending.birthdate,
			REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT);
	rcu_read_unlock_bh();

	if (unlikely(send)) {
		peer->sent_lastminute_handshake = true;
		wg_packet_send_queued_handshake_initiation(peer, false);
	}
}

static bool keypair_may_receive(struct noise_keypair *keypair)
{
	if (unlikely(!keypair))
		return false;

	if (unlikely(!READ_ONCE(keypair->receiving.is_valid) ||
		  wg_birthdate_has_expired(keypair->receiving.birthdate, REJECT_AFTER_TIME) ||
		  READ_ONCE(keypair->receiving_counter.counter) >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(keypair->receiving.is_valid, false);
		return false;
	}
	return true;
}

/*
 * TSWG: TSWG_RX_COPYBREAK is the plaintext size below which
 * tswg_decrypt_gso copies a message out rather than decrypting it in place
 * and referencing its pages: for small ones (TCP ACKs, say), copying is
 * cheap, and holding on to a page for them wastes memory.
 * TSWG_RX_HEADROOM is the headroom we give packets that reference pages,
 * for the link layer header if they're forwarded.
 */
#define TSWG_RX_COPYBREAK 256

/*
 * TSWG: rx_zerocopy turns on decrypting in place (tswg_decrypt_message_zc).
 * It's off by default: on a CPU-bound router it was 7% slower than
 * copying, since scatterlist decryption costs more than linear decryption
 * of a cache-hot copy; it may win where page allocation is the limit.
 */
static bool tswg_rx_zerocopy;
module_param_named(rx_zerocopy, tswg_rx_zerocopy, bool, 0644);
MODULE_PARM_DESC(rx_zerocopy, "decrypt received data messages in place, without copying them out");
#define TSWG_RX_HEADROOM (NET_SKB_PAD + LL_MAX_HEADER)

/*
 * tswg_writable reports whether we may change skb's data in place: no one
 * else can see it (as a clone, or a tap's copy, would), and it's all in
 * memory we can read (not devmem).
 */
static bool tswg_writable(struct sk_buff *skb)
{
	return !skb_cloned(skb) && !skb_has_shared_frag(skb) &&
	       skb_frags_readable(skb);
}

/*
 * tswg_ref_range appends to nskb's frags references to the len bytes of
 * skb's data at off, as skb_segment does. They must be in skb's head (if
 * that's a page fragment), its page frags, or (recursively) its frag_list
 * members, all writable. It reports whether it could.
 */
static bool tswg_ref_range(struct sk_buff *nskb, struct sk_buff *skb,
			   unsigned int off, unsigned int len)
{
	struct skb_shared_info *si = skb_shinfo(skb);
	unsigned int headlen = skb_headlen(skb);
	struct sk_buff *member;
	int i;

	if (!tswg_writable(skb) ||
	    (skb_shinfo(nskb)->nr_frags && nskb->pp_recycle != skb->pp_recycle))
		return false;
	nskb->pp_recycle = skb->pp_recycle;
	if (off < headlen) {
		unsigned int n = min(len, headlen - off);
		struct page *page;
		skb_frag_t *f;

		if (!skb->head_frag || skb_shinfo(nskb)->nr_frags >= MAX_SKB_FRAGS)
			return false;
		page = virt_to_head_page(skb->head);
		f = &skb_shinfo(nskb)->frags[skb_shinfo(nskb)->nr_frags];
		skb_frag_fill_page_desc(f, page,
					skb->data + off - (unsigned char *)page_address(page), n);
		skb_frag_ref(nskb, skb_shinfo(nskb)->nr_frags++);
		off += n;
		len -= n;
	}
	off -= min(off, headlen);
	for (i = 0; len && i < si->nr_frags; i++) {
		unsigned int size = skb_frag_size(&si->frags[i]), n;
		skb_frag_t *f;

		if (off >= size) {
			off -= size;
			continue;
		}
		if (skb_shinfo(nskb)->nr_frags >= MAX_SKB_FRAGS)
			return false;
		n = min(len, size - off);
		f = &skb_shinfo(nskb)->frags[skb_shinfo(nskb)->nr_frags];
		*f = si->frags[i];
		skb_frag_off_add(f, off);
		skb_frag_size_set(f, n);
		skb_frag_ref(nskb, skb_shinfo(nskb)->nr_frags++);
		off = 0;
		len -= n;
	}
	/*
	 * Past the frags (the loop has taken their sizes off off), off is
	 * relative to the frag_list's data. Its members are whole datagrams
	 * (see tswg_gro_merge), so a message doesn't usually straddle them.
	 */
	skb_walk_frags(skb, member) {
		unsigned int n;

		if (!len)
			break;
		if (off >= member->len) {
			off -= member->len;
			continue;
		}
		n = min(len, member->len - off);
		if (!tswg_ref_range(nskb, member, off, n))
			return false;
		off = 0;
		len -= n;
	}
	return !len;
}

/*
 * tswg_decrypt_message_zc decrypts the message at off in skb, of enc_len
 * bytes after its header, in place, and returns a new packet that
 * references its plaintext. It returns NULL if it can't, leaving skb
 * untouched, or ERR_PTR(-EBADMSG) if the message doesn't authenticate.
 */
static noinline_for_stack struct sk_buff *
tswg_decrypt_message_zc(struct sk_buff *skb, unsigned int off,
			unsigned int enc_len, u64 nonce,
			struct noise_keypair *keypair)
{
	unsigned int plain_len = enc_len - noise_encrypted_len(0);
	struct scatterlist sg[MAX_SKB_FRAGS + 2];
	struct sk_buff *nskb;
	int n;

	nskb = alloc_skb(TSWG_RX_HEADROOM, GFP_ATOMIC);
	if (unlikely(!nskb))
		return NULL;
	skb_reserve(nskb, TSWG_RX_HEADROOM);
	if (unlikely(!tswg_ref_range(nskb, skb, off, plain_len)))
		goto fail;
	sg_init_table(sg, ARRAY_SIZE(sg));
	n = skb_to_sgvec(skb, sg, off, enc_len);
	if (unlikely(n <= 0))
		goto fail;
	if (!chacha20poly1305_decrypt_sg_inplace(sg, enc_len, NULL, 0, nonce,
						 keypair->receiving.key)) {
		kfree_skb(nskb);
		return ERR_PTR(-EBADMSG);
	}
	nskb->len = nskb->data_len = plain_len;
	nskb->truesize += plain_len;
	return nskb;
fail:
	kfree_skb(nskb);
	return NULL;
}

/*
 * TSWG: tswg_contig returns a pointer to the len bytes of skb's data at off
 * if they're contiguous in memory: in its head, or in one page frag (of
 * its own or of a frag_list member's), which is where a message received
 * in one datagram ends up. Otherwise it returns NULL. *ahead says whether
 * the CHACHA_BLOCK_SIZE bytes before them are in the same memory (the
 * head's buffer, or the frag's page) too; see tswg_aead_decrypt_ahead.
 */
static const u8 *tswg_contig(const struct sk_buff *skb, unsigned int off,
			     unsigned int len, bool *ahead)
{
	unsigned int headlen = skb_headlen(skb);
	const struct sk_buff *member;
	int i;

	if (off + len <= headlen) {
		*ahead = skb->data + off >= skb->head + CHACHA_BLOCK_SIZE;
		return skb->data + off;
	}
	if (off < headlen)
		return NULL;
	off -= headlen;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *f = &skb_shinfo(skb)->frags[i];
		unsigned int size = skb_frag_size(f);
		struct page *page;

		if (off >= size) {
			off -= size;
			continue;
		}
		if (off + len > size)
			return NULL;
		page = skb_frag_page(f);
		if (!page || PageHighMem(page))
			return NULL;
		*ahead = skb_frag_off(f) + off >= CHACHA_BLOCK_SIZE;
		return (const u8 *)page_address(page) + skb_frag_off(f) + off;
	}
	skb_walk_frags(skb, member) {
		if (off < member->len)
			return tswg_contig(member, off, len, ahead);
		off -= member->len;
	}
	return NULL;
}

/*
 * TSWG: tswg_decrypt_message_copy decrypts the message at off in skb, of
 * enc_len bytes after its header, into a new packet, which it returns, or
 * NULL if it can't or the message doesn't authenticate.
 */
static noinline_for_stack struct sk_buff *
tswg_decrypt_message_copy(struct sk_buff *skb, unsigned int off,
			  unsigned int enc_len, u64 nonce,
			  struct noise_keypair *keypair, struct net_device *dev)
{
	struct sk_buff *nskb;
	const u8 *src;
	bool ok, ahead;

	nskb = netdev_alloc_skb(dev, enc_len);
	if (unlikely(!nskb))
		return NULL;
	/*
	 * Decrypt straight from skb when the message is contiguous there, as
	 * it usually is, rather than copy it out and decrypt the copy in
	 * place: one pass over it fewer.
	 */
	src = tswg_contig(skb, off, enc_len, &ahead);
	if (likely(src && ahead && skb_headroom(nskb) >= CHACHA_BLOCK_SIZE)) {
		ok = tswg_aead_decrypt_ahead(skb_put(nskb, enc_len - noise_encrypted_len(0)),
					     src, enc_len, nonce,
					     keypair->receiving.key);
	} else if (src) {
		ok = tswg_aead_decrypt(skb_put(nskb, enc_len - noise_encrypted_len(0)),
				       src, enc_len, nonce, keypair->receiving.key);
	} else {
		ok = !skb_copy_bits(skb, off, skb_put(nskb, enc_len), enc_len) &&
		     tswg_aead_decrypt(nskb->data, nskb->data, enc_len, nonce,
				       keypair->receiving.key);
		__skb_trim(nskb, enc_len - noise_encrypted_len(0));
	}
	if (unlikely(!ok)) {
		kfree_skb(nskb);
		return NULL;
	}
	return nskb;
}

/*
 * TSWG: tswg_decrypt_gso decrypts each data message of skb, a packet merged
 * by tswg_gro_receive, into a new packet, listed in
 * PACKET_CB(skb)->tswg_out. Messages that fail to decrypt are dropped,
 * like upstream drops packets that do.
 */
static bool tswg_decrypt_gso(struct sk_buff *skb, struct noise_keypair *keypair)
{
	struct sk_buff **tail = &PACKET_CB(skb)->tswg_out;
	unsigned int mss = skb_shinfo(skb)->gso_size;
	struct net_device *dev = keypair->entry.peer->device->dev;
	unsigned int off, len;

	if (unlikely(!mss))
		return false;
	for (off = 0; off < skb->len; off += len) {
		struct message_data hdr_buf;
		const struct message_data *hdr;
		unsigned int enc_len;
		struct sk_buff *nskb;
		u64 nonce;

		len = min(mss, skb->len - off);
		if (unlikely(len < message_data_len(0)))
			break;
		hdr = skb_header_pointer(skb, off, sizeof(*hdr), &hdr_buf);
		if (unlikely(!hdr))
			break;
		nonce = le64_to_cpu(hdr->counter);
		enc_len = len - sizeof(*hdr);
		nskb = NULL;
		if (READ_ONCE(tswg_rx_zerocopy) &&
		    enc_len - noise_encrypted_len(0) >= TSWG_RX_COPYBREAK) {
			nskb = tswg_decrypt_message_zc(skb, off + sizeof(*hdr),
						       enc_len, nonce, keypair);
			if (IS_ERR(nskb))
				continue;
		}
		if (!nskb)
			nskb = tswg_decrypt_message_copy(skb, off + sizeof(*hdr),
							 enc_len, nonce, keypair, dev);
		if (unlikely(!nskb))
			continue;
		skb_reset_mac_header(nskb);
		skb_reset_network_header(nskb);
		PACKET_CB(nskb)->nonce = nonce;
		PACKET_CB(nskb)->keypair = keypair; /* skb holds the reference */
		PACKET_CB(nskb)->ds = PACKET_CB(skb)->ds;
		*tail = nskb;
		tail = &nskb->next;
	}
	return true;
}

static bool decrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair)
{
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct sk_buff *trailer;
	unsigned int offset;
	int num_frags;

	if (unlikely(!keypair_may_receive(keypair)))
		return false;
	if (skb_is_gso(skb)) /* TSWG */
		return tswg_decrypt_gso(skb, keypair);

	PACKET_CB(skb)->nonce =
		le64_to_cpu(((struct message_data *)skb->data)->counter);

	/* We ensure that the network header is part of the packet before we
	 * call skb_cow_data, so that there's no chance that data is removed
	 * from the skb, so that later we can extract the original endpoint.
	 */
	offset = -skb_network_offset(skb);
	skb_push(skb, offset);
	num_frags = skb_cow_data(skb, 0, &trailer);
	offset += sizeof(struct message_data);
	skb_pull(skb, offset);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0)
		return false;

	if (!chacha20poly1305_decrypt_sg_inplace(sg, skb->len, NULL, 0,
					         PACKET_CB(skb)->nonce,
						 keypair->receiving.key))
		return false;

	/* Another ugly situation of pushing and pulling the header so as to
	 * keep endpoint information intact.
	 */
	skb_push(skb, offset);
	if (pskb_trim(skb, skb->len - noise_encrypted_len(0)))
		return false;
	skb_pull(skb, offset);

	return true;
}

/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
static bool counter_validate(struct noise_replay_counter *counter, u64 their_counter)
{
	unsigned long index, index_current, top, i;
	bool ret = false;

	spin_lock_bh(&counter->lock);

	if (unlikely(counter->counter >= REJECT_AFTER_MESSAGES + 1 ||
		     their_counter >= REJECT_AFTER_MESSAGES))
		goto out;

	++their_counter;

	if (unlikely((COUNTER_WINDOW_SIZE + their_counter) <
		     counter->counter))
		goto out;

	index = their_counter >> ilog2(BITS_PER_LONG);

	if (likely(their_counter > counter->counter)) {
		index_current = counter->counter >> ilog2(BITS_PER_LONG);
		top = min_t(unsigned long, index - index_current,
			    COUNTER_BITS_TOTAL / BITS_PER_LONG);
		for (i = 1; i <= top; ++i)
			counter->backtrack[(i + index_current) &
				((COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1)] = 0;
		WRITE_ONCE(counter->counter, their_counter);
	}

	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;
	ret = !test_and_set_bit(their_counter & (BITS_PER_LONG - 1),
				&counter->backtrack[index]);

out:
	spin_unlock_bh(&counter->lock);
	return ret;
}

#include "selftest/counter.c"

/*
 * wg_packet_consume_data_done delivers skb. TSWG: through the device's
 * per-CPU GRO cells if now (see tswg_receive_now), or else the peer's
 * NAPI, whose poll this is.
 */
static void wg_packet_consume_data_done(struct wg_peer *peer,
					struct sk_buff *skb,
					struct endpoint *endpoint, bool now)
{
	struct net_device *dev = peer->device->dev;
	unsigned int len, len_before_trim;
	struct wg_peer *routed_peer;

	if (tswg_peer_may_roam(peer)) /* TSWG */
		wg_socket_set_peer_endpoint(peer, endpoint);

	if (unlikely(wg_noise_received_with_keypair(&peer->keypairs,
						    PACKET_CB(skb)->keypair))) {
		wg_timers_handshake_complete(peer);
		wg_packet_send_staged_packets(peer);
	}

	keep_key_fresh(peer);

	wg_timers_any_authenticated_packet_received(peer);
	wg_timers_any_authenticated_packet_traversal(peer);

	/* A packet with length 0 is a keepalive packet */
	if (unlikely(!skb->len)) {
		update_rx_stats(peer, message_data_len(0));
		net_dbg_ratelimited("%s: Receiving keepalive packet from peer %llu (%pISpfsc)\n",
				    dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		goto packet_processed;
	}

	wg_timers_data_received(peer);

	if (unlikely(skb_network_header(skb) < skb->head))
		goto dishonest_packet_size;
	if (unlikely(!(pskb_network_may_pull(skb, sizeof(struct iphdr)) &&
		       (ip_hdr(skb)->version == 4 ||
			(ip_hdr(skb)->version == 6 &&
			 pskb_network_may_pull(skb, sizeof(struct ipv6hdr)))))))
		goto dishonest_packet_type;

	skb->dev = dev;
	/* We've already verified the Poly1305 auth tag, which means this packet
	 * was not modified in transit. We can therefore tell the networking
	 * stack that all checksums of every layer of encapsulation have already
	 * been checked "by the hardware" and therefore is unnecessary to check
	 * again in software.
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = ~0; /* All levels */
	skb->protocol = ip_tunnel_parse_protocol(skb);
	if (skb->protocol == htons(ETH_P_IP)) {
		len = ntohs(ip_hdr(skb)->tot_len);
		if (unlikely(len < sizeof(struct iphdr)))
			goto dishonest_packet_size;
		INET_ECN_decapsulate(skb, PACKET_CB(skb)->ds, ip_hdr(skb)->tos);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		len = ntohs(ipv6_hdr(skb)->payload_len) +
		      sizeof(struct ipv6hdr);
		INET_ECN_decapsulate(skb, PACKET_CB(skb)->ds, ipv6_get_dsfield(ipv6_hdr(skb)));
	} else {
		goto dishonest_packet_type;
	}

	if (unlikely(len > skb->len))
		goto dishonest_packet_size;
	len_before_trim = skb->len;
	if (unlikely(pskb_trim(skb, len)))
		goto packet_processed;

	routed_peer = wg_allowedips_lookup_src(&peer->device->peer_allowedips,
					       skb);
	wg_peer_put(routed_peer); /* We don't need the extra reference. */

	if (unlikely(routed_peer != peer))
		goto dishonest_packet_peer;

	if (now) /* TSWG */
		gro_cells_receive(&peer->device->tswg_gro_cells, skb);
	else
		napi_gro_receive(&peer->napi, skb);
	update_rx_stats(peer, message_data_len(len_before_trim));
	return;

dishonest_packet_peer:
	net_dbg_skb_ratelimited("%s: Packet has unallowed src IP (%pISc) from peer %llu (%pISpfsc)\n",
				dev->name, skb, peer->internal_id,
				&peer->endpoint.addr);
	DEV_STATS_INC(dev, rx_errors);
	DEV_STATS_INC(dev, rx_frame_errors);
	goto packet_processed;
dishonest_packet_type:
	net_dbg_ratelimited("%s: Packet is neither ipv4 nor ipv6 from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	DEV_STATS_INC(dev, rx_errors);
	DEV_STATS_INC(dev, rx_frame_errors);
	goto packet_processed;
dishonest_packet_size:
	net_dbg_ratelimited("%s: Packet has incorrect size from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	DEV_STATS_INC(dev, rx_errors);
	DEV_STATS_INC(dev, rx_length_errors);
	goto packet_processed;
packet_processed:
	dev_kfree_skb(skb);
}

/*
 * TSWG: tswg_receive_gso delivers the packets decrypted from skb (see
 * tswg_decrypt_gso) and returns how many there were.
 */
static int tswg_receive_gso(struct wg_peer *peer, struct sk_buff *skb,
			    bool now)
{
	struct noise_keypair *keypair = PACKET_CB(skb)->keypair;
	struct sk_buff *nskb = PACKET_CB(skb)->tswg_out, *next;
	struct endpoint endpoint;
	bool have_endpoint;
	int n = 0;

	PACKET_CB(skb)->tswg_out = NULL;
	have_endpoint = !wg_socket_endpoint_from_skb(&endpoint, skb);
	for (; nskb; nskb = next) {
		next = nskb->next;
		skb_mark_not_on_list(nskb);
		n++;
		if (unlikely(!have_endpoint ||
			     !counter_validate(&keypair->receiving_counter,
					       PACKET_CB(nskb)->nonce))) {
			dev_kfree_skb(nskb);
			continue;
		}
		wg_packet_consume_data_done(peer, nskb, &endpoint, now);
	}
	return n;
}

int wg_packet_rx_poll(struct napi_struct *napi, int budget)
{
	struct wg_peer *peer = container_of(napi, struct wg_peer, napi);
	struct noise_keypair *keypair;
	struct endpoint endpoint;
	enum packet_state state;
	struct sk_buff *skb;
	int work_done = 0;
	bool free;

	if (unlikely(budget <= 0))
		return 0;

	while ((skb = wg_prev_queue_peek(&peer->rx_queue)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(skb)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		wg_prev_queue_drop_peeked(&peer->rx_queue);
		keypair = PACKET_CB(skb)->keypair;
		free = true;

		if (unlikely(state != PACKET_STATE_CRYPTED))
			goto next;

		if (skb_is_gso(skb)) { /* TSWG */
			work_done += max(tswg_receive_gso(peer, skb, false), 1) - 1;
			goto next;
		}

		if (unlikely(!counter_validate(&keypair->receiving_counter,
					       PACKET_CB(skb)->nonce))) {
			net_dbg_ratelimited("%s: Packet has invalid nonce %llu (max %llu)\n",
					    peer->device->dev->name,
					    PACKET_CB(skb)->nonce,
					    READ_ONCE(keypair->receiving_counter.counter));
			goto next;
		}

		if (unlikely(wg_socket_endpoint_from_skb(&endpoint, skb)))
			goto next;

		wg_reset_packet(skb, false);
		wg_packet_consume_data_done(peer, skb, &endpoint, false);
		free = false;

next:
		/*
		 * TSWG: drop what tswg_decrypt_gso decrypted but we didn't
		 * deliver. Only while we still own skb: once delivered, its cb
		 * is GRO's.
		 */
		if (unlikely(free && PACKET_CB(skb)->tswg_out)) {
			kfree_skb_list(PACKET_CB(skb)->tswg_out);
			PACKET_CB(skb)->tswg_out = NULL;
		}
		wg_noise_keypair_put(keypair, false);
		wg_peer_put(peer);
		if (unlikely(free))
			dev_kfree_skb(skb);

		if (++work_done >= budget)
			break;
	}

	if (work_done < budget)
		napi_complete_done(napi, work_done);

	/* TSWG: a GSO packet counts as all its segments, so may overshoot. */
	return min(work_done, budget);
}

void wg_packet_decrypt_worker(struct work_struct *work)
{
	struct multicore_worker *w = container_of(work, struct multicore_worker,
						  work);
	struct crypt_queue *queue = w->ptr;
	struct sk_buff *skb;

	WRITE_ONCE(w->tswg_busy, true); /* TSWG */
again:
	while ((skb = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state =
			likely(decrypt_packet(skb, PACKET_CB(skb)->keypair)) ?
				PACKET_STATE_CRYPTED : PACKET_STATE_DEAD;
		wg_queue_enqueue_per_peer_rx(skb, state);
		if (need_resched())
			cond_resched();
	}
	if (!tswg_crypt_worker_idle(w, queue)) /* TSWG */
		goto again;
}

/*
 * TSWG: run-to-completion receive, as tswg_xmit_now is for transmit.
 *
 * Upstream hands each data packet to a crypt worker through a ring that
 * all of a device's CPUs share, and the decrypted packet to the peer's
 * NAPI through its in-order queue, so that one peer's packets can be
 * decrypted on many CPUs in parallel and still be delivered in order: two
 * device-wide locks, a wakeup or two, and two more CPUs per packet. But a
 * peer's packets, one UDP flow, already arrive on one CPU, in order (RSS),
 * so tswg_receive_now decrypts them there and delivers them through the
 * device's per-CPU GRO cells, as tunnels like VXLAN do. It's called in
 * softirq, from the UDP socket's encap_rcv, with the references
 * wg_packet_consume_data took, which it drops.
 *
 * But that's one CPU per peer, which a single fast peer outruns: one TCP
 * stream through a tunnel fell from 12.2 to 6.6 Gbps in the lab. So a peer
 * goes the parallel way while it's receiving more than rx_inline_mbps
 * (module parameter; 0 for never inline), over TSWG_RX_WINDOW (a jiffy was
 * too short: GRO's bursts put peers of a router averaging 2 Gbps over 4),
 * and for TSWG_RX_PARALLEL_FOR after (switching back and forth often cost
 * more than either way), and back only once that way has delivered all it
 * had, so that switching doesn't reorder the peer's packets; see
 * tswg_rx_path. Peers arriving on a CPU that's too busy go to other CPUs;
 * see tswg_steer.
 */
#define TSWG_RX_WINDOW max(HZ / 100, 1)
#define TSWG_RX_PARALLEL_FOR (HZ / 10)

static unsigned int tswg_rx_inline_mbps = 4000;
module_param_named(rx_inline_mbps, tswg_rx_inline_mbps, uint, 0644);
MODULE_PARM_DESC(rx_inline_mbps, "receive a peer's packets where they arrive while it's below this rate (0: never)");

/* tswg_squeeze is what tswg_cpu_squeezed knows of a CPU. */
struct tswg_squeeze {
	unsigned int seen; /* the CPU's softnet_data.time_squeeze, as last seen */
	unsigned long jiffy; /* when it last changed */
	bool ever; /* whether it has */
};
static DEFINE_PER_CPU(struct tswg_squeeze, tswg_squeeze);

/*
 * tswg_cpu_squeezed reports whether this CPU's softirq network work has
 * recently run out of budget or time (as softnet_data.time_squeeze, the
 * third column of /proc/net/softnet_stat, counts), and so is more than the
 * CPU can do. BHs must be off.
 */
static bool tswg_cpu_squeezed(void)
{
	unsigned int n = READ_ONCE(this_cpu_ptr(&softnet_data)->time_squeeze);
	struct tswg_squeeze *q = this_cpu_ptr(&tswg_squeeze);

	if (n != q->seen) {
		q->seen = n;
		q->jiffy = jiffies;
		q->ever = true;
	}
	return q->ever && time_before(jiffies, q->jiffy + TSWG_RX_PARALLEL_FOR);
}

static void tswg_receive_now(struct wg_peer *peer, struct sk_buff *skb);

/*
 * TSWG: steering. When the CPU a peer's packets arrive on is busy (as the
 * CPUs taking a NIC's interrupts are, when the NIC has fewer queues than
 * the host has CPUs, and the peers hash unevenly onto them), receiving
 * them all there holds them up: a big host downloading from 37 peers over
 * 32 queues reached 63 Gbps with its NIC's CPUs at 100% and the rest idle,
 * 91 with RPS. So then each of the CPU's peers' packets goes to the peer's
 * home CPU (by hash, as RPS does, but per peer and for our packets only),
 * through a lockless list, and that CPU's NAPI receives them. A peer's
 * packets all go to one CPU, in order.
 *
 * rx_steer_busy (module parameter) is how busy a CPU must be (percent, over
 * TSWG_LOAD_WINDOW_US) to steer its peers' packets; 0 turns steering off.
 */
static unsigned int tswg_rx_steer_busy = 90;
module_param_named(rx_steer_busy, tswg_rx_steer_busy, uint, 0644);
MODULE_PARM_DESC(rx_steer_busy, "percent busy a CPU must be to hand its peers' received packets to other CPUs (0: never)");

#define TSWG_LOAD_WINDOW_US 10000
#define TSWG_STEER_FOR HZ

/*
 * tswg_cpu_load is what tswg_cpu_busy knows of a CPU. Any CPU may update
 * it; racing updates just lose a window.
 */
struct tswg_cpu_load {
	u64 idle_us, wall_us; /* at the start of the current window */
	unsigned int busy; /* percent busy in the last window */
	unsigned long rx_jiffy; /* when it last received for us from a NIC */
};
static DEFINE_PER_CPU(struct tswg_cpu_load, tswg_cpu_load);

/*
 * tswg_cpu_busy returns how busy (percent) cpu was in its last whole
 * TSWG_LOAD_WINDOW_US, from its idle time, or -1 if that isn't known (no
 * NO_HZ accounting).
 */
static int tswg_cpu_busy(int cpu)
{
	struct tswg_cpu_load *l = per_cpu_ptr(&tswg_cpu_load, cpu);
	u64 wall, idle = get_cpu_idle_time_us(cpu, &wall);
	u64 start = READ_ONCE(l->wall_us);

	if (idle == (u64)-1)
		return -1;
	if (wall - start >= TSWG_LOAD_WINDOW_US) {
		u64 dw = wall - start, di = idle - READ_ONCE(l->idle_us);

		WRITE_ONCE(l->busy, start && di <= dw ? 100 - div64_u64(di * 100, dw) : 0);
		WRITE_ONCE(l->idle_us, idle);
		WRITE_ONCE(l->wall_us, wall);
	}
	return READ_ONCE(l->busy);
}

/*
 * tswg_cpu_overloaded reports whether this CPU was more than rx_steer_busy
 * percent busy in its last TSWG_LOAD_WINDOW_US, or its softirq work ran out
 * of budget or time (tswg_cpu_squeezed). BHs must be off.
 */
static bool tswg_cpu_overloaded(void)
{
	unsigned int max = READ_ONCE(tswg_rx_steer_busy);
	int busy;

	if (!max)
		return false;
	busy = tswg_cpu_busy(smp_processor_id());
	return busy > (int)max || tswg_cpu_squeezed();
}

/*
 * tswg_home_load returns how loaded cpu is as a home for steered packets:
 * its busy percent, or more than any CPU can be if it's offline or itself
 * receiving from a NIC (whose CPUs are what steering is to relieve).
 */
static int tswg_home_load(int cpu)
{
	struct tswg_cpu_load *l = per_cpu_ptr(&tswg_cpu_load, cpu);

	if (!cpu_online(cpu) || jiffies - READ_ONCE(l->rx_jiffy) <= HZ / 10)
		return 1000;
	return max(tswg_cpu_busy(cpu), 0);
}

/*
 * TSWG_HOME_CHOICES is how many CPUs, spread from a point peer's ID hashes
 * to, tswg_peer_home compares to pick a home. Taking the first that would
 * do, rather than the least loaded, piled peers onto a few.
 */
#define TSWG_HOME_CHOICES 8

/*
 * tswg_peer_home returns the CPU that peer's steered packets go to: the
 * one it went to last, while that isn't overloaded, or else the least
 * loaded of TSWG_HOME_CHOICES.
 */
static int tswg_peer_home(struct wg_peer *peer)
{
	int home = READ_ONCE(peer->tswg_home), k, cpu, load, best = INT_MAX;
	unsigned int n = num_online_cpus(), i;

	if (home >= 0 && home < nr_cpu_ids &&
	    tswg_home_load(home) <= (int)READ_ONCE(tswg_rx_steer_busy))
		return home;
	i = hash_64(peer->internal_id, 32);
	for (k = 0; k < TSWG_HOME_CHOICES; k++) {
		cpu = cpumask_nth((i + k * (n / TSWG_HOME_CHOICES + 1)) % n,
				  cpu_online_mask);
		load = tswg_home_load(cpu);
		if (load < best) {
			best = load;
			home = cpu;
		}
	}
	WRITE_ONCE(peer->tswg_home, home);
	return home;
}

static void tswg_steer_ipi(void *info)
{
	napi_schedule(&((struct tswg_steer *)info)->napi);
}

/*
 * tswg_steer hands skb, from peer, with the references
 * wg_packet_consume_data took, to cpu's tswg_steer_poll.
 */
static void tswg_steer(struct wg_device *wg, struct wg_peer *peer,
		       struct sk_buff *skb, int cpu)
{
	struct tswg_steer *s = per_cpu_ptr(wg->tswg_steer, cpu);

	atomic_inc(&peer->tswg_steered);
	/* The first to an empty list wakes its NAPI; see tswg_steer_poll. */
	if (llist_add(&skb->ll_node, &s->in))
		smp_call_function_single_async(cpu, &s->csd);
}

static int tswg_steer_poll(struct napi_struct *napi, int budget)
{
	struct tswg_steer *s = container_of(napi, struct tswg_steer, napi);
	struct sk_buff *skb, *tmp;
	struct llist_node *n;
	struct wg_peer *peer;
	int done = 0;

	if (skb_queue_empty(&s->todo)) {
		n = llist_reverse_order(llist_del_all(&s->in));
		llist_for_each_entry_safe(skb, tmp, n, ll_node)
			__skb_queue_tail(&s->todo, skb);
	}
	while (done < budget && (skb = __skb_dequeue(&s->todo)) != NULL) {
		peer = PACKET_PEER(skb);
		atomic_dec(&peer->tswg_steered);
		rcu_read_lock_bh();
		tswg_receive_now(peer, skb);
		rcu_read_unlock_bh();
		done++;
	}
	if (done < budget && napi_complete_done(napi, done) &&
	    !llist_empty(&s->in))
		napi_schedule(napi); /* added since we took them */
	return done;
}

int tswg_steer_init(struct wg_device *wg)
{
	int cpu;

	wg->tswg_steer = alloc_percpu(struct tswg_steer);
	if (!wg->tswg_steer)
		return -ENOMEM;
	for_each_possible_cpu(cpu) {
		struct tswg_steer *s = per_cpu_ptr(wg->tswg_steer, cpu);

		init_llist_head(&s->in);
		__skb_queue_head_init(&s->todo);
		INIT_CSD(&s->csd, tswg_steer_ipi, s);
		set_bit(NAPI_STATE_NO_BUSY_POLL, &s->napi.state);
		netif_napi_add(wg->dev, &s->napi, tswg_steer_poll);
		napi_enable(&s->napi);
	}
	return 0;
}

/* tswg_steer_drop drops skb, which was being steered. */
static void tswg_steer_drop(struct sk_buff *skb)
{
	struct wg_peer *peer = PACKET_PEER(skb);

	atomic_dec(&peer->tswg_steered);
	wg_noise_keypair_put(PACKET_CB(skb)->keypair, false);
	wg_peer_put(peer);
	kfree_skb(skb);
}

void tswg_steer_uninit(struct wg_device *wg)
{
	struct sk_buff *skb, *tmp;
	int cpu;

	for_each_possible_cpu(cpu) {
		struct tswg_steer *s = per_cpu_ptr(wg->tswg_steer, cpu);

		napi_disable(&s->napi);
		netif_napi_del(&s->napi);
		llist_for_each_entry_safe(skb, tmp, llist_del_all(&s->in), ll_node)
			tswg_steer_drop(skb);
		while ((skb = __skb_dequeue(&s->todo)) != NULL)
			tswg_steer_drop(skb);
	}
	free_percpu(wg->tswg_steer);
}

/* TSWG: the ways a peer's packets can be received; see tswg_rx_path. */
enum tswg_rx_mode {
	TSWG_RX_INLINE, /* tswg_receive_now, here */
	TSWG_RX_STEER, /* tswg_receive_now, on the peer's home CPU */
	TSWG_RX_PARALLEL /* the crypt workers and the peer's NAPI */
};

/*
 * tswg_rx_path returns how to receive skb, from peer, counting it in peer's
 * rate. A peer's packets change from steering or the parallel way only
 * once nothing is on its way that way, so that they don't reorder.
 */
static enum tswg_rx_mode tswg_rx_path(struct wg_peer *peer, struct sk_buff *skb)
{
	unsigned int mbps = READ_ONCE(tswg_rx_inline_mbps);
	enum tswg_rx_mode want = TSWG_RX_INLINE, was;
	unsigned long now = jiffies;

	if (now - READ_ONCE(peer->tswg_rx_jiffy) >= TSWG_RX_WINDOW) {
		WRITE_ONCE(peer->tswg_rx_jiffy, now);
		WRITE_ONCE(peer->tswg_rx_bytes, 0);
	}
	WRITE_ONCE(peer->tswg_rx_bytes, READ_ONCE(peer->tswg_rx_bytes) + skb->len);
	if (!mbps || (u64)READ_ONCE(peer->tswg_rx_bytes) * 8 * HZ >
		     (u64)mbps * 1000000 * TSWG_RX_WINDOW)
		WRITE_ONCE(peer->tswg_rx_parallel_until, now + TSWG_RX_PARALLEL_FOR);
	if (tswg_cpu_overloaded())
		WRITE_ONCE(peer->tswg_rx_steer_until, now + TSWG_STEER_FOR);

	if (!mbps || time_before(now, READ_ONCE(peer->tswg_rx_parallel_until)))
		want = TSWG_RX_PARALLEL;
	else if (time_before(now, READ_ONCE(peer->tswg_rx_steer_until)))
		want = TSWG_RX_STEER;

	was = READ_ONCE(peer->tswg_rx_mode);
	if (want != was &&
	    ((was == TSWG_RX_PARALLEL && atomic_read(&peer->rx_queue.count)) ||
	     (was == TSWG_RX_STEER && atomic_read(&peer->tswg_steered))))
		want = was;
	WRITE_ONCE(peer->tswg_rx_mode, want);
	return want;
}

static void tswg_receive_now(struct wg_peer *peer, struct sk_buff *skb)
{
	struct noise_keypair *keypair = PACKET_CB(skb)->keypair;
	struct endpoint endpoint;

	if (unlikely(!decrypt_packet(skb, keypair)))
		goto free;
	if (skb_is_gso(skb)) {
		tswg_receive_gso(peer, skb, true);
		goto free;
	}
	if (unlikely(!counter_validate(&keypair->receiving_counter,
				       PACKET_CB(skb)->nonce) ||
		     wg_socket_endpoint_from_skb(&endpoint, skb)))
		goto free;
	wg_reset_packet(skb, false);
	wg_packet_consume_data_done(peer, skb, &endpoint, true);
	skb = NULL;
free:
	if (skb) {
		kfree_skb_list(PACKET_CB(skb)->tswg_out);
		dev_kfree_skb(skb);
	}
	wg_noise_keypair_put(keypair, false);
	wg_peer_put(peer);
}

static void wg_packet_consume_data(struct wg_device *wg, struct sk_buff *skb)
{
	__le32 idx = ((struct message_data *)skb->data)->key_idx;
	struct wg_peer *peer = NULL;
	int ret;

	rcu_read_lock_bh();
	PACKET_CB(skb)->keypair =
		(struct noise_keypair *)wg_index_hashtable_lookup(
			wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx,
			&peer);
	if (unlikely(!wg_noise_keypair_get(PACKET_CB(skb)->keypair)))
		goto err_keypair;

	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	PACKET_CB(skb)->tswg_out = NULL; /* TSWG */
	PACKET_CB(skb)->tswg_count = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
	{ /* TSWG: see tswg_cpu_good_home */
		struct tswg_cpu_load *l = this_cpu_ptr(&tswg_cpu_load);

		if (l->rx_jiffy != jiffies)
			l->rx_jiffy = jiffies;
	}
	switch (tswg_rx_path(peer, skb)) { /* TSWG */
	case TSWG_RX_STEER: {
		/*
		 * Not to a new home while some are on their way to the old,
		 * which would reorder them.
		 */
		int cpu = atomic_read(&peer->tswg_steered) ?
				  READ_ONCE(peer->tswg_home) : tswg_peer_home(peer);

		if (cpu != smp_processor_id()) {
			tswg_steer(wg, peer, skb, cpu);
			rcu_read_unlock_bh();
			return;
		}
		fallthrough;
	}
	case TSWG_RX_INLINE:
		tswg_receive_now(peer, skb);
		rcu_read_unlock_bh();
		return;
	case TSWG_RX_PARALLEL:
		break;
	}
	/* TSWG: decrypt a lone packet here when the workers are idle. */
	if (!skb_is_gso(skb) && tswg_inline_ok(&wg->decrypt_queue)) {
		ret = tswg_enqueue_per_peer(&peer->rx_queue, skb);
		if (likely(!ret)) {
			wg_queue_enqueue_per_peer_rx(skb,
				likely(decrypt_packet(skb, PACKET_CB(skb)->keypair)) ?
					PACKET_STATE_CRYPTED : PACKET_STATE_DEAD);
			rcu_read_unlock_bh();
			return;
		}
		goto dropped;
	}
	ret = wg_queue_enqueue_per_device_and_peer(&wg->decrypt_queue, &peer->rx_queue, skb,
						   wg->packet_crypt_wq,
						   skb_is_gso(skb) ?
							TSWG_BATCH_BACKLOG :
							TSWG_PACKET_BACKLOG);
	if (unlikely(ret == -EPIPE)) {
		/* TSWG: count drops, which upstream doesn't. */
		DEV_STATS_INC(wg->dev, rx_fifo_errors);
		wg_queue_enqueue_per_peer_rx(skb, PACKET_STATE_DEAD);
	}
	if (likely(!ret || ret == -EPIPE)) {
		rcu_read_unlock_bh();
		return;
	}
dropped:
	DEV_STATS_INC(wg->dev, rx_dropped); /* TSWG: peer's queue is full */
err:
	wg_noise_keypair_put(PACKET_CB(skb)->keypair, false);
err_keypair:
	rcu_read_unlock_bh();
	wg_peer_put(peer);
	dev_kfree_skb(skb);
}

void wg_packet_receive(struct wg_device *wg, struct sk_buff *skb)
{
	if (unlikely(prepare_skb_header(skb, wg) < 0))
		goto err;
	switch (tswg_skb_type(skb)) { /* TSWG */
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION):
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):
	case cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE): {
		int cpu, ret = -EBUSY;

		if (unlikely(!rng_is_initialized()))
			goto drop;
		if (atomic_read(&wg->handshake_queue_len) > MAX_QUEUED_INCOMING_HANDSHAKES / 2) {
			if (spin_trylock_bh(&wg->handshake_queue.ring.producer_lock)) {
				ret = __ptr_ring_produce(&wg->handshake_queue.ring, skb);
				spin_unlock_bh(&wg->handshake_queue.ring.producer_lock);
			}
		} else
			ret = ptr_ring_produce_bh(&wg->handshake_queue.ring, skb);
		if (ret) {
	drop:
			net_dbg_skb_ratelimited("%s: Dropping handshake packet from %pISpfsc\n",
						wg->dev->name, skb);
			goto err;
		}
		atomic_inc(&wg->handshake_queue_len);
		cpu = wg_cpumask_next_online(&wg->handshake_queue.last_cpu);
		/* Queues up a call to packet_process_queued_handshake_packets(skb): */
		queue_work_on(cpu, wg->handshake_receive_wq,
			      &per_cpu_ptr(wg->handshake_queue.worker, cpu)->work);
		break;
	}
	case cpu_to_le32(MESSAGE_DATA):
		PACKET_CB(skb)->ds = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		wg_packet_consume_data(wg, skb);
		break;
	default:
		WARN(1, "Non-exhaustive parsing of packet header lead to unknown packet type!\n");
		goto err;
	}
	return;

err:
	dev_kfree_skb(skb);
}
