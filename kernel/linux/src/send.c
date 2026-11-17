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
#include "tswg_aead.h"

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/ip6_checksum.h> /* TSWG */

/*
 * TSWG: tswg_hybrid_initiation and tswg_hybrid_response lay out a hybrid
 * handshake message, of which noise.c filled in the encrypted_kem field
 * and the classic message src, from src; see wg_noise_handshake_*. If
 * retry, they set TSWG_MESSAGE_RETRY, as wireguard-go does.
 */
static void tswg_hybrid_initiation(struct message_handshake_initiation_hybrid *dst,
				   const struct message_handshake_initiation *src,
				   bool retry)
{
	dst->header.type = src->header.type;
	if (retry)
		dst->header.type |= cpu_to_le32(TSWG_MESSAGE_RETRY);
	dst->sender_index = src->sender_index;
	memcpy(dst->unencrypted_ephemeral, src->unencrypted_ephemeral,
	       sizeof(dst->unencrypted_ephemeral));
	memcpy(dst->encrypted_static, src->encrypted_static,
	       sizeof(dst->encrypted_static));
	memcpy(dst->encrypted_timestamp, src->encrypted_timestamp,
	       sizeof(dst->encrypted_timestamp));
}

static void tswg_hybrid_response(struct message_handshake_response_hybrid *dst,
				 const struct message_handshake_response *src,
				 bool retry)
{
	dst->header.type = src->header.type;
	if (retry)
		dst->header.type |= cpu_to_le32(TSWG_MESSAGE_RETRY);
	dst->sender_index = src->sender_index;
	dst->receiver_index = src->receiver_index;
	memcpy(dst->unencrypted_ephemeral, src->unencrypted_ephemeral,
	       sizeof(dst->unencrypted_ephemeral));
	memcpy(dst->encrypted_nothing, src->encrypted_nothing,
	       sizeof(dst->encrypted_nothing));
}

static void wg_packet_send_handshake_initiation(struct wg_peer *peer)
{
	struct message_handshake_initiation packet;
	/* TSWG: the message sent, which for hybrid handshakes is in hyb. */
	struct message_handshake_initiation_hybrid *hyb;
	void *msg = &packet;
	size_t len = sizeof(packet);
	bool hybrid;

	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      REKEY_TIMEOUT))
		return; /* This function is rate limited. */

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake initiation to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	hyb = kmalloc(sizeof(*hyb), GFP_KERNEL);
	if (!hyb)
		return;
	if (wg_noise_handshake_create_initiation(&packet, hyb->encrypted_kem,
						 &hybrid, &peer->handshake)) {
		if (hybrid) {
			/* timer_handshake_attempts counts retries. */
			tswg_hybrid_initiation(hyb, &packet,
					       peer->timer_handshake_attempts);
			msg = hyb;
			len = sizeof(*hyb);
		}
		wg_cookie_add_mac_to_packet(msg, len, peer);
		wg_timers_any_authenticated_packet_traversal(peer);
		wg_timers_any_authenticated_packet_sent(peer);
		atomic64_set(&peer->last_sent_handshake,
			     ktime_get_coarse_boottime_ns());
		wg_socket_send_buffer_to_peer(peer, msg, len, HANDSHAKE_DSCP);
		wg_timers_handshake_initiated(peer);
	}
	kfree(hyb);
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

void wg_packet_send_handshake_response(struct wg_peer *peer, bool retry)
{
	struct message_handshake_response packet;
	/* TSWG: as in wg_packet_send_handshake_initiation. */
	struct message_handshake_response_hybrid *hyb;
	void *msg = &packet;
	size_t len = sizeof(packet);
	bool hybrid;

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake response to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	hyb = kmalloc(sizeof(*hyb), GFP_KERNEL);
	if (!hyb)
		return;
	if (wg_noise_handshake_create_response(&packet, hyb->encrypted_kem,
					       &hybrid, &peer->handshake)) {
		if (hybrid) {
			tswg_hybrid_response(hyb, &packet, retry);
			msg = hyb;
			len = sizeof(*hyb);
		}
		wg_cookie_add_mac_to_packet(msg, len, peer);
		if (wg_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			wg_timers_session_derived(peer);
			wg_timers_any_authenticated_packet_traversal(peer);
			wg_timers_any_authenticated_packet_sent(peer);
			atomic64_set(&peer->last_sent_handshake,
				     ktime_get_coarse_boottime_ns());
			wg_socket_send_buffer_to_peer(peer, msg, len,
						      HANDSHAKE_DSCP);
		}
	}
	kfree(hyb);
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

/*
 * TSWG: calculate_padding is upstream's calculate_skb_padding, for a packet
 * (or a segment of one; see tswg_seg_len) of len bytes, of skb.
 */
static unsigned int calculate_padding(struct sk_buff *skb, unsigned int len)
{
	unsigned int padded_size, last_unit = len;

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
 * TSWG: encryption straight from GSO packets.
 *
 * A GSO packet (a TCP or UDP super-packet from a local socket, or one GRO
 * made, being forwarded) used to be segmented in wg_xmit
 * (skb_gso_segment), allocating a packet for each segment, copying the
 * headers into it, and (with no device features) copying and checksumming
 * its payload too, after which we copied it all again to encrypt it. Now
 * wg_xmit keeps such a packet whole when tswg_gso_whole_ok, and
 * tswg_encrypt_list encrypts each segment straight from it: the segment's
 * headers, fixed up as TCP's and UDP's segmentation would
 * (tswg_copy_segment), and its slice of the payload, checksummed as it's
 * copied. Each segment has its own nonce, assigned in a block
 * (wg_packet_send_staged_packets). Others are still segmented.
 */

/*
 * tswg_gso_hdr_len returns the length of the headers that each segment of
 * the GSO packet skb repeats: everything up to and including its TCP or
 * UDP header.
 */
static unsigned int tswg_gso_hdr_len(const struct sk_buff *skb)
{
	return skb_transport_offset(skb) +
	       (skb_is_gso_tcp(skb) ? tcp_hdrlen(skb) : sizeof(struct udphdr));
}

/* gso_whole turns encryption straight from GSO packets on (the default). */
static bool tswg_gso_whole = true;
module_param_named(gso_whole, tswg_gso_whole, bool, 0644);
MODULE_PARM_DESC(gso_whole, "encrypt GSO packets a segment at a time, rather than segmenting them first");

/*
 * tswg_gso_whole_ok reports whether wg_xmit may keep the GSO packet skb
 * whole, for tswg_encrypt_list to encrypt straight from.
 */
bool tswg_gso_whole_ok(struct sk_buff *skb)
{
	const struct skb_shared_info *si = skb_shinfo(skb);
	unsigned int hlen, mss = si->gso_size;
	u8 proto;

	if (!READ_ONCE(tswg_gso_whole))
		return false;
	/* Not, for example, DODGY (untrusted), tunnels or frag lists. */
	if (si->gso_type & ~(SKB_GSO_TCPV4 | SKB_GSO_TCPV6 | SKB_GSO_TCP_ECN |
			     SKB_GSO_TCP_FIXEDID | SKB_GSO_TCP_ACCECN |
			     SKB_GSO_UDP_L4))
		return false;
	if (skb->encapsulation || skb->ip_summed != CHECKSUM_PARTIAL ||
	    !skb_transport_header_was_set(skb) ||
	    (si->tx_flags & SKBTX_ANY_TSTAMP))
		return false;
	if (skb->protocol == htons(ETH_P_IP))
		proto = ip_hdr(skb)->protocol;
	else
		proto = ipv6_hdr(skb)->nexthdr;
	if (proto != (skb_is_gso_tcp(skb) ? IPPROTO_TCP : IPPROTO_UDP) ||
	    skb_checksum_start(skb) != skb_transport_header(skb))
		return false;
	if (skb_is_gso_tcp(skb) &&
	    (skb_headlen(skb) < skb_transport_offset(skb) + sizeof(struct tcphdr) ||
	     tcp_hdrlen(skb) < sizeof(struct tcphdr)))
		return false;
	hlen = tswg_gso_hdr_len(skb);
	return skb_headlen(skb) >= hlen && mss && skb->len > hlen + mss &&
	       si->gso_segs == DIV_ROUND_UP(skb->len - hlen, mss);
}

/* tswg_skb_segs returns how many packets skb is, as a whole GSO packet. */
static unsigned int tswg_skb_segs(const struct sk_buff *skb)
{
	return skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
}

/* tswg_seg_len returns the length of skb's segment i; see tswg_skb_segs. */
static unsigned int tswg_seg_len(const struct sk_buff *skb, unsigned int i)
{
	unsigned int hlen, mss;

	if (!skb_is_gso(skb))
		return skb->len;
	hlen = tswg_gso_hdr_len(skb);
	mss = skb_shinfo(skb)->gso_size;
	return hlen + min(mss, skb->len - hlen - i * mss);
}

/*
 * tswg_copy_segment writes segment i, of len bytes, of the GSO packet skb
 * to the linear buffer to: its headers, adjusted as tcp_gso_segment (or
 * __udp_gso_segment) and inet_gso_segment (or ipv6_gso_segment) would, and
 * its payload, with its checksum computed while copying it.
 */
static bool tswg_copy_segment(struct sk_buff *skb, unsigned int i, u8 *to,
			      unsigned int len)
{
	const struct skb_shared_info *si = skb_shinfo(skb);
	unsigned int nhoff = skb_network_offset(skb);
	unsigned int thoff = skb_transport_offset(skb);
	unsigned int hlen = tswg_gso_hdr_len(skb);
	unsigned int l4len = len - thoff;
	bool tcp = skb_is_gso_tcp(skb);
	u8 *l4 = to + thoff;
	__sum16 check;
	__wsum csum;

	if (unlikely(skb_copy_bits(skb, 0, to, hlen)))
		return false;
	csum = skb_copy_and_csum_bits(skb, hlen + i * si->gso_size, to + hlen,
				      len - hlen);

	if (tcp) {
		struct tcphdr *th = (struct tcphdr *)l4;

		th->seq = htonl(ntohl(th->seq) + i * si->gso_size);
		if (i != si->gso_segs - 1)
			th->fin = th->psh = 0;
		if (i && !(si->gso_type & SKB_GSO_TCP_ACCECN))
			th->cwr = 0;
		th->check = 0;
	} else {
		struct udphdr *uh = (struct udphdr *)l4;

		uh->len = htons(l4len);
		uh->check = 0;
	}
	/* The L4 header's length is even, so its sum just adds on. */
	csum = csum_partial(l4, hlen - thoff, csum);

	if (skb->protocol == htons(ETH_P_IP)) {
		struct iphdr *iph = (struct iphdr *)(to + nhoff);

		iph->tot_len = htons(len - nhoff);
		if (!(si->gso_type & SKB_GSO_TCP_FIXEDID))
			iph->id = htons(ntohs(iph->id) + i);
		ip_send_check(iph);
		check = csum_tcpudp_magic(iph->saddr, iph->daddr, l4len,
					  tcp ? IPPROTO_TCP : IPPROTO_UDP, csum);
	} else {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(to + nhoff);

		ip6h->payload_len = htons(len - nhoff - sizeof(*ip6h));
		check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, l4len,
					tcp ? IPPROTO_TCP : IPPROTO_UDP, csum);
	}
	if (tcp)
		((struct tcphdr *)l4)->check = check;
	else
		((struct udphdr *)l4)->check = check ?: CSUM_MANGLED_0;
	return true;
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
 * TSWG: verify_gso, for tests, checks every segment that
 * tswg_copy_segment writes against the kernel's own segmentation of the GSO
 * packet (skb_gso_segment, computing checksums in software), counting the
 * segments checked in gso_verified and those that differ in
 * gso_verify_errors. It's slow.
 */
static bool tswg_verify_gso;
module_param_named(verify_gso, tswg_verify_gso, bool, 0644);
MODULE_PARM_DESC(verify_gso, "check segments encrypted straight from GSO packets against skb_gso_segment (slow; for tests)");
static atomic_t tswg_gso_verified = ATOMIC_INIT(0);
static atomic_t tswg_gso_verify_errors = ATOMIC_INIT(0);
module_param_named(gso_verified, tswg_gso_verified.counter, int, 0444);
module_param_named(gso_verify_errors, tswg_gso_verify_errors.counter, int, 0444);

/*
 * tswg_verify_segments checks skb's segments as tswg_copy_segment writes
 * them against skb_gso_segment's; see verify_gso.
 */
static void tswg_verify_segments(struct sk_buff *skb)
{
	struct sk_buff *copy, *segs, *seg, *next;
	unsigned int i = 0, len;
	u8 *ours, *theirs;
	bool bad = false;

	copy = skb_copy(skb, GFP_ATOMIC);
	ours = kmalloc(2 * 65536, GFP_ATOMIC);
	if (!copy || !ours)
		goto out;
	theirs = ours + 65536;
	segs = skb_gso_segment(copy, 0);
	if (IS_ERR_OR_NULL(segs)) {
		bad = true;
		goto out;
	}
	skb_list_walk_safe(segs, seg, next) {
		len = tswg_seg_len(skb, i);
		if (i >= tswg_skb_segs(skb) || seg->len != len ||
		    !tswg_copy_segment(skb, i, ours, len) ||
		    skb_copy_bits(seg, 0, theirs, len) ||
		    memcmp(ours, theirs, len)) {
			if (!bad)
				pr_err_ratelimited("verify_gso: segment %u of %u (len %u, theirs %u, gso_type %#x) differs\n",
						   i, tswg_skb_segs(skb), len, seg->len,
						   skb_shinfo(skb)->gso_type);
			bad = true;
		}
		atomic_inc(&tswg_gso_verified);
		i++;
		kfree_skb(seg);
	}
	if (i != tswg_skb_segs(skb))
		bad = true;
out:
	if (bad)
		atomic_inc(&tswg_gso_verify_errors);
	kfree(ours);
	kfree_skb(copy);
}

/*
 * tswg_encrypt_into encrypts segment seg (see tswg_skb_segs), of len bytes,
 * of skb as a data message of msg_len bytes, appended to out's page frags.
 * out must have a free frag slot.
 */
static bool tswg_encrypt_into(struct sk_buff *out, struct sk_buff *skb,
			      unsigned int seg, unsigned int len,
			      unsigned int msg_len,
			      struct noise_keypair *keypair,
			      struct page_frag *pfrag)
{
	unsigned int plaintext_len = msg_len - message_data_len(0);
	u64 nonce = PACKET_CB(skb)->nonce + seg;
	int i = skb_shinfo(out)->nr_frags;
	struct message_data *header;
	u8 *plaintext;
	bool ok;

	if (unlikely(!skb_page_frag_refill(msg_len, pfrag, GFP_ATOMIC)))
		return false;
	header = page_address(pfrag->page) + pfrag->offset;
	plaintext = (u8 *)(header + 1);
	if (skb_is_gso(skb))
		ok = tswg_copy_segment(skb, seg, plaintext, len);
	else
		ok = tswg_copy_plaintext(skb, plaintext);
	if (unlikely(!ok))
		return false;
	memset(plaintext + len, 0, plaintext_len - len);
	header->header.type = cpu_to_le32(MESSAGE_DATA);
	header->key_idx = keypair->remote_index;
	header->counter = cpu_to_le64(nonce);
	tswg_aead_encrypt(plaintext, plaintext, plaintext_len, nonce,
			  keypair->sending.key);

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

/*
 * tswg_owner_movable reports whether skb's socket ownership can move to
 * another packet: whether its destructor just uncharges skb->truesize from
 * skb->sk. That's sock_wfree, and for TCP, tcp_wfree and __sock_wfree
 * (which aren't exported). Others, like AF_PACKET's for its mmapped ring,
 * need the very skb they were set on.
 */
static bool tswg_owner_movable(const struct sk_buff *skb)
{
	const struct sock *sk = skb->sk;

	if (!sk || !skb->destructor)
		return false;
	if (skb->destructor == sock_wfree)
		return true;
	return sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP;
}

/*
 * tswg_move_owner moves skb's socket ownership, and the socket's charge for
 * it (which it adds to *charged), to out, the packet skb was encrypted
 * into, if it can. tswg_settle_charge then makes the charge out's size.
 *
 * Upstream encrypts in place, so a packet stays its socket's (for TCP,
 * counted against its small queues limit) until the NIC is done sending
 * it, and TCP is held back by the NIC's pace. Our encrypted packets are
 * new, and without this, would let TCP fill the NIC's qdisc as fast as we
 * could encrypt: RTT under load went from about 5ms to over 10ms.
 */
static void tswg_move_owner(struct sk_buff *out, struct sk_buff *skb,
			    unsigned int *charged)
{
	if (!tswg_owner_movable(skb))
		return;
	if (!out->destructor) {
		out->sk = skb->sk;
		out->destructor = skb->destructor;
	} else if (out->sk != skb->sk || out->destructor != skb->destructor) {
		return;
	}
	*charged += skb->truesize;
	skb->sk = NULL;
	skb->destructor = NULL;
}

/*
 * tswg_share_owner makes out, a packet with no owner yet, owned by sk with
 * destructor, the owner moved from a GSO packet to an earlier packet that
 * some of its segments were encrypted into, as tcp_gso_segment and
 * __udp_gso_segment give every segment the GSO packet's owner. Its charge
 * starts at nothing, and tswg_settle_charge makes it out's size.
 */
static void tswg_share_owner(struct sk_buff *out, struct sock *sk,
			     void (*destructor)(struct sk_buff *))
{
	if (!sk || out->destructor)
		return;
	out->sk = sk;
	out->destructor = destructor;
}

/*
 * tswg_settle_charge adjusts the socket's charge for out from charged, what
 * its packets were charged, to out->truesize, which out's destructor will
 * uncharge. The packets' truesize (for TCP segments, about twice their
 * length) overstates what's in flight, and with it, TCP's small queues
 * limit (about a millisecond's worth) held throughput 20% below what it
 * is without.
 */
static void tswg_settle_charge(struct sk_buff *out, unsigned int charged)
{
	struct sock *sk = out->sk;

	if (!out->destructor)
		return;
	if (charged > out->truesize)
		WARN_ON_ONCE(refcount_sub_and_test(charged - out->truesize,
						   &sk->sk_wmem_alloc));
	else if (charged < out->truesize)
		refcount_add(out->truesize - charged, &sk->sk_wmem_alloc);
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
 * tswg_encrypt_list encrypts the list of packets at first (each perhaps a
 * whole GSO packet; see tswg_gso_whole_ok) into PACKET_CB(first)->tswg_out,
 * a list of packets to send. The tx worker frees the originals once it has
 * sent those (see wg_packet_create_data_done).
 */
static bool tswg_encrypt_list(struct sk_buff *first, struct page_frag *pfrag)
{
	struct noise_keypair *keypair = PACKET_CB(first)->keypair;
	struct sk_buff **tail = &PACKET_CB(first)->tswg_out;
	unsigned int mss = 0, segs = 0, charged = 0;
	struct sk_buff *skb, *out = NULL;
	bool ok = true;

	for (skb = first; skb && ok; skb = skb->next) {
		unsigned int seg, nsegs = tswg_skb_segs(skb);
		/* skb's owner, once moved to an out; see tswg_share_owner. */
		void (*destructor)(struct sk_buff *) = NULL;
		struct sock *sk = NULL;

		if (unlikely(READ_ONCE(tswg_verify_gso)) && skb_is_gso(skb))
			tswg_verify_segments(skb);

		for (seg = 0; seg < nsegs; seg++) {
			unsigned int len = tswg_seg_len(skb, seg);
			unsigned int msg_len =
				message_data_len(len + calculate_padding(skb, len));

			/* Only the last segment of a GSO packet may be shorter. */
			if (out && (msg_len > mss || out->len != mss * segs ||
				    msg_len == message_data_len(0) ||
				    mss == message_data_len(0) ||
				    segs >= TSWG_GSO_MAX_SEGS ||
				    out->len + msg_len > TSWG_GSO_MAX_BYTES ||
				    skb_shinfo(out)->nr_frags >= MAX_SKB_FRAGS ||
				    PACKET_CB(skb)->ds != PACKET_CB(out)->ds)) {
				tswg_finish_out(out, mss, segs);
				tswg_settle_charge(out, charged);
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
				charged = 0;
				tswg_share_owner(out, sk, destructor);
			}
			if (unlikely(!tswg_encrypt_into(out, skb, seg, len,
							msg_len, keypair,
							pfrag))) {
				ok = false;
				break;
			}
			if (!seg) {
				tswg_move_owner(out, skb, &charged);
				if (!skb->sk && out->sk) {
					sk = out->sk;
					destructor = out->destructor;
				}
			}
			segs++;
		}
	}
	if (out) {
		tswg_finish_out(out, mss, segs);
		tswg_settle_charge(out, charged);
	}
	return ok;
}

/* TSWG: inline_crypto turns inline crypto on; see tswg_crypt_idle. */
bool tswg_inline_crypto = true;
module_param_named(inline_crypto, tswg_inline_crypto, bool, 0644);
MODULE_PARM_DESC(inline_crypto, "encrypt and decrypt lone packets inline when the crypt workers are idle");

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

	/*
	 * TSWG: free the originals here, on the peer's one tx worker CPU,
	 * rather than in the encrypt workers. For TCP, freeing those that
	 * still have their socket (see tswg_move_owner) releases its small
	 * queues accounting (tcp_wfree), and from several CPUs at once, the
	 * resulting TSQ handlers fight over the socket lock.
	 */
	for (skb = first; skb; skb = next) {
		next = skb->next;
		skb_mark_not_on_list(skb);
		consume_skb(skb);
	}

	keep_key_fresh(peer);
}

/*
 * TSWG: sending a peer's encrypted packets by combining.
 *
 * Upstream sends a peer's tx_queue in order from its tx worker, one work
 * item, queued on the CPU that finished encrypting: a workqueue hop for
 * each entry, and all of a peer's sending on one CPU at a time. A device
 * without UDP segmentation offload (EC2's ENA) segments what we send in
 * software, on the sending CPU, so a big host serving 37 peers had the few
 * CPUs their tx workers landed on at 90% and more. Now the encrypt worker
 * that makes an entry ready sends it, and whatever else is ready in order,
 * itself, if no other CPU is sending the peer's (tswg_tx_lock); if another
 * is, that one sends it before it's done (tswg_tx_more). The peer's
 * sending is still one CPU at a time, which keeps it in order, but moves
 * among the CPUs encrypting for it, with no hop. Past TSWG_TX_BUDGET
 * entries at a time, the tx worker takes over.
 */
#define TSWG_TX_BUDGET 64

/*
 * tswg_tx_drain sends up to TSWG_TX_BUDGET ready entries from the head of
 * peer's tx_queue, returning whether it stopped with more ready. The
 * caller holds tswg_tx_lock.
 */
static bool tswg_tx_drain(struct wg_peer *peer)
{
	struct noise_keypair *keypair;
	enum packet_state state;
	struct sk_buff *first;
	int n = 0;

	while ((first = wg_prev_queue_peek(&peer->tx_queue)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(first)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		if (n++ == TSWG_TX_BUDGET)
			return true;
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
	}
	return false;
}

/*
 * tswg_tx_kick sends what's ready in peer's tx_queue, unless another CPU is
 * sending it, in which case that one will. The caller holds a reference to
 * peer.
 */
void tswg_tx_kick(struct wg_peer *peer)
{
	bool more = false;

	WRITE_ONCE(peer->tswg_tx_more, true);
	smp_mb(); /* tswg_tx_more before trying the lock; pairs with below */
	while (READ_ONCE(peer->tswg_tx_more) &&
	       spin_trylock_bh(&peer->tswg_tx_lock)) {
		WRITE_ONCE(peer->tswg_tx_more, false);
		smp_mb(); /* clear tswg_tx_more before looking at the queue */
		more = tswg_tx_drain(peer);
		spin_unlock_bh(&peer->tswg_tx_lock);
		if (more)
			break;
		smp_mb(); /* unlock before rechecking tswg_tx_more */
	}
	if (more)
		tswg_queue_work_on(raw_smp_processor_id(),
				   peer->device->packet_crypt_wq,
				   &peer->transmit_packet_work);
}

void wg_packet_tx_worker(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer, transmit_packet_work);

	tswg_tx_kick(peer); /* TSWG: requeues itself if there's more */
}

void wg_packet_encrypt_worker(struct work_struct *work)
{
	struct multicore_worker *w = container_of(work, struct multicore_worker,
						  work);
	struct crypt_queue *queue = w->ptr;
	struct sk_buff *first;

	tswg_crypt_worker_start(w, queue); /* TSWG */
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

	/*
	 * TSWG: encrypt a lone packet here when the workers are idle; see
	 * tswg_crypt_idle. BHs are off (rcu_read_lock_bh), which makes this
	 * CPU's inline page frag ours. Not when serving a softirq, though:
	 * that's forwarding, on a subnet router's CPUs taking the NIC's
	 * interrupts, where inlining cost 6% of its throughput.
	 */
	if (!first->next && !skb_is_gso(first) && !in_serving_softirq() &&
	    tswg_inline_ok(&wg->encrypt_queue)) {
		ret = tswg_enqueue_per_peer(&peer->tx_queue, first);
		if (likely(!ret)) {
			struct page_frag *pfrag =
				&this_cpu_ptr(wg->encrypt_queue.worker)->tswg_inline_frag;

			wg_queue_enqueue_per_peer_tx(first,
				likely(tswg_encrypt_list(first, pfrag)) ?
					PACKET_STATE_CRYPTED : PACKET_STATE_DEAD);
		}
		goto err;
	}
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

/*
 * TSWG: run-to-completion transmit.
 *
 * Upstream hands every packet to a crypt worker through a ring that all
 * of a device's CPUs share, and the encrypted packets to the peer's tx
 * worker through its in-order queue, so that one flow's packets can be
 * encrypted on many CPUs in parallel and still go out in order. That's two
 * device-wide locks (the ring's producer and consumer locks), a wakeup or
 * two, and two more CPUs per packet; on a 128-CPU subnet router sending
 * big responses to hundreds of flows, the workers spent 75-83% of the
 * router's CPU contending for the ring's consumer lock.
 *
 * Packets being forwarded (arriving here in softirq, on the CPU that took
 * them from the NIC, with no socket) need none of it: RSS already spreads
 * the flows over CPUs, and keeps each flow's packets on one, in order. So tswg_xmit_now
 * encrypts them and sends them right here, as IPsec does. That isn't the
 * softirq starvation seen before, which came from handing work to a
 * worker on a CPU busy with softirq work; this is that work. Packets of a
 * peer's different flows, encrypted on different CPUs, may leave out of
 * nonce order, which the receiver's replay window allows for.
 *
 * When the flows arrive on few CPUs (a NIC with few queues, or a veth with
 * one), doing it all there can saturate them, where handing off would
 * have spread the work: in the lab, forwarding one veth's traffic, 5.6
 * Gbps became 3.3 (though mostly from virtio's per-send notifications,
 * each a VM exit there). Handing off just the overflow, a share of each
 * jiffy, was worse still, as it reorders flows each time it switches.
 *
 * Local sockets' lone packets (TCP's ACKs, small requests) go too, when
 * nothing of the peer's is on its way the other way, so that they don't
 * overtake it: a big host downloading from 37 peers spent 7% of its CPU
 * contending for the encrypt ring's lock, for its ACKs.
 *
 * tx_inline (module parameter): 0 never, 1 (the default) for packets with
 * no socket (forwarded) and lone ones, 2 for all, including local sockets'
 * bulk (which costs a single flow its encryption on other CPUs: much of a
 * TCP sender's sending happens in softirq too, as ACKs arrive, so being in
 * softirq doesn't mean forwarding).
 */
static int tswg_tx_inline = 1;
module_param_named(tx_inline, tswg_tx_inline, int, 0644);
MODULE_PARM_DESC(tx_inline, "encrypt and send where packets arrive: 0 never, 1 forwarded ones, 2 always");

/*
 * TSWG: a local socket's bulk (GSO) sends to a peer sending under
 * tx_inline_mbps go inline too. Handing them to a crypt worker costs each
 * burst a wakeup and a handoff, which for request and response traffic is
 * on every response's critical path: one HTTP-like stream between two big
 * hosts got 2.5 Gbps to wireguard-go's 3.3 that way, 3.0 inline. But one
 * CPU can't keep up with a fast stream (7.2 -> 6.2 Gbps), so above the
 * rate, over TSWG_TX_WINDOW, the workers share it. 0 turns it off.
 */
static unsigned int tswg_tx_inline_mbps = 2000;
module_param_named(tx_inline_mbps, tswg_tx_inline_mbps, uint, 0644);
MODULE_PARM_DESC(tx_inline_mbps, "encrypt local bulk sends inline to a peer sending below this rate (0: never)");

#define TSWG_TX_WINDOW max(HZ / 100, 1)
#define TSWG_TX_FAST_FOR (HZ / 10)

/*
 * tswg_tx_slow counts len bytes sent to peer and reports whether it's
 * sending below tx_inline_mbps: under it this window, and not over it in
 * any window for TSWG_TX_FAST_FOR, as for receiving (see tswg_rx_path).
 * Without that, the first tx_inline_mbps' worth of every window went
 * inline however fast the peer was sending, which cost one 11 Gbps
 * stream in the QEMU lab 8% of its throughput.
 */
static bool tswg_tx_slow(struct wg_peer *peer, unsigned int len)
{
	unsigned int mbps = READ_ONCE(tswg_tx_inline_mbps);
	unsigned long now = jiffies;

	if (!mbps)
		return false;
	if (now - READ_ONCE(peer->tswg_tx_jiffy) >= TSWG_TX_WINDOW) {
		WRITE_ONCE(peer->tswg_tx_jiffy, now);
		WRITE_ONCE(peer->tswg_tx_bytes, 0);
	}
	WRITE_ONCE(peer->tswg_tx_bytes, READ_ONCE(peer->tswg_tx_bytes) + len);
	if ((u64)READ_ONCE(peer->tswg_tx_bytes) * 8 * HZ >
	    (u64)mbps * 1000000 * TSWG_TX_WINDOW)
		WRITE_ONCE(peer->tswg_tx_fast_until, now + TSWG_TX_FAST_FOR);
	return !time_before(now, READ_ONCE(peer->tswg_tx_fast_until));
}

bool tswg_xmit_now(struct wg_peer *peer, struct sk_buff_head *packets)
{
	int mode = READ_ONCE(tswg_tx_inline);
	struct noise_keypair *keypair;
	struct sk_buff *skb, *first;
	unsigned int count = 0;
	u64 nonce;

	if (!mode)
		return false;
	if (mode == 1 && packets->next->sk) {
		unsigned int len = 0;
		bool lone;

		skb_queue_walk(packets, skb)
			len += skb->len;
		lone = skb_queue_is_last(packets, packets->next) &&
		       !skb_is_gso(packets->next);
		/* Either way, not past what's on its way through the workers. */
		if ((!tswg_tx_slow(peer, len) && !lone) ||
		    atomic_read(&peer->tx_queue.count))
			return false;
	}
	/* Not past packets waiting for a handshake, nor without a key. */
	if (!skb_queue_empty_lockless(&peer->staged_packet_queue))
		return false;
	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	if (unlikely(!keypair || !READ_ONCE(keypair->sending.is_valid) ||
		     wg_birthdate_has_expired(keypair->sending.birthdate,
					      REJECT_AFTER_TIME)))
		goto slow;
	skb_queue_walk(packets, skb)
		count += tswg_skb_segs(skb);
	nonce = atomic64_add_return(count, &keypair->sending_counter) - count;
	if (unlikely(nonce + count - 1 >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(keypair->sending.is_valid, false);
		goto slow;
	}
	skb_queue_walk(packets, skb) {
		PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0, ip_hdr(skb), skb);
		PACKET_CB(skb)->nonce = nonce;
		nonce += tswg_skb_segs(skb);
	}
	first = packets->next;
	packets->prev->next = NULL;
	__skb_queue_head_init(packets);
	/*
	 * BHs are off, which makes this CPU's inline page frag ours, and the
	 * keypair, which RCU frees, safe to use without a reference.
	 */
	PACKET_CB(first)->keypair = keypair;
	PACKET_CB(first)->tswg_out = NULL;
	if (likely(tswg_encrypt_list(first,
			&this_cpu_ptr(peer->device->encrypt_queue.worker)->tswg_inline_frag))) {
		wg_packet_create_data_done(peer, first);
	} else {
		kfree_skb_list(PACKET_CB(first)->tswg_out);
		kfree_skb_list(first);
	}
	rcu_read_unlock_bh();
	return true;

slow:
	rcu_read_unlock_bh();
	return false;
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
	unsigned int count = 0; /* TSWG: packets, counting GSO segments */
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
		/* TSWG: a whole GSO packet gets a nonce per segment. */
		unsigned int segs = tswg_skb_segs(skb);

		/* 0 for no outer TOS: no leak. TODO: at some later point, we
		 * might consider using flowi->tos as outer instead.
		 */
		PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0, ip_hdr(skb), skb);
		PACKET_CB(skb)->nonce =
			atomic64_add_return(segs, &keypair->sending_counter) - segs;
		if (unlikely(PACKET_CB(skb)->nonce + segs - 1 >= REJECT_AFTER_MESSAGES))
			goto out_invalid;
		count += segs;
	}

	packets.prev->next = NULL;
	wg_peer_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	PACKET_CB(packets.next)->tswg_out = NULL; /* TSWG */
	PACKET_CB(packets.next)->tswg_count = min_t(u32, count, U16_MAX);
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
