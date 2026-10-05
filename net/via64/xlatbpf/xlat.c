//go:build ignore

// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

/*
Stateless IPv6/IPv4 translation for 4via6 (a subset of RFC 7915), on the netkit pair that net/via64/xlat sets up.

xlat6to4 runs on the primary's transmit, after nftables has DNATed the destination into the canonical /96 and NAT66 has made the source X6, so both addresses translate with the canonical /96 as an RFC 6052 prefix. xlat4to6 runs on the peer's transmit, which only replies to X4 reach. netkit hands the programs an Ethernet frame even in L3 mode, so offsets start after 14 bytes.

TCP, UDP with a checksum and ICMP echo are translated, whole or (TCP and UDP) as fragments, one fragment at a time; so are ICMPv4 errors about TCP and UDP. Everything else is dropped and counted. Fragmented ICMP cannot be translated: the ICMPv6 checksum covers the whole message's length, which no fragment knows.
*/

#include <linux/bpf.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>

#define TC_ACT_OK 0   // NETKIT_PASS
#define TC_ACT_SHOT 2 // NETKIT_DROP
#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMPV6 58
#define PROTO_FRAG 44
#define V4_HLEN 20
#define V6_HLEN 40
#define FRAG_HLEN 8
#define IPV4_DF 0x4000
#define IPV4_MF 0x2000
#define IPV4_OFF_MASK 0x1fff

struct v6hdr {
	__be32 vtcfl; // version, traffic class, flow label
	__be16 plen;
	__u8 nh;
	__u8 hlim;
	__be32 src[4];
	__be32 dst[4];
};

struct v4hdr {
	__u8 vihl;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag;
	__u8 ttl;
	__u8 proto;
	__u16 check;
	__be32 src;
	__be32 dst;
};

struct fraghdr6 {
	__u8 nh;
	__u8 reserved;
	__be16 offlg; // byte offset (a multiple of 8), two reserved bits, More Fragments
	__be32 id;
};

struct pseudo6 {
	__be32 src[4];
	__be32 dst[4];
	__be32 len;
	__be32 nh; // three zero bytes and the next header
};

struct config {
	__be32 prefix[3]; // the canonical /96
	__be32 x4;
};

enum counter {
	C_6TO4_OK,
	C_4TO6_OK,
	C_DROP_NOT_IP,
	C_DROP_SHORT,
	C_DROP_NOT_OURS,
	C_DROP_BAD_SRC,
	C_DROP_X4_DST,
	C_DROP_PROTO,
	C_DROP_ICMP_UNSUPPORTED,
	C_DROP_UDP_ZERO_CSUM,
	C_DROP_OPTIONS,
	C_DROP_FRAG,
	C_DROP_HELPER,
	C_ICMP_ERR_OK,
	C_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
} config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, C_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline int count(__u32 c, int verdict)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &c);
	if (v)
		*v += 1;
	return verdict;
}

static __always_inline __u16 fold(__s64 sum)
{
	__u32 c = (__u32)sum;
	c = (c & 0xffff) + (c >> 16);
	c = (c & 0xffff) + (c >> 16);
	return (__u16)~c;
}

SEC("netkit/primary")
int xlat6to4(struct __sk_buff *skb)
{
	struct v6hdr ip6;
	struct v4hdr ip4 = {};
	__u32 zero = 0;
	__u8 type6 = 0, type4 = 0;
	__s64 diff;

	struct config *cfg = bpf_map_lookup_elem(&config_map, &zero);
	if (!cfg || cfg->x4 == 0)
		return count(C_DROP_NOT_OURS, TC_ACT_SHOT);
	if (skb->protocol != bpf_htons(ETH_P_IPV6))
		return count(C_DROP_NOT_IP, TC_ACT_SHOT);
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6)) < 0)
		return count(C_DROP_SHORT, TC_ACT_SHOT);
	if ((bpf_ntohl(ip6.vtcfl) >> 28) != 6)
		return count(C_DROP_NOT_IP, TC_ACT_SHOT);
	// nftables must already have DNATed the destination into the canonical prefix ...
	if (ip6.dst[0] != cfg->prefix[0] || ip6.dst[1] != cfg->prefix[1] || ip6.dst[2] != cfg->prefix[2])
		return count(C_DROP_NOT_OURS, TC_ACT_SHOT);
	// ... and replaced the client with X6.
	if (ip6.src[0] != cfg->prefix[0] || ip6.src[1] != cfg->prefix[1] || ip6.src[2] != cfg->prefix[2] || ip6.src[3] != cfg->x4)
		return count(C_DROP_BAD_SRC, TC_ACT_SHOT);
	if (ip6.dst[3] == cfg->x4)
		return count(C_DROP_X4_DST, TC_ACT_SHOT);

	__u8 proto = ip6.nh;
	__u16 plen = bpf_ntohs(ip6.plen);
	__u32 l6 = ETH_HLEN + V6_HLEN; // where the upper layer starts before translation
	__u32 l4 = ETH_HLEN + V4_HLEN; // and after
	struct fraghdr6 fh = {};
	int frag = 0, first = 1;

	if (proto == PROTO_FRAG) {
		if (plen < FRAG_HLEN || bpf_skb_load_bytes(skb, l6, &fh, sizeof(fh)) < 0)
			return count(C_DROP_SHORT, TC_ACT_SHOT);
		if (fh.nh != PROTO_TCP && fh.nh != PROTO_UDP)
			return count(C_DROP_FRAG, TC_ACT_SHOT);
		frag = 1;
		first = (bpf_ntohs(fh.offlg) & 0xfff8) == 0;
		proto = fh.nh;
		plen -= FRAG_HLEN;
		l6 += FRAG_HLEN;
	}

	if (proto == PROTO_TCP || proto == PROTO_UDP) {
		if (proto == PROTO_UDP && first) {
			__u16 csum;
			if (bpf_skb_load_bytes(skb, l6 + 6, &csum, sizeof(csum)) < 0)
				return count(C_DROP_SHORT, TC_ACT_SHOT);
			if (csum == 0)
				return count(C_DROP_UDP_ZERO_CSUM, TC_ACT_SHOT);
		}
		__be32 to[2] = {ip6.src[3], ip6.dst[3]};
		diff = bpf_csum_diff(ip6.src, 32, to, sizeof(to), 0); // src and dst are adjacent
	} else if (proto == PROTO_ICMPV6) {
		if (bpf_skb_load_bytes(skb, l6, &type6, 1) < 0)
			return count(C_DROP_SHORT, TC_ACT_SHOT);
		if (type6 == 128)
			type4 = 8;
		else if (type6 == 129)
			type4 = 0;
		else
			return count(C_DROP_ICMP_UNSUPPORTED, TC_ACT_SHOT);
		struct pseudo6 ph = {
			.src = {ip6.src[0], ip6.src[1], ip6.src[2], ip6.src[3]},
			.dst = {ip6.dst[0], ip6.dst[1], ip6.dst[2], ip6.dst[3]},
			.len = bpf_htonl(plen),
			.nh = bpf_htonl(PROTO_ICMPV6),
		};
		diff = bpf_csum_diff((__be32 *)&ph, sizeof(ph), NULL, 0, 0); // ICMP has no pseudo-header
	} else {
		return count(C_DROP_PROTO, TC_ACT_SHOT); // other protocols, and IPv6 extension headers other than a fragment header
	}
	if (diff < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);

	__u32 tot = (__u32)plen + V4_HLEN;
	ip4.vihl = 0x45;
	ip4.tos = (bpf_ntohl(ip6.vtcfl) >> 20) & 0xff;
	ip4.tot_len = bpf_htons(tot);
	if (frag) {
		__u16 offlg = bpf_ntohs(fh.offlg);
		ip4.frag = bpf_htons(((offlg & 0xfff8) >> 3) | (offlg & 1 ? IPV4_MF : 0));
		ip4.id = bpf_htons((__u16)bpf_ntohl(fh.id));
	} else {
		// DF stays clear: RFC 7915 5.1 sets it only above 1260 bytes, and no packet or GSO segment the primary passes is that long (a GSO batch is, so its length must not decide DF).
		ip4.id = (__be16)bpf_get_prandom_u32();
	}
	ip4.ttl = ip6.hlim;
	ip4.proto = proto == PROTO_ICMPV6 ? PROTO_ICMP : proto;
	ip4.src = ip6.src[3];
	ip4.dst = ip6.dst[3];
	ip4.check = fold(bpf_csum_diff(NULL, 0, (__be32 *)&ip4, sizeof(ip4), 0));

	// Remove the fragment header (the room after the IPv6 header) before the IPv6 header shrinks to IPv4's.
	if (frag && bpf_skb_adjust_room(skb, -FRAG_HLEN, BPF_ADJ_ROOM_NET, 0) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	__be16 ethertype = bpf_htons(ETH_P_IP);
	if (bpf_skb_store_bytes(skb, 12, &ethertype, sizeof(ethertype), 0) < 0 ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip4, sizeof(ip4), BPF_F_RECOMPUTE_CSUM) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);

	if (!first) {
		// No L4 header in this fragment.
	} else if (proto == PROTO_TCP) {
		if (bpf_l4_csum_replace(skb, l4 + 16, 0, diff, BPF_F_PSEUDO_HDR) < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
	} else if (proto == PROTO_UDP) {
		if (bpf_l4_csum_replace(skb, l4 + 6, 0, diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0) < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
	} else {
		// Echo: remove the pseudo-header, then account for the type change (the code is 0 in both).
		__be16 from = bpf_htons((__u16)type6 << 8), to = bpf_htons((__u16)type4 << 8);
		if (bpf_l4_csum_replace(skb, l4 + 2, 0, diff, 0) < 0 ||
		    bpf_l4_csum_replace(skb, l4 + 2, from, to, 2) < 0 ||
		    bpf_skb_store_bytes(skb, l4, &type4, 1, 0) < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
	}
	return count(C_6TO4_OK, TC_ACT_OK);
}

/*
xlat_icmp4_error translates an ICMPv4 error about a client's TCP or UDP packet into ICMPv6 (RFC 7915 4.2), so that, for example, a connection to a LAN host that is down fails with "unreachable" instead of timing out. It is self-contained so that it can be removed if dropping ICMP errors is ever preferred.

Both the outer and the quoted IPv4 header become IPv6 headers; conntrack then maps the quoted packet back to the client's flow. Errors about a ping are dropped, as through netstack.
*/
#define ICMP6_ERR_MAX 1240 // ICMPv6 message bytes, so the packet fits 1280 (RFC 4443 2.4(c)); Linux sends ICMPv4 errors of at most 576 bytes
#define CSUM_CHUNK 64

struct icmphdr_err {
	__u8 type;
	__u8 code;
	__u16 check;
	__be16 unused;
	__be16 mtu; // next-hop MTU in ICMPv4 "fragmentation needed"
};

struct icmp6hdr_err {
	__u8 type;
	__u8 code;
	__u16 check;
	__be32 mtu; // in ICMPv6 Packet Too Big, unused otherwise
};

static __always_inline int xlat_icmp4_error(struct __sk_buff *skb, struct v4hdr *ip4, struct config *cfg)
{
	struct icmphdr_err icmp4;
	struct v4hdr in4;
	__u16 tot = bpf_ntohs(ip4->tot_len);

	if (tot < V4_HLEN + 8 + V4_HLEN + 8 ||
	    bpf_skb_load_bytes(skb, ETH_HLEN + V4_HLEN, &icmp4, sizeof(icmp4)) < 0 ||
	    bpf_skb_load_bytes(skb, ETH_HLEN + V4_HLEN + 8, &in4, sizeof(in4)) < 0)
		return count(C_DROP_SHORT, TC_ACT_SHOT);
	if (in4.vihl != 0x45)
		return count(C_DROP_OPTIONS, TC_ACT_SHOT);
	if (in4.src != cfg->x4)
		return count(C_DROP_NOT_OURS, TC_ACT_SHOT);
	if ((in4.proto != PROTO_TCP && in4.proto != PROTO_UDP) || (bpf_ntohs(in4.frag) & IPV4_OFF_MASK) || bpf_ntohs(in4.tot_len) < V4_HLEN)
		return count(C_DROP_ICMP_UNSUPPORTED, TC_ACT_SHOT);

	struct icmp6hdr_err icmp6 = {};
	if (icmp4.type == 11) { // time exceeded: the codes are the same
		if (icmp4.code > 1)
			return count(C_DROP_ICMP_UNSUPPORTED, TC_ACT_SHOT);
		icmp6.type = 3;
		icmp6.code = icmp4.code;
	} else {
		switch (icmp4.code) {
		case 0: case 1: case 5: case 6: case 7: case 8: case 11: case 12: // network or host unreachable
			icmp6.type = 1;
			icmp6.code = 0;
			break;
		case 3: // port unreachable
			icmp6.type = 1;
			icmp6.code = 4;
			break;
		case 9: case 10: case 13: // administratively prohibited
			icmp6.type = 1;
			icmp6.code = 1;
			break;
		case 4: { // fragmentation needed: Packet Too Big, with the MTU the IPv6 packet may have
			__u32 mtu = (__u32)bpf_ntohs(icmp4.mtu) + 20;
			icmp6.type = 2;
			icmp6.mtu = bpf_htonl(mtu < 1280 ? 1280 : mtu);
			break;
		}
		default: // protocol unreachable, precedence
			return count(C_DROP_ICMP_UNSUPPORTED, TC_ACT_SHOT);
		}
	}

	__u32 rest = tot - V4_HLEN - 8 - V4_HLEN; // quoted L4 bytes
	__u32 len6 = 8 + V6_HLEN + rest;          // the ICMPv6 message
	if (len6 > ICMP6_ERR_MAX)
		return count(C_DROP_ICMP_UNSUPPORTED, TC_ACT_SHOT);

	struct v6hdr out6 = {
		.vtcfl = bpf_htonl((6 << 28) | ((__u32)ip4->tos << 20)),
		.plen = bpf_htons(len6),
		.nh = PROTO_ICMPV6,
		.hlim = ip4->ttl,
		.src = {cfg->prefix[0], cfg->prefix[1], cfg->prefix[2], ip4->src},
		.dst = {cfg->prefix[0], cfg->prefix[1], cfg->prefix[2], ip4->dst},
	};
	struct v6hdr in6 = {
		.vtcfl = bpf_htonl((6 << 28) | ((__u32)in4.tos << 20)),
		.plen = bpf_htons(bpf_ntohs(in4.tot_len) - V4_HLEN),
		.nh = in4.proto,
		.hlim = in4.ttl,
		.src = {cfg->prefix[0], cfg->prefix[1], cfg->prefix[2], in4.src},
		.dst = {cfg->prefix[0], cfg->prefix[1], cfg->prefix[2], in4.dst},
	};

	// The quoted checksum, if the error quotes enough of the packet to include it.
	__u32 qoff = in4.proto == PROTO_TCP ? 16 : 6;
	__u16 qc = 0;
	int haveqc = rest >= qoff + 2 && bpf_skb_load_bytes(skb, ETH_HLEN + V4_HLEN + 8 + V4_HLEN + qoff, &qc, sizeof(qc)) == 0 &&
		     !(in4.proto == PROTO_UDP && qc == 0);
	if (haveqc) {
		__be32 from[2] = {in4.src, in4.dst};
		__s64 d = bpf_csum_diff(from, sizeof(from), in6.src, 32, (__u16)~qc);
		if (d < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
		qc = fold(d);
		if (in4.proto == PROTO_UDP && qc == 0)
			qc = 0xffff;
	}

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	__be16 ethertype = bpf_htons(ETH_P_IPV6);
	if (bpf_skb_store_bytes(skb, 12, &ethertype, sizeof(ethertype), 0) < 0 ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &out6, sizeof(out6), BPF_F_RECOMPUTE_CSUM) < 0 ||
	    bpf_skb_adjust_room(skb, V6_HLEN - V4_HLEN, BPF_ADJ_ROOM_NET, 0) < 0 ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + V6_HLEN, &icmp6, sizeof(icmp6), BPF_F_RECOMPUTE_CSUM) < 0 ||
	    bpf_skb_store_bytes(skb, ETH_HLEN + V6_HLEN + 8, &in6, sizeof(in6), BPF_F_RECOMPUTE_CSUM) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	if (haveqc && bpf_skb_store_bytes(skb, ETH_HLEN + V6_HLEN + 8 + V6_HLEN + qoff, &qc, sizeof(qc), BPF_F_RECOMPUTE_CSUM) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);

	struct pseudo6 ph = {
		.src = {out6.src[0], out6.src[1], out6.src[2], out6.src[3]},
		.dst = {out6.dst[0], out6.dst[1], out6.dst[2], out6.dst[3]},
		.len = bpf_htonl(len6),
		.nh = bpf_htonl(PROTO_ICMPV6),
	};
	__s64 sum = bpf_csum_diff(NULL, 0, (__be32 *)&ph, sizeof(ph), 0);
	for (int i = 0; i < ICMP6_ERR_MAX / CSUM_CHUNK + 1; i++) {
		__u32 off = i * CSUM_CHUNK;
		if (sum < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
		if (off >= len6)
			break;
		// Written so that the verifier sees n in [1, CSUM_CHUNK].
		__u32 n = len6 - off - 1;
		if (n > CSUM_CHUNK - 1)
			n = CSUM_CHUNK - 1;
		n += 1;
		__u8 buf[CSUM_CHUNK] = {}; // zero past the end of the message, which the checksum treats as padding
		if (bpf_skb_load_bytes(skb, ETH_HLEN + V6_HLEN + off, buf, n) < 0)
			return count(C_DROP_SHORT, TC_ACT_SHOT);
		sum = bpf_csum_diff(NULL, 0, (__be32 *)buf, CSUM_CHUNK, (__u32)sum);
	}
	if (sum < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	__u16 check = fold(sum);
	if (bpf_skb_store_bytes(skb, ETH_HLEN + V6_HLEN + 2, &check, sizeof(check), BPF_F_RECOMPUTE_CSUM) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	return count(C_ICMP_ERR_OK, TC_ACT_OK);
}

SEC("netkit/peer")
int xlat4to6(struct __sk_buff *skb)
{
	struct v4hdr ip4;
	struct v6hdr ip6 = {};
	__u32 zero = 0;
	__u8 type4 = 0, type6 = 0;
	__s64 diff;

	struct config *cfg = bpf_map_lookup_elem(&config_map, &zero);
	if (!cfg || cfg->x4 == 0)
		return count(C_DROP_NOT_OURS, TC_ACT_SHOT);
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return count(C_DROP_NOT_IP, TC_ACT_SHOT);
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip4, sizeof(ip4)) < 0)
		return count(C_DROP_SHORT, TC_ACT_SHOT);
	if (ip4.vihl != 0x45)
		return count((ip4.vihl >> 4) == 4 ? C_DROP_OPTIONS : C_DROP_NOT_IP, TC_ACT_SHOT);
	if (ip4.dst != cfg->x4)
		return count(C_DROP_NOT_OURS, TC_ACT_SHOT);

	__u16 tot = bpf_ntohs(ip4.tot_len);
	if (tot < V4_HLEN)
		return count(C_DROP_SHORT, TC_ACT_SHOT);
	__u16 plen = tot - V4_HLEN;
	__u8 proto = ip4.proto;
	__u16 fragf = bpf_ntohs(ip4.frag);
	int frag = (fragf & (IPV4_MF | IPV4_OFF_MASK)) != 0;
	int first = (fragf & IPV4_OFF_MASK) == 0;
	__u32 l4 = ETH_HLEN + V6_HLEN + (frag ? FRAG_HLEN : 0);
	struct fraghdr6 fh = {};

	if (frag) {
		if (proto != PROTO_TCP && proto != PROTO_UDP)
			return count(C_DROP_FRAG, TC_ACT_SHOT);
		fh.nh = proto;
		fh.offlg = bpf_htons(((fragf & IPV4_OFF_MASK) << 3) | (fragf & IPV4_MF ? 1 : 0));
		fh.id = bpf_htonl(bpf_ntohs(ip4.id));
	}

	ip6.vtcfl = bpf_htonl((6 << 28) | ((__u32)ip4.tos << 20));
	ip6.plen = bpf_htons(plen + (frag ? FRAG_HLEN : 0));
	ip6.nh = frag ? PROTO_FRAG : proto == PROTO_ICMP ? PROTO_ICMPV6 : proto;
	ip6.hlim = ip4.ttl;
	ip6.src[0] = cfg->prefix[0];
	ip6.src[1] = cfg->prefix[1];
	ip6.src[2] = cfg->prefix[2];
	ip6.src[3] = ip4.src;
	ip6.dst[0] = cfg->prefix[0];
	ip6.dst[1] = cfg->prefix[1];
	ip6.dst[2] = cfg->prefix[2];
	ip6.dst[3] = ip4.dst; // X4 inside the canonical prefix is X6

	if (proto == PROTO_TCP || proto == PROTO_UDP) {
		if (proto == PROTO_UDP && first) {
			__u16 csum;
			if (bpf_skb_load_bytes(skb, ETH_HLEN + V4_HLEN + 6, &csum, sizeof(csum)) < 0)
				return count(C_DROP_SHORT, TC_ACT_SHOT);
			if (csum == 0)
				return count(C_DROP_UDP_ZERO_CSUM, TC_ACT_SHOT);
		}
		__be32 from[2] = {ip4.src, ip4.dst};
		diff = bpf_csum_diff(from, sizeof(from), ip6.src, 32, 0);
	} else if (proto == PROTO_ICMP) {
		if (bpf_skb_load_bytes(skb, ETH_HLEN + V4_HLEN, &type4, 1) < 0)
			return count(C_DROP_SHORT, TC_ACT_SHOT);
		if (type4 == 0)
			type6 = 129;
		else if (type4 == 8)
			type6 = 128;
		else if (type4 == 3 || type4 == 11)
			return xlat_icmp4_error(skb, &ip4, cfg);
		else
			return count(C_DROP_ICMP_UNSUPPORTED, TC_ACT_SHOT);
		struct pseudo6 ph = {
			.src = {ip6.src[0], ip6.src[1], ip6.src[2], ip6.src[3]},
			.dst = {ip6.dst[0], ip6.dst[1], ip6.dst[2], ip6.dst[3]},
			.len = bpf_htonl(plen),
			.nh = bpf_htonl(PROTO_ICMPV6),
		};
		diff = bpf_csum_diff(NULL, 0, (__be32 *)&ph, sizeof(ph), 0); // ICMPv6 adds a pseudo-header
	} else {
		return count(C_DROP_PROTO, TC_ACT_SHOT);
	}
	if (diff < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);

	if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	__be16 ethertype = bpf_htons(ETH_P_IPV6);
	if (bpf_skb_store_bytes(skb, 12, &ethertype, sizeof(ethertype), 0) < 0 ||
	    bpf_skb_store_bytes(skb, ETH_HLEN, &ip6, sizeof(ip6), BPF_F_RECOMPUTE_CSUM) < 0)
		return count(C_DROP_HELPER, TC_ACT_SHOT);
	// Insert the fragment header in new room after the IPv6 header.
	if (frag && (bpf_skb_adjust_room(skb, FRAG_HLEN, BPF_ADJ_ROOM_NET, 0) < 0 ||
		     bpf_skb_store_bytes(skb, ETH_HLEN + V6_HLEN, &fh, sizeof(fh), BPF_F_RECOMPUTE_CSUM) < 0))
		return count(C_DROP_HELPER, TC_ACT_SHOT);

	if (!first) {
		// No L4 header in this fragment.
	} else if (proto == PROTO_TCP) {
		if (bpf_l4_csum_replace(skb, l4 + 16, 0, diff, BPF_F_PSEUDO_HDR) < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
	} else if (proto == PROTO_UDP) {
		if (bpf_l4_csum_replace(skb, l4 + 6, 0, diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0) < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
	} else {
		__be16 from = bpf_htons((__u16)type4 << 8), to = bpf_htons((__u16)type6 << 8);
		if (bpf_l4_csum_replace(skb, l4 + 2, 0, diff, 0) < 0 ||
		    bpf_l4_csum_replace(skb, l4 + 2, from, to, 2) < 0 ||
		    bpf_skb_store_bytes(skb, l4, &type6, 1, 0) < 0)
			return count(C_DROP_HELPER, TC_ACT_SHOT);
	}
	return count(C_4TO6_OK, TC_ACT_OK);
}
