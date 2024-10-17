//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>

struct config {
	// TODO(jwhited): if we add more fields consider endianness consistency in
	// the context of the data. cilium/ebpf uses native endian encoding for map
	// encoding even if we use big endian types here, e.g. __be16.
	__u16 dst_port;
	// If drop_stun is set to a nonzero value all UDP packets destined to
	// dst_port will be dropped. This is useful for shedding home client load
	// during maintenance.
	__u16 drop_stun;
};
struct config *unused_config __attribute__((unused)); // required by bpf2go -type

struct {
      __uint(type, BPF_MAP_TYPE_ARRAY);
      __uint(key_size, sizeof(__u32));
      __uint(value_size, sizeof(struct config));
      __uint(max_entries, 1);
} config_map SEC(".maps");

struct counters_key {
	__u8 unused;
	__u8 af;
	__u8 pba;
	__u8 prog_end;
};
struct counters_key *unused_counters_key __attribute__((unused)); // required by bpf2go -type

enum counter_key_af {
	COUNTER_KEY_AF_UNKNOWN,
	COUNTER_KEY_AF_IPV4,
	COUNTER_KEY_AF_IPV6,
	COUNTER_KEY_AF_LEN
};
enum counter_key_af *unused_counter_key_af __attribute__((unused)); // required by bpf2go -type

enum counter_key_packets_bytes_action {
	COUNTER_KEY_PACKETS_PASS_TOTAL,
	COUNTER_KEY_BYTES_PASS_TOTAL,
	COUNTER_KEY_PACKETS_ABORTED_TOTAL,
	COUNTER_KEY_BYTES_ABORTED_TOTAL,
	COUNTER_KEY_PACKETS_TX_TOTAL,
	COUNTER_KEY_BYTES_TX_TOTAL,
	COUNTER_KEY_PACKETS_DROP_TOTAL,
	COUNTER_KEY_BYTES_DROP_TOTAL,
	COUNTER_KEY_PACKETS_BYTES_ACTION_LEN
};
enum counter_key_packets_bytes_action *unused_counter_key_packets_bytes_action __attribute__((unused)); // required by bpf2go -type

enum counter_key_prog_end {
	COUNTER_KEY_END_UNSPECIFIED,
	COUNTER_KEY_END_UNEXPECTED_FIRST_STUN_ATTR,
	COUNTER_KEY_END_INVALID_UDP_CSUM,
	COUNTER_KEY_END_INVALID_IP_CSUM,
	COUNTER_KEY_END_NOT_STUN_PORT,
	COUNTER_KEY_END_INVALID_SW_ATTR_VAL,
	COUNTER_KEY_END_DROP_STUN,
	COUNTER_KEY_END_LEN
};
enum counter_key_prog_end *unused_counter_key_prog_end __attribute__((unused)); // required by bpf2go -type

#define COUNTERS_MAP_MAX_ENTRIES ((COUNTER_KEY_AF_LEN - 1) << 16) | \
                                 ((COUNTER_KEY_PACKETS_BYTES_ACTION_LEN - 1) << 8) | \
                                 (COUNTER_KEY_END_LEN - 1)

struct {
      __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
      __uint(key_size, sizeof(struct counters_key));
      __uint(value_size, sizeof(__u64));
      __uint(max_entries, COUNTERS_MAP_MAX_ENTRIES);
} counters_map SEC(".maps");

struct stunreq {
	__be16 type;
	__be16 length;
	__be32 magic;
	__be32 txid[3];
	// attributes follow
};

struct stunattr {
	__be16 num;
	__be16 length;
};

struct stunxor {
	__u8 unused;
	__u8 family;
	__be16 port;
	__be32 addr;
};

struct stunxor6 {
	__u8 unused;
	__u8 family;
	__be16 port;
	__be32 addr[4];
};

#define STUN_BINDING_REQUEST 1

#define STUN_MAGIC 0x2112a442

#define STUN_ATTR_SW 0x8022

#define STUN_ATTR_XOR_MAPPED_ADDR 0x0020

#define STUN_BINDING_RESPONSE 0x0101

#define STUN_MAGIC_FOR_PORT_XOR 0x2112

#define MAX_UDP_LEN_IPV4 1480

#define MAX_UDP_LEN_IPV6 1460

#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

static __always_inline __u16 csum_fold_flip(__u32 csum) {
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff); // maximum value 0x1fffe
	sum += (sum >> 16); // maximum value 0xffff
	return ~sum;
}

// csum_const_size is an alternative to bpf_csum_diff. It's a verifier
// workaround for when we are forced to use a constant max_size + bounds
// checking. The alternative being passing a dynamic length to bpf_csum_diff
// {from,to}_size arguments, which the verifier can't follow. For further info
// see: https://github.com/iovisor/bcc/issues/2463#issuecomment-512503958
static __always_inline __u16 csum_const_size(__u32 seed, void* from, void* data_end, int max_size) {
	__u16 *buf = from;
	for (int i = 0; i < max_size; i += 2) {
		if ((void *)(buf + 1) > data_end) {
			break;
		}
		seed += *buf;
		buf++;
	}
	if ((void *)buf + 1 <= data_end) {
		seed += *(__u8 *)buf;
	}
	return csum_fold_flip(seed);
}

static __always_inline __u32 pseudo_sum_ipv6(struct ipv6hdr* ip6, __u16 udp_len) {
	__u32 pseudo = 0; // TODO(jwhited): __u64 for intermediate checksum values to reduce number of ops
	for (int i = 0; i < 8; i ++) {
		pseudo += ip6->saddr.in6_u.u6_addr16[i];
		pseudo += ip6->daddr.in6_u.u6_addr16[i];
	}
	pseudo += bpf_htons(ip6->nexthdr);
	pseudo += udp_len;
	return pseudo;
}

static __always_inline __u32 pseudo_sum_ipv4(struct iphdr* ip, __u16 udp_len) {
	__u32 pseudo = (__u16)ip->saddr;
	pseudo += (__u16)(ip->saddr >> 16);
	pseudo += (__u16)ip->daddr;
	pseudo += (__u16)(ip->daddr >> 16);
	pseudo += bpf_htons(ip->protocol);
	pseudo += udp_len;
	return pseudo;
}

struct packet_context {
	enum counter_key_af af;
	enum counter_key_prog_end prog_end;
};

static __always_inline int inc_counter(struct counters_key key, __u64 val) {
	__u64 *counter = bpf_map_lookup_elem(&counters_map, &key);
	if (!counter) {
		return bpf_map_update_elem(&counters_map, &key, &val, BPF_ANY);
	}
	*counter += val;
	return bpf_map_update_elem(&counters_map, &key, counter, BPF_ANY);
}

static __always_inline int handle_counters(struct xdp_md *ctx, int action, struct packet_context *pctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	__u64 bytes = data_end - data;
	enum counter_key_packets_bytes_action packets_pba = COUNTER_KEY_PACKETS_PASS_TOTAL;
	enum counter_key_packets_bytes_action bytes_pba = COUNTER_KEY_BYTES_PASS_TOTAL;

	switch (action) {
		case XDP_ABORTED:
			packets_pba = COUNTER_KEY_PACKETS_ABORTED_TOTAL;
			bytes_pba = COUNTER_KEY_BYTES_ABORTED_TOTAL;
			break;
		case XDP_PASS:
			packets_pba = COUNTER_KEY_PACKETS_PASS_TOTAL;
			bytes_pba = COUNTER_KEY_BYTES_PASS_TOTAL;
			break;
		case XDP_TX:
			packets_pba = COUNTER_KEY_PACKETS_TX_TOTAL;
			bytes_pba = COUNTER_KEY_BYTES_TX_TOTAL;
			break;
		case XDP_DROP:
			packets_pba = COUNTER_KEY_PACKETS_DROP_TOTAL;
			bytes_pba = COUNTER_KEY_BYTES_DROP_TOTAL;
			break;
	}

	struct counters_key packets_key = {
		.af = pctx->af,
		.pba = packets_pba,
		.prog_end = pctx->prog_end,
	};

	struct counters_key bytes_key = {
		.af = pctx->af,
		.pba = bytes_pba,
		.prog_end = pctx->prog_end,
	};

	inc_counter(packets_key, 1);
	inc_counter(bytes_key, bytes);

	return 0;
}

#define is_ipv6 (pctx->af == COUNTER_KEY_AF_IPV6)
static __always_inline int handle_packet(struct xdp_md *ctx, struct packet_context *pctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	pctx->af = COUNTER_KEY_AF_UNKNOWN;
	pctx->prog_end = COUNTER_KEY_END_UNSPECIFIED;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_PASS;
	}

	struct iphdr *ip;
	struct ipv6hdr *ip6;
	struct udphdr *udp;

	int validate_udp_csum = 0;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		pctx->af = COUNTER_KEY_AF_IPV4;
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end) {
			return XDP_PASS;
		}

		if (ip->ihl != 5 ||
			ip->version != 4 ||
			ip->protocol != IPPROTO_UDP ||
			(ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0) {
			return XDP_PASS;
		}

		// validate ipv4 header checksum
		__u32 cs_unfolded = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), 0);
		__u16 cs = csum_fold_flip(cs_unfolded);
		if (cs != 0) {
			pctx->prog_end = COUNTER_KEY_END_INVALID_IP_CSUM;
			return XDP_PASS;
		}

		if (bpf_ntohs(ip->tot_len) != data_end - (void *)ip) {
			return XDP_PASS;
		}

		udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end) {
			return XDP_PASS;
		}

		if (udp->check != 0) {
			// https://datatracker.ietf.org/doc/html/rfc768#page-3
			// If the computed  checksum  is zero,  it is transmitted  as all
			// ones (the equivalent  in one's complement  arithmetic).   An all
			// zero  transmitted checksum  value means that the transmitter
			// generated  no checksum  (for debugging or for higher level
			// protocols that don't care).
			validate_udp_csum = 1;
		}
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		pctx->af = COUNTER_KEY_AF_IPV6;
		ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end) {
			return XDP_PASS;
		}

		if (ip6->version != 6 || ip6->nexthdr != IPPROTO_UDP) {
			return XDP_PASS;
		}

		udp = (void *)(ip6 + 1);
		if ((void *)(udp + 1) > data_end) {
			return XDP_PASS;
		}

		if (bpf_ntohs(ip6->payload_len) != data_end - (void *)udp) {
			return XDP_PASS;
		}

		// https://datatracker.ietf.org/doc/html/rfc8200#page-28
		// Unlike IPv4, the default behavior when UDP packets are
		// originated by an IPv6 node is that the UDP checksum is not
		// optional.  That is, whenever originating a UDP packet, an IPv6
		// node must compute a UDP checksum over the packet and the
		// pseudo-header, and, if that computation yields a result of
		// zero, it must be changed to hex FFFF for placement in the UDP
		// header.  IPv6 receivers must discard UDP packets containing a
		// zero checksum and should log the error.
		validate_udp_csum = 1;
	} else {
		return XDP_PASS;
	}

	__u32 config_key = 0;
	struct config *c = bpf_map_lookup_elem(&config_map, &config_key);
	if (!c) {
		return XDP_PASS;
	}

	if (bpf_ntohs(udp->len) != data_end - (void *)udp) {
		return XDP_PASS;
	}

	if (bpf_ntohs(udp->dest) != c->dst_port) {
		pctx->prog_end = COUNTER_KEY_END_NOT_STUN_PORT;
		return XDP_PASS;
	}

	if (c->drop_stun) {
		pctx->prog_end = COUNTER_KEY_END_DROP_STUN;
		return XDP_DROP;
	}

	if (validate_udp_csum) {
		__u16 cs;
		__u32 pseudo_sum;
		if (is_ipv6) {
			pseudo_sum = pseudo_sum_ipv6(ip6, udp->len);
			cs = csum_const_size(pseudo_sum, udp, data_end, MAX_UDP_LEN_IPV6);
		} else {
			pseudo_sum = pseudo_sum_ipv4(ip, udp->len);
			cs = csum_const_size(pseudo_sum, udp, data_end, MAX_UDP_LEN_IPV4);
		}
		if (cs != 0) {
			pctx->prog_end = COUNTER_KEY_END_INVALID_UDP_CSUM;
			return XDP_PASS;
		}
	}

	struct stunreq *req = (void *)(udp + 1);
	if ((void *)(req + 1) > data_end) {
		return XDP_PASS;
	}

	if (req->type != bpf_htons(STUN_BINDING_REQUEST)) {
		return XDP_PASS;
	}
	if (bpf_ntohl(req->magic) != STUN_MAGIC) {
		return XDP_PASS;
	}

	void *attrs = (void *)(req + 1);
	__u16 attrs_len = ((char *)data_end) - ((char *)attrs);
	if (bpf_ntohs(req->length) != attrs_len) {
		return XDP_PASS;
	}

	struct stunattr *sa = attrs;
	if ((void *)(sa + 1) > data_end) {
		return XDP_PASS;
	}

	// Assume the order and contents of attributes. We *could* loop through
	// them, but parsing their lengths and performing arithmetic against the
	// packet pointer is more pain than it's worth. Bounds checks are invisible
	// to the verifier in certain circumstances where things move from registers
	// to the stack and/or compilation optimizations remove them entirely. There
	// have only ever been two attributes included by the client, and we are
	// only interested in one of them, anyway. Verify the software attribute,
	// but ignore the fingerprint attribute as it's only useful where STUN is
	// multiplexed with other traffic on the same port/socket, which is not the
	// case here.
	void *attr_data = (void *)(sa + 1);
	if (bpf_ntohs(sa->length) != 8 || bpf_ntohs(sa->num) != STUN_ATTR_SW) {
		pctx->prog_end = COUNTER_KEY_END_UNEXPECTED_FIRST_STUN_ATTR;
		return XDP_PASS;
	}
	if (attr_data + 8 > data_end) {
		return XDP_PASS;
	}
	char want_sw[] = {0x74, 0x61, 0x69, 0x6c, 0x6e, 0x6f, 0x64, 0x65}; // tailnode
	char *got_sw = attr_data;
	for (int j = 0; j < 8; j++) {
		if (got_sw[j] != want_sw[j]) {
			pctx->prog_end = COUNTER_KEY_END_INVALID_SW_ATTR_VAL;
			return XDP_PASS;
		}
	}

	// Begin transforming packet into a STUN_BINDING_RESPONSE. From here
	// onwards we return XDP_ABORTED instead of XDP_PASS when transformations or
	// bounds checks fail as it would be nonsensical to pass a mangled packet
	// through to the kernel, and we may be interested in debugging via
	// tracepoint.

	// Set success response and new length. Magic cookie and txid remain the
	// same.
	req->type = bpf_htons(STUN_BINDING_RESPONSE);
	if (is_ipv6) {
		req->length = bpf_htons(sizeof(struct stunattr) + sizeof(struct stunxor6));
	} else {
		req->length = bpf_htons(sizeof(struct stunattr) + sizeof(struct stunxor));
	}

	// Set attr type. Length remains unchanged, but set it again for future
	// safety reasons.
	sa->num = bpf_htons(STUN_ATTR_XOR_MAPPED_ADDR);
	if (is_ipv6) {
		sa->length = bpf_htons(sizeof(struct stunxor6));
	} else {
		sa->length = bpf_htons(sizeof(struct stunxor));
	}

	struct stunxor *xor;
	struct stunxor6 *xor6;

	// Adjust tail and reset header pointers.
	int adjust_tail_by;
	if (is_ipv6) {
		xor6 = attr_data;
		adjust_tail_by = (void *)(xor6 + 1) - data_end;
	} else {
		xor = attr_data;
		adjust_tail_by = (void *)(xor + 1) - data_end;
	}
	if (bpf_xdp_adjust_tail(ctx, adjust_tail_by)) {
		return XDP_ABORTED;
	}
	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;
	eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}
	if (is_ipv6) {
		ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end) {
			return XDP_ABORTED;
		}
		udp = (void *)(ip6 + 1);
		if ((void *)(udp + 1) > data_end) {
			return XDP_ABORTED;
		}
	} else {
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end) {
			return XDP_ABORTED;
		}
		udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end) {
			return XDP_ABORTED;
		}
	}
	req = (void *)(udp + 1);
	if ((void *)(req + 1) > data_end) {
		return XDP_ABORTED;
	}
	sa = (void *)(req + 1);
	if ((void *)(sa + 1) > data_end) {
		return XDP_ABORTED;
	}

	// Set attr data.
	if (is_ipv6) {
		xor6 = (void *)(sa + 1);
		if ((void *)(xor6 + 1) > data_end) {
			return XDP_ABORTED;
		}
		xor6->unused = 0x00; // unused byte
		xor6->family = 0x02;
		xor6->port = udp->source ^ bpf_htons(STUN_MAGIC_FOR_PORT_XOR);
		xor6->addr[0] = ip6->saddr.in6_u.u6_addr32[0] ^ bpf_htonl(STUN_MAGIC);
		for (int i = 1; i < 4; i++) {
			// All three are __be32, no endianness flips.
			xor6->addr[i] = ip6->saddr.in6_u.u6_addr32[i] ^ req->txid[i-1];
		}
	} else {
		xor = (void *)(sa + 1);
		if ((void *)(xor + 1) > data_end) {
			return XDP_ABORTED;
		}
		xor->unused = 0x00; // unused byte
		xor->family = 0x01;
		xor->port = udp->source ^ bpf_htons(STUN_MAGIC_FOR_PORT_XOR);
		xor->addr = ip->saddr ^ bpf_htonl(STUN_MAGIC);
	}

	// Flip ethernet header source and destination address.
	__u8 eth_tmp[ETH_ALEN];
	__builtin_memcpy(eth_tmp, eth->h_source, ETH_ALEN);
	__builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	__builtin_memcpy(eth->h_dest, eth_tmp, ETH_ALEN);

	// Flip ip header source and destination address.
	if (is_ipv6) {
		struct in6_addr ip_tmp = ip6->saddr;
		ip6->saddr = ip6->daddr;
		ip6->daddr = ip_tmp;
	} else {
		__be32 ip_tmp = ip->saddr;
		ip->saddr = ip->daddr;
		ip->daddr = ip_tmp;
	}

	// Flip udp header source and destination ports;
	__be16 port_tmp = udp->source;
	udp->source = udp->dest;
	udp->dest = port_tmp;

	// Update total length, TTL, and checksum.
	__u32 cs = 0;
	if (is_ipv6) {
		if ((void *)(ip6 +1) > data_end) {
			return XDP_ABORTED;
		}
		__u16 payload_len = data_end - (void *)(ip6 + 1);
		ip6->payload_len = bpf_htons(payload_len);
		ip6->hop_limit = IPDEFTTL;
	} else {
		__u16 tot_len = data_end - (void *)ip;
		ip->tot_len = bpf_htons(tot_len);
		ip->ttl = IPDEFTTL;
		ip->check = 0;
		cs = bpf_csum_diff(0, 0, (void *)ip, sizeof(*ip), cs);
		ip->check = csum_fold_flip(cs);
	}

	// Avoid dynamic length math against the packet pointer, which is just a big
	// verifier headache. Instead sizeof() all the things.
	int to_csum_len = sizeof(*udp) + sizeof(*req) + sizeof(*sa);
	// Update udp header length and checksum.
	if (is_ipv6) {
		to_csum_len += sizeof(*xor6);
		udp = (void *)(ip6 + 1);
		if ((void *)(udp +1) > data_end) {
			return XDP_ABORTED;
		}
		__u16 udp_len = data_end - (void *)udp;
		udp->len = bpf_htons(udp_len);
		udp->check = 0;
		cs = pseudo_sum_ipv6(ip6, udp->len);
	} else {
		to_csum_len += sizeof(*xor);
		udp = (void *)(ip + 1);
		if ((void *)(udp +1) > data_end) {
			return XDP_ABORTED;
		}
		__u16 udp_len = data_end - (void *)udp;
		udp->len = bpf_htons(udp_len);
		udp->check = 0;
		cs = pseudo_sum_ipv4(ip, udp->len);
	}
	if ((void *)udp + to_csum_len > data_end) {
		return XDP_ABORTED;
	}
	cs = bpf_csum_diff(0, 0, (void*)udp, to_csum_len, cs);
	udp->check = csum_fold_flip(cs);
	return XDP_TX;
}
#undef is_ipv6

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	struct packet_context pctx = {
		.af = COUNTER_KEY_AF_UNKNOWN,
		.prog_end = COUNTER_KEY_END_UNSPECIFIED,
	};
	int action = XDP_PASS;
	action = handle_packet(ctx, &pctx);
	handle_counters(ctx, action, &pctx);
	return action;
}
