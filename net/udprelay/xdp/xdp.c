//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>

char _license[4] SEC("license") = "GPL";

struct config {
	__u16 dst_port;
};
struct config *unused_config __attribute__((unused)); // required by bpf2go -type

struct {
      __uint(type, BPF_MAP_TYPE_ARRAY);
      __uint(key_size, sizeof(__u32));
      __uint(value_size, sizeof(struct config));
      __uint(max_entries, 1);
} config_map SEC(".maps");

struct endpoint {
	__be32 participant_addrs[2][4];
	__u16 participant_ports[2];
	__u8 participant_is_ipv6[2];
};
struct endpoint *unused_endpoint __attribute__((unused)); // required by bpf2go -type

#define MAX_GENEVE_VNI (1 << 24) - 1

struct {
      __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
      __uint(key_size, sizeof(__u32)); // key is Geneve VNI
      __uint(value_size, sizeof(struct endpoint));
      __uint(max_entries, MAX_GENEVE_VNI);
} endpoint_map SEC(".maps");

#define MAX_UDP_LEN_IPV4 1480

#define MAX_UDP_LEN_IPV6 1460

#define IP_MF 0x2000
#define IP_OFFSET 0x1fff

/*
Geneve Header:
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Virtual Network Identifier (VNI)       |    Reserved   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                    Variable-Length Options                    ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct geneve_header {
    __u8 first;
    __u8 second;
    __be16 protocol;
    __be32 vni;
};

static __always_inline __u16 csum_fold(__u32 csum) {
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff); // maximum value 0x1fffe
	sum += (sum >> 16); // maximum value 0xffff
	return sum;
}

static __always_inline __u16 csum_fold_flip(__u32 csum) {
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff); // maximum value 0x1fffe
	sum += (sum >> 16); // maximum value 0xffff
	return ~sum;
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

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

	struct iphdr *ip;
	struct ipv6hdr *ip6;
	struct udphdr *udp;

    int validate_udp_csum = 0;
    int is_ipv6 = 0;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
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
        is_ipv6 = 1;
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
        return XDP_PASS;
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
			return XDP_PASS;
		}
	}

	struct geneve_header *geneve = (void *)(udp + 1);
	if ((void *)(geneve +1) > data_end) {
	    return XDP_PASS;
	}

	if (geneve->first != 0) {
	    // first 2 bits are version, must be zero
	    // next 6 bits are opt len, must be zero
	    return XDP_PASS;
	}

	if (geneve->second != 0) {
	    // first bit is control, must be zero
	    // next bit is critical (options), must be zero
	    // next 6 bits are reserved, must be zero
	    return XDP_PASS;
	}

	if ((geneve->vni & 0x000000FF) != 0) {
	    // last byte is reserved, must be zero
        return XDP_PASS;
	}

	__u32 vni_key = bpf_ntohl(geneve->vni) >> 8;
	struct endpoint *e = bpf_map_lookup_elem(&endpoint_map, &vni_key);
	if (!e) {
	    return XDP_PASS;
	}

    int out_participant_index = -1; // -1 = unmatched
    if (is_ipv6) {
        // TODO
    } else {
        for (int i = 0; i < 2; i ++) {
            if (e->participant_is_ipv6[i] == 0 &&
                e->participant_addrs[i][3] == ip->saddr &&
                e->participant_ports[i] == bpf_ntohs(udp->source))
            {
                if (i == 0) {
                    out_participant_index = 1;
                } else {
                    out_participant_index = 0;
                }
                break;
            }
        }
    }
    if (out_participant_index == -1) {
        return XDP_PASS;
    }

    if (e->participant_is_ipv6[out_participant_index] == is_ipv6) {
        // matching in/out address family
        if (is_ipv6) {
            // TODO: in ipv6, out ipv6
        } else {
            // TODO: in ipv4, out ipv4

            // Update IPv4 header
            __be32 p_addr = e->participant_addrs[out_participant_index][3];
            __u32 ip_csum = ~(__u32)ip->check;
            __u32 udp_csum = ~(__u32)udp->check;
            ip_csum = bpf_csum_diff(&ip->saddr, 4, &p_addr, 4, ip_csum);
            udp_csum = bpf_csum_diff(&ip->saddr, 4, &p_addr, 4, udp_csum);
            ip->check = csum_fold_flip(ip_csum);
            ip->saddr = ip->daddr;
            ip->daddr = p_addr;

            #define AF_INET 2
            struct bpf_fib_lookup fib_params = {};
            fib_params.family	= AF_INET;
            fib_params.tos		= ip->tos;
            fib_params.l4_protocol	= ip->protocol;
            fib_params.sport	= 0;
            fib_params.dport	= 0;
            fib_params.tot_len	= bpf_ntohs(ip->tot_len);
            fib_params.ipv4_src	= ip->saddr;
            fib_params.ipv4_dst	= ip->daddr;
            fib_params.ifindex = ctx->ingress_ifindex;

            int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
            if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
                return XDP_ABORTED;
            }

            // Rewrite ethernet header source and destination address.
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);

            // Update UDP header
            __u32 old_udp_port = (__u32)udp->source;
            __u32 new_udp_port = (__u32)bpf_htons(e->participant_ports[out_participant_index]);
            udp_csum = bpf_csum_diff(&old_udp_port, 4, &new_udp_port, 4, udp_csum);
            udp->check = csum_fold_flip(udp_csum);
            udp->source = udp->dest;
            udp->dest = bpf_htons(e->participant_ports[out_participant_index]);
            udp = (void *)(ip + 1);
            if ((void *)(udp +1) > data_end) {
              return XDP_ABORTED;
            }

            return XDP_TX;
        }
    } else if (e->participant_is_ipv6[out_participant_index] == 0) {
        // TODO: in ipv4, out ipv6
    } else {
        // TODO: in ipv6, out ipv4
    }

	return XDP_PASS;
}