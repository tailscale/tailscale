//go:build ignore

#define	_FEATURES_H	1

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "types.h"

volatile const __u32 ifidx_divert;
volatile const __u32 ifidx_tailscale;

struct bpf_map_def SEC("maps") acl_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(acl_key),
  .value_size = sizeof(acl_action),
  .max_entries = 10000,
};

struct bpf_map_def SEC("maps") src_to_id = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct bpf_lpm_trie_key),
  .value_size = sizeof(endpoint_id),
  .max_entries = 10000,
};

struct bpf_map_def SEC("maps") dst_to_id = {
  .type = BPF_MAP_TYPE_LPM_TRIE,
  .key_size = sizeof(struct bpf_lpm_trie_key),
  .value_size = sizeof(endpoint_id),
  .max_entries = 10000,
};

SEC("classifier/ingress_tailscale")
int ingress_tailscale(struct __sk_buff *skb) {
  void *data = (void*)(long)skb->data;
  void *data_end = (void*)(long)skb->data_end;
  lpm_key srck, dstk;
  u16 dst_port = 0;
  void *l4_header = 0;
  u8 l4_proto = 0;

  switch (bpf_ntohs(skb->protocol)) {
  case ETH_P_IP:
	struct iphdr *v4_hdr = data;
	if (v4_hdr->ver_len != 45) {
	  return TC_ACT_OK; // TODO: drop
	}

	srck.lpm.prefixlen = 32;
	memset(&srck.addr[0], 0, 12);
	memcpy(&srck.addr[12], &v4_hdr->saddr, 4);
	dstk.lpm.prefixlen = 32;
	memset(&dstk.addr[0], 0, 12);
	memcpy(&dstk.addr[12], &v4_hdr->daddr, 4);
	l4_header = data + sizeof(v4_hdr);
	l4_proto = v4_hdr->proto;
	break;
  case ETH_P_IPV6:
	struct ipv6hdr *v6_hdr = data;
	srck.lpm.prefixlen = 128;
	memcpy(&srck.addr[0], &ipv6_hdr->saddr, 16);
	dstk.lpm.prefixlen = 128;
	memcpy(&srck.addr[0], &ipv6_hdr->daddr, 16);
	l4_header = data + sizeof(v6_hdr);
	l4_proto = v6_hdr->nexthdr;
	break;
  default:
	return TC_ACT_OK; // TODO: should drop unknown things, not accept.
  }

  switch (l4_proto) {
  case 6: // TCP
	struct tcphdr *tcp_hdr = l4_header;
	dst_port = ntohs(tcp_hdr->dest);
	break;
  case 17: // UDP
	struct udphdr *udp_hdr = l4_header;
	dst_port = ntohs(udp_hdr->dest);
	break;
  default:
	return TC_ACT_OK; // TODO: should drop
  }

  bpf_printk("src: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			 srck.addr[0],
			 srck.addr[1],
			 srck.addr[2],
			 srck.addr[3],
			 srck.addr[4],
			 srck.addr[5],
			 srck.addr[6],
			 srck.addr[7],
			 srck.addr[8],
			 srck.addr[9],
			 srck.addr[10],
			 srck.addr[11],
			 srck.addr[12],
			 srck.addr[13],
			 srck.addr[14],
			 srck.addr[15]);
  bpf_printk("dst: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			 dstk.addr[0],
			 dstk.addr[1],
			 dstk.addr[2],
			 dstk.addr[3],
			 dstk.addr[4],
			 dstk.addr[5],
			 dstk.addr[6],
			 dstk.addr[7],
			 dstk.addr[8],
			 dstk.addr[9],
			 dstk.addr[10],
			 dstk.addr[11],
			 dstk.addr[12],
			 dstk.addr[13],
			 dstk.addr[14],
			 dstk.addr[15]);
  bpf_printk("port: %d", dst_port);

  return TC_ACT_OK;
}

SEC("classifier/egress_tailscale")
int egress_tailscale(struct __sk_buff *skb) {
  // Ignore non-ipv4
  if (skb->protocol != bpf_htons(ETH_P_IP)) {
	return TC_ACT_OK;
  }

  // Ignore packets too small to be UDP.
  if (skb->data + sizeof(struct iphdr) + sizeof(struct udphdr) > skb->data_end) {
	return TC_ACT_OK;
  }

  void *data = (void*)(long)skb->data;
  struct iphdr *iph = data;
  struct udphdr *udph = data + sizeof(*iph);

  if (iph->protocol != 17 || iph->ihl != 5) {
	return TC_ACT_OK;
  }
  if (bpf_ntohl(iph->daddr) != 0x64646464) {
	return TC_ACT_OK;
  }
  if (bpf_ntohs(udph->dest) != 53) {
	return TC_ACT_OK;
  }

  return bpf_clone_redirect(skb, ifidx_divert, 0);
}

SEC("classifier/egress_divert")
int egress_divert(struct __sk_buff *skb) {
  return bpf_redirect(ifidx_tailscale, BPF_F_INGRESS);
}

char __license[] SEC("license") = "GPL";
