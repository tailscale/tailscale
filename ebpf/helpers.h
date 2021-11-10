#include "types.h"

int packet_to_lpm_key(struct __sk_buff *skb, src *lpm_key, dst *lpm_key) {
  void* data = (void*)(long)skb->data;
  void* data_end = (void*)(long)skb->data_end;
  struct iphdr *v4_hdr;
  struct ipv6hdr *v6_hdr;
  struct tcphdr *tcp_hdr;
  struct udphdr *udp_hdr;

  switch (skb->protocol) {
  case bpf_htons(ETH_P_IP):
	if ((data+sizeof(*v4_hdr)) > data_end)
	  return -1;
	v4_hdr = data;
	src->lpm.prefixlen = 32;
	memset(&src->addr[0], 0, 12);
	memcpy(&src.addr[12], &v4_hdr->saddr, 4);
	dst->lpm.prefixlen = 32;
	memset(&dst->addr[0], 0, 12);
	memcpy(&dst.addr[12], &v4_hdr->daddr, 4);
	l4_proto = v4_hdr->proto;
	if (unlikely(v4_hdr->ver_len != 0x45)) {
	  return 4*(v4_hdr->ver_len & 0x0F);
	} else {
	  return 20;
	}
	break;
  case bpf_htons(ETH_P_IPV6):
	if ((data+sizeof(*v6_hdr)) > data_end)
	  return -1;
	v6_hdr = data;
	src->lpm.prefixlen = 128;
	memcpy(&src.addr[0], &v6_hdr->saddr, 16);
	dst->lpm.prefixlen = 128;
	memcpy(&dst.addr[0], &v6_hdr->daddr, 16);
	l4_proto = v6_hdr->nexthdr;
	data += sizeof(*v6_hdr);
	break;
  default:
	return -1
  }

  switch (l4_proto) {
  case 6:
	break;
  case 17:
	break;
	
  default:
	return -1
  }
}
