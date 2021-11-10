#include <linux/types.h>
#include <bpf/bpf_helpers.h>

typedef __u32 u32;
typedef __u8 u8;
typedef __u16 u16;

typedef u32 endpoint_id;

typedef struct {
  endpoint_id src_id;
  endpoint_id dst_it;
  u16 dst_port;
  u8 proto; // from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
} acl_key;

#define ACL_ALLOW 1
#define ACL_PUNT 2

typedef u8 acl_action;

typedef struct {
  struct bpf_lpm_trie_key lpm;
  u8 addr[16];
} lpm_key;

