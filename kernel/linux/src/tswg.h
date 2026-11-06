/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Declarations for tswg's additions to WireGuard. Keeping them in their own
 * header keeps the diff against upstream's headers small.
 */

#ifndef _TSWG_H
#define _TSWG_H

#include <linux/types.h>

struct wg_device;
struct wg_peer;
struct sock;
struct sk_buff;
struct nlattr;
struct netlink_ext_ack;

/* socket.c */
int tswg_socket_set_user(struct wg_device *wg, int family, int fd,
			 struct netlink_ext_ack *extack);
bool tswg_socket_has_user(struct wg_device *wg);
void tswg_socket_detach_all_user(struct wg_device *wg);
u32 tswg_socket_flags(struct wg_device *wg);

/* netlink.c */
int tswg_set_device(struct wg_device *wg, struct nlattr *attr,
		    struct netlink_ext_ack *extack);
int tswg_get_device(struct sk_buff *skb, struct wg_device *wg);
int tswg_set_peer(struct wg_peer *peer, struct nlattr *attr);
int tswg_get_peer(struct sk_buff *skb, struct wg_peer *peer);

#endif /* _TSWG_H */
