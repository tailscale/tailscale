/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Declarations for tswg's additions to WireGuard. Keeping them in their own
 * header keeps the diff against upstream's headers small.
 */

#ifndef _TSWG_H
#define _TSWG_H

#include <linux/atomic.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <uapi/linux/tswg.h>

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
void tswg_notify_peer(struct wg_peer *peer, u32 flags);

/*
 * TSWG_ACTIVITY_EVENT_INTERVAL is the minimum interval between a peer's TX
 * (or RX) activity events. Userspace uses them to keep the peer's session
 * marked active (tailscaled's magicsock considers a session idle after 45
 * seconds without traffic and heartbeats every 3 seconds), so they needn't
 * be frequent.
 */
#define TSWG_ACTIVITY_EVENT_INTERVAL (2 * HZ)

/*
 * tswg_note_activity sends a peer event with flag if the last one, whose
 * time is in *last, was at least TSWG_ACTIVITY_EVENT_INTERVAL ago. It's
 * cheap enough for the packet path: one comparison in the common case.
 */
static inline void tswg_note_activity(struct wg_peer *peer, unsigned long *last,
				      u32 flag)
{
	unsigned long now = jiffies, prev = READ_ONCE(*last);

	if (time_before(now, prev + TSWG_ACTIVITY_EVENT_INTERVAL))
		return;
	if (cmpxchg(last, prev, now) != prev)
		return; /* another CPU won the race to report it */
	tswg_notify_peer(peer, flag);
}

#endif /* _TSWG_H */
