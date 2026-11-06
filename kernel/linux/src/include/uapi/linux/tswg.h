/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	Documentation/netlink/specs/wireguard.yaml */
/* YNL-GEN uapi header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _UAPI_LINUX_TSWG_H
#define _UAPI_LINUX_TSWG_H

#define WG_GENL_NAME	"tswg"
#define WG_GENL_VERSION	1

#define WG_KEY_LEN	32

enum wgdevice_flag {
	WGDEVICE_F_REPLACE_PEERS = 1,
};

enum wgpeer_flag {
	WGPEER_F_REMOVE_ME = 1,
	WGPEER_F_REPLACE_ALLOWEDIPS = 2,
	WGPEER_F_UPDATE_ONLY = 4,
};

enum wgallowedip_flag {
	WGALLOWEDIP_F_REMOVE_ME = 1,
};

enum wgdevice_attribute {
	WGDEVICE_A_UNSPEC,
	WGDEVICE_A_IFINDEX,
	WGDEVICE_A_IFNAME,
	WGDEVICE_A_PRIVATE_KEY,
	WGDEVICE_A_PUBLIC_KEY,
	WGDEVICE_A_FLAGS,
	WGDEVICE_A_LISTEN_PORT,
	WGDEVICE_A_FWMARK,
	WGDEVICE_A_PEERS,

	__WGDEVICE_A_LAST
};
#define WGDEVICE_A_MAX (__WGDEVICE_A_LAST - 1)

/*
 * tswg additions. They live in a single nested attribute whose number is
 * far above upstream WireGuard's, so that upstream can keep appending its
 * own attributes without colliding with ours.
 */
#define WGDEVICE_A_TSWG 64 /* NLA_NESTED, of enum tswgdevice_attribute */

enum tswgdevice_flag {
	TSWGDEVICE_F_USER_SOCK4 = 1, /* a user-supplied IPv4 socket is attached */
	TSWGDEVICE_F_USER_SOCK6 = 2, /* a user-supplied IPv6 socket is attached */
};

enum tswgdevice_attribute {
	TSWGDEVICE_A_UNSPEC,
	/*
	 * NLA_S32, set only: the file descriptor, in the calling process, of a
	 * bound UDP socket for the device to use instead of creating its own.
	 * WireGuard messages arriving on it are consumed by the device; all
	 * other datagrams (disco, STUN, ...) stay on the socket for the
	 * process to read, and the process may send its own datagrams on it.
	 * The device drops the socket when the process closes it. -1 detaches
	 * the current socket, so the device creates its own again.
	 */
	TSWGDEVICE_A_SOCK_FD4,
	TSWGDEVICE_A_SOCK_FD6, /* NLA_S32, like SOCK_FD4; must be IPV6_V6ONLY */
	TSWGDEVICE_A_FLAGS, /* NLA_U32 of enum tswgdevice_flag, get only */

	__TSWGDEVICE_A_LAST
};
#define TSWGDEVICE_A_MAX (__TSWGDEVICE_A_LAST - 1)

enum wgpeer_attribute {
	WGPEER_A_UNSPEC,
	WGPEER_A_PUBLIC_KEY,
	WGPEER_A_PRESHARED_KEY,
	WGPEER_A_FLAGS,
	WGPEER_A_ENDPOINT,
	WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
	WGPEER_A_LAST_HANDSHAKE_TIME,
	WGPEER_A_RX_BYTES,
	WGPEER_A_TX_BYTES,
	WGPEER_A_ALLOWEDIPS,
	WGPEER_A_PROTOCOL_VERSION,

	__WGPEER_A_LAST
};
#define WGPEER_A_MAX (__WGPEER_A_LAST - 1)

enum wgallowedip_attribute {
	WGALLOWEDIP_A_UNSPEC,
	WGALLOWEDIP_A_FAMILY,
	WGALLOWEDIP_A_IPADDR,
	WGALLOWEDIP_A_CIDR_MASK,
	WGALLOWEDIP_A_FLAGS,

	__WGALLOWEDIP_A_LAST
};
#define WGALLOWEDIP_A_MAX (__WGALLOWEDIP_A_LAST - 1)

enum wg_cmd {
	WG_CMD_GET_DEVICE,
	WG_CMD_SET_DEVICE,

	__WG_CMD_MAX
};
#define WG_CMD_MAX (__WG_CMD_MAX - 1)

#endif /* _UAPI_LINUX_TSWG_H */
