// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin,cgo

package interfaces

/*
#import "route.h"
#import <netinet/in.h>
#import <sys/sysctl.h>
#import <stdlib.h>
#import <stdio.h>

// privateGatewayIPFromRoute returns the private gateway ip address from rtm, if it exists.
// Otherwise, it returns 0.
uint32_t privateGatewayIPFromRoute(struct rt_msghdr2 *rtm)
{
    // sockaddrs are after the message header
    struct sockaddr* dst_sa = (struct sockaddr *)(rtm + 1);

    if((rtm->rtm_addrs & (RTA_DST|RTA_GATEWAY)) != (RTA_DST|RTA_GATEWAY))
        return 0; // missing dst or gateway addr
    if (dst_sa->sa_family != AF_INET)
        return 0; // dst not IPv4
    if ((rtm->rtm_flags & RTF_GATEWAY) == 0)
        return 0; // gateway flag not set

    struct sockaddr_in* dst_si = (struct sockaddr_in *)dst_sa;
    if (dst_si->sin_addr.s_addr != INADDR_ANY)
        return 0; // not default route

    #define ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

    struct sockaddr* gateway_sa = (struct sockaddr *)((char *)dst_sa + ROUNDUP(dst_sa->sa_len));
    if (gateway_sa->sa_family != AF_INET)
        return 0; // gateway not IPv4

    struct sockaddr_in* gateway_si= (struct sockaddr_in *)gateway_sa;
    uint32_t ip;
    ip = gateway_si->sin_addr.s_addr;

    unsigned char a, b;
    a = (ip >> 0) & 0xff;
    b = (ip >> 8) & 0xff;

    // Check whether ip is private, that is, whether it is
    // in one of 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16.
    if (a == 10)
        return ip; // matches 10.0.0.0/8
    if (a == 172 && (b >> 4) == 1)
        return ip; // matches 172.16.0.0/12
    if (a == 192 && b == 168)
        return ip; // matches 192.168.0.0/16

    // Not a private IP.
    return 0;
}

// privateGatewayIP returns the private gateway IP address, if it exists.
// If no private gateway IP address was found, it returns 0.
// On an error, it returns an error code in (0, 255].
// Any private gateway IP address is > 255.
uint32_t privateGatewayIP()
{
    size_t needed;
    int mib[6];
    char *buf;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = 0;
    mib[4] = NET_RT_DUMP2;
    mib[5] = 0;

    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
        return 1; // route dump size estimation failed
    if ((buf = malloc(needed)) == 0)
        return 2; // malloc failed
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
        free(buf);
        return 3; // route dump failed
    }

    // Loop over all routes.
    char *next, *lim;
    lim = buf + needed;
	struct rt_msghdr2 *rtm;
    for (next = buf; next < lim; next += rtm->rtm_msglen) {
        rtm = (struct rt_msghdr2 *)next;
        uint32_t ip;
        ip = privateGatewayIPFromRoute(rtm);
        if (ip) {
            free(buf);
            return ip;
        }
    }
    free(buf);
    return 0; // no gateway found
}
*/
import "C"

import (
	"encoding/binary"
	"log"

	"inet.af/netaddr"
)

func init() {
	likelyHomeRouterIP = likelyHomeRouterIPDarwinSyscall
}

func likelyHomeRouterIPDarwinSyscall() (ret netaddr.IP, ok bool) {
	ip := C.privateGatewayIP()
	if ip < 255 {
		log.Printf("likelyHomeRouterIPDarwinSyscall: error code %v", ip)
		return netaddr.IP{}, false
	}
	var q [4]byte
	binary.LittleEndian.PutUint32(q[:], uint32(ip))
	return netaddr.IPv4(q[0], q[1], q[2], q[3]), true
}
