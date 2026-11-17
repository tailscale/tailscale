// SPDX-License-Identifier: GPL-2.0
// Probe for struct sockaddr_inet.
#include <linux/in6.h>

static unsigned short __maybe_unused probe(struct sockaddr_inet *sa)
{
	return sa->sa_family;
}
