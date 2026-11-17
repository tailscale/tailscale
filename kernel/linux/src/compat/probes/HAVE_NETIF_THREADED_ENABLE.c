// SPDX-License-Identifier: GPL-2.0
// Probe for netif_threaded_enable().
#include <linux/netdevice.h>

static void __maybe_unused probe(struct net_device *dev)
{
	netif_threaded_enable(dev);
}
