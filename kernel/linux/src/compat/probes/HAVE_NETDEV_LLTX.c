// SPDX-License-Identifier: GPL-2.0
// Probe for the net_device lltx bit.
#include <linux/netdevice.h>

static void __maybe_unused probe(struct net_device *dev)
{
	dev->lltx = true;
}
