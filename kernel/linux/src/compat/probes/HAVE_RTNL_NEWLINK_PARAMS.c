// SPDX-License-Identifier: GPL-2.0
// Probe for struct rtnl_newlink_params in rtnl_link_ops.newlink.
#include <net/rtnetlink.h>

static int probe_newlink(struct net_device *dev, struct rtnl_newlink_params *params,
			 struct netlink_ext_ack *extack)
{
	return 0;
}

static struct rtnl_link_ops probe_ops __maybe_unused = {
	.newlink = probe_newlink,
};
