// SPDX-License-Identifier: GPL-2.0
// Probe for rtnl_newlink_link_net().
#include <net/rtnetlink.h>

static __maybe_unused struct net *probe(struct rtnl_newlink_params *params)
{
	return rtnl_newlink_link_net(params);
}
