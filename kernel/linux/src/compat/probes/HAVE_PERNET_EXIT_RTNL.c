// SPDX-License-Identifier: GPL-2.0
// Probe for pernet_operations.exit_rtnl.
#include <net/net_namespace.h>

static void probe_exit_rtnl(struct net *net, struct list_head *dev_kill_list)
{
}

static struct pernet_operations probe_ops __maybe_unused = {
	.exit_rtnl = probe_exit_rtnl,
};
