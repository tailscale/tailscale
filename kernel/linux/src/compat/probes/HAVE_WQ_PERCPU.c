// SPDX-License-Identifier: GPL-2.0
// Probe for the WQ_PERCPU workqueue flag.
#include <linux/workqueue.h>

static int __maybe_unused probe(void)
{
	return WQ_PERCPU;
}
