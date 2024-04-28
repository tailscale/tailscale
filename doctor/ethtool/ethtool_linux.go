// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ethtool

import (
	"net/netip"
	"sort"

	"github.com/safchain/ethtool"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/set"
)

func ethtoolImpl(logf logger.Logf) error {
	et, err := ethtool.NewEthtool()
	if err != nil {
		logf("could not create ethtool: %v", err)
		return nil
	}
	defer et.Close()

	netmon.ForeachInterface(func(iface netmon.Interface, _ []netip.Prefix) {
		ilogf := logger.WithPrefix(logf, iface.Name+": ")
		features, err := et.Features(iface.Name)
		if err == nil {
			enabled := []string{}
			for feature, value := range features {
				if value {
					enabled = append(enabled, feature)
				}
			}
			sort.Strings(enabled)
			ilogf("features: %v", enabled)
		} else {
			ilogf("features: error: %v", err)
		}

		stats, err := et.Stats(iface.Name)
		if err == nil {
			printStats(ilogf, stats)
		} else {
			ilogf("stats: error: %v", err)
		}
	})

	return nil
}

// Stats that should be printed if non-zero
var nonzeroStats = set.SetOf([]string{
	// AWS ENA driver statistics; see:
	//    https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html
	"bw_in_allowance_exceeded",
	"bw_out_allowance_exceeded",
	"conntrack_allowance_exceeded",
	"linklocal_allowance_exceeded",
	"pps_allowance_exceeded",
})

// Stats that should be printed if zero
var zeroStats = set.SetOf([]string{
	// AWS ENA driver statistics; see:
	//    https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html
	"conntrack_allowance_available",
})

func printStats(logf logger.Logf, stats map[string]uint64) {
	for name, value := range stats {
		if value != 0 && nonzeroStats.Contains(name) {
			logf("stats: warning: %s = %d > 0", name, value)
		}
		if value == 0 && zeroStats.Contains(name) {
			logf("stats: warning: %s = %d == 0", name, value)
		}
	}
}
