// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netkernelconf

import (
	"fmt"

	"github.com/safchain/ethtool"
)

// CheckUDPGROForwarding checks if the machine is optimally configured to
// forward UDP packets between the default route and Tailscale TUN interfaces.
// It returns a non-nil warn in the case that the configuration is suboptimal.
// It returns a non-nil err in the case that an error is encountered while
// performing the check.
func CheckUDPGROForwarding(tunInterface, defaultRouteInterface string) (warn, err error) {
	const txFeature = "tx-udp-segmentation"
	const rxWantFeature = "rx-udp-gro-forwarding"
	const rxDoNotWantFeature = "rx-gro-list"
	const kbLink = "\nSee https://tailscale.com/s/ethtool-config-udp-gro"
	errWithPrefix := func(format string, a ...any) error {
		const errPrefix = "couldn't check system's UDP GRO forwarding configuration, "
		return fmt.Errorf(errPrefix+format, a...)
	}
	e, err := ethtool.NewEthtool()
	if err != nil {
		return nil, errWithPrefix("failed to init ethtool: %v", err)
	}
	defer e.Close()
	tunFeatures, err := e.Features(tunInterface)
	if err != nil {
		return nil, errWithPrefix("failed to retrieve TUN device features: %v", err)
	}
	if !tunFeatures[txFeature] {
		// if txFeature is disabled/nonexistent on the TUN then UDP GRO
		// forwarding doesn't matter, we won't be taking advantage of it.
		return nil, nil
	}
	defaultFeatures, err := e.Features(defaultRouteInterface)
	if err != nil {
		return nil, errWithPrefix("failed to retrieve default route interface features: %v", err)
	}
	defaultHasRxWant, ok := defaultFeatures[rxWantFeature]
	if !ok {
		// unlikely the feature is nonexistant with txFeature in the TUN driver
		// being added to the kernel later than rxWantFeature, but let's be sure
		return nil, nil
	}
	if !defaultHasRxWant || defaultFeatures[rxDoNotWantFeature] {
		return fmt.Errorf("UDP GRO forwarding is suboptimally configured on %s, UDP forwarding throughput capability will increase with a configuration change.%s", defaultRouteInterface, kbLink), nil
	}
	return nil, nil
}
