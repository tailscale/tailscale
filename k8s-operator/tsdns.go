// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package kube

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

// TSHosts is a mapping of MagicDNS names to a list IPv4 or IPv6 addresses.
type TSHosts struct {
	Hosts map[string][]string `json:"hosts"`
}

func NewTSHosts(bs []byte, log logger.Logf) (*TSHosts, error) {
	cfg := &TSHosts{}
	if err := json.Unmarshal(bs, cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling json bytes: %w", err)
	}
	// Validate the unmarshalled Hosts entries. In case of an invalid entry,
	// delete it and log an error, but do not invalidate the result.
	for key, val := range cfg.Hosts {
		fqdn, err := dnsname.ToFQDN(key)
		if err != nil {
			log("error parsing DNS name %s: %v, skipping", key, err)
			delete(cfg.Hosts, key)
			break
		}
		if !IsMagicDNSName(string(fqdn)) {
			log("DNS name %s is not a MagicDNS name, skipping", fqdn)
			delete(cfg.Hosts, key)
			break
		}
		for _, ip := range val {
			if _, err := netip.ParseAddr(ip); err != nil {
				log("IP %s is not a valid IP address, skipping", ip)
			}
		}
	}
	return cfg, nil
}
