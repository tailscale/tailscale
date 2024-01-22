// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"

	"go4.org/netipx"
)

// See https://ip-ranges.atlassian.com/
type AtlassianMeta struct {
	CreationDate string `json:"creationDate"`
	SyncToken    int    `json:"syncToken"`
	Items        []struct {
		Network   string   `json:"network"`
		MaskLen   int      `json:"mask_len"`
		Cidr      string   `json:"cidr"`
		Mask      string   `json:"mask"`
		Region    []string `json:"region"`
		Product   []string `json:"product"`
		Direction []string `json:"direction"`
		Perimeter string   `json:"perimeter"`
	} `json:"items"`
}

func jira() {
	parseAtlassian("jira")
}

func confluence() {
	parseAtlassian("confluence")
}

func parseAtlassian(productName string) {
	r, err := http.Get("https://ip-ranges.atlassian.com/")
	if err != nil {
		log.Fatal(err)
	}

	var meta AtlassianMeta

	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
		log.Fatal(err)
	}
	r.Body.Close()

	var ips netipx.IPSetBuilder
	for _, item := range meta.Items {
		isProductName := false
		isIngress := false

		for _, direction := range item.Direction {
			if direction != "ingress" {
				// For routes, we are only interested in
				// ingress routes. Skip over any that aren't
				// marked as such.
				continue
			}
			isIngress = true
			break
		}

		for _, product := range item.Product {
			if product != productName {
				continue
			}
			isProductName = true
			break
		}

		if !isProductName || !isIngress {
			continue
		}

		ips.AddPrefix(netip.MustParsePrefix(item.Cidr))
	}

	set, err := ips.IPSet()
	if err != nil {
		log.Fatal(err)
	}

	for _, addr := range set.Prefixes() {
		fmt.Println(fmt.Sprintf(`"%s",`, addr))
	}
}
