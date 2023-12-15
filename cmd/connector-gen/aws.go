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

// See https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html

type AWSMeta struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	Prefixes   []struct {
		IPPrefix           string `json:"ip_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"prefixes"`
	Ipv6Prefixes []struct {
		Ipv6Prefix         string `json:"ipv6_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"ipv6_prefixes"`
}

func aws() {
	r, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()

	var aws AWSMeta
	if err := json.NewDecoder(r.Body).Decode(&aws); err != nil {
		log.Fatal(err)
	}

	var ips netipx.IPSetBuilder

	for _, prefix := range aws.Prefixes {
		ips.AddPrefix(netip.MustParsePrefix(prefix.IPPrefix))
	}
	for _, prefix := range aws.Ipv6Prefixes {
		ips.AddPrefix(netip.MustParsePrefix(prefix.Ipv6Prefix))
	}

	set, err := ips.IPSet()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(`"routes": [`)
	for _, pfx := range set.Prefixes() {
		fmt.Printf(`"%s": ["tag:connector"],%s`, pfx.String(), "\n")
	}
	fmt.Println(`]`)

	advertiseRoutes(set)
}
