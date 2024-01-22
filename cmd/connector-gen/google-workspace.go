// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// See https://www.gstatic.com/ipranges/goog.json

type Workspace struct {
	SyncToken    string `json:"syncToken"`
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		Ipv4Prefix string `json:"ipv4Prefix,omitempty"`
		Ipv6Prefix string `json:"ipv6Prefix,omitempty"`
	} `json:"prefixes"`
}

func workspace() {
	r, err := http.Get("https://www.gstatic.com/ipranges/goog.json")
	if err != nil {
		log.Fatal(err)
	}

	var workspaceAddresses Workspace

	if err := json.NewDecoder(r.Body).Decode(&workspaceAddresses); err != nil {
		log.Fatal(err)
	}
	r.Body.Close()

	var v4 []string
	var v6 []string
	for _, item := range workspaceAddresses.Prefixes {
		if item.Ipv4Prefix != "" {
			v4 = append(v4, item.Ipv4Prefix)
		}

		if item.Ipv6Prefix != "" {
			v6 = append(v6, item.Ipv6Prefix)
		}
	}

	for _, addr := range v4 {
		fmt.Println(fmt.Sprintf(`"%s",`, addr))
	}
	for _, addr := range v6 {
		fmt.Println(fmt.Sprintf(`"%s",`, addr))
	}
}
