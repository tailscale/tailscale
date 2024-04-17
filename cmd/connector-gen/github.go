// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"go4.org/netipx"
)

// See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses

type GithubMeta struct {
	VerifiablePasswordAuthentication bool `json:"verifiable_password_authentication"`
	SSHKeyFingerprints               struct {
		Sha256Ecdsa   string `json:"SHA256_ECDSA"`
		Sha256Ed25519 string `json:"SHA256_ED25519"`
		Sha256Rsa     string `json:"SHA256_RSA"`
	} `json:"ssh_key_fingerprints"`
	SSHKeys                  []string `json:"ssh_keys"`
	Hooks                    []string `json:"hooks"`
	Web                      []string `json:"web"`
	API                      []string `json:"api"`
	Git                      []string `json:"git"`
	GithubEnterpriseImporter []string `json:"github_enterprise_importer"`
	Packages                 []string `json:"packages"`
	Pages                    []string `json:"pages"`
	Importer                 []string `json:"importer"`
	Actions                  []string `json:"actions"`
	Dependabot               []string `json:"dependabot"`
	Domains                  struct {
		Website    []string `json:"website"`
		Codespaces []string `json:"codespaces"`
		Copilot    []string `json:"copilot"`
		Packages   []string `json:"packages"`
	} `json:"domains"`
}

func github() {
	r, err := http.Get("https://api.github.com/meta")
	if err != nil {
		log.Fatal(err)
	}

	var ghm GithubMeta

	if err := json.NewDecoder(r.Body).Decode(&ghm); err != nil {
		log.Fatal(err)
	}
	r.Body.Close()

	var ips netipx.IPSetBuilder

	var lists []string
	lists = append(lists, ghm.Hooks...)
	lists = append(lists, ghm.Web...)
	lists = append(lists, ghm.API...)
	lists = append(lists, ghm.Git...)
	lists = append(lists, ghm.GithubEnterpriseImporter...)
	lists = append(lists, ghm.Packages...)
	lists = append(lists, ghm.Pages...)
	lists = append(lists, ghm.Importer...)
	lists = append(lists, ghm.Actions...)
	lists = append(lists, ghm.Dependabot...)

	for _, s := range lists {
		ips.AddPrefix(netip.MustParsePrefix(s))
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

	fmt.Println()

	var domains []string
	domains = append(domains, ghm.Domains.Website...)
	domains = append(domains, ghm.Domains.Codespaces...)
	domains = append(domains, ghm.Domains.Copilot...)
	domains = append(domains, ghm.Domains.Packages...)
	slices.Sort(domains)
	domains = slices.Compact(domains)

	var bareDomains []string
	for _, domain := range domains {
		trimmed := strings.TrimPrefix(domain, "*.")
		if trimmed != domain {
			bareDomains = append(bareDomains, trimmed)
		}
	}
	domains = append(domains, bareDomains...)
	slices.Sort(domains)
	domains = slices.Compact(domains)

	fmt.Println(`"domains": [`)
	for _, domain := range domains {
		fmt.Printf(`"%s",%s`, domain, "\n")
	}
	fmt.Println(`]`)

	advertiseRoutes(set)
}
