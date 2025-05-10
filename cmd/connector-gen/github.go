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
	xmaps "golang.org/x/exp/maps"
)

// omitDomains are domains that appear in the github API /meta output
// that we do not need to have app connectors route traffic for (and
// to do so would result in advertising more routes than we want).
var omitDomains = map[string]bool{
	"*.githubassets.com":      true,
	"*.githubusercontent.com": true,
	"*.windows.net":           true,
	"*.azureedge.net":         true,
}

// See https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-githubs-ip-addresses

// GithubMeta is a subset of the response from the github APIs /meta endpoint.
type GithubMeta struct {
	Web                      []string `json:"web"`
	API                      []string `json:"api"`
	Git                      []string `json:"git"`
	GithubEnterpriseImporter []string `json:"github_enterprise_importer"`
	Packages                 []string `json:"packages"`
	Pages                    []string `json:"pages"`
	Domains                  struct {
		Website    []string `json:"website"`
		Codespaces []string `json:"codespaces"`
		Copilot    []string `json:"copilot"`
	} `json:"domains"`
}

func (ghm GithubMeta) routesLists() [][]string {
	return [][]string{
		ghm.Web,
		ghm.API,
		ghm.Git,
		ghm.GithubEnterpriseImporter,
		ghm.Packages,
		ghm.Pages,
	}
}

func (ghm GithubMeta) domainsLists() [][]string {
	return [][]string{
		ghm.Domains.Website,
		ghm.Domains.Codespaces,
		ghm.Domains.Copilot,
	}
}

func (ghm GithubMeta) routes() *netipx.IPSet {
	var ips netipx.IPSetBuilder
	for _, routes := range ghm.routesLists() {
		for _, r := range routes {
			ips.AddPrefix(netip.MustParsePrefix(r))
		}
	}
	set, err := ips.IPSet()
	if err != nil {
		log.Fatal(err)
	}
	return set
}

func (ghm GithubMeta) domains() []string {
	ds := map[string]bool{}
	for _, list := range ghm.domainsLists() {
		for _, d := range list {
			if !omitDomains[d] {
				ds[d] = true
			}
		}
	}
	return xmaps.Keys(ds)
}

type Output struct {
	Routes  []netip.Prefix `json:"routes"`
	Domains []string       `json:"domains"`
}

func (o Output) format() []byte {
	s, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return s
}

// github prints app connector config to standard out.
// The /meta github endpoint lists the routes and domains needed to use GitHub. It
// lists thousands of routes, and includes broad wildcard domains like *.microsoft.com.
// Not all tailnets function well with an app connector that's advertising thousands of
// routes.
// GitHub has an enterprise "allowed IPs only" feature.  The goal of this script is
// to capture only the domains and routes needed to configure an app connector so that
// users of that app connector can enable that GitHub feature pointing at the app connector
// IP address and have github work.
// We don't know exactly which routes and domains are needed, but I got an email from GitHub
// support saying that only the routes provided in 'web', 'api', and 'git' are needed,
// but that doesn't seem very likely, surely users of eg private packages will
// need to be coming from an allowed IP? Still, attempt to be reasonably restrictive.
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

	var domains []string
	for _, domain := range ghm.domains() {
		domains = append(domains, domain)
		trimmed := strings.TrimPrefix(domain, "*.")
		if trimmed != domain {
			domains = append(domains, trimmed)
		}
	}
	slices.Sort(domains)
	domains = slices.Compact(domains)

	set := ghm.routes()

	fmt.Println(string(Output{
		Routes:  set.Prefixes(),
		Domains: domains,
	}.format()))

	advertiseRoutes(set)
}
