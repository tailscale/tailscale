// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsfallback contains a DNS fallback mechanism
// for starting up Tailscale when the system DNS is broken or otherwise unavailable.
package dnsfallback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"inet.af/netaddr"
	"tailscale.com/derp/derpmap"
	"tailscale.com/net/netns"
	"tailscale.com/net/tshttpproxy"
)

func Lookup(ctx context.Context, host string) ([]netaddr.IP, error) {
	type nameIP struct {
		dnsName string
		ip      netaddr.IP
	}

	var cands []nameIP
	dm := derpmap.Prod()
	for _, dr := range dm.Regions {
		for _, n := range dr.Nodes {
			if ip, err := netaddr.ParseIP(n.IPv4); err == nil {
				cands = append(cands, nameIP{n.HostName, ip})
			}
			if ip, err := netaddr.ParseIP(n.IPv6); err == nil {
				cands = append(cands, nameIP{n.HostName, ip})
			}
		}
	}
	rand.Shuffle(len(cands), func(i, j int) {
		cands[i], cands[j] = cands[j], cands[i]
	})
	if len(cands) == 0 {
		return nil, fmt.Errorf("no DNS fallback options for %q", host)
	}
	for ctx.Err() == nil && len(cands) > 0 {
		cand := cands[0]
		log.Printf("trying bootstrapDNS(%q, %q) for %q ...", cand.dnsName, cand.ip, host)
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		dm, err := bootstrapDNSMap(ctx, cand.dnsName, cand.ip, host)
		if err != nil {
			log.Printf("bootstrapDNS(%q, %q) for %q error: %v", cand.dnsName, cand.ip, host, err)
			continue
		}
		if ips := dm[host]; len(ips) > 0 {
			log.Printf("bootstrapDNS(%q, %q) for %q = %v", cand.dnsName, cand.ip, host, ips)
			return ips, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no DNS fallback candidates remain for %q", host)
}

// serverName and serverIP of are, say, "derpN.tailscale.com".
// queryName is the name being sought (e.g. "login.tailscale.com"), passed as hint.
func bootstrapDNSMap(ctx context.Context, serverName string, serverIP netaddr.IP, queryName string) (dnsMap, error) {
	dialer := netns.NewDialer()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = tshttpproxy.ProxyFromEnvironment
	tr.DialContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(serverIP.String(), "443"))
	}
	c := &http.Client{Transport: tr}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+serverName+"/bootstrap-dns?q="+url.QueryEscape(queryName), nil)
	if err != nil {
		return nil, err
	}
	dm := make(dnsMap)
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New(res.Status)
	}
	if err := json.NewDecoder(res.Body).Decode(&dm); err != nil {
		return nil, err
	}
	return dm, nil
}

// dnsMap is the JSON type returned by the DERP /bootstrap-dns handler:
// https://derp10.tailscale.com/bootstrap-dns
type dnsMap map[string][]netaddr.IP
