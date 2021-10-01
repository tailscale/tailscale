// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run update-dns-fallbacks.go

// Package dnsfallback contains a DNS fallback mechanism
// for starting up Tailscale when the system DNS is broken or otherwise unavailable.
package dnsfallback

import (
	"context"
	_ "embed"
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
	"tailscale.com/net/netns"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/tailcfg"
)

func Lookup(ctx context.Context, host string) ([]netaddr.IP, error) {
	type nameIP struct {
		dnsName string
		ip      netaddr.IP
	}

	dm := getDERPMap()
	var cands4, cands6 []nameIP
	for _, dr := range dm.Regions {
		for _, n := range dr.Nodes {
			if ip, err := netaddr.ParseIP(n.IPv4); err == nil {
				cands4 = append(cands4, nameIP{n.HostName, ip})
			}
			if ip, err := netaddr.ParseIP(n.IPv6); err == nil {
				cands6 = append(cands6, nameIP{n.HostName, ip})
			}
		}
	}
	rand.Shuffle(len(cands4), func(i, j int) { cands4[i], cands4[j] = cands4[j], cands4[i] })
	rand.Shuffle(len(cands6), func(i, j int) { cands6[i], cands6[j] = cands6[j], cands6[i] })

	const maxCands = 6
	var cands []nameIP // up to maxCands alternating v4/v6 as long as we have both
	for (len(cands4) > 0 || len(cands6) > 0) && len(cands) < maxCands {
		if len(cands4) > 0 {
			cands = append(cands, cands4[0])
			cands4 = cands4[1:]
		}
		if len(cands6) > 0 {
			cands = append(cands, cands6[0])
			cands6 = cands6[1:]
		}
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no DNS fallback options for %q", host)
	}
	for _, cand := range cands {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
// queryName is the name being sought (e.g. "controlplane.tailscale.com"), passed as hint.
func bootstrapDNSMap(ctx context.Context, serverName string, serverIP netaddr.IP, queryName string) (dnsMap, error) {
	dialer := netns.NewDialer()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = tshttpproxy.ProxyFromEnvironment
	tr.DialContext = func(ctx context.Context, netw, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", net.JoinHostPort(serverIP.String(), "443"))
	}
	tr.TLSClientConfig = tlsdial.Config(serverName, tr.TLSClientConfig)
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

// getDERPMap returns some DERP map. The DERP servers also run a fallback
// DNS server.
func getDERPMap() *tailcfg.DERPMap {
	// TODO(bradfitz): try to read the last known DERP map from disk,
	// at say /var/lib/tailscale/derpmap.txt and write it when it changes,
	// and read it here.
	// But ultimately the fallback will be to use a copy baked into the binary,
	// which is this part:

	dm := new(tailcfg.DERPMap)
	if err := json.Unmarshal(staticDERPMapJSON, dm); err != nil {
		panic(err)
	}
	return dm
}

//go:embed dns-fallback-servers.json
var staticDERPMapJSON []byte
