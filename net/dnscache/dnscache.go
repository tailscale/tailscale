// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnscache contains a minimal DNS cache that makes a bunch of
// assumptions that are only valid for us. Not recommended for general use.
package dnscache

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

var single = &Resolver{
	Forward: &net.Resolver{PreferGo: preferGoResolver()},
}

func preferGoResolver() bool {
	// There does not appear to be a local resolver running
	// on iOS, and NetworkExtension is good at isolating DNS.
	// So do not use the Go resolver on macOS/iOS.
	if runtime.GOOS == "darwin" {
		return false
	}

	// The local resolver is not available on Android.
	if runtime.GOOS == "android" {
		return false
	}

	// Otherwise, the Go resolver is fine and slightly preferred
	// since it's lighter, not using cgo calls & threads.
	return true
}

// Get returns a caching Resolver singleton.
func Get() *Resolver { return single }

const fixedTTL = 10 * time.Minute

// Resolver is a minimal DNS caching resolver.
//
// The TTL is always fixed for now. It's not intended for general use.
// Cache entries are never cleaned up so it's intended that this is
// only used with a fixed set of hostnames.
type Resolver struct {
	// Forward is the resolver to use to populate the cache.
	// If nil, net.DefaultResolver is used.
	Forward *net.Resolver

	sf singleflight.Group

	mu      sync.Mutex
	ipCache map[string]ipCacheEntry
}

type ipCacheEntry struct {
	ip      net.IP
	expires time.Time
}

func (r *Resolver) fwd() *net.Resolver {
	if r.Forward != nil {
		return r.Forward
	}
	return net.DefaultResolver
}

// LookupIP returns the first IPv4 address found, otherwise the first IPv6 address.
func (r *Resolver) LookupIP(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		return ip, nil
	}

	if ip, ok := r.lookupIPCache(host); ok {
		return ip, nil
	}

	ch := r.sf.DoChan(host, func() (interface{}, error) {
		ip, err := r.lookupIP(host)
		if err != nil {
			return nil, err
		}
		return ip, nil
	})
	select {
	case res := <-ch:
		if res.Err != nil {
			return nil, res.Err
		}
		return res.Val.(net.IP), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (r *Resolver) lookupIPCache(host string) (ip net.IP, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ent, ok := r.ipCache[host]; ok && ent.expires.After(time.Now()) {
		return ent.ip, true
	}
	return nil, false
}

func (r *Resolver) lookupIP(host string) (net.IP, error) {
	if ip, ok := r.lookupIPCache(host); ok {
		return ip, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := r.fwd().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs for %q found", host)
	}

	for _, ipa := range ips {
		if ip4 := ipa.IP.To4(); ip4 != nil {
			return r.addIPCache(host, ip4, fixedTTL), nil
		}
	}
	return r.addIPCache(host, ips[0].IP, fixedTTL), nil
}

func (r *Resolver) addIPCache(host string, ip net.IP, d time.Duration) net.IP {
	if isPrivateIP(ip) {
		// Don't cache obviously wrong entries from captive portals.
		// TODO: use DoH or DoT for the forwarding resolver?
		return ip
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ipCache == nil {
		r.ipCache = make(map[string]ipCacheEntry)
	}
	r.ipCache[host] = ipCacheEntry{ip: ip, expires: time.Now().Add(d)}
	return ip
}

func mustCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return ipNet
}

func isPrivateIP(ip net.IP) bool {
	return private1.Contains(ip) || private2.Contains(ip) || private3.Contains(ip)
}

var (
	private1 = mustCIDR("10.0.0.0/8")
	private2 = mustCIDR("172.16.0.0/12")
	private3 = mustCIDR("192.168.0.0/16")
)
