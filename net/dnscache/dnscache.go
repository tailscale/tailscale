// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnscache contains a minimal DNS cache that makes a bunch of
// assumptions that are only valid for us. Not recommended for general use.
package dnscache

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"strconv"
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
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
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

// Resolver is a minimal DNS caching resolver.
//
// The TTL is always fixed for now. It's not intended for general use.
// Cache entries are never cleaned up so it's intended that this is
// only used with a fixed set of hostnames.
type Resolver struct {
	// Forward is the resolver to use to populate the cache.
	// If nil, net.DefaultResolver is used.
	Forward *net.Resolver

	// TTL is how long to keep entries cached
	//
	// If zero, a default (currently 10 minutes) is used.
	TTL time.Duration

	// UseLastGood controls whether a cached entry older than TTL is used
	// if a refresh fails.
	UseLastGood bool

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

func (r *Resolver) ttl() time.Duration {
	if r.TTL > 0 {
		return r.TTL
	}
	return 10 * time.Minute
}

var debug, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_DNS_CACHE"))

// LookupIP returns the first IPv4 address found, otherwise the first IPv6 address.
func (r *Resolver) LookupIP(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
		if debug {
			log.Printf("dnscache: %q is an IP", host)
		}
		return ip, nil
	}

	if ip, ok := r.lookupIPCache(host); ok {
		if debug {
			log.Printf("dnscache: %q = %v (cached)", host, ip)
		}
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
			if r.UseLastGood {
				if ip, ok := r.lookupIPCacheExpired(host); ok {
					if debug {
						log.Printf("dnscache: %q using %v after error", host, ip)
					}
					return ip, nil
				}
			}
			if debug {
				log.Printf("dnscache: error resolving %q: %v", host, res.Err)
			}
			return nil, res.Err
		}
		return res.Val.(net.IP), nil
	case <-ctx.Done():
		if debug {
			log.Printf("dnscache: context done while resolving %q: %v", host, ctx.Err())
		}
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

func (r *Resolver) lookupIPCacheExpired(host string) (ip net.IP, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ent, ok := r.ipCache[host]; ok {
		return ent.ip, true
	}
	return nil, false
}

func (r *Resolver) lookupTimeoutForHost(host string) time.Duration {
	if r.UseLastGood {
		if _, ok := r.lookupIPCacheExpired(host); ok {
			// If we have some previous good value for this host,
			// don't give this DNS lookup much time. If we're in a
			// situation where the user's DNS server is unreachable
			// (e.g. their corp DNS server is behind a subnet router
			// that can't come up due to Tailscale needing to
			// connect to itself), then we want to fail fast and let
			// our caller (who set UseLastGood) fall back to using
			// the last-known-good IP address.
			return 3 * time.Second
		}
	}
	return 10 * time.Second
}

func (r *Resolver) lookupIP(host string) (net.IP, error) {
	if ip, ok := r.lookupIPCache(host); ok {
		if debug {
			log.Printf("dnscache: %q found in cache as %v", host, ip)
		}
		return ip, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.lookupTimeoutForHost(host))
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
			return r.addIPCache(host, ip4, r.ttl()), nil
		}
	}
	return r.addIPCache(host, ips[0].IP, r.ttl()), nil
}

func (r *Resolver) addIPCache(host string, ip net.IP, d time.Duration) net.IP {
	if isPrivateIP(ip) {
		// Don't cache obviously wrong entries from captive portals.
		// TODO: use DoH or DoT for the forwarding resolver?
		if debug {
			log.Printf("dnscache: %q resolved to private IP %v; using but not caching", host, ip)
		}
		return ip
	}

	if debug {
		log.Printf("dnscache: %q resolved to IP %v; caching", host, ip)
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

type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Dialer returns a wrapped DialContext func that uses the provided dnsCache.
func Dialer(fwd DialContextFunc, dnsCache *Resolver) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			// Bogus. But just let the real dialer return an error rather than
			// inventing a similar one.
			return fwd(ctx, network, address)
		}
		ip, err := dnsCache.LookupIP(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %q: %w", host, err)
		}
		dst := net.JoinHostPort(ip.String(), port)
		if debug {
			log.Printf("dnscache: dialing %s, %s for %s", network, dst, address)
		}
		return fwd(ctx, network, dst)
	}
}
