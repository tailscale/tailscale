// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package dnsresolvecache persists successful DNS resolutions from
// net/dnscache to disk, one JSON file per hostname, so that a later
// tailscaled boot with misconfigured DNS can still find
// last-known-good IPs for critical hostnames such as the control
// plane. It is intended to eventually replace the DERP-based
// bootstrap DNS in net/dnsfallback.
//
// A file is rewritten only when its contents change, so its
// modification time records when the answer last changed, not when
// it was last confirmed.
//
// This package is linked into tailscaled by default and omitted from
// tsnet. Nothing here is automatic for tsnet-based apps: to use it,
// they must both blank-import this package and configure the cache
// directory themselves by invoking [dnscache.HookSetCacheDir], which
// is otherwise only called by tailscaled at startup.
//
// This package's state is process-global. In tsnet-based apps running
// multiple tsnet.Server instances in one process, only the cache
// directory from the first [dnscache.HookSetCacheDir] call is used;
// later calls are ignored and all servers share the first cache.
package dnsresolvecache

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"tailscale.com/atomicfile"
	"tailscale.com/feature"
	"tailscale.com/net/dnscache"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

func init() {
	feature.Register("dnsresolvecache")
	dnscache.HookSetCacheDir.Set(setCacheDir)
	dnscache.HookPersistResolution.Set(persist)
	dnscache.HookLookupDiskCache.Set(lookup)
}

var (
	mu          sync.Mutex        // guards the variables below
	cacheDir    string            // empty until the first successful setCacheDir call
	logf        logger.Logf       // non-nil once cacheDir is set
	lastWritten map[string]string // hostname => digest of last JSON written
)

// record is the JSON structure of each persisted per-hostname file.
type record struct {
	Resolver   string       // resolver source of the answer: "forward", "cloud", or "fallback"
	A          []netip.Addr `json:",omitempty"` // IPv4 addresses, sorted
	AAAA       []netip.Addr `json:",omitempty"` // IPv6 addresses, sorted
	TTLSeconds int          `json:",omitzero"`  // TTL of the answer, if known (currently never set)
}

// setCacheDir creates dir if needed and enables persistence to it.
// It implements [dnscache.HookSetCacheDir].
//
// Only the first successful call has any effect; later calls are
// no-ops that keep using the first directory. See the package doc
// for what that means for multi-server tsnet apps.
func setCacheDir(dir string, lf logger.Logf) {
	if lf == nil {
		lf = logger.Discard
	}
	mu.Lock()
	defer mu.Unlock()
	if cacheDir != "" {
		if dir != cacheDir {
			lf("dnsresolvecache: cache dir already set to %q; ignoring %q", cacheDir, dir)
		}
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		lf("dnsresolvecache: %v", err)
		return
	}
	cacheDir = dir
	logf = lf
}

// filePath returns the path of the cache file for host.
// The caller must have validated host and hold mu (for cacheDir).
func filePath(host string) string {
	return filepath.Join(cacheDir, "dns-"+host+".json")
}

// persist writes the resolution of host to disk, unless the on-disk
// contents would be unchanged. It implements
// [dnscache.HookPersistResolution].
func persist(host, resolver string, ips []netip.Addr) {
	host = strings.ToLower(host)
	if !validHostname(host) || len(ips) == 0 {
		return
	}
	rec := record{Resolver: resolver}
	ips = slices.Clone(ips)
	slices.SortFunc(ips, netip.Addr.Compare)
	for _, ip := range slices.Compact(ips) {
		if ip.Is4() {
			rec.A = append(rec.A, ip)
		} else {
			rec.AAAA = append(rec.AAAA, ip)
		}
	}
	j, err := json.Marshal(rec)
	if err != nil {
		return
	}
	digest := sha256.Sum256(j)

	mu.Lock()
	defer mu.Unlock()
	if cacheDir == "" {
		return
	}
	path := filePath(host)
	if last, ok := lastWritten[host]; ok {
		if last == string(digest[:]) {
			return
		}
	} else if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, j) {
		// First resolution since process start and the file already
		// matches; skip the write to preserve its modtime.
		mak.Set(&lastWritten, host, string(digest[:]))
		return
	}
	if err := atomicfile.WriteFile(path, j, 0600); err != nil {
		logf("dnsresolvecache: writing %v: %v", path, err)
		return
	}
	mak.Set(&lastWritten, host, string(digest[:]))
}

// lookup returns the persisted last-known-good IPs for host, if any.
// It implements [dnscache.HookLookupDiskCache].
func lookup(host string) ([]netip.Addr, bool) {
	host = strings.ToLower(host)
	if !validHostname(host) {
		return nil, false
	}
	mu.Lock()
	defer mu.Unlock()
	if cacheDir == "" {
		return nil, false
	}
	j, err := os.ReadFile(filePath(host))
	if err != nil {
		return nil, false
	}
	var rec record
	if err := json.Unmarshal(j, &rec); err != nil {
		logf("dnsresolvecache: parsing cache for %q: %v", host, err)
		return nil, false
	}
	ips := append(rec.A, rec.AAAA...)
	if len(ips) == 0 {
		return nil, false
	}
	return ips, true
}

// validHostname reports whether host is a DNS hostname that is safe
// to embed in a filename: dot-separated non-empty labels of
// lowercase letters, digits, hyphens, and underscores. It is
// intentionally stricter than DNS itself (which permits nearly
// arbitrary bytes in labels) to keep hostile names out of paths.
func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := range len(label) {
			b := label[i]
			if b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_' {
				continue
			}
			return false
		}
	}
	return true
}
