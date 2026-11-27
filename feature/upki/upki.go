// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package upki rejects TLS server certificates that are revoked according to
// a local upki revocation cache, if one is present.
//
// upki (https://github.com/rustls/upki) keeps CRLite revocation filters in a
// local cache directory (see https://c2sp.org/upki-revocation), refreshed in
// the background by "upki fetch". This package only reads that cache; it
// never downloads anything. If no cache is found, or the cache doesn't cover
// a certificate, connections proceed as they would without this package.
package upki

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/cpu/go-upki/upki"
	"tailscale.com/feature"
	"tailscale.com/net/tlsdial"
)

func init() {
	if !feature.Register("upki") {
		return
	}
	tlsdial.HookCheckRevocation.Set(checkRevocation)
}

// indexFile is the name of the index file that upki publishes atomically
// into a revocation cache directory once the filters it names are in place.
const indexFile = "index.bin"

// cacheDirs returns the candidate upki revocation cache directories, in
// order of preference: the user cache first, then the system cache. It's a
// variable for tests.
var cacheDirs = func() []string {
	var dirs []string
	userCache, _ := os.UserCacheDir()
	switch runtime.GOOS {
	case "windows":
		if userCache != "" {
			dirs = append(dirs, filepath.Join(userCache, "rustls", "upki", "cache", "revocation"))
		}
		if pd := os.Getenv("ProgramData"); pd != "" {
			dirs = append(dirs, filepath.Join(pd, "rustls", "upki", "cache", "revocation"))
		}
	case "darwin", "ios":
		if userCache != "" {
			dirs = append(dirs, filepath.Join(userCache, "dev.rustls.upki", "revocation"))
		}
		dirs = append(dirs, "/Library/Caches/dev.rustls.upki/revocation")
	default:
		if userCache != "" {
			dirs = append(dirs, filepath.Join(userCache, "upki", "revocation"))
		}
		dirs = append(dirs, "/var/cache/upki/revocation")
	}
	return dirs
}

// findCacheDir returns the first directory from [cacheDirs] that contains a
// published index, or "" if there is none.
//
// A directory without an index is skipped rather than selected, so a cache
// that has been created but not yet populated by its first fetch doesn't
// shadow a populated one, and isn't treated as an error.
func findCacheDir() string {
	for _, dir := range cacheDirs() {
		if fi, err := os.Stat(filepath.Join(dir, indexFile)); err == nil && fi.Mode().IsRegular() {
			return dir
		}
	}
	return ""
}

// checkRevocation implements [tlsdial.HookCheckRevocation].
//
// It rejects only certificates that the cache says are revoked. Certificates
// the cache doesn't cover (private CAs, certificates without embedded SCTs,
// or logs not yet in the filters) are allowed, and so is everything if no
// cache is present. Errors reading the cache are logged and the connection
// is allowed: a local user able to corrupt the cache could equally delete
// it, and failing closed would cut a node off from its control server
// because of a bad local file.
func checkRevocation(dnsName string, chain []*x509.Certificate) error {
	dir := findCacheDir()
	if dir == "" {
		return nil
	}
	// The checker is cheap to open (it reads only the index header and log
	// table), and opening it fresh each time picks up new data from upki's
	// periodic fetches without needing to watch the directory.
	opener := upki.DirOpener{Dir: dir}
	checker, err := upki.NewCheckerWith(opener, opener)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) { // lost a race with a cache update
			logError(dir, err)
		}
		return nil
	}
	defer checker.Close()

	status, err := checker.Check(chain)
	if err != nil {
		logError(dir, err)
		return nil
	}
	if status == upki.StatusRevoked {
		leaf := chain[0]
		log.Printf("upki: certificate for %q (serial %x, issuer %q) is revoked according to %s", dnsName, leaf.SerialNumber, leaf.Issuer, dir)
		return fmt.Errorf("certificate for %q is revoked according to upki cache %s", dnsName, dir)
	}
	return nil
}

var (
	logMu      sync.Mutex
	lastLogged time.Time // last time logError wrote a log line
)

// logError logs an error reading the upki cache at dir, at most once per
// hour.
func logError(dir string, err error) {
	logMu.Lock()
	defer logMu.Unlock()
	if !lastLogged.IsZero() && time.Since(lastLogged) < time.Hour {
		return
	}
	lastLogged = time.Now()
	log.Printf("upki: ignoring error checking revocation using %s: %v", dir, err)
}
