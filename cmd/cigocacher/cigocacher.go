// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// cigocacher is an opinionated-to-Tailscale client for gocached. It connects
// at a URL like "https://ci-gocached-azure-1.corp.ts.net:31364", but that is
// stored in a GitHub actions variable so that its hostname can be updated for
// all branches at the same time in sync with the actual infrastructure.
//
// It authenticates using GitHub OIDC tokens, and all HTTP errors are ignored
// so that its failure mode is just that builds get slower and fall back to
// disk-only cache.
package main

import (
	"bytes"
	"context"
	jsonv1 "encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bradfitz/go-tool-cache/cacheproc"
	"github.com/bradfitz/go-tool-cache/cachers"
)

func main() {
	var (
		version     = flag.Bool("version", false, "print version and exit")
		auth        = flag.Bool("auth", false, "auth with cigocached and exit, printing the access token as output")
		stats       = flag.Bool("stats", false, "fetch and print cigocached stats and exit")
		token       = flag.String("token", "", "the cigocached access token to use, as created using --auth")
		srvURL      = flag.String("cigocached-url", "", "optional cigocached URL (scheme, host, and port). Empty means to not use one.")
		srvHostDial = flag.String("cigocached-host", "", "optional cigocached host to dial instead of the host in the provided --cigocached-url. Useful for public TLS certs on private addresses.")
		dir         = flag.String("cache-dir", "", "cache directory; empty means automatic")
		verbose     = flag.Bool("verbose", false, "enable verbose logging")
	)
	flag.Parse()

	if *version {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			log.Fatal("no build info")
		}
		var (
			rev   string
			dirty bool
		)
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				dirty, _ = strconv.ParseBool(s.Value)
			}
		}
		if dirty {
			rev += "-dirty"
		}
		fmt.Println(rev)
		return
	}

	var srvHost string
	if *srvHostDial != "" && *srvURL != "" {
		u, err := url.Parse(*srvURL)
		if err != nil {
			log.Fatal(err)
		}
		srvHost = u.Hostname()
	}

	if *auth {
		if *srvURL == "" {
			log.Print("--cigocached-url is empty, skipping auth")
			return
		}
		tk, err := fetchAccessToken(httpClient(srvHost, *srvHostDial), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"), *srvURL)
		if err != nil {
			log.Printf("error fetching access token, skipping auth: %v", err)
			return
		}
		fmt.Println(tk)
		return
	}

	if *stats {
		if *srvURL == "" {
			log.Fatal("--cigocached-url is empty; cannot fetch stats")
		}
		tk := *token
		if tk == "" {
			log.Fatal("--token is empty; cannot fetch stats")
		}
		c := &gocachedClient{
			baseURL:     *srvURL,
			cl:          httpClient(srvHost, *srvHostDial),
			accessToken: tk,
			verbose:     *verbose,
		}
		stats, err := c.fetchStats()
		if err != nil {
			log.Fatalf("error fetching gocached stats: %v", err)
		}
		fmt.Println(stats)
		return
	}

	if *dir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			log.Fatal(err)
		}
		*dir = filepath.Join(d, "go-cacher")
		log.Printf("Defaulting to cache dir %v ...", *dir)
	}
	if err := os.MkdirAll(*dir, 0750); err != nil {
		log.Fatal(err)
	}

	c := &cigocacher{
		disk: &cachers.DiskCache{
			Dir:     *dir,
			Verbose: *verbose,
		},
		verbose: *verbose,
	}
	if *srvURL != "" {
		if *verbose {
			log.Printf("Using cigocached at %s", *srvURL)
		}
		c.gocached = &gocachedClient{
			baseURL:     *srvURL,
			cl:          httpClient(srvHost, *srvHostDial),
			accessToken: *token,
			verbose:     *verbose,
		}
	}
	var p *cacheproc.Process
	p = &cacheproc.Process{
		Close: func() error {
			if c.verbose {
				log.Printf("gocacheprog: closing; %d gets (%d hits, %d misses, %d errors); %d puts (%d errors)",
					p.Gets.Load(), p.GetHits.Load(), p.GetMisses.Load(), p.GetErrors.Load(), p.Puts.Load(), p.PutErrors.Load())
			}
			return c.close()
		},
		Get: c.get,
		Put: c.put,
	}

	if err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

func httpClient(srvHost, srvHostDial string) *http.Client {
	if srvHost == "" || srvHostDial == "" {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if host, port, err := net.SplitHostPort(addr); err == nil && host == srvHost {
					// This allows us to serve a publicly trusted TLS cert
					// while also minimising latency by explicitly using a
					// private network address.
					addr = net.JoinHostPort(srvHostDial, port)
				}
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}
}

type cigocacher struct {
	disk     *cachers.DiskCache
	gocached *gocachedClient
	verbose  bool

	getNanos      atomic.Int64 // total nanoseconds spent in gets
	putNanos      atomic.Int64 // total nanoseconds spent in puts
	getHTTP       atomic.Int64 // HTTP get requests made
	getHTTPBytes  atomic.Int64 // HTTP get bytes transferred
	getHTTPHits   atomic.Int64 // HTTP get hits
	getHTTPMisses atomic.Int64 // HTTP get misses
	getHTTPErrors atomic.Int64 // HTTP get errors ignored on best-effort basis
	getHTTPNanos  atomic.Int64 // total nanoseconds spent in HTTP gets
	putHTTP       atomic.Int64 // HTTP put requests made
	putHTTPBytes  atomic.Int64 // HTTP put bytes transferred
	putHTTPErrors atomic.Int64 // HTTP put errors ignored on best-effort basis
	putHTTPNanos  atomic.Int64 // total nanoseconds spent in HTTP puts
}

func (c *cigocacher) get(ctx context.Context, actionID string) (outputID, diskPath string, err error) {
	t0 := time.Now()
	defer func() {
		c.getNanos.Add(time.Since(t0).Nanoseconds())
	}()
	if c.gocached == nil {
		return c.disk.Get(ctx, actionID)
	}

	outputID, diskPath, err = c.disk.Get(ctx, actionID)
	if err == nil && outputID != "" {
		return outputID, diskPath, nil
	}

	c.getHTTP.Add(1)
	t0HTTP := time.Now()
	defer func() {
		c.getHTTPNanos.Add(time.Since(t0HTTP).Nanoseconds())
	}()
	outputID, res, err := c.gocached.get(ctx, actionID)
	if err != nil {
		c.getHTTPErrors.Add(1)
		return "", "", nil
	}
	if outputID == "" || res == nil {
		c.getHTTPMisses.Add(1)
		return "", "", nil
	}

	defer res.Body.Close()

	diskPath, err = put(c.disk, actionID, outputID, res.ContentLength, res.Body)
	if err != nil {
		return "", "", fmt.Errorf("error filling disk cache from HTTP: %w", err)
	}

	c.getHTTPHits.Add(1)
	c.getHTTPBytes.Add(res.ContentLength)
	return outputID, diskPath, nil
}

func (c *cigocacher) put(ctx context.Context, actionID, outputID string, size int64, r io.Reader) (diskPath string, err error) {
	t0 := time.Now()
	defer func() {
		c.putNanos.Add(time.Since(t0).Nanoseconds())
	}()
	if c.gocached == nil {
		return put(c.disk, actionID, outputID, size, r)
	}

	c.putHTTP.Add(1)
	var diskReader, httpReader io.Reader
	tee := &bestEffortTeeReader{r: r}
	if size == 0 {
		// Special case the empty file so NewRequest sets "Content-Length: 0",
		// as opposed to thinking we didn't set it and not being able to sniff its size
		// from the type.
		diskReader, httpReader = bytes.NewReader(nil), bytes.NewReader(nil)
	} else {
		pr, pw := io.Pipe()
		defer pw.Close()
		// The diskReader is in the driving seat. We will try to forward data
		// to httpReader as well, but only best-effort.
		diskReader = tee
		tee.w = pw
		httpReader = pr
	}
	httpErrCh := make(chan error)
	go func() {
		t0HTTP := time.Now()
		defer func() {
			c.putHTTPNanos.Add(time.Since(t0HTTP).Nanoseconds())
		}()
		httpErrCh <- c.gocached.put(ctx, actionID, outputID, size, httpReader)
	}()

	diskPath, err = put(c.disk, actionID, outputID, size, diskReader)
	if err != nil {
		return "", fmt.Errorf("error writing to disk cache: %w", errors.Join(err, tee.err))
	}

	select {
	case err := <-httpErrCh:
		if err != nil {
			c.putHTTPErrors.Add(1)
		} else {
			c.putHTTPBytes.Add(size)
		}
	case <-ctx.Done():
	}

	return diskPath, nil
}

func (c *cigocacher) close() error {
	if !c.verbose || c.gocached == nil {
		return nil
	}

	log.Printf("cigocacher HTTP stats: %d gets (%.1fMiB, %.2fs, %d hits, %d misses, %d errors ignored); %d puts (%.1fMiB, %.2fs, %d errors ignored)",
		c.getHTTP.Load(), float64(c.getHTTPBytes.Load())/float64(1<<20), float64(c.getHTTPNanos.Load())/float64(time.Second), c.getHTTPHits.Load(), c.getHTTPMisses.Load(), c.getHTTPErrors.Load(),
		c.putHTTP.Load(), float64(c.putHTTPBytes.Load())/float64(1<<20), float64(c.putHTTPNanos.Load())/float64(time.Second), c.putHTTPErrors.Load())

	stats, err := c.gocached.fetchStats()
	if err != nil {
		log.Printf("error fetching gocached stats: %v", err)
	} else {
		log.Printf("gocached session stats: %s", stats)
	}

	return nil
}

func fetchAccessToken(cl *http.Client, idTokenURL, idTokenRequestToken, gocachedURL string) (string, error) {
	req, err := http.NewRequest("GET", idTokenURL+"&audience=gocached", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+idTokenRequestToken)
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	type idTokenResp struct {
		Value string `json:"value"`
	}
	var idToken idTokenResp
	if err := jsonv1.NewDecoder(resp.Body).Decode(&idToken); err != nil {
		return "", err
	}

	req, _ = http.NewRequest("POST", gocachedURL+"/auth/exchange-token", strings.NewReader(`{"jwt":"`+idToken.Value+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err = cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	type accessTokenResp struct {
		AccessToken string `json:"access_token"`
	}
	var accessToken accessTokenResp
	if err := jsonv1.NewDecoder(resp.Body).Decode(&accessToken); err != nil {
		return "", err
	}

	return accessToken.AccessToken, nil
}

type bestEffortTeeReader struct {
	r   io.Reader
	w   io.WriteCloser
	err error
}

func (t *bestEffortTeeReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 && t.w != nil {
		if _, err := t.w.Write(p[:n]); err != nil {
			t.err = errors.Join(err, t.w.Close())
			t.w = nil
		}
	}
	return n, err
}
