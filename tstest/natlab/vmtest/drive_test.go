// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/mds/shell"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

const (
	driveShareName = "docs"
	driveShareDir  = "/srv/taildrive-share"

	driveASCIIName    = "hello.txt"
	driveASCIIContent = "hello world"

	// driveKanaNFC and driveKanaNFD are the same filename (テズト ä.wav) in
	// NFC (precomposed) and NFD (decomposed) Unicode normalization forms,
	// from tailscale/tailscale#15020. They are canonically equivalent but
	// byte-wise different: in NFC, ズ is the single code point U+30BA and ä
	// is U+00E4; in NFD they are ス U+30B9 plus the combining voiced sound
	// mark U+3099, and "a" plus the combining diaeresis U+0308.
	driveKanaNFC     = "\u30c6\u30ba\u30c8 \u00e4.wav"
	driveKanaNFD     = "\u30c6\u30b9\u3099\u30c8 a\u0308.wav"
	driveKanaContent = "kana content"
)

// TestTaildrive shares a directory from one node and accesses it from another
// via the accessing node's local Taildrive WebDAV proxy at
// 100.100.100.100:8080, first with a plain ASCII filename and then with
// filenames whose Unicode normalization form differs between the request and
// the on-disk name.
//
// The Unicode cases simulate a macOS WebDAV client, which requests paths in
// NFD form, accessing a share on a Linux disk whose filenames are NFC bytes
// (tailscale/tailscale#15020). Requesting a directory listing immediately
// before the NFD PROPFIND also exercises the accessing node's StatCache,
// which caches children under their NFC hrefs and previously inferred 404
// for the NFD name without contacting the share host.
func TestTaildrive(t *testing.T) {
	env := vmtest.New(t, vmtest.AllOnline())

	hostNet := env.AddNetwork("1.0.0.1", "192.168.1.1/24", vnet.EasyNAT)
	clientNet := env.AddNetwork("2.0.0.1", "192.168.2.1/24", vnet.EasyNAT)

	// Taildrive is disabled unless control sends these node attributes.
	driveCaps := tailcfg.NodeCapMap{
		tailcfg.NodeAttrsTaildriveShare:  nil,
		tailcfg.NodeAttrsTaildriveAccess: nil,
	}
	host := env.AddNode("drivehost", hostNet,
		vmtest.OS(vmtest.Ubuntu2404),
		driveCaps)
	client := env.AddNode("driveclient", clientNet,
		vmtest.OS(vmtest.Ubuntu2404),
		driveCaps)

	// Declare test-specific steps for the web UI.
	setupStep := env.AddStep("Create files and share on host")
	waitStep := env.AddStep("Wait for share to be accessible from client")
	asciiStep := env.AddStep("ASCII file access (client -> host)")
	unicodeStep := env.AddStep("NFC/NFD normalization mismatch access")

	env.Start()

	// Access to a peer's shares additionally requires peer capabilities,
	// normally granted via ACL grants. Grant every peer read/write access to
	// every share, plus the sharer capability that makes share hosts show up
	// in directory listings on accessing nodes.
	env.ControlServer().SetGlobalAppCaps(tailcfg.PeerCapMap{
		tailcfg.PeerCapabilityTaildrive:       {`{"shares":["*"],"access":"rw"}`},
		tailcfg.PeerCapabilityTaildriveSharer: {`true`},
	})

	setupStep.Begin()
	setupCmd := fmt.Sprintf("mkdir -p %s && printf %%s %s > %s && printf %%s %s > %s",
		shell.Quote(driveShareDir),
		shell.Quote(driveASCIIContent), shell.Quote(driveShareDir+"/"+driveASCIIName),
		shell.Quote(driveKanaContent), shell.Quote(driveShareDir+"/"+driveKanaNFC))
	if out, err := env.SSHExec(host, setupCmd); err != nil {
		setupStep.Fatalf("share dir setup: %v\n%s", err, out)
		return
	}
	if out, err := env.Tailscale(host, "drive", "share", driveShareName, driveShareDir); err != nil {
		setupStep.Fatalf("tailscale drive share: %v\n%s", err, out)
		return
	}
	setupStep.End(nil)

	// Discover the tailnet domain (the top-level directory of the WebDAV
	// tree) by listing the root, then wait until the host's share is
	// reachable from the client. The peer capability grants pushed above
	// take a map update to arrive at both nodes.
	waitStep.Begin()
	var shareBase string // /<domain>/drivehost/docs, percent-encoded
	if err := tstest.WaitFor(2*time.Minute, func() error {
		status, body, err := webdavCurl(env, client, "PROPFIND", "/", "-H", "Depth: 1")
		if err != nil {
			return err
		}
		if status != 207 {
			return fmt.Errorf("PROPFIND /: status %d: %s", status, body)
		}
		domain := ""
		for _, m := range hrefRegex.FindAllStringSubmatch(body, -1) {
			if p := strings.Trim(m[1], "/"); p != "" {
				domain = p
				break
			}
		}
		if domain == "" {
			return fmt.Errorf("no domain in root listing: %s", body)
		}
		shareBase = "/" + domain + "/" + url.PathEscape(host.Name()) + "/" + url.PathEscape(driveShareName)
		status, body, err = webdavCurl(env, client, "GET", shareBase+"/"+url.PathEscape(driveASCIIName))
		if err != nil {
			return err
		}
		if status != 200 {
			return fmt.Errorf("GET %s: status %d: %s", driveASCIIName, status, body)
		}
		return nil
	}); err != nil {
		waitStep.Fatalf("share never became accessible: %v", err)
		return
	}
	waitStep.End(nil)

	asciiStep.Begin()
	status, body, err := webdavCurl(env, client, "GET", shareBase+"/"+url.PathEscape(driveASCIIName))
	if err != nil || status != 200 || body != driveASCIIContent {
		asciiStep.Fatalf("GET %s = %d, %q, %v; want 200, %q", driveASCIIName, status, body, err, driveASCIIContent)
		return
	}
	status, body, err = webdavCurl(env, client, "PROPFIND", shareBase+"/", "-H", "Depth: 1")
	if err != nil || status != 207 || !strings.Contains(body, driveASCIIName) {
		asciiStep.Fatalf("PROPFIND share = %d, %v; want 207 mentioning %s:\n%s", status, err, driveASCIIName, body)
		return
	}
	asciiStep.End(nil)

	unicodeStep.Begin()
	// List the directory first. The response hrefs carry the NFC bytes from
	// the host's disk, and the listing primes the client's StatCache, whose
	// entries live for 10 seconds. The depth 0 PROPFIND for the NFD name
	// that follows is answered from that cache, so it must treat the two
	// forms as the same name.
	status, body, err = webdavCurl(env, client, "PROPFIND", shareBase+"/", "-H", "Depth: 1")
	if err != nil || status != 207 || !strings.Contains(body, url.PathEscape(driveKanaNFC)) {
		unicodeStep.Fatalf("PROPFIND share = %d, %v; want 207 mentioning NFC name:\n%s", status, err, body)
		return
	}
	nfdPath := shareBase + "/" + url.PathEscape(driveKanaNFD)
	status, body, err = webdavCurl(env, client, "PROPFIND", nfdPath, "-H", "Depth: 0")
	if err != nil || status != 207 {
		unicodeStep.Fatalf("PROPFIND NFD name = %d, %v; want 207:\n%s", status, err, body)
		return
	}
	status, body, err = webdavCurl(env, client, "GET", nfdPath)
	if err != nil || status != 200 || body != driveKanaContent {
		unicodeStep.Fatalf("GET NFD name = %d, %q, %v; want 200, %q", status, body, err, driveKanaContent)
		return
	}
	// Overwriting via the NFD name must update the NFC file on the host's
	// disk rather than creating a second file.
	const updatedContent = "updated kana content"
	status, body, err = webdavCurl(env, client, "PUT", nfdPath, "--data-binary", updatedContent)
	if err != nil || status/100 != 2 {
		unicodeStep.Fatalf("PUT NFD name = %d, %v; want 2xx:\n%s", status, err, body)
		return
	}
	out, err := env.SSHExec(host, "cat "+shell.Quote(driveShareDir+"/"+driveKanaNFC))
	if err != nil || out != updatedContent {
		unicodeStep.Fatalf("host file after PUT = %q, %v; want %q", out, err, updatedContent)
		return
	}
	out, err = env.SSHExec(host, "ls "+shell.Quote(driveShareDir)+" | wc -l")
	if err != nil || strings.TrimSpace(out) != "2" {
		unicodeStep.Fatalf("host share has %s files after PUT, %v; want 2", strings.TrimSpace(out), err)
		return
	}
	unicodeStep.End(nil)
}

var hrefRegex = regexp.MustCompile(`<D:href>([^<]*)</D:href>`)

// webdavCurl performs a WebDAV request from the given node against the
// node's local Taildrive WebDAV proxy at 100.100.100.100:8080 by running
// curl over the node's debug SSH connection. The path must already be
// percent-encoded; extraArgs are passed to curl before the URL. It returns
// the HTTP status code and the response body.
func webdavCurl(env *vmtest.Env, n *vmtest.Node, method, path string, extraArgs ...string) (status int, body string, err error) {
	cmd := "curl -s --max-time 15 -X " + shell.Quote(method)
	for _, arg := range extraArgs {
		cmd += " " + shell.Quote(arg)
	}
	// curl expands the \n itself, putting the status code on its own final
	// line after the unmodified response body.
	cmd += ` -w '\n%{http_code}' ` + shell.Quote("http://100.100.100.100:8080"+path)
	out, err := env.SSHExec(n, cmd)
	if err != nil {
		return 0, "", fmt.Errorf("curl: %v\n%s", err, out)
	}
	i := strings.LastIndexByte(out, '\n')
	if i == -1 {
		return 0, "", fmt.Errorf("no status line in curl output: %q", out)
	}
	status, err = strconv.Atoi(strings.TrimSpace(out[i+1:]))
	if err != nil {
		return 0, "", fmt.Errorf("bad status line in curl output: %q", out)
	}
	return status, out[:i], nil
}
