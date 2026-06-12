// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package clientupdate

import (
	"archive/zip"
	"context"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"tailscale.com/types/logger"
)

const (
	gokrazyUpdateSocket  = "/run/gokrazy-http.sock"
	gokrazyUpdateBaseURL = "http://gokrazy-local-unixsock"
)

// GokrazyUpdateFromURL downloads a Gokrazy archive format file from args.URL,
// installs its partitions using the local gokrazy init update API, switches to
// the new root partition, and asks gokrazy to reboot.
//
// The local gokrazy API is reached over gokrazyUpdateSocket. The
// gokrazyUpdateBaseURL host is only a net/http URL sentinel; it is not resolved
// with DNS.
func init() {
	GokrazyUpdateFromURL.Set(gokrazyUpdateFromURL)
}

func gokrazyUpdateFromURL(ctx context.Context, args GokrazyUpdateArgs) error {
	logf := args.Logf
	if logf == nil {
		logf = logger.Discard
	}
	if !args.AllowUnsigned {
		return fmt.Errorf("signed GAF verification is not implemented yet; see https://github.com/tailscale/tailscale/issues/20002")
	}

	tmp, err := os.CreateTemp("", "tailscale-gokrazy-*.gaf")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	req, err := http.NewRequestWithContext(ctx, "GET", args.URL, nil)
	if err != nil {
		tmp.Close()
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		tmp.Close()
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		tmp.Close()
		return fmt.Errorf("download GAF: %s", res.Status)
	}
	if _, err := io.Copy(tmp, res.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	zr, err := zip.OpenReader(tmpName)
	if err != nil {
		return err
	}
	defer zr.Close()

	gokClient := gokrazyHTTPClient()
	for _, part := range []struct {
		name string
		path string
	}{
		{"root.img", "/update/root"},
		{"boot.img", "/update/boot"},
		{"mbr.img", "/update/mbr"},
	} {
		if err := putGokrazyGAFMember(ctx, gokClient, zr.File, part.name, part.path); err != nil {
			return err
		}
		logf("wrote %s", part.name)
	}
	if err := postGokrazy(ctx, gokClient, "/update/switch"); err != nil {
		return err
	}
	logf("switched boot target")
	if err := postGokrazy(ctx, gokClient, "/reboot?async=true&kexec_merge_cmdline=true"); err != nil {
		return err
	}
	logf("reboot requested")
	return nil
}

func gokrazyHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", gokrazyUpdateSocket)
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func putGokrazyGAFMember(ctx context.Context, hc *http.Client, files []*zip.File, name, path string) error {
	var zf *zip.File
	for _, f := range files {
		if f.Name == name {
			zf = f
			break
		}
	}
	if zf == nil {
		return fmt.Errorf("GAF is missing %s", name)
	}
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	h := crc32.NewIEEE()
	body := io.TeeReader(rc, h)
	req, err := http.NewRequestWithContext(ctx, "PUT", gokrazyUpdateBaseURL+path, body)
	if err != nil {
		return err
	}
	req.ContentLength = int64(zf.UncompressedSize64)
	req.Header.Set("X-Gokrazy-Update-Hash", "crc32")
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	resBody, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("PUT %s: %s: %s", path, res.Status, strings.TrimSpace(string(resBody)))
	}
	if got, want := strings.TrimSpace(string(resBody)), fmt.Sprintf("%08x", h.Sum32()); got != want {
		return fmt.Errorf("PUT %s: gokrazy checksum = %q; want %q", path, got, want)
	}
	return nil
}

func postGokrazy(ctx context.Context, hc *http.Client, path string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", gokrazyUpdateBaseURL+path, nil)
	if err != nil {
		return err
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		return fmt.Errorf("POST %s: %s: %s", path, res.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
