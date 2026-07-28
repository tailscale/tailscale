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
	"time"

	"tailscale.com/clientupdate/distsign"
	"tailscale.com/types/logger"
	"tailscale.com/util/progresstracking"
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

	tmp, err := os.CreateTemp("", "tailscale-gokrazy-*.gaf")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpName)

	logf("downloading %s", args.URL)
	if args.AllowUnsigned {
		if err := downloadUnverified(ctx, logf, args.URL, tmpName); err != nil {
			return err
		}
	} else {
		if err := distsign.DownloadVerified(ctx, logf, args.URL, tmpName); err != nil {
			return err
		}
	}

	zr, err := zip.OpenReader(tmpName)
	if err != nil {
		return err
	}
	defer zr.Close()

	logf("download complete")

	gokClient := gokrazyHTTPClient()
	for _, part := range []struct {
		name string
		path string
	}{
		{"root.img", "/update/root"},
		{"boot.img", "/update/boot"},
		{"mbr.img", "/update/mbr"},
	} {
		logf("writing %s...", part.name)
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

// downloadUnverified saves the GAF at srcURL to dstPath without verifying
// a signature. It is used only when args.AllowUnsigned is set, for tests
// that serve the GAF from a fileserver that does not publish distsign.pub
// and for the gafpush "sftp the GAF onto the appliance and update from a
// local path" flow, which uses a "file://" URL.
func downloadUnverified(ctx context.Context, logf logger.Logf, srcURL, dstPath string) error {
	if after, ok := strings.CutPrefix(srcURL, "file://"); ok {
		return copyLocalFile(after, dstPath, logf)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", srcURL, nil)
	if err != nil {
		return err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("download GAF: %s", res.Status)
	}
	f, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	total := res.ContentLength
	pw := progresstracking.NewWriter(io.Discard, total, time.Second, func(done int64) {
		if total > 0 {
			logf("downloading: %d / %d MB (%.0f%%)", done>>20, total>>20, float64(done)/float64(total)*100)
		}
	})
	if _, err := io.Copy(f, io.TeeReader(res.Body, pw)); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// copyLocalFile copies the GAF at src to dst. Used by the "file://" branch
// of downloadUnverified. The source file is left in place; callers that
// staged it (e.g. gafpush) clean up after the update completes.
func copyLocalFile(src, dst string, logf logger.Logf) error {
	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()
	df, err := os.Create(dst)
	if err != nil {
		return err
	}
	fi, err := sf.Stat()
	if err != nil {
		df.Close()
		return err
	}
	total := fi.Size()
	logf("copying local GAF %s (%d MB)", src, total>>20)
	pw := progresstracking.NewWriter(io.Discard, total, time.Second, func(done int64) {
		if total > 0 {
			logf("copying: %d / %d MB (%.0f%%)", done>>20, total>>20, float64(done)/float64(total)*100)
		}
	})
	if _, err := io.Copy(df, io.TeeReader(sf, pw)); err != nil {
		df.Close()
		return err
	}
	return df.Close()
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
