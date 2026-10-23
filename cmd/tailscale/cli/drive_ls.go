// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/studio-b12/gowebdav"
	"tailscale.com/drive/driveimpl/shared"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

func driveWebDAVURL() string {
	// Matches ipnlocal.DriveLocalPort. Importing ipnlocal would pull the
	// daemon implementation into the CLI just to obtain this constant.
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(tsaddr.TailscaleServiceIP().String(), "8080")}).String()
}

// driveDAVPath uses the same domain and node display name as driveRemoteSource.
// Like the Taildrive integration tests, it passes an unescaped shared.Join path
// to gowebdav, which escapes each segment exactly once.
func driveDAVPath(st *ipnstate.Status, remote driveRemotePath) (string, error) {
	peer, ok := peerStatusFromArg(st, remote.node)
	if !ok {
		return "", fmt.Errorf("Taildrive node %q not found", remote.node)
	}
	if st.CurrentTailnet == nil || st.CurrentTailnet.Name == "" {
		return "", errors.New("Taildrive: current tailnet is unavailable")
	}
	node := &tailcfg.Node{
		Name:     peer.DNSName,
		Key:      peer.PublicKey,
		Hostinfo: (&tailcfg.Hostinfo{Hostname: peer.HostName}).View(),
	}
	node.InitDisplayNames(st.CurrentTailnet.MagicDNSSuffix)
	name := node.DisplayName(false)
	for _, component := range []string{st.CurrentTailnet.Name, name} {
		if component == "" || component == "." || component == ".." || strings.ContainsAny(component, "/\x00") {
			return "", errors.New("Taildrive: invalid tailnet or node name")
		}
	}
	return shared.Join(st.CurrentTailnet.Name, name, remote.share, remote.path), nil
}

func listDriveDirectory(ctx context.Context, out io.Writer, st *ipnstate.Status, remote driveRemotePath, endpoint string) error {
	path, err := driveDAVPath(st, remote)
	if err != nil {
		return err
	}
	client, cleanup := newDriveDAVClient(ctx, endpoint, 30*time.Second)
	defer cleanup()
	files, err := client.ReadDir(path)
	if err != nil {
		return driveDAVError(path, err)
	}
	slices.SortFunc(files, func(a, b os.FileInfo) int {
		if a.IsDir() != b.IsDir() {
			if a.IsDir() {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name(), b.Name())
	})
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSIZE\tMODIFIED")
	for _, file := range files {
		name := file.Name()
		// Escape control characters so filenames cannot inject terminal output.
		if strings.ContainsFunc(name, unicode.IsControl) {
			name = fmt.Sprintf("%q", name)
		}
		size := fmt.Sprintf("%d B", file.Size())
		if file.IsDir() {
			name += "/"
			size = "-"
		}
		modified := "-"
		// gowebdav uses the Unix epoch when getlastmodified is absent.
		if t := file.ModTime(); !t.IsZero() && !t.Equal(time.Unix(0, 0)) {
			modified = t.Local().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", name, size, modified)
	}
	return w.Flush()
}

// driveDAVFailure keeps the underlying error available without printing server XML
// or untrusted XML parser diagnostics to the terminal.
type driveDAVFailure struct {
	message string
	cause   error
}

func (e *driveDAVFailure) Error() string { return e.message }
func (e *driveDAVFailure) Unwrap() error { return e.cause }

type driveDAVTransport struct{ http.RoundTripper }

func (t driveDAVTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.RoundTripper.RoundTrip(r)
	if err != nil || resp.StatusCode != http.StatusMultiStatus {
		return resp, err
	}
	// gowebdav v0.13.0 silently discards XML decoding errors. Validate the
	// envelope so a broken response cannot masquerade as an empty directory.
	// Property interpretation and child/self handling remain in ReadDir.
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	var envelope struct {
		XMLName   xml.Name   `xml:"DAV: multistatus"`
		Responses []struct{} `xml:"DAV: response"`
	}
	if err := xml.Unmarshal(body, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.Responses) == 0 {
		return nil, errors.New("WebDAV response has no directory entry")
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// newDriveDAVClient configures the local service client. A zero timeout permits
// long transfers; connection and response-header waits remain bounded.
func newDriveDAVClient(ctx context.Context, endpoint string, timeout time.Duration) (*gowebdav.Client, func()) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.Proxy = nil // The local service must not go through an HTTP proxy.
	client := gowebdav.NewAuthClient(endpoint, gowebdav.NewEmptyAuth())
	client.SetTransport(driveDAVTransport{transport})
	client.SetTimeout(timeout)
	client.SetHeader(gowebdav.XInhibitRedirect, "1")
	client.SetInterceptor(func(_ string, r *http.Request) { *r = *r.WithContext(ctx) })
	return client, transport.CloseIdleConnections
}

func driveDAVError(path string, err error) error {
	message := "Taildrive WebDAV protocol error"
	var status gowebdav.StatusError
	var netErr *net.OpError
	var urlErr *url.Error
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		message = "Taildrive request interrupted"
	case errors.As(err, &status):
		switch status.Status {
		case http.StatusForbidden, http.StatusUnauthorized:
			message = "Taildrive access denied"
		case http.StatusNotFound:
			message = "Taildrive share or path not found (or not accessible)"
		case http.StatusMethodNotAllowed:
			message = "Taildrive WebDAV method not allowed for this path"
		default:
			message = fmt.Sprintf("Taildrive WebDAV returned HTTP %d", status.Status)
		}
	case errors.As(err, &netErr), errors.Is(err, io.EOF), errors.As(err, &urlErr) && urlErr.Timeout():
		message = "Taildrive local service unavailable; check that Tailscale is running and drive:access is enabled"
	}
	return &driveDAVFailure{fmt.Sprintf("%s for %q", message, path), err}
}
