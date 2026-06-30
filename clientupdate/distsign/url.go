// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package distsign

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"tailscale.com/types/logger"
)

// DownloadVerified is a convenience wrapper around [Client.Download]
// for callers that have a full URL (e.g.
// https://pkgs.tailscale.com/unstable/foo.gaf) rather than a base URL
// plus path. It splits srcURL into a base ("scheme://host") and a path,
// constructs a [Client] for the base, and downloads with signature
// verification to dstPath.
func DownloadVerified(ctx context.Context, logf logger.Logf, srcURL, dstPath string) error {
	if logf == nil {
		logf = logger.Discard
	}
	u, err := url.Parse(srcURL)
	if err != nil {
		return fmt.Errorf("parsing URL %q: %w", srcURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("URL %q is missing scheme or host", srcURL)
	}
	base := &url.URL{Scheme: u.Scheme, User: u.User, Host: u.Host}
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		return fmt.Errorf("URL %q has no path component", srcURL)
	}
	c, err := NewClient(logf, base.String())
	if err != nil {
		return err
	}
	return c.Download(ctx, path, dstPath)
}
