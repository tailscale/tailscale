// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"tailscale.com/types/logger"
)

// versionRE matches a concrete X.Y.Z release version.
var versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// resolveTestVersion returns the concrete release version (e.g. "1.97.255")
// for the given --test-version flag value. If v is "unstable" or "stable", it
// queries pkgs.tailscale.com for the latest TarballsVersion on that track.
// Otherwise it returns v unchanged.
func resolveTestVersion(ctx context.Context, v string) (string, error) {
	if v != "unstable" && v != "stable" {
		if !versionRE.MatchString(v) {
			return "", fmt.Errorf("invalid --test-version %q: want \"stable\", \"unstable\", or X.Y.Z", v)
		}
		return v, nil
	}
	url := "https://pkgs.tailscale.com/" + v + "/?mode=json"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetching %s: HTTP %s", url, resp.Status)
	}
	var meta struct {
		TarballsVersion string
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return "", fmt.Errorf("decoding %s: %w", url, err)
	}
	if meta.TarballsVersion == "" {
		return "", fmt.Errorf("no TarballsVersion in %s response", url)
	}
	return meta.TarballsVersion, nil
}

// versionTrack returns the pkgs.tailscale.com track ("stable" or "unstable")
// for a release version. Even minors are stable; odd minors are unstable.
func versionTrack(version string) (string, error) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("bad version %q (expected like 1.97.255)", version)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", fmt.Errorf("bad minor in version %q: %w", version, err)
	}
	if minor%2 == 0 {
		return "stable", nil
	}
	return "unstable", nil
}

// versionCacheRoot returns the root cache directory for downloaded version
// tarballs.
func versionCacheRoot() string {
	if d := os.Getenv("VMTEST_BUILDS_CACHE_DIR"); d != "" {
		return d
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		panic(fmt.Sprintf("os.UserCacheDir: %v", err))
	}
	return filepath.Join(cache, "tailscale-vmtest", "builds")
}

// versionCacheDir returns the directory holding the extracted binaries for
// the given version+arch.
func versionCacheDir(version, arch string) string {
	return filepath.Join(versionCacheRoot(), fmt.Sprintf("%s_%s", version, arch))
}

// ensureVersionBinaries downloads (if needed) and extracts the tailscale
// release tarball for the given concrete version+arch, returning the
// directory containing tailscale and tailscaled.
func ensureVersionBinaries(ctx context.Context, version, arch string, logf logger.Logf) (string, error) {
	dir := versionCacheDir(version, arch)
	tailscaled := filepath.Join(dir, "tailscaled")
	tailscale := filepath.Join(dir, "tailscale")
	if _, err1 := os.Stat(tailscaled); err1 == nil {
		if _, err2 := os.Stat(tailscale); err2 == nil {
			return dir, nil
		}
	}

	track, err := versionTrack(version)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://pkgs.tailscale.com/%s/tailscale_%s_%s.tgz", track, version, arch)
	logf("downloading %s", url)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetching %s: HTTP %s", url, resp.Status)
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return "", fmt.Errorf("gzip reader for %s: %w", url, err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)

	wantBase := map[string]bool{
		"tailscale":  true,
		"tailscaled": true,
	}
	got := map[string]bool{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading tarball %s: %w", url, err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := path.Base(hdr.Name)
		if !wantBase[base] {
			continue
		}
		if err := writeAtomic(filepath.Join(dir, base), tr, 0755); err != nil {
			return "", fmt.Errorf("extracting %s from %s: %w", base, url, err)
		}
		got[base] = true
	}
	for b := range wantBase {
		if !got[b] {
			return "", fmt.Errorf("tarball %s missing %s", url, b)
		}
	}
	logf("extracted %s and %s to %s", "tailscale", "tailscaled", dir)
	return dir, nil
}

// writeAtomic writes the contents of r to dst with the given permission
// bits, by writing to a sibling temp file and renaming on success.
func writeAtomic(dst string, r io.Reader, perm os.FileMode) error {
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
