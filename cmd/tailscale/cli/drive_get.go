// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive && !ts_mac_gui

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/util/quarantine"
)

func runDriveGet(ctx context.Context, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("usage: %s", driveGetUsage)
	}
	remote, err := parseDriveRemotePath(args[0])
	if err != nil {
		return err
	}
	if err := checkDriveGetPath(remote); err != nil {
		return err
	}
	destination := "."
	if len(args) == 2 {
		destination = args[1]
	}
	st, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("getting Tailscale status: %w", err)
	}
	local, n, err := getDriveFile(ctx, st, remote, destination, driveWebDAVURL())
	if err != nil {
		return err
	}
	fmt.Fprintf(Stdout, "Downloaded %q -> %q (%d B)\n", args[0], local, n)
	return nil
}

func checkDriveGetPath(remote driveRemotePath) error {
	if remote.path == "" || path.Clean(remote.path) == "." || path.Clean(remote.path) == "/" {
		return errors.New("remote file path missing; expected <node>:<share>/<file>")
	}
	if strings.HasSuffix(remote.path, "/") || strings.HasSuffix(remote.path, "/.") {
		return errors.New("remote path is a directory; recursive downloads are not supported")
	}
	return nil
}

func driveGetDestination(remote driveRemotePath, destination string) (string, error) {
	if fi, err := os.Stat(destination); err == nil && fi.IsDir() {
		base := path.Base(remote.path)
		if !filepath.IsLocal(base) || filepath.Base(base) != base {
			return "", fmt.Errorf("remote basename %q cannot be used as a local filename", base)
		}
		destination = filepath.Join(destination, base)
	}
	// Lstat also rejects dangling symlinks. The final Link is the authoritative
	// no-overwrite check, including files created after this early check.
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("destination %q already exists: %w", destination, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("checking destination %q: %w", destination, err)
	}
	return destination, nil
}

func getDriveFile(ctx context.Context, st *ipnstate.Status, remote driveRemotePath, destination, endpoint string) (local string, size int64, retErr error) {
	if err := checkDriveGetPath(remote); err != nil {
		return "", 0, err
	}
	davPath, err := driveDAVPath(st, remote)
	if err != nil {
		return "", 0, err
	}
	destination, err = driveGetDestination(remote, destination)
	if err != nil {
		return "", 0, err
	}
	client, cleanup := newDriveDAVClient(ctx, endpoint, 0)
	defer cleanup()
	info, err := client.Stat(davPath)
	if err != nil {
		return "", 0, driveDAVError(davPath, err)
	}
	if info == nil {
		return "", 0, driveDAVError(davPath, errors.New("missing WebDAV file metadata"))
	}
	if info.IsDir() {
		return "", 0, errors.New("remote path is a directory; recursive downloads are not supported")
	}
	f, err := os.CreateTemp(filepath.Dir(destination), ".tailscale-drive-*")
	if err != nil {
		return "", 0, fmt.Errorf("creating download in destination directory %q: %w", filepath.Dir(destination), err)
	}
	// Keep CreateTemp's private permissions (0600 before umask). Publishing
	// another link to this inode must not broaden access to downloaded data.
	defer func() {
		if err := os.Remove(f.Name()); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("removing temporary download %q: %w", f.Name(), err))
		}
	}()
	defer f.Close()
	// Match Taildrop downloads. The metadata stays attached to the inode
	// when the completed file is published under its final name.
	if err := quarantine.SetOnFile(f); err != nil {
		return "", 0, fmt.Errorf("applying download quarantine metadata: %w", err)
	}
	stream, err := client.ReadStream(davPath)
	if err != nil {
		return "", 0, driveDAVError(davPath, err)
	}
	n, copyErr := io.Copy(f, stream)
	closeErr := stream.Close()
	if err := ctx.Err(); err != nil {
		return "", 0, fmt.Errorf("download interrupted: %w", err)
	}
	if copyErr != nil {
		return "", 0, fmt.Errorf("download failed while copying to %q: %w", destination, copyErr)
	}
	if closeErr != nil {
		return "", 0, fmt.Errorf("closing download: %w", closeErr)
	}
	if err := f.Sync(); err != nil {
		return "", 0, fmt.Errorf("syncing download: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", 0, fmt.Errorf("closing local download: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", 0, fmt.Errorf("download interrupted: %w", err)
	}
	// Rename can overwrite a concurrently-created destination. Linking the
	// completed file publishes it atomically and fails if the name exists.
	// Both paths are on the same filesystem; the deferred Remove drops only
	// the temporary name. Filesystems without hard links fail safely.
	if err := os.Link(f.Name(), destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", 0, fmt.Errorf("destination %q already exists: %w", destination, err)
		}
		return "", 0, fmt.Errorf("publishing download as %q: %w", destination, err)
	}
	return destination, n, nil
}
