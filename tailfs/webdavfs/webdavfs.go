// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// package webdavfs provides an implementation of webdav.FileSystem backed by
// a gowebdav.Client.
package webdavfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tailscale/gowebdav"
	"github.com/tailscale/xnet/webdav"

	"tailscale.com/tailfs/shared"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/util/pathutil"
)

const (
	// keep requests from taking too long if the server is down or slow to respond
	opTimeout = 2 * time.Second // TODO(oxtoacart): tune this
)

type Opts struct {
	// Logf us a logging function to use for debug and error logging.
	Logf logger.Logf
	// URL is the base URL of the remote WebDAV server.
	URL string
	// Transport is the http.Transport to use for connecting to the WebDAV
	// server.
	Transport http.RoundTripper
	// StatRoot, if true, will cause this filesystem to actually stat its own
	// root via the remote server. If false, it will use a static directory
	// info for the root to avoid a round-trip.
	StatRoot bool
	// StatCacheTTL, when greater than 0, enables caching of file metadata
	StatCacheTTL time.Duration
	// Clock, if specified, determines the current time. If not specified, we
	// default to time.Now().
	Clock tstime.Clock
}

// webdavFS adapts gowebdav.Client to webdav.FileSystem
type webdavFS struct {
	logf      logger.Logf
	transport http.RoundTripper
	*gowebdav.Client
	now       func() time.Time
	statRoot  bool
	statCache *statCache
}

// New creates a new webdav.FileSystem backed by the given gowebdav.Client.
// If cacheTTL is greater than zero, the filesystem will cache results from
// Stat calls for the given duration.
func New(opts *Opts) webdav.FileSystem {
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	wfs := &webdavFS{
		logf:      opts.Logf,
		transport: opts.Transport,
		Client:    gowebdav.New(&gowebdav.Opts{URI: opts.URL, Transport: opts.Transport}),
		statRoot:  opts.StatRoot,
	}
	if opts.StatCacheTTL > 0 {
		wfs.statCache = newStatCache(opts.StatCacheTTL)
	}
	if opts.Clock != nil {
		wfs.now = opts.Clock.Now
	} else {
		wfs.now = time.Now
	}
	return wfs
}

func (wfs *webdavFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	if wfs.statCache != nil {
		wfs.statCache.invalidate()
	}
	return translateWebDAVError(wfs.Client.Mkdir(ctxWithTimeout, name, perm))
}

func (wfs *webdavFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if hasFlag(flag, os.O_APPEND) {
		return nil, &os.PathError{
			Op:   "open",
			Path: name,
			Err:  errors.New("mode APPEND not supported"),
		}
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	if hasFlag(flag, os.O_WRONLY) || hasFlag(flag, os.O_RDWR) {
		if wfs.statCache != nil {
			wfs.statCache.invalidate()
		}

		fi, err := wfs.Stat(ctxWithTimeout, name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err == nil && fi.IsDir() {
			return nil, &os.PathError{
				Op:   "open",
				Path: name,
				Err:  errors.New("is a directory"),
			}
		}

		pipeReader, pipeWriter := io.Pipe()
		f := &writeOnlyFile{
			WriteCloser: pipeWriter,
			name:        name,
			perm:        perm,
			fs:          wfs,
			finalError:  make(chan error, 1),
		}
		go func() {
			defer pipeReader.Close()
			err := wfs.Client.WriteStream(context.Background(), name, pipeReader, perm)
			f.finalError <- err
			close(f.finalError)
		}()

		return f, nil
	}

	// Assume reading
	fi, err := wfs.Stat(ctxWithTimeout, name)
	if err != nil {
		return nil, translateWebDAVError(err)
	}
	if fi.IsDir() {
		return wfs.dirWithChildren(name, fi), nil
	}

	return &readOnlyFile{
		client:       wfs.Client,
		name:         name,
		initialFI:    fi,
		rewindBuffer: make([]byte, 0, MaxRewindBuffer),
	}, nil
}

func (wfs *webdavFS) dirWithChildren(name string, fi fs.FileInfo) webdav.File {
	return &shared.DirFile{
		Info: fi,
		LoadChildren: func() ([]fs.FileInfo, error) {
			ctxWithTimeout, cancel := context.WithTimeout(context.Background(), opTimeout)
			defer cancel()

			dirInfos, err := wfs.Client.ReadDir(ctxWithTimeout, name)
			if err != nil {
				wfs.logf("encountered error reading children of '%v', returning empty list: %v", name, err)
				// We do not return the actual error here because some WebDAV clients
				// will take that as an invitation to retry, hanging in the process.
				return dirInfos, nil
			}
			if wfs.statCache != nil {
				wfs.statCache.set(name, dirInfos)
			}
			return dirInfos, nil
		},
	}
}

func (wfs *webdavFS) RemoveAll(ctx context.Context, name string) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	if wfs.statCache != nil {
		wfs.statCache.invalidate()
	}
	return wfs.Client.RemoveAll(ctxWithTimeout, name)
}

func (wfs *webdavFS) Rename(ctx context.Context, oldName, newName string) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	if wfs.statCache != nil {
		wfs.statCache.invalidate()
	}
	return wfs.Client.Rename(ctxWithTimeout, oldName, newName, false)
}

func (wfs *webdavFS) Stat(ctx context.Context, name string) (fs.FileInfo, error) {
	if wfs.statCache != nil {
		return wfs.statCache.getOrFetch(name, wfs.doStat)
	}
	return wfs.doStat(name)
}

func (wfs *webdavFS) Close() error {
	if wfs.statCache != nil {
		wfs.statCache.stop()
	}
	tr, ok := wfs.transport.(*http.Transport)
	if ok {
		tr.CloseIdleConnections()
	}
	return nil
}

func (wfs *webdavFS) doStat(name string) (fs.FileInfo, error) {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	if !wfs.statRoot && pathutil.IsRoot(name) {
		// use a static directory info for the root
		// always use now() as the modified time to bust caches
		return shared.ReadOnlyDirInfo(name, wfs.now()), nil
	}
	fi, err := wfs.Client.Stat(ctxWithTimeout, name)
	return fi, translateWebDAVError(err)
}

func translateWebDAVError(err error) error {
	if err == nil {
		return nil
	}
	var se gowebdav.StatusError
	if errors.As(err, &se) {
		if se.Status == http.StatusNotFound {
			return os.ErrNotExist
		}
	}
	// Note, we intentionally don't wrap the error because we don't want
	// github.com/tailscale/xnet/webdav to try to interpret the underlying
	// error.
	return fmt.Errorf("unexpected WebDAV error: %v", err)
}

func hasFlag(flags int, flag int) bool {
	return (flags & flag) == flag
}
