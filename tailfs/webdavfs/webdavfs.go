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
	"net/http"
	"os"
	"time"

	"github.com/tailscale/gowebdav"
	"golang.org/x/net/webdav"
	"tailscale.com/tailfs/shared"
	"tailscale.com/types/logger"
)

const (
	// keep requests from taking too long if the server is down or slow to respond
	opTimeout = 2 * time.Second // TODO(oxtoacart): tune this
)

// webdavFS adapts gowebdav.Client to webdav.FileSystem
type webdavFS struct {
	logf logger.Logf
	*gowebdav.Client
	statCache *statCache
}

type Opts struct {
	*gowebdav.Client
	// StatCacheTTL, when greater than 0, enables caching of file metadata
	StatCacheTTL time.Duration
	Logf         logger.Logf
}

// New creates a new webdav.FileSystem backed by the given gowebdav.Client.
// If cacheTTL is greater than zero, the filesystem will cache
func New(opts *Opts) webdav.FileSystem {
	wfs := &webdavFS{
		logf:   opts.Logf,
		Client: opts.Client,
	}
	if opts.StatCacheTTL > 0 {
		wfs.statCache = newStatCache(opts.StatCacheTTL)
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
	if isRoot(name) {
		// Root is a directory
		fi := shared.ReadOnlyDirInfo(name)
		return wfs.dirWithChildren(name, fi), nil
	}

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

		fi, err := wfs.Client.Stat(ctxWithTimeout, name)
		err = translateWebDAVError(err)
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
		writeErrChan := make(chan error, 1)
		go func() {
			defer pipeReader.Close()
			writeErr := wfs.Client.WriteStream(context.Background(), name, pipeReader, perm)
			if writeErr != nil {
				fmt.Printf("webdavfs writeErr: %v\n", writeErr)
			}
			writeErrChan <- writeErr
		}()
		// TODO(oxtoacart): do something with the error in writeonlyFile

		return &writeOnlyFile{
			WriteCloser: pipeWriter,
			name:        name,
			perm:        perm,
			fs:          wfs,
			errCh:       writeErrChan,
		}, nil
	}

	// Assume reading
	fi, err := wfs.Client.Stat(ctxWithTimeout, name)
	if err != nil {
		return nil, translateWebDAVError(err)
	}
	if fi.IsDir() {
		return wfs.dirWithChildren(name, fi), nil
	}
	stream, err := wfs.Client.ReadStream(ctx, name)
	if err != nil {
		return nil, translateWebDAVError(err)
	}
	return &readOnlyFile{
		ReadCloser: stream,
		fi:         fi,
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
				return nil, translateWebDAVError(err)
			}
			if wfs.statCache != nil {
				wfs.statCache.Set(name, dirInfos)
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
		return wfs.statCache.GetOrFetch(name, wfs.doStat)
	}
	return wfs.doStat(name)
}

func (wfs *webdavFS) doStat(name string) (fs.FileInfo, error) {
	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	wfs.logf("ZZZZ webdavfs stating %v", name)
	fi, err := wfs.Client.Stat(ctxWithTimeout, name)
	wfs.logf("ZZZZ webdavfs stat result %v %v", fi, err)
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
	return err
}

func hasFlag(flags int, flag int) bool {
	return (flags & flag) == flag
}

func isRoot(name string) bool {
	return name == "/"
}
