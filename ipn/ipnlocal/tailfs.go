// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/logtail/backoff"
	"tailscale.com/tailfs"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

const (
	TailfsInternalPort = 8080
)

func (b *LocalBackend) TailfsAddShare(name, path string) error {
	fs, ok := b.sys.TailfsForRemote.GetOK()
	if !ok {
		return errors.New("tailfs not enabled")
	}
	fs.AddShare(name, path)
	return nil
}

func (b *LocalBackend) TailfsRemoveShare(name string) error {
	fs, ok := b.sys.TailfsForRemote.GetOK()
	if !ok {
		return errors.New("tailfs not enabled")
	}
	fs.RemoveShare(name)
	return nil
}

// updateTailfsListenersLocked creates listeners on the internal Tailfs port.
// This is needed to properly route local traffic when using kernel networking
// mode.
func (b *LocalBackend) updateTailfsListenersLocked() {
	if b.netMap == nil {
		return
	}

	tailfsPorts := map[uint16]tailfs.FileSystem{}

	if fs, ok := b.sys.TailfsForLocal.GetOK(); ok {
		tailfsPorts[TailfsInternalPort] = fs
	}

	addrs := b.netMap.GetAddresses()
	for i := range addrs.LenIter() {
		for port, fs := range tailfsPorts {
			addrPort := netip.AddrPortFrom(addrs.At(i).Addr(), port)
			if _, ok := b.tailfsListeners[addrPort]; ok {
				continue // already listening
			}

			sl := b.newTailfsListener(context.Background(), fs, addrPort, b.logf)
			mak.Set(&b.webClientListeners, addrPort, sl)

			go sl.Run()
		}
	}
}

// newTailfsListener returns a listener for local connections to a Tailfs
// WebDAV FileSystem.
func (b *LocalBackend) newTailfsListener(ctx context.Context, fs tailfs.FileSystem, ap netip.AddrPort, logf logger.Logf) *localListener {
	ctx, cancel := context.WithCancel(ctx)
	return &localListener{
		b:      b,
		ap:     ap,
		ctx:    ctx,
		cancel: cancel,
		logf:   logf,

		handler: func(conn net.Conn) error {
			return fs.HandleConn(conn, conn.RemoteAddr())
		},
		bo: backoff.NewBackoff(fmt.Sprintf("tailfs-listener-%d", ap.Port()), logf, 30*time.Second),
	}
}
