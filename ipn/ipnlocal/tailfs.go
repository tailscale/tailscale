// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/logtail/backoff"
	"tailscale.com/tailfs"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

const (
	TailfsInternalPort = 8080

	tailfsSharesStateKey = ipn.StateKey("_tailfs-shares")
)

func (b *LocalBackend) TailfsAddShare(share *tailfs.Share) error {
	fs, ok := b.sys.TailfsForRemote.GetOK()
	if !ok {
		return errors.New("tailfs not enabled")
	}

	b.mu.Lock()
	shares, err := b.tailfsAddShareLocked(fs, share)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailfsNotifyShares(shares)
	return nil
}

func (b *LocalBackend) tailfsAddShareLocked(fs tailfs.ForRemote, share *tailfs.Share) (map[string]*tailfs.Share, error) {
	shares, err := b.tailfsGetSharesLocked()
	if err != nil {
		return nil, err
	}
	shares[share.Name] = share
	data, err := json.Marshal(shares)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	err = b.store.WriteState(tailfsSharesStateKey, data)
	if err != nil {
		return nil, fmt.Errorf("write state: %w", err)
	}
	fs.SetShares(shares)
	return shares, nil
}

func (b *LocalBackend) TailfsRemoveShare(name string) error {
	fs, ok := b.sys.TailfsForRemote.GetOK()
	if !ok {
		return errors.New("tailfs not enabled")
	}

	b.mu.Lock()
	shares, err := b.tailfsRemoveShareLocked(fs, name)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailfsNotifyShares(shares)
	return nil
}

func (b *LocalBackend) tailfsRemoveShareLocked(fs tailfs.ForRemote, name string) (map[string]*tailfs.Share, error) {
	shares, err := b.tailfsGetSharesLocked()
	if err != nil {
		return nil, err
	}
	_, shareExists := shares[name]
	if !shareExists {
		return nil, os.ErrNotExist
	}
	delete(shares, name)
	data, err := json.Marshal(shares)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	err = b.store.WriteState(tailfsSharesStateKey, data)
	if err != nil {
		return nil, fmt.Errorf("write state: %w", err)
	}
	fs.SetShares(shares)
	return shares, nil
}

// tailfsNotifyShares notifies IPN bus listeners (e.g. Mac Application process)
// about the latest set of shares.
func (b *LocalBackend) tailfsNotifyShares(shares map[string]*tailfs.Share) {
	sharesMap := make(map[string]string, len(shares))
	for _, share := range shares {
		sharesMap[share.Name] = share.Path
	}
	b.send(ipn.Notify{TailfsShares: sharesMap})
}

func (b *LocalBackend) TailfsGetShares() (map[string]*tailfs.Share, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.tailfsGetSharesLocked()
}

func (b *LocalBackend) tailfsGetSharesLocked() (map[string]*tailfs.Share, error) {
	data, err := b.store.ReadState(tailfsSharesStateKey)
	if err != nil {
		if errors.Is(err, ipn.ErrStateNotExist) {
			return make(map[string]*tailfs.Share), nil
		} else {
			return nil, fmt.Errorf("read state: %w", err)
		}
	}

	var shares map[string]*tailfs.Share
	err = json.Unmarshal(data, &shares)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return shares, nil
}

// updateTailfsListenersLocked creates listeners on the internal Tailfs port.
// This is needed to properly route local traffic when using kernel networking
// mode.
func (b *LocalBackend) updateTailfsListenersLocked() {
	if b.netMap == nil {
		return
	}

	addrs := b.netMap.GetAddresses()
	for i := range addrs.LenIter() {
		if fs, ok := b.sys.TailfsForLocal.GetOK(); ok {
			addrPort := netip.AddrPortFrom(addrs.At(i).Addr(), TailfsInternalPort)
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
func (b *LocalBackend) newTailfsListener(ctx context.Context, fs tailfs.ForLocal, ap netip.AddrPort, logf logger.Logf) *localListener {
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
