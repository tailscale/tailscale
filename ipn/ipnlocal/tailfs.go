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
	"tailscale.com/tailcfg"
	"tailscale.com/tailfs"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/mak"
)

const (
	// TailfsLocalPort is the port on which the Tailfs listens for location
	// connections on quad 100.
	TailfsLocalPort = 8080

	tailfsSharesStateKey = ipn.StateKey("_tailfs-shares")
)

// TailfsSharingEnabled indicates whether sharing to remote nodes via tailfs is
// enabled. This is currently based on checking for the tailfs:share node
// attribute.
func (b *LocalBackend) TailfsSharingEnabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.tailfsSharingEnabledLocked()
}

func (b *LocalBackend) tailfsSharingEnabledLocked() bool {
	return b.netMap != nil && b.netMap.SelfNode.HasCap(tailcfg.NodeAttrsTailfsSharingEnabled)
}

// TailfsSetFileServerAddr tells tailfs to use the given address for connecting
// to the tailfs.FileServer that's exposing local files as an unprivileged
// user.
func (b *LocalBackend) TailfsSetFileServerAddr(addr string) error {
	b.mu.Lock()
	fs := b.tailfsForRemote
	b.mu.Unlock()
	if fs == nil {
		return errors.New("tailfs not enabled")
	}

	fs.SetFileServerAddr(addr)
	return nil
}

// TailfsAddShare adds/edits a share.
func (b *LocalBackend) TailfsAddShare(share *tailfs.Share) error {
	b.mu.Lock()
	fs := b.tailfsForRemote
	b.mu.Unlock()
	if fs == nil {
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

// TailfsRemoveShare removes the named share.
func (b *LocalBackend) TailfsRemoveShare(name string) error {
	b.mu.Lock()
	fs := b.tailfsForRemote
	b.mu.Unlock()
	if fs == nil {
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

// tailfsNotifyCurrentSharesLocked sends an ipn.Notify with the current set of
// tailfs shares.
func (b *LocalBackend) tailfsNotifyCurrentSharesLocked() {
	shares, err := b.tailfsGetSharesLocked()
	if err != nil {
		b.logf("error notifying current tailfs shares: %v", err)
		return
	}
	// Do the below on a goroutine to avoid deadlocking on b.mu in b.send().
	go b.tailfsNotifyShares(shares)
}

// TailfsGetShares() returns the current set of shares from the state store.
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

// updateTailfsListenersLocked creates listeners on the local Tailfs port.
// This is needed to properly route local traffic when using kernel networking
// mode.
func (b *LocalBackend) updateTailfsListenersLocked() {
	if b.netMap == nil {
		return
	}

	addrs := b.netMap.GetAddresses()
	for i := range addrs.LenIter() {
		if fs, ok := b.sys.TailfsForLocal.GetOK(); ok {
			addrPort := netip.AddrPortFrom(addrs.At(i).Addr(), TailfsLocalPort)
			if _, ok := b.tailfsListeners[addrPort]; ok {
				continue // already listening
			}

			sl := b.newTailfsListener(context.Background(), fs, addrPort, b.logf)
			mak.Set(&b.tailfsListeners, addrPort, sl)

			go sl.Run()
		}
	}
}

// newTailfsListener returns a listener for local connections to a tailfs
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

// updateTailfsPeersLocked sets all applicable peers from the netmap as tailfs
// remotes.
func (b *LocalBackend) updateTailfsPeersLocked(nm *netmap.NetworkMap) {
	fs, ok := b.sys.TailfsForLocal.GetOK()
	if !ok {
		return
	}

	tailfsRemotes := make([]*tailfs.Remote, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		peerID := p.ID()
		url := fmt.Sprintf("%s/%s", peerAPIBase(nm, p), tailfsPrefix[1:])
		tailfsRemotes = append(tailfsRemotes, &tailfs.Remote{
			Name: p.DisplayName(false),
			URL:  url,
			Available: func() bool {
				// TODO(oxtoacart): need to figure out a performant and reliable way to only
				// show the peers that have shares to which we have access
				// This will require work on the control server to transmit the inverse
				// of the "tailscale.com/cap/tailfs" capability.
				// For now, at least limit it only to nodes that are online.
				// Note, we have to iterate the latest netmap because the peer we got from the first iteration may not be it
				b.mu.Lock()
				latestNetMap := b.netMap
				b.mu.Unlock()

				for _, candidate := range latestNetMap.Peers {
					if candidate.ID() == peerID {
						online := candidate.Online()
						// TODO(oxtoacart): for some reason, this correctly
						// catches when a node goes from offline to online,
						// but not the other way around...
						return online != nil && *online
					}
				}

				// peer not found, must not be available
				return false
			},
		})
	}
	fs.SetRemotes(b.netMap.Domain, tailfsRemotes, &tailfsTransport{b: b})
}
