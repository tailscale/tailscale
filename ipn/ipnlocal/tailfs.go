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
	"regexp"
	"strings"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/logtail/backoff"
	"tailscale.com/tailcfg"
	"tailscale.com/tailfs"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
)

const (
	// TailfsLocalPort is the port on which the Tailfs listens for location
	// connections on quad 100.
	TailfsLocalPort = 8080

	tailfsSharesStateKey = ipn.StateKey("_tailfs-shares")
)

var (
	shareNameRegex      = regexp.MustCompile(`^[a-z0-9_\(\) ]+$`)
	errInvalidShareName = errors.New("Share names may only contain the letters a-z, underscore _, parentheses (), or spaces")
)

// TailfsSharingEnabled reports whether sharing to remote nodes via tailfs is
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

// TailfsAddShare adds the given share if no share with that name exists, or
// replaces the existing share if one with the same name already exists.
// To avoid potential incompatibilities across file systems, share names are
// limited to alphanumeric characters and the underscore _.
func (b *LocalBackend) TailfsAddShare(share *tailfs.Share) error {
	var err error
	share.Name, err = normalizeShareName(share.Name)
	if err != nil {
		return err
	}

	b.mu.Lock()
	shares, err := b.tailfsAddShareLocked(share)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailfsNotifyShares(shares)
	return nil
}

// normalizeShareName normalizes the given share name and returns an error if
// it contains any disallowed characters.
func normalizeShareName(name string) (string, error) {
	// Force all share names to lowercase to avoid potential incompatibilities
	// with clients that don't support case-sensitive filenames.
	name = strings.ToLower(name)

	// Trim whitespace
	name = strings.TrimSpace(name)

	if !shareNameRegex.MatchString(name) {
		return "", errInvalidShareName
	}

	return name, nil
}

func (b *LocalBackend) tailfsAddShareLocked(share *tailfs.Share) (map[string]string, error) {
	if b.tailfsForRemote == nil {
		return nil, errors.New("tailfs not enabled")
	}

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
	b.tailfsForRemote.SetShares(shares)

	return shareNameMap(shares), nil
}

// TailfsRemoveShare removes the named share. Share names are forced to
// lowercase.
func (b *LocalBackend) TailfsRemoveShare(name string) error {
	// Force all share names to lowercase to avoid potential incompatibilities
	// with clients that don't support case-sensitive filenames.
	name = strings.ToLower(name)

	b.mu.Lock()
	shares, err := b.tailfsRemoveShareLocked(name)
	b.mu.Unlock()
	if err != nil {
		return err
	}

	b.tailfsNotifyShares(shares)
	return nil
}

func (b *LocalBackend) tailfsRemoveShareLocked(name string) (map[string]string, error) {
	if b.tailfsForRemote == nil {
		return nil, errors.New("tailfs not enabled")
	}

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
	b.tailfsForRemote.SetShares(shares)

	return shareNameMap(shares), nil
}

func shareNameMap(sharesByName map[string]*tailfs.Share) map[string]string {
	sharesMap := make(map[string]string, len(sharesByName))
	for _, share := range sharesByName {
		sharesMap[share.Name] = share.Path
	}
	return sharesMap
}

// tailfsNotifyShares notifies IPN bus listeners (e.g. Mac Application process)
// about the latest set of shares, supplied as a map of name -> directory.
func (b *LocalBackend) tailfsNotifyShares(shares map[string]string) {
	b.send(ipn.Notify{TailfsShares: shares})
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
	go b.tailfsNotifyShares(shareNameMap(shares))
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
		}
		return nil, fmt.Errorf("read state: %w", err)
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
	oldListeners := b.tailfsListeners
	newListeners := make(map[netip.AddrPort]*localListener, addrs.Len())
	for i := range addrs.LenIter() {
		if fs, ok := b.sys.TailfsForLocal.GetOK(); ok {
			addrPort := netip.AddrPortFrom(addrs.At(i).Addr(), TailfsLocalPort)
			if sl, ok := b.tailfsListeners[addrPort]; ok {
				newListeners[addrPort] = sl
				delete(oldListeners, addrPort)
				continue // already listening
			}

			sl := b.newTailfsListener(context.Background(), fs, addrPort, b.logf)
			newListeners[addrPort] = sl
			go sl.Run()
		}
	}

	// At this point, anything left in oldListeners can be stopped.
	for _, sl := range oldListeners {
		sl.cancel()
	}
}

// newTailfsListener returns a listener for local connections to a tailfs
// WebDAV FileSystem.
func (b *LocalBackend) newTailfsListener(ctx context.Context, fs *tailfs.FileSystemForLocal, ap netip.AddrPort, logf logger.Logf) *localListener {
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
