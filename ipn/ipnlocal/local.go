// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-multierror/multierror"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/policy"
	"tailscale.com/net/dns"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/tsaddr"
	"tailscale.com/paths"
	"tailscale.com/portlist"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/deephash"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/osshare"
	"tailscale.com/util/systemd"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgcfg/nmcfg"
)

var controlDebugFlags = getControlDebugFlags()

func getControlDebugFlags() []string {
	if e := os.Getenv("TS_DEBUG_CONTROL_FLAGS"); e != "" {
		return strings.Split(e, ",")
	}
	return nil
}

// LocalBackend is the glue between the major pieces of the Tailscale
// network software: the cloud control plane (via controlclient), the
// network data plane (via wgengine), and the user-facing UIs and CLIs
// (collectively called "frontends", via LocalBackend's implementation
// of the Backend interface).
//
// LocalBackend implements the overall state machine for the Tailscale
// application. Frontends, controlclient and wgengine can feed events
// into LocalBackend to advance the state machine, and advancing the
// state machine generates events back out to zero or more components.
type LocalBackend struct {
	// Elements that are thread-safe or constant after construction.
	ctx                   context.Context    // canceled by Close
	ctxCancel             context.CancelFunc // cancels ctx
	logf                  logger.Logf        // general logging
	keyLogf               logger.Logf        // for printing list of peers on change
	statsLogf             logger.Logf        // for printing peers stats on change
	e                     wgengine.Engine
	store                 ipn.StateStore
	backendLogID          string
	unregisterLinkMon     func()
	unregisterHealthWatch func()
	portpoll              *portlist.Poller // may be nil
	portpollOnce          sync.Once        // guards starting readPoller
	gotPortPollRes        chan struct{}    // closed upon first readPoller result
	serverURL             string           // tailcontrol URL
	newDecompressor       func() (controlclient.Decompressor, error)

	filterHash deephash.Sum

	// The mutex protects the following elements.
	mu             sync.Mutex
	httpTestClient *http.Client // for controlclient. nil by default, used by tests.
	ccGen          clientGen    // function for producing controlclient; lazily populated
	notify         func(ipn.Notify)
	cc             controlclient.Client
	stateKey       ipn.StateKey // computed in part from user-provided value
	userID         string       // current controlling user ID (for Windows, primarily)
	prefs          *ipn.Prefs
	inServerMode   bool
	machinePrivKey key.MachinePrivate
	state          ipn.State
	capFileSharing bool // whether netMap contains the file sharing capability
	// hostinfo is mutated in-place while mu is held.
	hostinfo *tailcfg.Hostinfo
	// netMap is not mutated in-place once set.
	netMap           *netmap.NetworkMap
	nodeByAddr       map[netaddr.IP]*tailcfg.Node
	activeLogin      string // last logged LoginName from netMap
	engineStatus     ipn.EngineStatus
	endpoints        []tailcfg.Endpoint
	blocked          bool
	authURL          string // cleared on Notify
	authURLSticky    string // not cleared on Notify
	interact         bool
	prevIfState      *interfaces.State
	peerAPIServer    *peerAPIServer // or nil
	peerAPIListeners []*peerAPIListener
	incomingFiles    map[*incomingFile]bool
	// directFileRoot, if non-empty, means to write received files
	// directly to this directory, without staging them in an
	// intermediate buffered directory for "pick-up" later. If
	// empty, the files are received in a daemon-owned location
	// and the localapi is used to enumerate, download, and delete
	// them. This is used on macOS where the GUI lifetime is the
	// same as the Network Extension lifetime and we can thus avoid
	// double-copying files by writing them to the right location
	// immediately.
	directFileRoot string

	// statusLock must be held before calling statusChanged.Wait() or
	// statusChanged.Broadcast().
	statusLock    sync.Mutex
	statusChanged *sync.Cond
}

// clientGen is a func that creates a control plane client.
// It's the type used by LocalBackend.SetControlClientGetterForTesting.
type clientGen func(controlclient.Options) (controlclient.Client, error)

// NewLocalBackend returns a new LocalBackend that is ready to run,
// but is not actually running.
func NewLocalBackend(logf logger.Logf, logid string, store ipn.StateStore, e wgengine.Engine) (*LocalBackend, error) {
	if e == nil {
		panic("ipn.NewLocalBackend: wgengine must not be nil")
	}

	osshare.SetFileSharingEnabled(false, logf)

	// Default filter blocks everything and logs nothing, until Start() is called.
	e.SetFilter(filter.NewAllowNone(logf, &netaddr.IPSet{}))

	ctx, cancel := context.WithCancel(context.Background())
	portpoll, err := portlist.NewPoller()
	if err != nil {
		logf("skipping portlist: %s", err)
	}

	b := &LocalBackend{
		ctx:            ctx,
		ctxCancel:      cancel,
		logf:           logf,
		keyLogf:        logger.LogOnChange(logf, 5*time.Minute, time.Now),
		statsLogf:      logger.LogOnChange(logf, 5*time.Minute, time.Now),
		e:              e,
		store:          store,
		backendLogID:   logid,
		state:          ipn.NoState,
		portpoll:       portpoll,
		gotPortPollRes: make(chan struct{}),
	}
	b.statusChanged = sync.NewCond(&b.statusLock)
	b.e.SetStatusCallback(b.setWgengineStatus)

	linkMon := e.GetLinkMonitor()
	b.prevIfState = linkMon.InterfaceState()
	// Call our linkChange code once with the current state, and
	// then also whenever it changes:
	b.linkChange(false, linkMon.InterfaceState())
	b.unregisterLinkMon = linkMon.RegisterChangeCallback(b.linkChange)

	b.unregisterHealthWatch = health.RegisterWatcher(b.onHealthChange)

	wiredPeerAPIPort := false
	if ig, ok := e.(wgengine.InternalsGetter); ok {
		if tunWrap, _, ok := ig.GetInternals(); ok {
			tunWrap.PeerAPIPort = b.getPeerAPIPortForTSMPPing
			wiredPeerAPIPort = true
		}
	}
	if !wiredPeerAPIPort {
		b.logf("[unexpected] failed to wire up peer API port for engine %T", e)
	}

	return b, nil
}

// SetDirectFileRoot sets the directory to download files to directly,
// without buffering them through an intermediate daemon-owned
// tailcfg.UserID-specific directory.
//
// This must be called before the LocalBackend starts being used.
func (b *LocalBackend) SetDirectFileRoot(dir string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.directFileRoot = dir
}

// b.mu must be held.
func (b *LocalBackend) maybePauseControlClientLocked() {
	if b.cc == nil {
		return
	}
	networkUp := b.prevIfState.AnyInterfaceUp()
	b.cc.SetPaused((b.state == ipn.Stopped && b.netMap != nil) || !networkUp)
}

// linkChange is our link monitor callback, called whenever the network changes.
// major is whether ifst is different than earlier.
func (b *LocalBackend) linkChange(major bool, ifst *interfaces.State) {
	b.mu.Lock()
	defer b.mu.Unlock()

	hadPAC := b.prevIfState.HasPAC()
	b.prevIfState = ifst
	b.maybePauseControlClientLocked()

	// If the PAC-ness of the network changed, reconfig wireguard+route to
	// add/remove subnets.
	if hadPAC != ifst.HasPAC() {
		b.logf("linkChange: in state %v; PAC changed from %v->%v", b.state, hadPAC, ifst.HasPAC())
		switch b.state {
		case ipn.NoState, ipn.Stopped:
			// Do nothing.
		default:
			go b.authReconfig()
		}
	}

	// If the local network configuration has changed, our filter may
	// need updating to tweak default routes.
	b.updateFilter(b.netMap, b.prefs)

	if peerAPIListenAsync && b.netMap != nil && b.state == ipn.Running {
		want := len(b.netMap.Addresses)
		if len(b.peerAPIListeners) < want {
			b.logf("linkChange: peerAPIListeners too low; trying again")
			go b.initPeerAPIListener()
		}
	}
}

func (b *LocalBackend) onHealthChange(sys health.Subsystem, err error) {
	if err == nil {
		b.logf("health(%q): ok", sys)
	} else {
		b.logf("health(%q): error: %v", sys, err)
	}
}

// Shutdown halts the backend and all its sub-components. The backend
// can no longer be used after Shutdown returns.
func (b *LocalBackend) Shutdown() {
	b.mu.Lock()
	cc := b.cc
	b.mu.Unlock()

	b.unregisterLinkMon()
	b.unregisterHealthWatch()
	if cc != nil {
		cc.Shutdown()
	}
	b.ctxCancel()
	b.e.Close()
	b.e.Wait()
}

// Prefs returns a copy of b's current prefs, with any private keys removed.
func (b *LocalBackend) Prefs() *ipn.Prefs {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.prefs.Clone()
	if p != nil && p.Persist != nil {
		p.Persist.LegacyFrontendPrivateMachineKey = key.MachinePrivate{}
		p.Persist.PrivateNodeKey = wgkey.Private{}
		p.Persist.OldPrivateNodeKey = wgkey.Private{}
	}
	return p
}

// Status returns the latest status of the backend and its
// sub-components.
func (b *LocalBackend) Status() *ipnstate.Status {
	sb := new(ipnstate.StatusBuilder)
	b.UpdateStatus(sb)
	return sb.Status()
}

// StatusWithoutPeers is like Status but omits any details
// of peers.
func (b *LocalBackend) StatusWithoutPeers() *ipnstate.Status {
	sb := new(ipnstate.StatusBuilder)
	b.updateStatus(sb, nil)
	return sb.Status()
}

// UpdateStatus implements ipnstate.StatusUpdater.
func (b *LocalBackend) UpdateStatus(sb *ipnstate.StatusBuilder) {
	b.e.UpdateStatus(sb)
	b.updateStatus(sb, b.populatePeerStatusLocked)
}

// updateStatus populates sb with status.
//
// extraLocked, if non-nil, is called while b.mu is still held.
func (b *LocalBackend) updateStatus(sb *ipnstate.StatusBuilder, extraLocked func(*ipnstate.StatusBuilder)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	sb.MutateStatus(func(s *ipnstate.Status) {
		s.Version = version.Long
		s.BackendState = b.state.String()
		s.AuthURL = b.authURLSticky

		if err := health.OverallError(); err != nil {
			switch e := err.(type) {
			case multierror.MultipleErrors:
				for _, err := range e {
					s.Health = append(s.Health, err.Error())
				}
			default:
				s.Health = append(s.Health, err.Error())
			}
		}
		if b.netMap != nil {
			s.MagicDNSSuffix = b.netMap.MagicDNSSuffix()
			s.CertDomains = append([]string(nil), b.netMap.DNS.CertDomains...)
		}
	})
	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
		if b.netMap != nil && b.netMap.SelfNode != nil {
			ss.ID = b.netMap.SelfNode.StableID
		}
		for _, pln := range b.peerAPIListeners {
			ss.PeerAPIURL = append(ss.PeerAPIURL, pln.urlStr)
		}
	})
	// TODO: hostinfo, and its networkinfo
	// TODO: EngineStatus copy (and deprecate it?)

	if extraLocked != nil {
		extraLocked(sb)
	}
}

func (b *LocalBackend) populatePeerStatusLocked(sb *ipnstate.StatusBuilder) {
	if b.netMap == nil {
		return
	}
	for id, up := range b.netMap.UserProfiles {
		sb.AddUser(id, up)
	}
	for _, p := range b.netMap.Peers {
		var lastSeen time.Time
		if p.LastSeen != nil {
			lastSeen = *p.LastSeen
		}
		var tailAddr4 string
		var tailscaleIPs = make([]netaddr.IP, 0, len(p.Addresses))
		for _, addr := range p.Addresses {
			if addr.IsSingleIP() && tsaddr.IsTailscaleIP(addr.IP()) {
				if addr.IP().Is4() && tailAddr4 == "" {
					// The peer struct previously only allowed a single
					// Tailscale IP address. For compatibility for a few releases starting
					// with 1.8, keep it pulled out as IPv4-only for a bit.
					tailAddr4 = addr.IP().String()
				}
				tailscaleIPs = append(tailscaleIPs, addr.IP())
			}
		}
		sb.AddPeer(key.Public(p.Key), &ipnstate.PeerStatus{
			InNetworkMap:       true,
			ID:                 p.StableID,
			UserID:             p.User,
			TailAddrDeprecated: tailAddr4,
			TailscaleIPs:       tailscaleIPs,
			HostName:           p.Hostinfo.Hostname,
			DNSName:            p.Name,
			OS:                 p.Hostinfo.OS,
			KeepAlive:          p.KeepAlive,
			Created:            p.Created,
			LastSeen:           lastSeen,
			ShareeNode:         p.Hostinfo.ShareeNode,
			ExitNode:           p.StableID != "" && p.StableID == b.prefs.ExitNodeID,
		})
	}
}

// WhoIs reports the node and user who owns the node with the given IP:port.
// If the IP address is a Tailscale IP, the provided port may be 0.
// If ok == true, n and u are valid.
func (b *LocalBackend) WhoIs(ipp netaddr.IPPort) (n *tailcfg.Node, u tailcfg.UserProfile, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok = b.nodeByAddr[ipp.IP()]
	if !ok {
		var ip netaddr.IP
		if ipp.Port() != 0 {
			ip, ok = b.e.WhoIsIPPort(ipp)
		}
		if !ok {
			return nil, u, false
		}
		n, ok = b.nodeByAddr[ip]
		if !ok {
			return nil, u, false
		}
	}
	u, ok = b.netMap.UserProfiles[n.User]
	if !ok {
		return nil, u, false
	}
	return n, u, true
}

// SetDecompressor sets a decompression function, which must be a zstd
// reader.
//
// This exists because the iOS/Mac NetworkExtension is very resource
// constrained, and the zstd package is too heavy to fit in the
// constrained RSS limit.
func (b *LocalBackend) SetDecompressor(fn func() (controlclient.Decompressor, error)) {
	b.newDecompressor = fn
}

// setClientStatus is the callback invoked by the control client whenever it posts a new status.
// Among other things, this is where we update the netmap, packet filters, DNS and DERP maps.
func (b *LocalBackend) setClientStatus(st controlclient.Status) {
	// The following do not depend on any data for which we need to lock b.
	if st.Err != "" {
		// TODO(crawshaw): display in the UI.
		if st.Err == "EOF" {
			b.logf("[v1] Received error: EOF")
		} else {
			b.logf("Received error: %v", st.Err)
		}
		return
	}

	b.mu.Lock()
	wasBlocked := b.blocked
	b.mu.Unlock()

	if st.LoginFinished != nil && wasBlocked {
		// Auth completed, unblock the engine
		b.blockEngineUpdates(false)
		b.authReconfig()
		b.send(ipn.Notify{LoginFinished: &empty.Message{}})
	}

	prefsChanged := false

	// Lock b once and do only the things that require locking.
	b.mu.Lock()

	if st.LogoutFinished != nil {
		// Since we're logged out now, our netmap cache is invalid.
		// Since st.NetMap==nil means "netmap is unchanged", there is
		// no other way to represent this change.
		b.setNetMapLocked(nil)
	}

	prefs := b.prefs
	stateKey := b.stateKey
	netMap := b.netMap
	interact := b.interact

	if prefs.ControlURL == "" {
		// Once we get a message from the control plane, set
		// our ControlURL pref explicitly. This causes a
		// future "tailscale up" to start checking for
		// implicit setting reverts, which it doesn't do when
		// ControlURL is blank.
		prefs.ControlURL = prefs.ControlURLOrDefault()
		prefsChanged = true
	}
	if st.Persist != nil {
		if !b.prefs.Persist.Equals(st.Persist) {
			prefsChanged = true
			b.prefs.Persist = st.Persist.Clone()
		}
	}
	if st.NetMap != nil {
		if b.findExitNodeIDLocked(st.NetMap) {
			prefsChanged = true
		}
		b.setNetMapLocked(st.NetMap)
	}
	if st.URL != "" {
		b.authURL = st.URL
		b.authURLSticky = st.URL
	}
	if wasBlocked && st.LoginFinished != nil {
		// Interactive login finished successfully (URL visited).
		// After an interactive login, the user always wants
		// WantRunning.
		if !b.prefs.WantRunning || b.prefs.LoggedOut {
			prefsChanged = true
		}
		b.prefs.WantRunning = true
		b.prefs.LoggedOut = false
	}
	// Prefs will be written out; this is not safe unless locked or cloned.
	if prefsChanged {
		prefs = b.prefs.Clone()
	}

	b.mu.Unlock()

	// Now complete the lock-free parts of what we started while locked.
	if prefsChanged {
		if stateKey != "" {
			if err := b.store.WriteState(stateKey, prefs.ToBytes()); err != nil {
				b.logf("Failed to save new controlclient state: %v", err)
			}
		}
		b.send(ipn.Notify{Prefs: prefs})
	}
	if st.NetMap != nil {
		if netMap != nil {
			diff := st.NetMap.ConciseDiffFrom(netMap)
			if strings.TrimSpace(diff) == "" {
				b.logf("[v1] netmap diff: (none)")
			} else {
				b.logf("netmap diff:\n%v", diff)
			}
		}

		b.updateFilter(st.NetMap, prefs)
		b.e.SetNetworkMap(st.NetMap)
		b.e.SetDERPMap(st.NetMap.DERPMap)

		b.send(ipn.Notify{NetMap: st.NetMap})
	}
	if st.URL != "" {
		b.logf("Received auth URL: %.20v...", st.URL)
		if interact {
			b.popBrowserAuthNow()
		}
	}
	b.stateMachine()
	// This is currently (2020-07-28) necessary; conditionally disabling it is fragile!
	// This is where netmap information gets propagated to router and magicsock.
	b.authReconfig()
}

// findExitNodeIDLocked updates b.prefs to reference an exit node by ID,
// rather than by IP. It returns whether prefs was mutated.
func (b *LocalBackend) findExitNodeIDLocked(nm *netmap.NetworkMap) (prefsChanged bool) {
	// If we have a desired IP on file, try to find the corresponding
	// node.
	if b.prefs.ExitNodeIP.IsZero() {
		return false
	}

	// IP takes precedence over ID, so if both are set, clear ID.
	if b.prefs.ExitNodeID != "" {
		b.prefs.ExitNodeID = ""
		prefsChanged = true
	}

	for _, peer := range nm.Peers {
		for _, addr := range peer.Addresses {
			if !addr.IsSingleIP() || addr.IP() != b.prefs.ExitNodeIP {
				continue
			}
			// Found the node being referenced, upgrade prefs to
			// reference it directly for next time.
			b.prefs.ExitNodeID = peer.StableID
			b.prefs.ExitNodeIP = netaddr.IP{}
			return true
		}
	}

	return false
}

// setWgengineStatus is the callback by the wireguard engine whenever it posts a new status.
// This updates the endpoints both in the backend and in the control client.
func (b *LocalBackend) setWgengineStatus(s *wgengine.Status, err error) {
	if err != nil {
		b.logf("wgengine status error: %v", err)
		b.broadcastStatusChanged()
		return
	}
	if s == nil {
		b.logf("[unexpected] non-error wgengine update with status=nil: %v", s)
		b.broadcastStatusChanged()
		return
	}

	b.mu.Lock()
	es := b.parseWgStatusLocked(s)
	cc := b.cc
	b.engineStatus = es
	needUpdateEndpoints := !endpointsEqual(s.LocalAddrs, b.endpoints)
	if needUpdateEndpoints {
		b.endpoints = append([]tailcfg.Endpoint{}, s.LocalAddrs...)
	}
	b.mu.Unlock()

	if cc != nil {
		if needUpdateEndpoints {
			cc.UpdateEndpoints(0, s.LocalAddrs)
		}
		b.stateMachine()
	}
	b.broadcastStatusChanged()
	b.send(ipn.Notify{Engine: &es})
}

func (b *LocalBackend) broadcastStatusChanged() {
	// The sync.Cond docs say: "It is allowed but not required for the caller to hold c.L during the call."
	// In this particular case, we must acquire b.statusLock. Otherwise we might broadcast before
	// the waiter (in requestEngineStatusAndWait) starts to wait, in which case
	// the waiter can get stuck indefinitely. See PR 2865.
	b.statusLock.Lock()
	b.statusChanged.Broadcast()
	b.statusLock.Unlock()
}

func endpointsEqual(x, y []tailcfg.Endpoint) bool {
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func (b *LocalBackend) SetNotifyCallback(notify func(ipn.Notify)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.notify = notify
}

// SetHTTPTestClient sets an alternate HTTP client to use with
// connections to the coordination server. It exists for
// testing. Using nil means to use the default.
func (b *LocalBackend) SetHTTPTestClient(c *http.Client) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.httpTestClient = c
}

// SetControlClientGetterForTesting sets the func that creates a
// control plane client. It can be called at most once, before Start.
func (b *LocalBackend) SetControlClientGetterForTesting(newControlClient func(controlclient.Options) (controlclient.Client, error)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ccGen != nil {
		panic("invalid use of SetControlClientGetterForTesting after Start")
	}
	b.ccGen = newControlClient
}

func (b *LocalBackend) getNewControlClientFunc() clientGen {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ccGen == nil {
		// Initialize it rather than just returning the
		// default to make any future call to
		// SetControlClientGetterForTesting panic.
		b.ccGen = func(opts controlclient.Options) (controlclient.Client, error) {
			return controlclient.New(opts)
		}
	}
	return b.ccGen
}

// startIsNoopLocked reports whether a Start call on this LocalBackend
// with the provided Start Options would be a useless no-op.
//
// TODO(apenwarr): we shouldn't need this.
//  The state machine is now nearly clean enough where it can accept a new
//  connection while in any state, not just Running, and on any platform.
//  We'd want to add a few more tests to state_test.go to ensure this continues
//  to work as expected.
//
// b.mu must be held.
func (b *LocalBackend) startIsNoopLocked(opts ipn.Options) bool {
	// Options has 5 fields; check all of them:
	//   * FrontendLogID
	//   * StateKey
	//   * Prefs
	//   * UpdatePrefs
	//   * AuthKey
	return b.state == ipn.Running &&
		b.hostinfo != nil &&
		b.hostinfo.FrontendLogID == opts.FrontendLogID &&
		b.stateKey == opts.StateKey &&
		opts.Prefs == nil &&
		opts.UpdatePrefs == nil &&
		opts.AuthKey == ""
}

// Start applies the configuration specified in opts, and starts the
// state machine.
//
// TODO(danderson): this function is trying to do too many things at
// once: it loads state, or imports it, or updates prefs sometimes,
// contains some settings that are one-shot things done by `tailscale
// up` because we had nowhere else to put them, and there's no clear
// guarantee that switching from one user's state to another is
// actually a supported operation (it should be, but it's very unclear
// from the following whether or not that is a safe transition).
func (b *LocalBackend) Start(opts ipn.Options) error {
	if opts.Prefs == nil && opts.StateKey == "" {
		return errors.New("no state key or prefs provided")
	}

	if opts.Prefs != nil {
		b.logf("Start: %v", opts.Prefs.Pretty())
	} else {
		b.logf("Start")
	}

	b.mu.Lock()

	// The iOS client sends a "Start" whenever its UI screen comes
	// up, just because it wants a netmap. That should be fixed,
	// but meanwhile we can make Start cheaper here for such a
	// case and not restart the world (which takes a few seconds).
	// Instead, just send a notify with the state that iOS needs.
	if b.startIsNoopLocked(opts) {
		b.logf("Start: already running; sending notify")
		nm := b.netMap
		state := b.state
		b.mu.Unlock()
		b.send(ipn.Notify{
			State:         &state,
			NetMap:        nm,
			Prefs:         b.prefs,
			LoginFinished: new(empty.Message),
		})
		return nil
	}

	hostinfo := hostinfo.New()
	hostinfo.BackendLogID = b.backendLogID
	hostinfo.FrontendLogID = opts.FrontendLogID

	if b.cc != nil {
		// TODO(apenwarr): avoid the need to reinit controlclient.
		// This will trigger a full relogin/reconfigure cycle every
		// time a Handle reconnects to the backend. Ideally, we
		// would send the new Prefs and everything would get back
		// into sync with the minimal changes. But that's not how it
		// is right now, which is a sign that the code is still too
		// complicated.
		b.mu.Unlock()
		b.cc.Shutdown()
		b.mu.Lock()
	}
	httpTestClient := b.httpTestClient

	if b.hostinfo != nil {
		hostinfo.Services = b.hostinfo.Services // keep any previous session and netinfo
		hostinfo.NetInfo = b.hostinfo.NetInfo
	}
	b.hostinfo = hostinfo
	b.state = ipn.NoState

	if err := b.loadStateLocked(opts.StateKey, opts.Prefs); err != nil {
		b.mu.Unlock()
		return fmt.Errorf("loading requested state: %v", err)
	}

	if opts.UpdatePrefs != nil {
		newPrefs := opts.UpdatePrefs
		newPrefs.Persist = b.prefs.Persist
		b.prefs = newPrefs

		if opts.StateKey != "" {
			if err := b.store.WriteState(opts.StateKey, b.prefs.ToBytes()); err != nil {
				b.logf("failed to save UpdatePrefs state: %v", err)
			}
		}
	}

	wantRunning := b.prefs.WantRunning
	if wantRunning {
		if err := b.initMachineKeyLocked(); err != nil {
			return fmt.Errorf("initMachineKeyLocked: %w", err)
		}
	}

	loggedOut := b.prefs.LoggedOut

	b.inServerMode = b.prefs.ForceDaemon
	b.serverURL = b.prefs.ControlURLOrDefault()
	if b.inServerMode || runtime.GOOS == "windows" {
		b.logf("Start: serverMode=%v", b.inServerMode)
	}
	applyPrefsToHostinfo(hostinfo, b.prefs)

	b.setNetMapLocked(nil)
	persistv := b.prefs.Persist
	b.mu.Unlock()

	b.updateFilter(nil, nil)

	if b.portpoll != nil {
		b.portpollOnce.Do(func() {
			go b.portpoll.Run(b.ctx)
			go b.readPoller()

			// Give the poller a second to get results to
			// prevent it from restarting our map poll
			// HTTP request (via doSetHostinfoFilterServices >
			// cli.SetHostinfo). In practice this is very quick.
			t0 := time.Now()
			timer := time.NewTimer(time.Second)
			select {
			case <-b.gotPortPollRes:
				b.logf("got initial portlist info in %v", time.Since(t0).Round(time.Millisecond))
				timer.Stop()
			case <-timer.C:
				b.logf("timeout waiting for initial portlist")
			}
		})
	}

	var discoPublic tailcfg.DiscoKey
	if controlclient.Debug.Disco {
		discoPublic = b.e.DiscoPublicKey()
	}

	var err error
	if persistv == nil {
		// let controlclient initialize it
		persistv = &persist.Persist{}
	}

	isNetstack := wgengine.IsNetstackRouter(b.e)
	debugFlags := controlDebugFlags
	if isNetstack {
		debugFlags = append([]string{"netstack"}, debugFlags...)
	}

	// TODO(apenwarr): The only way to change the ServerURL is to
	// re-run b.Start(), because this is the only place we create a
	// new controlclient. SetPrefs() allows you to overwrite ServerURL,
	// but it won't take effect until the next Start().
	cc, err := b.getNewControlClientFunc()(controlclient.Options{
		GetMachinePrivateKey: b.createGetMachinePrivateKeyFunc(),
		Logf:                 logger.WithPrefix(b.logf, "control: "),
		Persist:              *persistv,
		ServerURL:            b.serverURL,
		AuthKey:              opts.AuthKey,
		Hostinfo:             hostinfo,
		KeepAlive:            true,
		NewDecompressor:      b.newDecompressor,
		HTTPTestClient:       httpTestClient,
		DiscoPublicKey:       discoPublic,
		DebugFlags:           debugFlags,
		LinkMonitor:          b.e.GetLinkMonitor(),
		Pinger:               b.e,

		// Don't warn about broken Linux IP forwarding when
		// netstack is being used.
		SkipIPForwardingCheck: isNetstack,
	})
	if err != nil {
		return err
	}

	b.mu.Lock()
	b.cc = cc
	endpoints := b.endpoints
	b.mu.Unlock()

	if endpoints != nil {
		cc.UpdateEndpoints(0, endpoints)
	}

	cc.SetStatusFunc(b.setClientStatus)
	b.e.SetNetInfoCallback(b.setNetInfo)

	b.mu.Lock()
	prefs := b.prefs.Clone()
	b.mu.Unlock()

	blid := b.backendLogID
	b.logf("Backend: logs: be:%v fe:%v", blid, opts.FrontendLogID)
	b.send(ipn.Notify{BackendLogID: &blid})
	b.send(ipn.Notify{Prefs: prefs})

	if !loggedOut && b.hasNodeKey() {
		// Even if !WantRunning, we should verify our key, if there
		// is one. If you want tailscaled to be completely idle,
		// use logout instead.
		cc.Login(nil, controlclient.LoginDefault)
	}
	b.stateMachine()
	return nil
}

// updateFilter updates the packet filter in wgengine based on the
// given netMap and user preferences.
func (b *LocalBackend) updateFilter(netMap *netmap.NetworkMap, prefs *ipn.Prefs) {
	// NOTE(danderson): keep change detection as the first thing in
	// this function. Don't try to optimize by returning early, more
	// likely than not you'll just end up breaking the change
	// detection and end up with the wrong filter installed. This is
	// quite hard to debug, so save yourself the trouble.
	var (
		haveNetmap   = netMap != nil
		addrs        []netaddr.IPPrefix
		packetFilter []filter.Match
		localNetsB   netaddr.IPSetBuilder
		logNetsB     netaddr.IPSetBuilder
		shieldsUp    = prefs == nil || prefs.ShieldsUp // Be conservative when not ready
	)
	// Log traffic for Tailscale IPs.
	logNetsB.AddPrefix(tsaddr.CGNATRange())
	logNetsB.AddPrefix(tsaddr.TailscaleULARange())
	logNetsB.RemovePrefix(tsaddr.ChromeOSVMRange())
	if haveNetmap {
		addrs = netMap.Addresses
		for _, p := range addrs {
			localNetsB.AddPrefix(p)
		}
		packetFilter = netMap.PacketFilter
	}
	if prefs != nil {
		for _, r := range prefs.AdvertiseRoutes {
			if r.Bits() == 0 {
				// When offering a default route to the world, we
				// filter out locally reachable LANs, so that the
				// default route effectively appears to be a "guest
				// wifi": you get internet access, but to additionally
				// get LAN access the LAN(s) need to be offered
				// explicitly as well.
				s, err := shrinkDefaultRoute(r)
				if err != nil {
					b.logf("computing default route filter: %v", err)
					continue
				}
				localNetsB.AddSet(s)
			} else {
				localNetsB.AddPrefix(r)
				// When advertising a non-default route, we assume
				// this is a corporate subnet that should be present
				// in the audit logs.
				logNetsB.AddPrefix(r)
			}
		}
	}
	localNets, _ := localNetsB.IPSet()
	logNets, _ := logNetsB.IPSet()

	changed := deephash.Update(&b.filterHash, haveNetmap, addrs, packetFilter, localNets.Ranges(), logNets.Ranges(), shieldsUp)
	if !changed {
		return
	}

	if !haveNetmap {
		b.logf("netmap packet filter: (not ready yet)")
		b.e.SetFilter(filter.NewAllowNone(b.logf, logNets))
		return
	}

	oldFilter := b.e.GetFilter()
	if shieldsUp {
		b.logf("netmap packet filter: (shields up)")
		b.e.SetFilter(filter.NewShieldsUpFilter(localNets, logNets, oldFilter, b.logf))
	} else {
		b.logf("netmap packet filter: %v filters", len(packetFilter))
		b.e.SetFilter(filter.New(packetFilter, localNets, logNets, oldFilter, b.logf))
	}
}

var removeFromDefaultRoute = []netaddr.IPPrefix{
	// RFC1918 LAN ranges
	netaddr.MustParseIPPrefix("192.168.0.0/16"),
	netaddr.MustParseIPPrefix("172.16.0.0/12"),
	netaddr.MustParseIPPrefix("10.0.0.0/8"),
	// IPv4 link-local
	netaddr.MustParseIPPrefix("169.254.0.0/16"),
	// IPv4 multicast
	netaddr.MustParseIPPrefix("224.0.0.0/4"),
	// Tailscale IPv4 range
	tsaddr.CGNATRange(),
	// IPv6 Link-local addresses
	netaddr.MustParseIPPrefix("fe80::/10"),
	// IPv6 multicast
	netaddr.MustParseIPPrefix("ff00::/8"),
	// Tailscale IPv6 range
	tsaddr.TailscaleULARange(),
}

// internalAndExternalInterfaces splits interface routes into "internal"
// and "external" sets. Internal routes are those of virtual ethernet
// network interfaces used by guest VMs and containers, such as WSL and
// Docker.
//
// Given that "internal" routes don't leave the device, we choose to
// trust them more, allowing access to them when an Exit Node is enabled.
func internalAndExternalInterfaces() (internal, external []netaddr.IPPrefix, err error) {
	if err := interfaces.ForeachInterfaceAddress(func(iface interfaces.Interface, pfx netaddr.IPPrefix) {
		if tsaddr.IsTailscaleIP(pfx.IP()) {
			return
		}
		if pfx.IsSingleIP() {
			return
		}
		if runtime.GOOS == "windows" {
			// Windows Hyper-V prefixes all MAC addresses with 00:15:5d.
			// https://docs.microsoft.com/en-us/troubleshoot/windows-server/virtualization/default-limit-256-dynamic-mac-addresses
			//
			// This includes WSL2 vEthernet.
			// Importantly: by default WSL2 /etc/resolv.conf points to
			// a stub resolver running on the host vEthernet IP.
			// So enabling exit nodes with the default tailnet
			// configuration breaks WSL2 DNS without this.
			mac := iface.Interface.HardwareAddr
			if len(mac) == 6 && mac[0] == 0x00 && mac[1] == 0x15 && mac[2] == 0x5d {
				internal = append(internal, pfx)
				return
			}
		}
		external = append(external, pfx)
	}); err != nil {
		return nil, nil, err
	}

	return internal, external, nil
}

func interfaceRoutes() (ips *netaddr.IPSet, hostIPs []netaddr.IP, err error) {
	var b netaddr.IPSetBuilder
	if err := interfaces.ForeachInterfaceAddress(func(_ interfaces.Interface, pfx netaddr.IPPrefix) {
		if tsaddr.IsTailscaleIP(pfx.IP()) {
			return
		}
		if pfx.IsSingleIP() {
			return
		}
		hostIPs = append(hostIPs, pfx.IP())
		b.AddPrefix(pfx)
	}); err != nil {
		return nil, nil, err
	}

	ipSet, _ := b.IPSet()
	return ipSet, hostIPs, nil
}

// shrinkDefaultRoute returns an IPSet representing the IPs in route,
// minus those in removeFromDefaultRoute and local interface subnets.
func shrinkDefaultRoute(route netaddr.IPPrefix) (*netaddr.IPSet, error) {
	interfaceRoutes, hostIPs, err := interfaceRoutes()
	if err != nil {
		return nil, err
	}
	var b netaddr.IPSetBuilder
	// Add the default route.
	b.AddPrefix(route)
	// Remove the local interface routes.
	b.RemoveSet(interfaceRoutes)

	// Having removed all the LAN subnets, re-add the hosts's own
	// IPs. It's fine for clients to connect to an exit node's public
	// IP address, just not the attached subnet.
	//
	// Truly forbidden subnets (in removeFromDefaultRoute) will still
	// be stripped back out by the next step.
	for _, ip := range hostIPs {
		if route.Contains(ip) {
			b.Add(ip)
		}
	}

	for _, pfx := range removeFromDefaultRoute {
		b.RemovePrefix(pfx)
	}
	return b.IPSet()
}

// dnsCIDRsEqual determines whether two CIDR lists are equal
// for DNS map construction purposes (that is, only the first entry counts).
func dnsCIDRsEqual(newAddr, oldAddr []netaddr.IPPrefix) bool {
	if len(newAddr) != len(oldAddr) {
		return false
	}
	if len(newAddr) == 0 || newAddr[0] == oldAddr[0] {
		return true
	}
	return false
}

// dnsMapsEqual determines whether the new and the old network map
// induce the same DNS map. It does so without allocating memory,
// at the expense of giving false negatives if peers are reordered.
func dnsMapsEqual(new, old *netmap.NetworkMap) bool {
	if (old == nil) != (new == nil) {
		return false
	}
	if old == nil && new == nil {
		return true
	}

	if len(new.Peers) != len(old.Peers) {
		return false
	}

	if new.Name != old.Name {
		return false
	}
	if !dnsCIDRsEqual(new.Addresses, old.Addresses) {
		return false
	}

	for i, newPeer := range new.Peers {
		oldPeer := old.Peers[i]
		if newPeer.Name != oldPeer.Name {
			return false
		}
		if !dnsCIDRsEqual(newPeer.Addresses, oldPeer.Addresses) {
			return false
		}
	}

	return true
}

// readPoller is a goroutine that receives service lists from
// b.portpoll and propagates them into the controlclient's HostInfo.
func (b *LocalBackend) readPoller() {
	n := 0
	for {
		ports, ok := <-b.portpoll.C
		if !ok {
			return
		}
		sl := []tailcfg.Service{}
		for _, p := range ports {
			s := tailcfg.Service{
				Proto:       tailcfg.ServiceProto(p.Proto),
				Port:        p.Port,
				Description: p.Process,
			}
			if policy.IsInterestingService(s, version.OS()) {
				sl = append(sl, s)
			}
		}

		b.mu.Lock()
		if b.hostinfo == nil {
			b.hostinfo = new(tailcfg.Hostinfo)
		}
		b.hostinfo.Services = sl
		hi := b.hostinfo
		b.mu.Unlock()

		b.doSetHostinfoFilterServices(hi)

		n++
		if n == 1 {
			close(b.gotPortPollRes)
		}
	}
}

// send delivers n to the connected frontend. If no frontend is
// connected, the notification is dropped without being delivered.
func (b *LocalBackend) send(n ipn.Notify) {
	b.mu.Lock()
	notifyFunc := b.notify
	apiSrv := b.peerAPIServer
	b.mu.Unlock()

	if notifyFunc == nil {
		return
	}

	if apiSrv != nil && apiSrv.hasFilesWaiting() {
		n.FilesWaiting = &empty.Message{}
	}

	n.Version = version.Long
	notifyFunc(n)
}

func (b *LocalBackend) sendFileNotify() {
	var n ipn.Notify

	b.mu.Lock()
	notifyFunc := b.notify
	apiSrv := b.peerAPIServer
	if notifyFunc == nil || apiSrv == nil {
		b.mu.Unlock()
		return
	}

	// Make sure we always set n.IncomingFiles non-nil so it gets encoded
	// in JSON to clients. They distinguish between empty and non-nil
	// to know whether a Notify should be able about files.
	n.IncomingFiles = make([]ipn.PartialFile, 0)
	for f := range b.incomingFiles {
		n.IncomingFiles = append(n.IncomingFiles, f.PartialFile())
	}
	b.mu.Unlock()

	sort.Slice(n.IncomingFiles, func(i, j int) bool {
		return n.IncomingFiles[i].Started.Before(n.IncomingFiles[j].Started)
	})

	b.send(n)
}

// popBrowserAuthNow shuts down the data plane and sends an auth URL
// to the connected frontend, if any.
func (b *LocalBackend) popBrowserAuthNow() {
	b.mu.Lock()
	url := b.authURL
	b.interact = false
	b.authURL = "" // but NOT clearing authURLSticky
	b.mu.Unlock()

	b.logf("popBrowserAuthNow: url=%v", url != "")

	b.blockEngineUpdates(true)
	b.stopEngineAndWait()
	b.send(ipn.Notify{BrowseToURL: &url})
	if b.State() == ipn.Running {
		b.enterState(ipn.Starting)
	}
}

// For testing lazy machine key generation.
var panicOnMachineKeyGeneration, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_PANIC_MACHINE_KEY"))

func (b *LocalBackend) createGetMachinePrivateKeyFunc() func() (key.MachinePrivate, error) {
	var cache atomic.Value
	return func() (key.MachinePrivate, error) {
		if panicOnMachineKeyGeneration {
			panic("machine key generated")
		}
		if v, ok := cache.Load().(key.MachinePrivate); ok {
			return v, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if v, ok := cache.Load().(key.MachinePrivate); ok {
			return v, nil
		}
		if err := b.initMachineKeyLocked(); err != nil {
			return key.MachinePrivate{}, err
		}
		cache.Store(b.machinePrivKey)
		return b.machinePrivKey, nil
	}
}

// initMachineKeyLocked is called to initialize b.machinePrivKey.
//
// b.prefs must already be initialized.
// b.stateKey should be set too, but just for nicer log messages.
// b.mu must be held.
func (b *LocalBackend) initMachineKeyLocked() (err error) {
	if !b.machinePrivKey.IsZero() {
		// Already set.
		return nil
	}

	var legacyMachineKey key.MachinePrivate
	if b.prefs.Persist != nil {
		legacyMachineKey = b.prefs.Persist.LegacyFrontendPrivateMachineKey
	}

	keyText, err := b.store.ReadState(ipn.MachineKeyStateKey)
	if err == nil {
		if err := b.machinePrivKey.UnmarshalText(keyText); err != nil {
			return fmt.Errorf("invalid key in %s key of %v: %w", ipn.MachineKeyStateKey, b.store, err)
		}
		if b.machinePrivKey.IsZero() {
			return fmt.Errorf("invalid zero key stored in %v key of %v", ipn.MachineKeyStateKey, b.store)
		}
		if !legacyMachineKey.IsZero() && !legacyMachineKey.Equal(b.machinePrivKey) {
			b.logf("frontend-provided legacy machine key ignored; used value from server state")
		}
		return nil
	}
	if err != ipn.ErrStateNotExist {
		return fmt.Errorf("error reading %v key of %v: %w", ipn.MachineKeyStateKey, b.store, err)
	}

	// If we didn't find one already on disk and the prefs already
	// have a legacy machine key, use that. Otherwise generate a
	// new one.
	if !legacyMachineKey.IsZero() {
		if b.stateKey == "" {
			b.logf("using frontend-provided legacy machine key")
		} else {
			b.logf("using legacy machine key from state key %q", b.stateKey)
		}
		b.machinePrivKey = legacyMachineKey
	} else {
		b.logf("generating new machine key")
		b.machinePrivKey = key.NewMachine()
	}

	keyText, _ = b.machinePrivKey.MarshalText()
	if err := b.store.WriteState(ipn.MachineKeyStateKey, keyText); err != nil {
		b.logf("error writing machine key to store: %v", err)
		return err
	}

	b.logf("machine key written to store")
	return nil
}

// writeServerModeStartState stores the ServerModeStartKey value based on the current
// user and prefs. If userID is blank or prefs is blank, no work is done.
//
// b.mu may either be held or not.
func (b *LocalBackend) writeServerModeStartState(userID string, prefs *ipn.Prefs) {
	if userID == "" || prefs == nil {
		return
	}

	if prefs.ForceDaemon {
		stateKey := ipn.StateKey("user-" + userID)
		if err := b.store.WriteState(ipn.ServerModeStartKey, []byte(stateKey)); err != nil {
			b.logf("WriteState error: %v", err)
		}
		// It's important we do this here too, even if it looks
		// redundant with the one in the 'if stateKey != ""'
		// check block above. That one won't fire in the case
		// where the Windows client started up in client mode.
		// This happens when we transition into server mode:
		if err := b.store.WriteState(stateKey, prefs.ToBytes()); err != nil {
			b.logf("WriteState error: %v", err)
		}
	} else {
		if err := b.store.WriteState(ipn.ServerModeStartKey, nil); err != nil {
			b.logf("WriteState error: %v", err)
		}
	}
}

// loadStateLocked sets b.prefs and b.stateKey based on a complex
// combination of key, prefs, and legacyPath. b.mu must be held when
// calling.
func (b *LocalBackend) loadStateLocked(key ipn.StateKey, prefs *ipn.Prefs) (err error) {
	if prefs == nil && key == "" {
		panic("state key and prefs are both unset")
	}

	// Optimistically set stateKey (for initMachineKeyLocked's
	// logging), but revert it if we return an error so a later SetPrefs
	// call can't pick it up if it's bogus.
	b.stateKey = key
	defer func() {
		if err != nil {
			b.stateKey = ""
		}
	}()

	if key == "" {
		// Frontend owns the state, we just need to obey it.
		//
		// If the frontend (e.g. on Windows) supplied the
		// optional/legacy machine key then it's used as the
		// value instead of making up a new one.
		b.logf("using frontend prefs: %s", prefs.Pretty())
		b.prefs = prefs.Clone()
		b.writeServerModeStartState(b.userID, b.prefs)
		return nil
	}

	if prefs != nil {
		// Backend owns the state, but frontend is trying to migrate
		// state into the backend.
		b.logf("importing frontend prefs into backend store; frontend prefs: %s", prefs.Pretty())
		if err := b.store.WriteState(key, prefs.ToBytes()); err != nil {
			return fmt.Errorf("store.WriteState: %v", err)
		}
	}

	b.logf("using backend prefs")
	bs, err := b.store.ReadState(key)
	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		b.prefs = ipn.NewPrefs()
		b.prefs.WantRunning = false
		b.logf("created empty state for %q: %s", key, b.prefs.Pretty())
		return nil
	case err != nil:
		return fmt.Errorf("store.ReadState(%q): %v", key, err)
	}
	b.prefs, err = ipn.PrefsFromBytes(bs, false)
	if err != nil {
		return fmt.Errorf("PrefsFromBytes: %v", err)
	}

	// On mobile platforms, ignore any old stored preferences for
	// https://login.tailscale.com as the control server that
	// would override the new default of controlplane.tailscale.com.
	// This makes sure that mobile clients go through the new
	// frontends where we're (2021-10-02) doing battery
	// optimization work ahead of turning down the old backends.
	// TODO(bradfitz): make this the default for all platforms
	// later. But mobile is a relatively small chunk (compared to
	// Linux, Windows, macOS) and moving mobile early for battery
	// gains is nice.
	switch runtime.GOOS {
	case "android", "ios":
		if b.prefs != nil && b.prefs.ControlURL != "" &&
			b.prefs.ControlURL != ipn.DefaultControlURL &&
			ipn.IsLoginServerSynonym(b.prefs.ControlURL) {
			b.prefs.ControlURL = ""
		}
	}

	b.logf("backend prefs for %q: %s", key, b.prefs.Pretty())
	return nil
}

// State returns the backend state machine's current state.
func (b *LocalBackend) State() ipn.State {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.state
}

func (b *LocalBackend) InServerMode() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inServerMode
}

// Login implements Backend.
func (b *LocalBackend) Login(token *tailcfg.Oauth2Token) {
	b.mu.Lock()
	b.assertClientLocked()
	cc := b.cc
	b.mu.Unlock()

	cc.Login(token, controlclient.LoginInteractive)
}

// StartLoginInteractive implements Backend. It requests a new
// interactive login from controlclient, unless such a flow is already
// in progress, in which case StartLoginInteractive attempts to pick
// up the in-progress flow where it left off.
func (b *LocalBackend) StartLoginInteractive() {
	b.mu.Lock()
	b.assertClientLocked()
	b.interact = true
	url := b.authURL
	cc := b.cc
	b.mu.Unlock()
	b.logf("StartLoginInteractive: url=%v", url != "")

	if url != "" {
		b.popBrowserAuthNow()
	} else {
		cc.Login(nil, controlclient.LoginInteractive)
	}
}

// FakeExpireAfter implements Backend.
func (b *LocalBackend) FakeExpireAfter(x time.Duration) {
	b.logf("FakeExpireAfter: %v", x)

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.netMap == nil {
		return
	}

	// This function is called very rarely,
	// so we prefer to fully copy the netmap over introducing in-place modification here.
	mapCopy := *b.netMap
	e := mapCopy.Expiry
	if e.IsZero() || time.Until(e) > x {
		mapCopy.Expiry = time.Now().Add(x)
	}
	b.setNetMapLocked(&mapCopy)
	b.send(ipn.Notify{NetMap: b.netMap})
}

func (b *LocalBackend) Ping(ipStr string, useTSMP bool) {
	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		b.logf("ignoring Ping request to invalid IP %q", ipStr)
		return
	}
	b.e.Ping(ip, useTSMP, func(pr *ipnstate.PingResult) {
		b.send(ipn.Notify{PingResult: pr})
	})
}

// parseWgStatusLocked returns an EngineStatus based on s.
//
// b.mu must be held; mostly because the caller is about to anyway, and doing so
// gives us slightly better guarantees about the two peers stats lines not
// being intermixed if there are concurrent calls to our caller.
func (b *LocalBackend) parseWgStatusLocked(s *wgengine.Status) (ret ipn.EngineStatus) {
	var peerStats, peerKeys strings.Builder

	ret.LiveDERPs = s.DERPs
	ret.LivePeers = map[tailcfg.NodeKey]ipnstate.PeerStatusLite{}
	for _, p := range s.Peers {
		if !p.LastHandshake.IsZero() {
			fmt.Fprintf(&peerStats, "%d/%d ", p.RxBytes, p.TxBytes)
			fmt.Fprintf(&peerKeys, "%s ", p.NodeKey.ShortString())

			ret.NumLive++
			ret.LivePeers[p.NodeKey] = p

		}
		ret.RBytes += p.RxBytes
		ret.WBytes += p.TxBytes
	}

	// [GRINDER STATS LINES] - please don't remove (used for log parsing)
	if peerStats.Len() > 0 {
		b.keyLogf("[v1] peer keys: %s", strings.TrimSpace(peerKeys.String()))
		b.statsLogf("[v1] v%v peers: %v", version.Long, strings.TrimSpace(peerStats.String()))
	}
	return ret
}

// shouldUploadServices reports whether this node should include services
// in Hostinfo. When the user preferences currently request "shields up"
// mode, all inbound connections are refused, so services are not reported.
// Otherwise, shouldUploadServices respects NetMap.CollectServices.
func (b *LocalBackend) shouldUploadServices() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.prefs == nil || b.netMap == nil {
		return false // default to safest setting
	}
	return !b.prefs.ShieldsUp && b.netMap.CollectServices
}

func (b *LocalBackend) SetCurrentUserID(uid string) {
	b.mu.Lock()
	b.userID = uid
	b.mu.Unlock()
}

func (b *LocalBackend) EditPrefs(mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	b.mu.Lock()
	p0 := b.prefs.Clone()
	p1 := b.prefs.Clone()
	p1.ApplyEdits(mp)
	if p1.Equals(p0) {
		b.mu.Unlock()
		return p1, nil
	}
	b.logf("EditPrefs: %v", mp.Pretty())
	b.setPrefsLockedOnEntry("EditPrefs", p1) // does a b.mu.Unlock

	// Note: don't perform any actions for the new prefs here. Not
	// every prefs change goes through EditPrefs. Put your actions
	// in setPrefsLocksOnEntry instead.
	return p1, nil
}

// SetPrefs saves new user preferences and propagates them throughout
// the system. Implements Backend.
func (b *LocalBackend) SetPrefs(newp *ipn.Prefs) {
	if newp == nil {
		panic("SetPrefs got nil prefs")
	}
	b.mu.Lock()
	b.setPrefsLockedOnEntry("SetPrefs", newp)
}

// setPrefsLockedOnEntry requires b.mu be held to call it, but it
// unlocks b.mu when done.
func (b *LocalBackend) setPrefsLockedOnEntry(caller string, newp *ipn.Prefs) {
	netMap := b.netMap
	stateKey := b.stateKey

	oldp := b.prefs
	newp.Persist = oldp.Persist // caller isn't allowed to override this
	b.prefs = newp
	b.inServerMode = newp.ForceDaemon
	// We do this to avoid holding the lock while doing everything else.
	newp = b.prefs.Clone()

	oldHi := b.hostinfo
	newHi := oldHi.Clone()
	applyPrefsToHostinfo(newHi, newp)
	b.hostinfo = newHi
	hostInfoChanged := !oldHi.Equal(newHi)
	userID := b.userID
	cc := b.cc

	b.mu.Unlock()

	if stateKey != "" {
		if err := b.store.WriteState(stateKey, newp.ToBytes()); err != nil {
			b.logf("failed to save new controlclient state: %v", err)
		}
	}
	b.writeServerModeStartState(userID, newp)

	// [GRINDER STATS LINE] - please don't remove (used for log parsing)
	if caller == "SetPrefs" {
		b.logf("SetPrefs: %v", newp.Pretty())
	}
	if netMap != nil {
		if login := netMap.UserProfiles[netMap.User].LoginName; login != "" {
			if newp.Persist == nil {
				b.logf("active login: %s", login)
			} else if newp.Persist.LoginName != login {
				// Corp issue 461: sometimes the wrong prefs are
				// logged; the frontend isn't always getting
				// notified (to update its prefs/persist) on
				// account switch.  Log this while we figure it
				// out.
				b.logf("active login: %s ([unexpected] corp#461, not %s)", newp.Persist.LoginName)
			}
		}
	}

	if oldp.ShieldsUp != newp.ShieldsUp || hostInfoChanged {
		b.doSetHostinfoFilterServices(newHi)
	}

	b.updateFilter(netMap, newp)

	if netMap != nil {
		b.e.SetDERPMap(netMap.DERPMap)
	}

	if !oldp.WantRunning && newp.WantRunning {
		b.logf("transitioning to running; doing Login...")
		cc.Login(nil, controlclient.LoginDefault)
	}

	if oldp.WantRunning != newp.WantRunning {
		b.stateMachine()
	} else {
		b.authReconfig()
	}

	b.send(ipn.Notify{Prefs: newp})
}

func (b *LocalBackend) getPeerAPIPortForTSMPPing(ip netaddr.IP) (port uint16, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, pln := range b.peerAPIListeners {
		if pln.ip == ip {
			return uint16(pln.port), true
		}
	}
	return 0, false
}

func (b *LocalBackend) peerAPIServicesLocked() (ret []tailcfg.Service) {
	for _, pln := range b.peerAPIListeners {
		proto := tailcfg.ServiceProto("peerapi4")
		if pln.ip.Is6() {
			proto = "peerapi6"
		}
		ret = append(ret, tailcfg.Service{
			Proto: proto,
			Port:  uint16(pln.port),
		})
	}
	return ret
}

// doSetHostinfoFilterServices calls SetHostinfo on the controlclient,
// possibly after mangling the given hostinfo.
//
// TODO(danderson): we shouldn't be mangling hostinfo here after
// painstakingly constructing it in twelvety other places.
func (b *LocalBackend) doSetHostinfoFilterServices(hi *tailcfg.Hostinfo) {
	if hi == nil {
		b.logf("[unexpected] doSetHostinfoFilterServices with nil hostinfo")
		return
	}
	b.mu.Lock()
	cc := b.cc
	if cc == nil {
		// Control client isn't up yet.
		b.mu.Unlock()
		return
	}
	peerAPIServices := b.peerAPIServicesLocked()
	b.mu.Unlock()

	// Make a shallow copy of hostinfo so we can mutate
	// at the Service field.
	hi2 := *hi // shallow copy
	if !b.shouldUploadServices() {
		hi2.Services = []tailcfg.Service{}
	}
	// Don't mutate hi.Service's underlying array. Append to
	// the slice with no free capacity.
	c := len(hi2.Services)
	hi2.Services = append(hi2.Services[:c:c], peerAPIServices...)
	cc.SetHostinfo(&hi2)
}

// NetMap returns the latest cached network map received from
// controlclient, or nil if no network map was received yet.
func (b *LocalBackend) NetMap() *netmap.NetworkMap {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.netMap
}

// blockEngineUpdate sets b.blocked to block, while holding b.mu. Its
// indirect effect is to turn b.authReconfig() into a no-op if block
// is true.
func (b *LocalBackend) blockEngineUpdates(block bool) {
	b.logf("blockEngineUpdates(%v)", block)

	b.mu.Lock()
	b.blocked = block
	b.mu.Unlock()
}

// authReconfig pushes a new configuration into wgengine, if engine
// updates are not currently blocked, based on the cached netmap and
// user prefs.
func (b *LocalBackend) authReconfig() {
	b.mu.Lock()
	blocked := b.blocked
	prefs := b.prefs
	nm := b.netMap
	hasPAC := b.prevIfState.HasPAC()
	disableSubnetsIfPAC := nm != nil && nm.Debug != nil && nm.Debug.DisableSubnetsIfPAC.EqualBool(true)
	b.mu.Unlock()

	if blocked {
		b.logf("authReconfig: blocked, skipping.")
		return
	}
	if nm == nil {
		b.logf("authReconfig: netmap not yet valid. Skipping.")
		return
	}
	if !prefs.WantRunning {
		b.logf("authReconfig: skipping because !WantRunning.")
		return
	}

	var flags netmap.WGConfigFlags
	if prefs.RouteAll {
		flags |= netmap.AllowSubnetRoutes
	}
	if prefs.AllowSingleHosts {
		flags |= netmap.AllowSingleHosts
	}
	if hasPAC && disableSubnetsIfPAC {
		if flags&netmap.AllowSubnetRoutes != 0 {
			b.logf("authReconfig: have PAC; disabling subnet routes")
			flags &^= netmap.AllowSubnetRoutes
		}
	}

	cfg, err := nmcfg.WGCfg(nm, b.logf, flags, prefs.ExitNodeID)
	if err != nil {
		b.logf("wgcfg: %v", err)
		return
	}

	rcfg := b.routerConfig(cfg, prefs)
	dcfg := dnsConfigForNetmap(nm, prefs, b.logf, version.OS())

	err = b.e.Reconfig(cfg, rcfg, dcfg, nm.Debug)
	if err == wgengine.ErrNoChanges {
		return
	}
	b.logf("[v1] authReconfig: ra=%v dns=%v 0x%02x: %v", prefs.RouteAll, prefs.CorpDNS, flags, err)

	b.initPeerAPIListener()
}

// dnsConfigForNetmap returns a *dns.Config for the given netmap,
// prefs, and client OS version.
//
// The versionOS is a Tailscale-style version ("iOS", "macOS") and not
// a runtime.GOOS.
func dnsConfigForNetmap(nm *netmap.NetworkMap, prefs *ipn.Prefs, logf logger.Logf, versionOS string) *dns.Config {
	dcfg := &dns.Config{
		Routes: map[dnsname.FQDN][]dnstype.Resolver{},
		Hosts:  map[dnsname.FQDN][]netaddr.IP{},
	}

	// selfV6Only is whether we only have IPv6 addresses ourselves.
	selfV6Only := tsaddr.PrefixesContainsFunc(nm.Addresses, tsaddr.PrefixIs6) &&
		!tsaddr.PrefixesContainsFunc(nm.Addresses, tsaddr.PrefixIs4)

	// Populate MagicDNS records. We do this unconditionally so that
	// quad-100 can always respond to MagicDNS queries, even if the OS
	// isn't configured to make MagicDNS resolution truly
	// magic. Details in
	// https://github.com/tailscale/tailscale/issues/1886.
	set := func(name string, addrs []netaddr.IPPrefix) {
		if len(addrs) == 0 || name == "" {
			return
		}
		fqdn, err := dnsname.ToFQDN(name)
		if err != nil {
			return // TODO: propagate error?
		}
		have4 := tsaddr.PrefixesContainsFunc(addrs, tsaddr.PrefixIs4)
		var ips []netaddr.IP
		for _, addr := range addrs {
			if selfV6Only {
				if addr.IP().Is6() {
					ips = append(ips, addr.IP())
				}
				continue
			}
			// If this node has an IPv4 address, then
			// remove peers' IPv6 addresses for now, as we
			// don't guarantee that the peer node actually
			// can speak IPv6 correctly.
			//
			// https://github.com/tailscale/tailscale/issues/1152
			// tracks adding the right capability reporting to
			// enable AAAA in MagicDNS.
			if addr.IP().Is6() && have4 {
				continue
			}
			ips = append(ips, addr.IP())
		}
		dcfg.Hosts[fqdn] = ips
	}
	set(nm.Name, nm.Addresses)
	for _, peer := range nm.Peers {
		set(peer.Name, peer.Addresses)
	}
	for _, rec := range nm.DNS.ExtraRecords {
		switch rec.Type {
		case "", "A", "AAAA":
			// Treat these all the same for now: infer from the value
		default:
			// TODO: more
			continue
		}
		ip, err := netaddr.ParseIP(rec.Value)
		if err != nil {
			// Ignore.
			continue
		}
		fqdn, err := dnsname.ToFQDN(rec.Name)
		if err != nil {
			continue
		}
		dcfg.Hosts[fqdn] = append(dcfg.Hosts[fqdn], ip)
	}

	if !prefs.CorpDNS {
		return dcfg
	}

	addDefault := func(resolvers []dnstype.Resolver) {
		for _, r := range resolvers {
			dcfg.DefaultResolvers = append(dcfg.DefaultResolvers, normalizeResolver(r))
		}
	}

	addDefault(nm.DNS.Resolvers)
	for suffix, resolvers := range nm.DNS.Routes {
		fqdn, err := dnsname.ToFQDN(suffix)
		if err != nil {
			logf("[unexpected] non-FQDN route suffix %q", suffix)
		}

		// Create map entry even if len(resolvers) == 0; Issue 2706.
		// This lets the control plane send ExtraRecords for which we
		// can authoritatively answer "name not exists" for when the
		// control plane also sends this explicit but empty route
		// making it as something we handle.
		//
		// While we're already populating it, might as well size the
		// slice appropriately.
		dcfg.Routes[fqdn] = make([]dnstype.Resolver, 0, len(resolvers))

		for _, r := range resolvers {
			dcfg.Routes[fqdn] = append(dcfg.Routes[fqdn], normalizeResolver(r))
		}
	}
	for _, dom := range nm.DNS.Domains {
		fqdn, err := dnsname.ToFQDN(dom)
		if err != nil {
			logf("[unexpected] non-FQDN search domain %q", dom)
		}
		dcfg.SearchDomains = append(dcfg.SearchDomains, fqdn)
	}
	if nm.DNS.Proxied { // actually means "enable MagicDNS"
		for _, dom := range magicDNSRootDomains(nm) {
			dcfg.Routes[dom] = nil // resolve internally with dcfg.Hosts
		}
	}

	// Set FallbackResolvers as the default resolvers in the
	// scenarios that can't handle a purely split-DNS config. See
	// https://github.com/tailscale/tailscale/issues/1743 for
	// details.
	switch {
	case len(dcfg.DefaultResolvers) != 0:
		// Default resolvers already set.
	case !prefs.ExitNodeID.IsZero():
		// When using exit nodes, it's very likely the LAN
		// resolvers will become unreachable. So, force use of the
		// fallback resolvers until we implement DNS forwarding to
		// exit nodes.
		//
		// This is especially important on Apple OSes, where
		// adding the default route to the tunnel interface makes
		// it "primary", and we MUST provide VPN-sourced DNS
		// settings or we break all DNS resolution.
		//
		// https://github.com/tailscale/tailscale/issues/1713
		addDefault(nm.DNS.FallbackResolvers)
	case len(dcfg.Routes) == 0:
		// No settings requiring split DNS, no problem.
	case versionOS == "android":
		// We don't support split DNS at all on Android yet.
		addDefault(nm.DNS.FallbackResolvers)
	}

	return dcfg
}

func normalizeResolver(cfg dnstype.Resolver) dnstype.Resolver {
	if ip, err := netaddr.ParseIP(cfg.Addr); err == nil {
		// Add 53 here for bare IPs for consistency with previous data type.
		return dnstype.Resolver{
			Addr: netaddr.IPPortFrom(ip, 53).String(),
		}
	}
	return cfg
}

// TailscaleVarRoot returns the root directory of Tailscale's writable
// storage area. (e.g. "/var/lib/tailscale")
//
// It returns an empty string if there's no configured or discovered
// location.
func (b *LocalBackend) TailscaleVarRoot() string {
	switch runtime.GOOS {
	case "ios", "android":
		dir, _ := paths.AppSharedDir.Load().(string)
		return dir
	}
	// Temporary (2021-09-27) transitional fix for #2927 (Synology
	// cert dir) on the way towards a more complete fix
	// (#2932). It fixes any case where the state file is provided
	// to tailscaled explicitly when it's not in the default
	// location.
	if fs, ok := b.store.(*ipn.FileStore); ok {
		if fp := fs.Path(); fp != "" {
			if dir := filepath.Dir(fp); strings.EqualFold(filepath.Base(dir), "tailscale") {
				return dir
			}
		}
	}
	stateFile := paths.DefaultTailscaledStateFile()
	if stateFile == "" {
		return ""
	}
	return filepath.Dir(stateFile)
}

func (b *LocalBackend) fileRootLocked(uid tailcfg.UserID) string {
	if v := b.directFileRoot; v != "" {
		return v
	}
	varRoot := b.TailscaleVarRoot()
	if varRoot == "" {
		b.logf("peerapi disabled; no state directory")
		return ""
	}
	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(b.activeLogin, "@", "-"),
		uid)
	dir := filepath.Join(varRoot, "files", baseDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		b.logf("peerapi disabled; error making directory: %v", err)
		return ""
	}
	return dir
}

// closePeerAPIListenersLocked closes any existing peer API listeners
// and clears out the peer API server state.
//
// It does not kick off any Hostinfo update with new services.
//
// b.mu must be held.
func (b *LocalBackend) closePeerAPIListenersLocked() {
	b.peerAPIServer = nil
	for _, pln := range b.peerAPIListeners {
		pln.Close()
	}
	b.peerAPIListeners = nil
}

// peerAPIListenAsync is whether the operating system requires that we
// retry listening on the peerAPI ip/port for whatever reason.
//
// On Windows, see Issue 1620.
// On Android, see Issue 1960.
const peerAPIListenAsync = runtime.GOOS == "windows" || runtime.GOOS == "android"

func (b *LocalBackend) initPeerAPIListener() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.netMap == nil {
		// We're called from authReconfig which checks that
		// netMap is non-nil, but if a concurrent Logout,
		// ResetForClientDisconnect, or Start happens when its
		// mutex was released, the netMap could be
		// nil'ed out (Issue 1996). Bail out early here if so.
		return
	}

	if len(b.netMap.Addresses) == len(b.peerAPIListeners) {
		allSame := true
		for i, pln := range b.peerAPIListeners {
			if pln.ip != b.netMap.Addresses[i].IP() {
				allSame = false
				break
			}
		}
		if allSame {
			// Nothing to do.
			return
		}
	}

	b.closePeerAPIListenersLocked()

	selfNode := b.netMap.SelfNode
	if len(b.netMap.Addresses) == 0 || selfNode == nil {
		return
	}

	fileRoot := b.fileRootLocked(selfNode.User)
	if fileRoot == "" {
		return
	}

	var tunName string
	if ge, ok := b.e.(wgengine.InternalsGetter); ok {
		if tunWrap, _, ok := ge.GetInternals(); ok {
			tunName, _ = tunWrap.Name()
		}
	}

	ps := &peerAPIServer{
		b:              b,
		rootDir:        fileRoot,
		tunName:        tunName,
		selfNode:       selfNode,
		directFileMode: b.directFileRoot != "",
	}
	b.peerAPIServer = ps

	isNetstack := wgengine.IsNetstack(b.e)
	for i, a := range b.netMap.Addresses {
		var ln net.Listener
		var err error
		skipListen := i > 0 && isNetstack
		if !skipListen {
			ln, err = ps.listen(a.IP(), b.prevIfState)
			if err != nil {
				if peerAPIListenAsync {
					// Expected. But we fix it later in linkChange
					// ("peerAPIListeners too low").
					continue
				}
				b.logf("[unexpected] peerapi listen(%q) error: %v", a.IP(), err)
				continue
			}
		}
		pln := &peerAPIListener{
			ps: ps,
			ip: a.IP(),
			ln: ln, // nil for 2nd+ on netstack
			lb: b,
		}
		if skipListen {
			pln.port = b.peerAPIListeners[0].port
		} else {
			pln.port = ln.Addr().(*net.TCPAddr).Port
		}
		pln.urlStr = "http://" + net.JoinHostPort(a.IP().String(), strconv.Itoa(pln.port))
		b.logf("peerapi: serving on %s", pln.urlStr)
		go pln.serve()
		b.peerAPIListeners = append(b.peerAPIListeners, pln)
	}

	go b.doSetHostinfoFilterServices(b.hostinfo.Clone())
}

// magicDNSRootDomains returns the subset of nm.DNS.Domains that are the search domains for MagicDNS.
func magicDNSRootDomains(nm *netmap.NetworkMap) []dnsname.FQDN {
	if v := nm.MagicDNSSuffix(); v != "" {
		fqdn, err := dnsname.ToFQDN(v)
		if err != nil {
			// TODO: propagate error
			return nil
		}
		ret := []dnsname.FQDN{
			fqdn,
			dnsname.FQDN("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."),
		}
		for i := 64; i <= 127; i++ {
			fqdn, err = dnsname.ToFQDN(fmt.Sprintf("%d.100.in-addr.arpa.", i))
			if err != nil {
				// TODO: propagate error
				continue
			}
			ret = append(ret, fqdn)
		}
		return ret
	}
	return nil
}

var (
	ipv4Default = netaddr.MustParseIPPrefix("0.0.0.0/0")
	ipv6Default = netaddr.MustParseIPPrefix("::/0")
)

// peerRoutes returns the routerConfig.Routes to access peers.
// If there are over cgnatThreshold CGNAT routes, one big CGNAT route
// is used instead.
func peerRoutes(peers []wgcfg.Peer, cgnatThreshold int) (routes []netaddr.IPPrefix) {
	tsULA := tsaddr.TailscaleULARange()
	cgNAT := tsaddr.CGNATRange()
	var didULA bool
	var cgNATIPs []netaddr.IPPrefix
	for _, peer := range peers {
		for _, aip := range peer.AllowedIPs {
			aip = unmapIPPrefix(aip)
			// Only add the Tailscale IPv6 ULA once, if we see anybody using part of it.
			if aip.IP().Is6() && aip.IsSingleIP() && tsULA.Contains(aip.IP()) {
				if !didULA {
					didULA = true
					routes = append(routes, tsULA)
				}
				continue
			}
			if aip.IsSingleIP() && cgNAT.Contains(aip.IP()) {
				cgNATIPs = append(cgNATIPs, aip)
			} else {
				routes = append(routes, aip)
			}
		}
	}
	if len(cgNATIPs) > cgnatThreshold {
		// Probably the hello server. Just append one big route.
		routes = append(routes, cgNAT)
	} else {
		routes = append(routes, cgNATIPs...)
	}
	return routes
}

// routerConfig produces a router.Config from a wireguard config and IPN prefs.
func (b *LocalBackend) routerConfig(cfg *wgcfg.Config, prefs *ipn.Prefs) *router.Config {
	rs := &router.Config{
		LocalAddrs:       unmapIPPrefixes(cfg.Addresses),
		SubnetRoutes:     unmapIPPrefixes(prefs.AdvertiseRoutes),
		SNATSubnetRoutes: !prefs.NoSNAT,
		NetfilterMode:    prefs.NetfilterMode,
		Routes:           peerRoutes(cfg.Peers, 10_000),
	}

	if distro.Get() == distro.Synology {
		// Issue 1995: we don't use iptables on Synology.
		rs.NetfilterMode = preftype.NetfilterOff
	}

	// Sanity check: we expect the control server to program both a v4
	// and a v6 default route, if default routing is on. Fill in
	// blackhole routes appropriately if we're missing some. This is
	// likely to break some functionality, but if the user expressed a
	// preference for routing remotely, we want to avoid leaking
	// traffic at the expense of functionality.
	if prefs.ExitNodeID != "" || !prefs.ExitNodeIP.IsZero() {
		var default4, default6 bool
		for _, route := range rs.Routes {
			switch route {
			case ipv4Default:
				default4 = true
			case ipv6Default:
				default6 = true
			}
			if default4 && default6 {
				break
			}
		}
		if !default4 {
			rs.Routes = append(rs.Routes, ipv4Default)
		}
		if !default6 {
			rs.Routes = append(rs.Routes, ipv6Default)
		}
		internalIPs, externalIPs, err := internalAndExternalInterfaces()
		if err != nil {
			b.logf("failed to discover interface ips: %v", err)
		}
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			rs.LocalRoutes = internalIPs // unconditionally allow access to guest VM networks
			if prefs.ExitNodeAllowLANAccess {
				rs.LocalRoutes = append(rs.LocalRoutes, externalIPs...)
				if len(externalIPs) != 0 {
					b.logf("allowing exit node access to internal IPs: %v", internalIPs)
				}
			} else {
				// Explicitly add routes to the local network so that we do not
				// leak any traffic.
				rs.Routes = append(rs.Routes, externalIPs...)
			}
		}
	}

	rs.Routes = append(rs.Routes, netaddr.IPPrefixFrom(tsaddr.TailscaleServiceIP(), 32))

	return rs
}

func unmapIPPrefix(ipp netaddr.IPPrefix) netaddr.IPPrefix {
	return netaddr.IPPrefixFrom(ipp.IP().Unmap(), ipp.Bits())
}

func unmapIPPrefixes(ippsList ...[]netaddr.IPPrefix) (ret []netaddr.IPPrefix) {
	for _, ipps := range ippsList {
		for _, ipp := range ipps {
			ret = append(ret, unmapIPPrefix(ipp))
		}
	}
	return ret
}

func applyPrefsToHostinfo(hi *tailcfg.Hostinfo, prefs *ipn.Prefs) {
	if h := prefs.Hostname; h != "" {
		hi.Hostname = h
	}
	if v := prefs.OSVersion; v != "" && hi.OSVersion == "" {
		hi.OSVersion = v
	}
	if m := prefs.DeviceModel; m != "" && hi.DeviceModel == "" {
		hi.DeviceModel = m
	}
	hi.RoutableIPs = append(prefs.AdvertiseRoutes[:0:0], prefs.AdvertiseRoutes...)
	hi.RequestTags = append(prefs.AdvertiseTags[:0:0], prefs.AdvertiseTags...)
	hi.ShieldsUp = prefs.ShieldsUp
}

// enterState transitions the backend into newState, updating internal
// state and propagating events out as needed.
//
// TODO(danderson): while this isn't a lie, exactly, a ton of other
// places twiddle IPN internal state without going through here, so
// really this is more "one of several places in which random things
// happen".
func (b *LocalBackend) enterState(newState ipn.State) {
	b.mu.Lock()
	oldState := b.state
	b.state = newState
	prefs := b.prefs
	netMap := b.netMap
	activeLogin := b.activeLogin
	authURL := b.authURL
	if newState == ipn.Running {
		b.authURL = ""
		b.authURLSticky = ""
	} else if oldState == ipn.Running {
		// Transitioning away from running.
		b.closePeerAPIListenersLocked()
	}
	b.maybePauseControlClientLocked()
	b.mu.Unlock()

	if oldState == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)",
		oldState, newState, prefs.WantRunning, netMap != nil)
	health.SetIPNState(newState.String(), prefs.WantRunning)
	b.send(ipn.Notify{State: &newState})

	switch newState {
	case ipn.NeedsLogin:
		systemd.Status("Needs login: %s", authURL)
		b.blockEngineUpdates(true)
		fallthrough
	case ipn.Stopped:
		err := b.e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{}, nil)
		if err != nil {
			b.logf("Reconfig(down): %v", err)
		}

		if authURL == "" {
			systemd.Status("Stopped; run 'tailscale up' to log in")
		}
	case ipn.Starting, ipn.NeedsMachineAuth:
		b.authReconfig()
		// Needed so that UpdateEndpoints can run
		b.e.RequestStatus()
	case ipn.Running:
		var addrs []string
		for _, addr := range netMap.Addresses {
			addrs = append(addrs, addr.IP().String())
		}
		systemd.Status("Connected; %s; %s", activeLogin, strings.Join(addrs, " "))
	default:
		b.logf("[unexpected] unknown newState %#v", newState)
	}

}

func (b *LocalBackend) hasNodeKey() bool {
	// we can't use b.Prefs(), because it strips the keys, oops!
	b.mu.Lock()
	p := b.prefs
	b.mu.Unlock()

	return p.Persist != nil && !p.Persist.PrivateNodeKey.IsZero()
}

// nextState returns the state the backend seems to be in, based on
// its internal state.
func (b *LocalBackend) nextState() ipn.State {
	b.mu.Lock()
	b.assertClientLocked()
	var (
		cc          = b.cc
		netMap      = b.netMap
		state       = b.state
		blocked     = b.blocked
		wantRunning = b.prefs.WantRunning
		loggedOut   = b.prefs.LoggedOut
		st          = b.engineStatus
	)
	b.mu.Unlock()

	switch {
	case !wantRunning && !loggedOut && !blocked && b.hasNodeKey():
		return ipn.Stopped
	case netMap == nil:
		if cc.AuthCantContinue() || loggedOut {
			// Auth was interrupted or waiting for URL visit,
			// so it won't proceed without human help.
			return ipn.NeedsLogin
		}
		switch state {
		case ipn.Stopped:
			// If we were already in the Stopped state, then
			// we can assume auth is in good shape (or we would
			// have been in NeedsLogin), so transition to Starting
			// right away.
			return ipn.Starting
		case ipn.NoState:
			// Our first time connecting to control, and we
			// don't know if we'll NeedsLogin or not yet.
			// UIs should print "Loading..." in this state.
			return ipn.NoState
		case ipn.Starting, ipn.Running, ipn.NeedsLogin:
			return state
		default:
			b.logf("unexpected no-netmap state transition for %v", state)
			return state
		}
	case !wantRunning:
		return ipn.Stopped
	case !netMap.Expiry.IsZero() && time.Until(netMap.Expiry) <= 0:
		return ipn.NeedsLogin
	case netMap.MachineStatus != tailcfg.MachineAuthorized:
		// TODO(crawshaw): handle tailcfg.MachineInvalid
		return ipn.NeedsMachineAuth
	case state == ipn.NeedsMachineAuth:
		// (if we get here, we know MachineAuthorized == true)
		return ipn.Starting
	case state == ipn.Starting:
		if st.NumLive > 0 || st.LiveDERPs > 0 {
			return ipn.Running
		} else {
			return state
		}
	case state == ipn.Running:
		return ipn.Running
	default:
		return ipn.Starting
	}
}

// RequestEngineStatus implements Backend.
func (b *LocalBackend) RequestEngineStatus() {
	b.e.RequestStatus()
}

// stateMachine updates the state machine state based on other things
// that have happened. It is invoked from the various callbacks that
// feed events into LocalBackend.
//
// TODO(apenwarr): use a channel or something to prevent re-entrancy?
//  Or maybe just call the state machine from fewer places.
func (b *LocalBackend) stateMachine() {
	b.enterState(b.nextState())
}

// stopEngineAndWait deconfigures the local network data plane, and
// waits for it to deliver a status update before returning.
//
// TODO(danderson): this may be racy. We could unblock upon receiving
// a status update that predates the "I've shut down" update.
func (b *LocalBackend) stopEngineAndWait() {
	b.logf("stopEngineAndWait...")
	b.e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{}, nil)
	b.requestEngineStatusAndWait()
	b.logf("stopEngineAndWait: done.")
}

// Requests the wgengine status, and does not return until the status
// was delivered (to the usual callback).
func (b *LocalBackend) requestEngineStatusAndWait() {
	b.logf("requestEngineStatusAndWait")

	b.statusLock.Lock()
	go b.e.RequestStatus()
	b.logf("requestEngineStatusAndWait: waiting...")
	b.statusChanged.Wait() // temporarily releases lock while waiting
	b.logf("requestEngineStatusAndWait: got status update.")
	b.statusLock.Unlock()
}

// ResetForClientDisconnect resets the backend for GUI clients running
// in interactive (non-headless) mode. This is currently used only by
// Windows. This causes all state to be cleared, lest an unrelated user
// connect to tailscaled next. But it does not trigger a logout; we
// don't want to the user to have to reauthenticate in the future
// when they restart the GUI.
func (b *LocalBackend) ResetForClientDisconnect() {
	defer b.enterState(ipn.Stopped)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.logf("LocalBackend.ResetForClientDisconnect")

	if b.cc != nil {
		go b.cc.Shutdown()
		b.cc = nil
	}
	b.stateKey = ""
	b.userID = ""
	b.setNetMapLocked(nil)
	b.prefs = new(ipn.Prefs)
	b.authURL = ""
	b.authURLSticky = ""
	b.activeLogin = ""
}

// Logout tells the controlclient that we want to log out, and
// transitions the local engine to the logged-out state without
// waiting for controlclient to be in that state.
func (b *LocalBackend) Logout() {
	b.logout(context.Background(), false)
}

func (b *LocalBackend) LogoutSync(ctx context.Context) error {
	return b.logout(ctx, true)
}

func (b *LocalBackend) logout(ctx context.Context, sync bool) error {
	b.mu.Lock()
	cc := b.cc
	b.mu.Unlock()

	b.EditPrefs(&ipn.MaskedPrefs{
		WantRunningSet: true,
		LoggedOutSet:   true,
		Prefs:          ipn.Prefs{WantRunning: false, LoggedOut: true},
	})

	if cc == nil {
		// Double Logout can happen via repeated IPN
		// connections to ipnserver making it repeatedly
		// transition from 1->0 total connections, which on
		// Windows by default ("client mode") causes a Logout
		// on the transition to zero.
		// Previously this crashed when we asserted that c was non-nil
		// here.
		return errors.New("no controlclient")
	}

	var err error
	if sync {
		err = cc.Logout(ctx)
	} else {
		cc.StartLogout()
	}

	b.stateMachine()
	return err
}

// assertClientLocked crashes if there is no controlclient in this backend.
func (b *LocalBackend) assertClientLocked() {
	if b.cc == nil {
		panic("LocalBackend.assertClient: b.cc == nil")
	}
}

// setNetInfo sets b.hostinfo.NetInfo to ni, and passes ni along to the
// controlclient, if one exists.
func (b *LocalBackend) setNetInfo(ni *tailcfg.NetInfo) {
	b.mu.Lock()
	cc := b.cc
	if b.hostinfo != nil {
		b.hostinfo.NetInfo = ni.Clone()
	}
	b.mu.Unlock()

	if cc == nil {
		return
	}
	cc.SetNetInfo(ni)
}

func hasCapability(nm *netmap.NetworkMap, cap string) bool {
	if nm != nil && nm.SelfNode != nil {
		for _, c := range nm.SelfNode.Capabilities {
			if c == cap {
				return true
			}
		}
	}
	return false
}

func (b *LocalBackend) setNetMapLocked(nm *netmap.NetworkMap) {
	var login string
	if nm != nil {
		login = nm.UserProfiles[nm.User].LoginName
		if login == "" {
			login = "<missing-profile>"
		}
	}
	b.netMap = nm
	if login != b.activeLogin {
		b.logf("active login: %v", login)
		b.activeLogin = login
	}
	b.maybePauseControlClientLocked()

	if nm != nil {
		health.SetControlHealth(nm.ControlHealth)
	} else {
		health.SetControlHealth(nil)
	}

	// Determine if file sharing is enabled
	fs := hasCapability(nm, tailcfg.CapabilityFileSharing)
	if fs != b.capFileSharing {
		osshare.SetFileSharingEnabled(fs, b.logf)
	}
	b.capFileSharing = fs

	if nm == nil {
		b.nodeByAddr = nil
		return
	}

	// Update the nodeByAddr index.
	if b.nodeByAddr == nil {
		b.nodeByAddr = map[netaddr.IP]*tailcfg.Node{}
	}
	// First pass, mark everything unwanted.
	for k := range b.nodeByAddr {
		b.nodeByAddr[k] = nil
	}
	addNode := func(n *tailcfg.Node) {
		for _, ipp := range n.Addresses {
			if ipp.IsSingleIP() {
				b.nodeByAddr[ipp.IP()] = n
			}
		}
	}
	if nm.SelfNode != nil {
		addNode(nm.SelfNode)
	}
	for _, p := range nm.Peers {
		addNode(p)
	}
	// Third pass, actually delete the unwanted items.
	for k, v := range b.nodeByAddr {
		if v == nil {
			delete(b.nodeByAddr, k)
		}
	}
}

// OperatorUserID returns the current pref's OperatorUser's ID (in
// os/user.User.Uid string form), or the empty string if none.
func (b *LocalBackend) OperatorUserID() string {
	b.mu.Lock()
	if b.prefs == nil {
		b.mu.Unlock()
		return ""
	}
	opUserName := b.prefs.OperatorUser
	b.mu.Unlock()
	if opUserName == "" {
		return ""
	}
	u, err := user.Lookup(opUserName)
	if err != nil {
		b.logf("error looking up operator %q uid: %v", opUserName, err)
		return ""
	}
	return u.Uid
}

// TestOnlyPublicKeys returns the current machine and node public
// keys. Used in tests only to facilitate automated node authorization
// in the test harness.
func (b *LocalBackend) TestOnlyPublicKeys() (machineKey key.MachinePublic, nodeKey tailcfg.NodeKey) {
	b.mu.Lock()
	prefs := b.prefs
	machinePrivKey := b.machinePrivKey
	b.mu.Unlock()

	if prefs == nil || machinePrivKey.IsZero() {
		return
	}

	mk := machinePrivKey.Public()
	nk := prefs.Persist.PrivateNodeKey.Public()
	return mk, tailcfg.NodeKey(nk)
}

func (b *LocalBackend) WaitingFiles() ([]apitype.WaitingFile, error) {
	b.mu.Lock()
	apiSrv := b.peerAPIServer
	b.mu.Unlock()
	if apiSrv == nil {
		return nil, errors.New("peerapi disabled")
	}
	return apiSrv.WaitingFiles()
}

func (b *LocalBackend) DeleteFile(name string) error {
	b.mu.Lock()
	apiSrv := b.peerAPIServer
	b.mu.Unlock()
	if apiSrv == nil {
		return errors.New("peerapi disabled")
	}
	return apiSrv.DeleteFile(name)
}

func (b *LocalBackend) OpenFile(name string) (rc io.ReadCloser, size int64, err error) {
	b.mu.Lock()
	apiSrv := b.peerAPIServer
	b.mu.Unlock()
	if apiSrv == nil {
		return nil, 0, errors.New("peerapi disabled")
	}
	return apiSrv.OpenFile(name)
}

// hasCapFileSharing reports whether the current node has the file
// sharing capability enabled.
func (b *LocalBackend) hasCapFileSharing() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.capFileSharing
}

// FileTargets lists nodes that the current node can send files to.
func (b *LocalBackend) FileTargets() ([]*apitype.FileTarget, error) {
	var ret []*apitype.FileTarget

	b.mu.Lock()
	defer b.mu.Unlock()
	nm := b.netMap
	if b.state != ipn.Running || nm == nil {
		return nil, errors.New("not connected")
	}
	if !b.capFileSharing {
		return nil, errors.New("file sharing not enabled by Tailscale admin")
	}
	for _, p := range nm.Peers {
		if p.User != nm.User {
			continue
		}
		peerAPI := peerAPIBase(b.netMap, p)
		if peerAPI == "" {
			continue

		}
		ret = append(ret, &apitype.FileTarget{
			Node:       p,
			PeerAPIURL: peerAPI,
		})
	}
	// TODO: sort a different way than the netmap already is?
	return ret, nil
}

// SetDNS adds a DNS record for the given domain name & TXT record
// value.
//
// It's meant for use with dns-01 ACME (LetsEncrypt) challenges.
//
// This is the low-level interface. Other layers will provide more
// friendly options to get HTTPS certs.
func (b *LocalBackend) SetDNS(ctx context.Context, name, value string) error {
	req := &tailcfg.SetDNSRequest{
		Version: 1,
		Type:    "TXT",
		Name:    name,
		Value:   value,
	}

	b.mu.Lock()
	cc := b.cc
	if prefs := b.prefs; prefs != nil {
		req.NodeKey = tailcfg.NodeKey(prefs.Persist.PrivateNodeKey.Public())
	}
	b.mu.Unlock()
	if cc == nil {
		return errors.New("not connected")
	}
	if req.NodeKey.IsZero() {
		return errors.New("no nodekey")
	}
	if name == "" {
		return errors.New("missing 'name'")
	}
	if value == "" {
		return errors.New("missing 'value'")
	}
	return cc.SetDNS(ctx, req)
}

func (b *LocalBackend) registerIncomingFile(inf *incomingFile, active bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.incomingFiles == nil {
		b.incomingFiles = make(map[*incomingFile]bool)
	}
	if active {
		b.incomingFiles[inf] = true
	} else {
		delete(b.incomingFiles, inf)
	}
}

// peerAPIBase returns the "http://ip:port" URL base to reach peer's peerAPI.
// It returns the empty string if the peer doesn't support the peerapi
// or there's no matching address family based on the netmap's own addresses.
func peerAPIBase(nm *netmap.NetworkMap, peer *tailcfg.Node) string {
	if nm == nil || peer == nil {
		return ""
	}
	var have4, have6 bool
	for _, a := range nm.Addresses {
		if !a.IsSingleIP() {
			continue
		}
		switch {
		case a.IP().Is4():
			have4 = true
		case a.IP().Is6():
			have6 = true
		}
	}
	var p4, p6 uint16
	for _, s := range peer.Hostinfo.Services {
		switch s.Proto {
		case "peerapi4":
			p4 = s.Port
		case "peerapi6":
			p6 = s.Port
		}
	}
	var ipp netaddr.IPPort
	switch {
	case have4 && p4 != 0:
		ipp = netaddr.IPPortFrom(nodeIP(peer, netaddr.IP.Is4), p4)
	case have6 && p6 != 0:
		ipp = netaddr.IPPortFrom(nodeIP(peer, netaddr.IP.Is6), p6)
	}
	if ipp.IP().IsZero() {
		return ""
	}
	return fmt.Sprintf("http://%v", ipp)
}

func nodeIP(n *tailcfg.Node, pred func(netaddr.IP) bool) netaddr.IP {
	for _, a := range n.Addresses {
		if a.IsSingleIP() && pred(a.IP()) {
			return a.IP()
		}
	}
	return netaddr.IP{}
}

func isBSD(s string) bool {
	return s == "dragonfly" || s == "freebsd" || s == "netbsd" || s == "openbsd"
}

func (b *LocalBackend) CheckIPForwarding() error {
	if wgengine.IsNetstackRouter(b.e) {
		return nil
	}
	if isBSD(runtime.GOOS) {
		return fmt.Errorf("Subnet routing and exit nodes only work with additional manual configuration on %v, and is not currently officially supported.", runtime.GOOS)
	}

	var keys []string

	if runtime.GOOS == "linux" {
		keys = append(keys, "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding")
	} else if isBSD(runtime.GOOS) {
		keys = append(keys, "net.inet.ip.forwarding")
	} else {
		return nil
	}

	const suffix = "\nSubnet routes won't work without IP forwarding.\nSee https://tailscale.com/kb/1104/enable-ip-forwarding/"
	for _, key := range keys {
		bs, err := exec.Command("sysctl", "-n", key).Output()
		if err != nil {
			return fmt.Errorf("couldn't check %s (%v)%s", key, err, suffix)
		}
		on, err := strconv.ParseBool(string(bytes.TrimSpace(bs)))
		if err != nil {
			return fmt.Errorf("couldn't parse %s (%v)%s.", key, err, suffix)
		}
		if !on {
			return fmt.Errorf("%s is disabled.%s", key, suffix)
		}
	}
	return nil
}

// peerDialControlFunc is non-nil on platforms that require a way to
// bind to dial out to other peers.
var peerDialControlFunc func(*LocalBackend) func(network, address string, c syscall.RawConn) error

// PeerDialControlFunc returns a net.Dialer.Control func (possibly nil) to use to
// dial other Tailscale peers from the current environment.
func (b *LocalBackend) PeerDialControlFunc() func(network, address string, c syscall.RawConn) error {
	if peerDialControlFunc != nil {
		return peerDialControlFunc(b)
	}
	return nil
}

// DERPMap returns the current DERPMap in use, or nil if not connected.
func (b *LocalBackend) DERPMap() *tailcfg.DERPMap {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.netMap == nil {
		return nil
	}
	return b.netMap.DERPMap
}
