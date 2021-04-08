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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/internal/deepprint"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/policy"
	"tailscale.com/net/dns"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/tsaddr"
	"tailscale.com/paths"
	"tailscale.com/portlist"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/systemd"
	"tailscale.com/version"
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

	filterHash string

	// The mutex protects the following elements.
	mu             sync.Mutex
	httpTestClient *http.Client // for controlclient. nil by default, used by tests.
	notify         func(ipn.Notify)
	cc             *controlclient.Client
	stateKey       ipn.StateKey // computed in part from user-provided value
	userID         string       // current controlling user ID (for Windows, primarily)
	prefs          *ipn.Prefs
	inServerMode   bool
	machinePrivKey wgkey.Private
	state          ipn.State
	// hostinfo is mutated in-place while mu is held.
	hostinfo *tailcfg.Hostinfo
	// netMap is not mutated in-place once set.
	netMap           *netmap.NetworkMap
	nodeByAddr       map[netaddr.IP]*tailcfg.Node
	activeLogin      string // last logged LoginName from netMap
	engineStatus     ipn.EngineStatus
	endpoints        []string
	blocked          bool
	authURL          string
	interact         bool
	prevIfState      *interfaces.State
	peerAPIServer    *peerAPIServer // or nil
	peerAPIListeners []*peerAPIListener

	// statusLock must be held before calling statusChanged.Wait() or
	// statusChanged.Broadcast().
	statusLock    sync.Mutex
	statusChanged *sync.Cond
}

// NewLocalBackend returns a new LocalBackend that is ready to run,
// but is not actually running.
func NewLocalBackend(logf logger.Logf, logid string, store ipn.StateStore, e wgengine.Engine) (*LocalBackend, error) {
	if e == nil {
		panic("ipn.NewLocalBackend: wgengine must not be nil")
	}

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

// linkChange is our link monitor callback, called whenever the network changes.
// major is whether ifst is different than earlier.
func (b *LocalBackend) linkChange(major bool, ifst *interfaces.State) {
	b.mu.Lock()
	defer b.mu.Unlock()

	hadPAC := b.prevIfState.HasPAC()
	b.prevIfState = ifst

	networkUp := ifst.AnyInterfaceUp()
	if b.cc != nil {
		go b.cc.SetPaused(b.state == ipn.Stopped || !networkUp)
	}

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

	if runtime.GOOS == "windows" && b.netMap != nil {
		want := len(b.netMap.Addresses)
		b.logf("linkChange: peerAPIListeners too low; trying again")
		if len(b.peerAPIListeners) < want {
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
		p.Persist.LegacyFrontendPrivateMachineKey = wgkey.Private{}
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
		s.AuthURL = b.authURL
		if b.netMap != nil {
			s.MagicDNSSuffix = b.netMap.MagicDNSSuffix()
		}
	})
	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
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
		var tailAddr string
		for _, addr := range p.Addresses {
			// The peer struct currently only allows a single
			// Tailscale IP address. For compatibility with the
			// old display, make sure it's the IPv4 address.
			if addr.IP.Is4() && addr.IsSingleIP() && tsaddr.IsTailscaleIP(addr.IP) {
				tailAddr = addr.IP.String()
				break
			}
		}
		sb.AddPeer(key.Public(p.Key), &ipnstate.PeerStatus{
			InNetworkMap: true,
			UserID:       p.User,
			TailAddr:     tailAddr,
			HostName:     p.Hostinfo.Hostname,
			DNSName:      p.Name,
			OS:           p.Hostinfo.OS,
			KeepAlive:    p.KeepAlive,
			Created:      p.Created,
			LastSeen:     lastSeen,
			ShareeNode:   p.Hostinfo.ShareeNode,
			ExitNode:     p.StableID != "" && p.StableID == b.prefs.ExitNodeID,
		})
	}
}

// WhoIs reports the node and user who owns the node with the given IP:port.
// If the IP address is a Tailscale IP, the provided port may be 0.
// If ok == true, n and u are valid.
func (b *LocalBackend) WhoIs(ipp netaddr.IPPort) (n *tailcfg.Node, u tailcfg.UserProfile, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok = b.nodeByAddr[ipp.IP]
	if !ok {
		var ip netaddr.IP
		if ipp.Port != 0 {
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
	if st.LoginFinished != nil {
		// Auth completed, unblock the engine
		b.blockEngineUpdates(false)
		b.authReconfig()
		b.send(ipn.Notify{LoginFinished: &empty.Message{}})
	}

	prefsChanged := false

	// Lock b once and do only the things that require locking.
	b.mu.Lock()

	prefs := b.prefs
	stateKey := b.stateKey
	netMap := b.netMap
	interact := b.interact

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
	}
	if b.state == ipn.NeedsLogin {
		if !b.prefs.WantRunning {
			prefsChanged = true
		}
		b.prefs.WantRunning = true
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
			if !addr.IsSingleIP() || addr.IP != b.prefs.ExitNodeIP {
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
		return
	}
	if s == nil {
		b.logf("[unexpected] non-error wgengine update with status=nil: %v", s)
		return
	}

	b.mu.Lock()
	es := b.parseWgStatusLocked(s)
	cc := b.cc
	b.engineStatus = es
	b.endpoints = append([]string{}, s.LocalAddrs...)
	b.mu.Unlock()

	if cc != nil {
		cc.UpdateEndpoints(0, s.LocalAddrs)
	}
	b.stateMachine()

	b.statusLock.Lock()
	b.statusChanged.Broadcast()
	b.statusLock.Unlock()

	b.send(ipn.Notify{Engine: &es})
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

	hostinfo := controlclient.NewHostinfo()
	hostinfo.BackendLogID = b.backendLogID
	hostinfo.FrontendLogID = opts.FrontendLogID

	b.mu.Lock()

	if b.cc != nil {
		// TODO(apenwarr): avoid the need to reinit controlclient.
		// This will trigger a full relogin/reconfigure cycle every
		// time a Handle reconnects to the backend. Ideally, we
		// would send the new Prefs and everything would get back
		// into sync with the minimal changes. But that's not how it
		// is right now, which is a sign that the code is still too
		// complicated.
		b.cc.Shutdown()
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

	wantRunning := b.prefs.WantRunning
	if wantRunning {
		if err := b.initMachineKeyLocked(); err != nil {
			return fmt.Errorf("initMachineKeyLocked: %w", err)
		}
	}

	b.inServerMode = b.prefs.ForceDaemon
	b.serverURL = b.prefs.ControlURL
	hostinfo.RoutableIPs = append(hostinfo.RoutableIPs, b.prefs.AdvertiseRoutes...)
	hostinfo.RequestTags = append(hostinfo.RequestTags, b.prefs.AdvertiseTags...)
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
	cc, err := controlclient.New(controlclient.Options{
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
		DebugFlags:           controlDebugFlags,
		LinkMonitor:          b.e.GetLinkMonitor(),

		// Don't warn about broken Linux IP forwading when
		// netstack is being used.
		SkipIPForwardingCheck: wgengine.IsNetstackRouter(b.e),
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
	b.e.SetStatusCallback(b.setWgengineStatus)
	b.e.SetNetInfoCallback(b.setNetInfo)

	b.mu.Lock()
	prefs := b.prefs.Clone()
	b.mu.Unlock()

	blid := b.backendLogID
	b.logf("Backend: logs: be:%v fe:%v", blid, opts.FrontendLogID)
	b.send(ipn.Notify{BackendLogID: &blid})
	b.send(ipn.Notify{Prefs: prefs})

	if wantRunning {
		cc.Login(nil, controlclient.LoginDefault)
	}
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
			if r.Bits == 0 {
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
	localNets := localNetsB.IPSet()
	logNets := logNetsB.IPSet()

	changed := deepprint.UpdateHash(&b.filterHash, haveNetmap, addrs, packetFilter, localNets.Ranges(), logNets.Ranges(), shieldsUp)
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
		b.logf("netmap packet filter: %v", packetFilter)
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

// shrinkDefaultRoute returns an IPSet representing the IPs in route,
// minus those in removeFromDefaultRoute and local interface subnets.
func shrinkDefaultRoute(route netaddr.IPPrefix) (*netaddr.IPSet, error) {
	var b netaddr.IPSetBuilder
	b.AddPrefix(route)
	var hostIPs []netaddr.IP
	err := interfaces.ForeachInterfaceAddress(func(_ interfaces.Interface, pfx netaddr.IPPrefix) {
		if tsaddr.IsTailscaleIP(pfx.IP) {
			return
		}
		if pfx.IsSingleIP() {
			return
		}
		hostIPs = append(hostIPs, pfx.IP)
		b.RemovePrefix(pfx)
	})
	if err != nil {
		return nil, err
	}

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
	return b.IPSet(), nil
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
		b.logf("nil notify callback; dropping %+v", n)
		return
	}

	n.Version = version.Long
	if apiSrv != nil && apiSrv.hasFilesWaiting() {
		n.FilesWaiting = &empty.Message{}
	}
	notifyFunc(n)
}

// popBrowserAuthNow shuts down the data plane and sends an auth URL
// to the connected frontend, if any.
func (b *LocalBackend) popBrowserAuthNow() {
	b.mu.Lock()
	url := b.authURL
	b.interact = false
	b.authURL = ""
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

func (b *LocalBackend) createGetMachinePrivateKeyFunc() func() (wgkey.Private, error) {
	var cache atomic.Value
	return func() (wgkey.Private, error) {
		if panicOnMachineKeyGeneration {
			panic("machine key generated")
		}
		if v, ok := cache.Load().(wgkey.Private); ok {
			return v, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if v, ok := cache.Load().(wgkey.Private); ok {
			return v, nil
		}
		if err := b.initMachineKeyLocked(); err != nil {
			return wgkey.Private{}, err
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

	var legacyMachineKey wgkey.Private
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
		if !legacyMachineKey.IsZero() && !bytes.Equal(legacyMachineKey[:], b.machinePrivKey[:]) {
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
		var err error
		b.machinePrivKey, err = wgkey.NewPrivate()
		if err != nil {
			return fmt.Errorf("initializing new machine key: %w", err)
		}
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

// getEngineStatus returns a copy of b.engineStatus.
//
// TODO(bradfitz): remove this and use Status() throughout.
func (b *LocalBackend) getEngineStatus() ipn.EngineStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.engineStatus
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

func (b *LocalBackend) EditPrefs(mp *ipn.MaskedPrefs) {
	b.mu.Lock()
	p0 := b.prefs.Clone()
	p1 := b.prefs.Clone()
	p1.ApplyEdits(mp)
	if p1.Equals(p0) {
		b.mu.Unlock()
		return
	}
	b.logf("EditPrefs: %v", mp.Pretty())
	b.setPrefsLockedOnEntry("EditPrefs", p1)
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
	newHi.RoutableIPs = append([]netaddr.IPPrefix(nil), b.prefs.AdvertiseRoutes...)
	applyPrefsToHostinfo(newHi, newp)
	b.hostinfo = newHi
	hostInfoChanged := !oldHi.Equal(newHi)
	userID := b.userID

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
	uc := b.prefs
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
	if !uc.WantRunning {
		b.logf("authReconfig: skipping because !WantRunning.")
		return
	}

	var flags netmap.WGConfigFlags
	if uc.RouteAll {
		flags |= netmap.AllowSubnetRoutes
	}
	if uc.AllowSingleHosts {
		flags |= netmap.AllowSingleHosts
	}
	if hasPAC && disableSubnetsIfPAC {
		if flags&netmap.AllowSubnetRoutes != 0 {
			b.logf("authReconfig: have PAC; disabling subnet routes")
			flags &^= netmap.AllowSubnetRoutes
		}
	}

	cfg, err := nmcfg.WGCfg(nm, b.logf, flags, uc.ExitNodeID)
	if err != nil {
		b.logf("wgcfg: %v", err)
		return
	}

	rcfg := routerConfig(cfg, uc)

	var dcfg dns.Config

	// If CorpDNS is false, dcfg remains the zero value.
	if uc.CorpDNS {
		for _, resolver := range nm.DNS.Resolvers {
			res, err := parseResolver(resolver)
			if err != nil {
				b.logf(err.Error())
				continue
			}
			dcfg.DefaultResolvers = append(dcfg.DefaultResolvers, res)
		}
		if len(nm.DNS.Routes) > 0 {
			dcfg.Routes = map[string][]netaddr.IPPort{}
		}
		for suffix, resolvers := range nm.DNS.Routes {
			if !strings.HasSuffix(suffix, ".") || strings.HasPrefix(suffix, ".") {
				b.logf("[unexpected] malformed DNS route suffix %q", suffix)
				continue
			}
			for _, resolver := range resolvers {
				res, err := parseResolver(resolver)
				if err != nil {
					b.logf(err.Error())
					continue
				}
				dcfg.Routes[suffix] = append(dcfg.Routes[suffix], res)
			}
		}
		dcfg.SearchDomains = nm.DNS.Domains
		dcfg.AuthoritativeSuffixes = magicDNSRootDomains(nm)
		set := func(name string, addrs []netaddr.IPPrefix) {
			if len(addrs) == 0 || name == "" {
				return
			}
			var ips []netaddr.IP
			for _, addr := range addrs {
				ips = append(ips, addr.IP)
			}
			dcfg.Hosts[name] = ips
		}
		if nm.DNS.Proxied { // actually means "enable MagicDNS"
			dcfg.Hosts = map[string][]netaddr.IP{}
			set(nm.Name, nm.Addresses)
			for _, peer := range nm.Peers {
				set(peer.Name, peer.Addresses)
			}
		}
	}

	err = b.e.Reconfig(cfg, rcfg, &dcfg)
	if err == wgengine.ErrNoChanges {
		return
	}
	b.logf("[v1] authReconfig: ra=%v dns=%v 0x%02x: %v", uc.RouteAll, uc.CorpDNS, flags, err)

	b.initPeerAPIListener()
}

func parseResolver(cfg tailcfg.DNSResolver) (netaddr.IPPort, error) {
	ip, err := netaddr.ParseIP(cfg.Addr)
	if err != nil {
		return netaddr.IPPort{}, fmt.Errorf("[unexpected] non-IP resolver %q", cfg.Addr)
	}
	return netaddr.IPPort{
		IP:   ip,
		Port: 53,
	}, nil
}

// tailscaleVarRoot returns the root directory of Tailscale's writable
// storage area. (e.g. "/var/lib/tailscale")
func tailscaleVarRoot() string {
	if runtime.GOOS == "ios" {
		dir, _ := paths.IOSSharedDir.Load().(string)
		return dir
	}
	stateFile := paths.DefaultTailscaledStateFile()
	if stateFile == "" {
		return ""
	}
	return filepath.Dir(stateFile)
}

func (b *LocalBackend) initPeerAPIListener() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.peerAPIServer = nil
	for _, pln := range b.peerAPIListeners {
		pln.Close()
	}
	b.peerAPIListeners = nil

	selfNode := b.netMap.SelfNode
	if len(b.netMap.Addresses) == 0 || selfNode == nil {
		return
	}

	varRoot := tailscaleVarRoot()
	if varRoot == "" {
		b.logf("peerapi disabled; no state directory")
		return
	}
	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(b.activeLogin, "@", "-"),
		selfNode.User)
	dir := filepath.Join(varRoot, "files", baseDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		b.logf("peerapi disabled; error making directory: %v", err)
		return
	}

	var tunName string
	if ge, ok := b.e.(wgengine.InternalsGetter); ok {
		if tunWrap, _, ok := ge.GetInternals(); ok {
			tunName, _ = tunWrap.Name()
		}
	}

	ps := &peerAPIServer{
		b:        b,
		rootDir:  dir,
		tunName:  tunName,
		selfNode: selfNode,
	}
	b.peerAPIServer = ps

	isNetstack := wgengine.IsNetstack(b.e)
	for i, a := range b.netMap.Addresses {
		var ln net.Listener
		var err error
		skipListen := i > 0 && isNetstack
		if !skipListen {
			ln, err = ps.listen(a.IP, b.prevIfState)
			if err != nil {
				b.logf("[unexpected] peerapi listen(%q) error: %v", a.IP, err)
				continue
			}
		}
		pln := &peerAPIListener{
			ps: ps,
			ip: a.IP,
			ln: ln, // nil for 2nd+ on netstack
			lb: b,
		}
		if skipListen {
			pln.port = b.peerAPIListeners[0].port
		} else {
			pln.port = ln.Addr().(*net.TCPAddr).Port
		}
		pln.urlStr = "http://" + net.JoinHostPort(a.IP.String(), strconv.Itoa(pln.port))
		b.logf("peerapi: serving on %s", pln.urlStr)
		go pln.serve()
		b.peerAPIListeners = append(b.peerAPIListeners, pln)
	}
}

// magicDNSRootDomains returns the subset of nm.DNS.Domains that are the search domains for MagicDNS.
func magicDNSRootDomains(nm *netmap.NetworkMap) []string {
	if v := nm.MagicDNSSuffix(); v != "" {
		return []string{strings.Trim(v, ".")}
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
			if aip.IP.Is6() && aip.IsSingleIP() && tsULA.Contains(aip.IP) {
				if !didULA {
					didULA = true
					routes = append(routes, tsULA)
				}
				continue
			}
			if aip.IsSingleIP() && cgNAT.Contains(aip.IP) {
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
func routerConfig(cfg *wgcfg.Config, prefs *ipn.Prefs) *router.Config {
	rs := &router.Config{
		LocalAddrs:       unmapIPPrefixes(cfg.Addresses),
		SubnetRoutes:     unmapIPPrefixes(prefs.AdvertiseRoutes),
		SNATSubnetRoutes: !prefs.NoSNAT,
		NetfilterMode:    prefs.NetfilterMode,
		Routes:           peerRoutes(cfg.Peers, 10_000),
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
			if route == ipv4Default {
				default4 = true
			} else if route == ipv6Default {
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
	}

	rs.Routes = append(rs.Routes, netaddr.IPPrefix{
		IP:   tsaddr.TailscaleServiceIP(),
		Bits: 32,
	})

	return rs
}

func unmapIPPrefix(ipp netaddr.IPPrefix) netaddr.IPPrefix {
	return netaddr.IPPrefix{IP: ipp.IP.Unmap(), Bits: ipp.Bits}
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
	if v := prefs.OSVersion; v != "" {
		hi.OSVersion = v
	}
	if m := prefs.DeviceModel; m != "" {
		hi.DeviceModel = m
	}
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
	state := b.state
	b.state = newState
	prefs := b.prefs
	notify := b.notify
	cc := b.cc
	networkUp := b.prevIfState.AnyInterfaceUp()
	activeLogin := b.activeLogin
	authURL := b.authURL
	b.mu.Unlock()

	if state == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v)",
		state, newState, prefs.WantRunning)
	health.SetIPNState(newState.String(), prefs.WantRunning)
	if notify != nil {
		b.send(ipn.Notify{State: &newState})
	}

	if cc != nil {
		cc.SetPaused(newState == ipn.Stopped || !networkUp)
	}

	switch newState {
	case ipn.NeedsLogin:
		systemd.Status("Needs login: %s", authURL)
		b.blockEngineUpdates(true)
		fallthrough
	case ipn.Stopped:
		err := b.e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{})
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
		for _, addr := range b.netMap.Addresses {
			addrs = append(addrs, addr.IP.String())
		}
		systemd.Status("Connected; %s; %s", activeLogin, strings.Join(addrs, " "))
	default:
		b.logf("[unexpected] unknown newState %#v", newState)
	}

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
		wantRunning = b.prefs.WantRunning
	)
	b.mu.Unlock()

	switch {
	case netMap == nil:
		if cc.AuthCantContinue() {
			// Auth was interrupted or waiting for URL visit,
			// so it won't proceed without human help.
			return ipn.NeedsLogin
		} else {
			// Auth or map request needs to finish
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
		if st := b.getEngineStatus(); st.NumLive > 0 || st.LiveDERPs > 0 {
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
	b.e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{})
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

// Logout tells the controlclient that we want to log out, and
// transitions the local engine to the logged-out state without
// waiting for controlclient to be in that state.
//
// TODO(danderson): controlclient Logout does nothing useful, and we
// shouldn't be transitioning to a state based on what we believe
// controlclient may have done.
//
// NOTE(apenwarr): No easy way to persist logged-out status.
//  Maybe that's for the better; if someone logs out accidentally,
//  rebooting will fix it.
func (b *LocalBackend) Logout() {
	b.mu.Lock()
	cc := b.cc
	b.setNetMapLocked(nil)
	b.mu.Unlock()

	if cc == nil {
		// Double Logout can happen via repeated IPN
		// connections to ipnserver making it repeatedly
		// transition from 1->0 total connections, which on
		// Windows by default ("client mode") causes a Logout
		// on the transition to zero.
		// Previously this crashed when we asserted that c was non-nil
		// here.
		return
	}

	cc.Logout()

	b.mu.Lock()
	b.setNetMapLocked(nil)
	b.mu.Unlock()

	b.stateMachine()
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
				b.nodeByAddr[ipp.IP] = n
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

// TestOnlyPublicKeys returns the current machine and node public
// keys. Used in tests only to facilitate automated node authorization
// in the test harness.
func (b *LocalBackend) TestOnlyPublicKeys() (machineKey tailcfg.MachineKey, nodeKey tailcfg.NodeKey) {
	b.mu.Lock()
	prefs := b.prefs
	machinePrivKey := b.machinePrivKey
	b.mu.Unlock()

	if prefs == nil || machinePrivKey.IsZero() {
		return
	}

	mk := machinePrivKey.Public()
	nk := prefs.Persist.PrivateNodeKey.Public()
	return tailcfg.MachineKey(mk), tailcfg.NodeKey(nk)
}

func (b *LocalBackend) WaitingFiles() ([]WaitingFile, error) {
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

// FileTarget is a node to which files can be sent, and the PeerAPI
// URL base to do so via.
type FileTarget struct {
	Node *tailcfg.Node

	// PeerAPI is the http://ip:port URL base of the node's peer API,
	// without any path (not even a single slash).
	PeerAPIURL string
}

// FileTargets lists nodes that the current node can send files to.
func (b *LocalBackend) FileTargets() ([]*FileTarget, error) {
	var ret []*FileTarget

	b.mu.Lock()
	defer b.mu.Unlock()
	nm := b.netMap
	if b.state != ipn.Running || nm == nil {
		return nil, errors.New("not connected")
	}
	for _, p := range nm.Peers {
		if p.User != nm.User {
			continue
		}
		peerAPI := peerAPIBase(b.netMap, p)
		if peerAPI == "" {
			continue
		}
		ret = append(ret, &FileTarget{
			Node:       p,
			PeerAPIURL: peerAPI,
		})
	}
	// TODO: sort a different way than the netmap already is?
	return ret, nil
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
		case a.IP.Is4():
			have4 = true
		case a.IP.Is6():
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
		ipp = netaddr.IPPort{IP: nodeIP(peer, netaddr.IP.Is4), Port: p4}
	case have6 && p6 != 0:
		ipp = netaddr.IPPort{IP: nodeIP(peer, netaddr.IP.Is6), Port: p6}
	}
	if ipp.IP.IsZero() {
		return ""
	}
	return fmt.Sprintf("http://%v", ipp)
}

func nodeIP(n *tailcfg.Node, pred func(netaddr.IP) bool) netaddr.IP {
	for _, a := range n.Addresses {
		if a.IsSingleIP() && pred(a.IP) {
			return a.IP
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
		//lint:ignore ST1005 output to users as is
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

	for _, key := range keys {
		bs, err := exec.Command("sysctl", "-n", key).Output()
		if err != nil {
			//lint:ignore ST1005 output to users as is
			return fmt.Errorf("couldn't check %s (%v).\nSubnet routes won't work without IP forwarding.", key, err)
		}
		on, err := strconv.ParseBool(string(bytes.TrimSpace(bs)))
		if err != nil {
			//lint:ignore ST1005 output to users as is
			return fmt.Errorf("couldn't parse %s (%v).\nSubnet routes won't work without IP forwarding.", key, err)
		}
		if !on {
			//lint:ignore ST1005 output to users as is
			return fmt.Errorf("%s is disabled. Subnet routes won't work.", key)
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
