// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/oauth2"
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/internal/deepprint"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/policy"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/tsaddr"
	"tailscale.com/portlist"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/router/dns"
	"tailscale.com/wgengine/tsdns"
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
	ctx             context.Context    // canceled by Close
	ctxCancel       context.CancelFunc // cancels ctx
	logf            logger.Logf        // general logging
	keyLogf         logger.Logf        // for printing list of peers on change
	statsLogf       logger.Logf        // for printing peers stats on change
	e               wgengine.Engine
	store           StateStore
	backendLogID    string
	portpoll        *portlist.Poller // may be nil
	portpollOnce    sync.Once        // guards starting readPoller
	gotPortPollRes  chan struct{}    // closed upon first readPoller result
	serverURL       string           // tailcontrol URL
	newDecompressor func() (controlclient.Decompressor, error)

	filterHash string

	// The mutex protects the following elements.
	mu             sync.Mutex
	notify         func(Notify)
	c              *controlclient.Client
	stateKey       StateKey // computed in part from user-provided value
	userID         string   // current controlling user ID (for Windows, primarily)
	prefs          *Prefs
	inServerMode   bool
	machinePrivKey wgcfg.PrivateKey
	state          State
	// hostinfo is mutated in-place while mu is held.
	hostinfo *tailcfg.Hostinfo
	// netMap is not mutated in-place once set.
	netMap       *controlclient.NetworkMap
	activeLogin  string // last logged LoginName from netMap
	engineStatus EngineStatus
	endpoints    []string
	blocked      bool
	authURL      string
	interact     bool
	prevIfState  *interfaces.State

	// statusLock must be held before calling statusChanged.Wait() or
	// statusChanged.Broadcast().
	statusLock    sync.Mutex
	statusChanged *sync.Cond
}

// NewLocalBackend returns a new LocalBackend that is ready to run,
// but is not actually running.
func NewLocalBackend(logf logger.Logf, logid string, store StateStore, e wgengine.Engine) (*LocalBackend, error) {
	if e == nil {
		panic("ipn.NewLocalBackend: wgengine must not be nil")
	}

	// Default filter blocks everything, until Start() is called.
	e.SetFilter(filter.NewAllowNone(logf))

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
		state:          NoState,
		portpoll:       portpoll,
		gotPortPollRes: make(chan struct{}),
	}
	e.SetLinkChangeCallback(b.linkChange)
	b.statusChanged = sync.NewCond(&b.statusLock)

	return b, nil
}

// linkChange is called (in a new goroutine) by wgengine when its link monitor
// detects a network change.
func (b *LocalBackend) linkChange(major bool, ifst *interfaces.State) {
	b.mu.Lock()
	defer b.mu.Unlock()

	hadPAC := b.prevIfState.HasPAC()
	b.prevIfState = ifst

	networkUp := ifst.AnyInterfaceUp()
	if b.c != nil {
		go b.c.SetPaused(b.state == Stopped || !networkUp)
	}

	// If the PAC-ness of the network changed, reconfig wireguard+route to
	// add/remove subnets.
	if hadPAC != ifst.HasPAC() {
		b.logf("linkChange: in state %v; PAC changed from %v->%v", b.state, hadPAC, ifst.HasPAC())
		switch b.state {
		case NoState, Stopped:
			// Do nothing.
		default:
			go b.authReconfig()
		}
	}
}

// Shutdown halts the backend and all its sub-components. The backend
// can no longer be used after Shutdown returns.
func (b *LocalBackend) Shutdown() {
	b.mu.Lock()
	cli := b.c
	b.mu.Unlock()

	if cli != nil {
		cli.Shutdown()
	}
	b.ctxCancel()
	b.e.Close()
	b.e.Wait()
}

// Status returns the latest status of the backend and its
// sub-components.
func (b *LocalBackend) Status() *ipnstate.Status {
	sb := new(ipnstate.StatusBuilder)
	b.UpdateStatus(sb)
	return sb.Status()
}

// UpdateStatus implements ipnstate.StatusUpdater.
func (b *LocalBackend) UpdateStatus(sb *ipnstate.StatusBuilder) {
	b.e.UpdateStatus(sb)

	b.mu.Lock()
	defer b.mu.Unlock()

	sb.SetBackendState(b.state.String())

	// TODO: hostinfo, and its networkinfo
	// TODO: EngineStatus copy (and deprecate it?)
	if b.netMap != nil {
		for id, up := range b.netMap.UserProfiles {
			sb.AddUser(id, up)
		}
		for _, p := range b.netMap.Peers {
			var lastSeen time.Time
			if p.LastSeen != nil {
				lastSeen = *p.LastSeen
			}
			var tailAddr string
			if len(p.Addresses) > 0 {
				tailAddr = strings.TrimSuffix(p.Addresses[0].String(), "/32")
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
			})
		}
	}

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
		b.logf("Received error: %v", st.Err)
		return
	}
	if st.LoginFinished != nil {
		// Auth completed, unblock the engine
		b.blockEngineUpdates(false)
		b.authReconfig()
		b.send(Notify{LoginFinished: &empty.Message{}})
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
	if temporarilySetMachineKeyInPersist() && b.prefs.Persist != nil &&
		b.prefs.Persist.LegacyFrontendPrivateMachineKey.IsZero() {
		b.prefs.Persist.LegacyFrontendPrivateMachineKey = b.machinePrivKey
		prefsChanged = true
	}
	if st.NetMap != nil {
		b.setNetMapLocked(st.NetMap)

	}
	if st.URL != "" {
		b.authURL = st.URL
	}
	if b.state == NeedsLogin {
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
		b.send(Notify{Prefs: prefs})
	}
	if st.NetMap != nil {
		if netMap != nil {
			diff := st.NetMap.ConciseDiffFrom(netMap)
			if strings.TrimSpace(diff) == "" {
				b.logf("netmap diff: (none)")
			} else {
				b.logf("netmap diff:\n%v", diff)
			}
		}

		b.updateFilter(st.NetMap, prefs)
		b.e.SetNetworkMap(st.NetMap)
		if !dnsMapsEqual(st.NetMap, netMap) {
			b.updateDNSMap(st.NetMap)
		}
		b.e.SetDERPMap(st.NetMap.DERPMap)

		b.send(Notify{NetMap: st.NetMap})
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

// setWgengineStatus is the callback by the wireguard engine whenever it posts a new status.
// This updates the endpoints both in the backend and in the control client.
func (b *LocalBackend) setWgengineStatus(s *wgengine.Status, err error) {
	if err != nil {
		b.logf("wgengine status error: %#v", err)
		return
	}
	if s == nil {
		b.logf("[unexpected] non-error wgengine update with status=nil: %v", s)
		return
	}

	b.mu.Lock()
	es := b.parseWgStatusLocked(s)
	c := b.c
	b.engineStatus = es
	b.endpoints = append([]string{}, s.LocalAddrs...)
	b.mu.Unlock()

	if c != nil {
		c.UpdateEndpoints(0, s.LocalAddrs)
	}
	b.stateMachine()

	b.statusLock.Lock()
	b.statusChanged.Broadcast()
	b.statusLock.Unlock()

	b.send(Notify{Engine: &es})
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
func (b *LocalBackend) Start(opts Options) error {
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

	if b.c != nil {
		// TODO(apenwarr): avoid the need to reinit controlclient.
		// This will trigger a full relogin/reconfigure cycle every
		// time a Handle reconnects to the backend. Ideally, we
		// would send the new Prefs and everything would get back
		// into sync with the minimal changes. But that's not how it
		// is right now, which is a sign that the code is still too
		// complicated.
		b.c.Shutdown()
	}

	if b.hostinfo != nil {
		hostinfo.Services = b.hostinfo.Services // keep any previous session and netinfo
		hostinfo.NetInfo = b.hostinfo.NetInfo
	}
	b.hostinfo = hostinfo
	b.state = NoState

	if err := b.loadStateLocked(opts.StateKey, opts.Prefs, opts.LegacyConfigPath); err != nil {
		b.mu.Unlock()
		return fmt.Errorf("loading requested state: %v", err)
	}

	b.inServerMode = b.prefs.ForceDaemon
	b.serverURL = b.prefs.ControlURL
	hostinfo.RoutableIPs = append(hostinfo.RoutableIPs, b.prefs.AdvertiseRoutes...)
	hostinfo.RequestTags = append(hostinfo.RequestTags, b.prefs.AdvertiseTags...)
	if b.inServerMode || runtime.GOOS == "windows" {
		b.logf("Start: serverMode=%v", b.inServerMode)
	}
	applyPrefsToHostinfo(hostinfo, b.prefs)

	b.notify = opts.Notify
	b.setNetMapLocked(nil)
	persist := b.prefs.Persist
	machinePrivKey := b.machinePrivKey
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
	if persist == nil {
		// let controlclient initialize it
		persist = &controlclient.Persist{}
	}
	cli, err := controlclient.New(controlclient.Options{
		MachinePrivateKey: machinePrivKey,
		Logf:              logger.WithPrefix(b.logf, "control: "),
		Persist:           *persist,
		ServerURL:         b.serverURL,
		AuthKey:           opts.AuthKey,
		Hostinfo:          hostinfo,
		KeepAlive:         true,
		NewDecompressor:   b.newDecompressor,
		HTTPTestClient:    opts.HTTPTestClient,
		DiscoPublicKey:    discoPublic,
		DebugFlags:        controlDebugFlags,
	})
	if err != nil {
		return err
	}

	b.mu.Lock()
	b.c = cli
	endpoints := b.endpoints
	b.mu.Unlock()

	if endpoints != nil {
		cli.UpdateEndpoints(0, endpoints)
	}

	cli.SetStatusFunc(b.setClientStatus)
	b.e.SetStatusCallback(b.setWgengineStatus)
	b.e.SetNetInfoCallback(b.setNetInfo)

	b.mu.Lock()
	prefs := b.prefs.Clone()

	if temporarilySetMachineKeyInPersist() && prefs.Persist != nil &&
		prefs.Persist.LegacyFrontendPrivateMachineKey.IsZero() {
		prefs.Persist.LegacyFrontendPrivateMachineKey = b.machinePrivKey
	}

	b.mu.Unlock()

	blid := b.backendLogID
	b.logf("Backend: logs: be:%v fe:%v", blid, opts.FrontendLogID)
	b.send(Notify{BackendLogID: &blid})
	b.send(Notify{Prefs: prefs})

	cli.Login(nil, controlclient.LoginDefault)
	return nil
}

// updateFilter updates the packet filter in wgengine based on the
// given netMap and user preferences.
func (b *LocalBackend) updateFilter(netMap *controlclient.NetworkMap, prefs *Prefs) {
	// NOTE(danderson): keep change detection as the first thing in
	// this function. Don't try to optimize by returning early, more
	// likely than not you'll just end up breaking the change
	// detection and end up with the wrong filter installed. This is
	// quite hard to debug, so save yourself the trouble.
	var (
		haveNetmap   = netMap != nil
		addrs        []wgcfg.CIDR
		packetFilter []filter.Match
		advRoutes    []wgcfg.CIDR
		shieldsUp    = prefs == nil || prefs.ShieldsUp // Be conservative when not ready
	)
	if haveNetmap {
		addrs = netMap.Addresses
		packetFilter = netMap.PacketFilter
	}
	if prefs != nil {
		advRoutes = prefs.AdvertiseRoutes
	}

	changed := deepprint.UpdateHash(&b.filterHash, haveNetmap, addrs, packetFilter, advRoutes, shieldsUp)
	if !changed {
		return
	}

	if !haveNetmap {
		b.logf("netmap packet filter: (not ready yet)")
		b.e.SetFilter(filter.NewAllowNone(b.logf))
		return
	}

	localNets := wgCIDRsToNetaddr(netMap.Addresses, advRoutes)

	if shieldsUp {
		b.logf("netmap packet filter: (shields up)")
		var prevFilter *filter.Filter // don't reuse old filter state
		b.e.SetFilter(filter.New(nil, localNets, prevFilter, b.logf))
	} else {
		b.logf("netmap packet filter: %v", packetFilter)
		b.e.SetFilter(filter.New(packetFilter, localNets, b.e.GetFilter(), b.logf))
	}
}

// dnsCIDRsEqual determines whether two CIDR lists are equal
// for DNS map construction purposes (that is, only the first entry counts).
func dnsCIDRsEqual(newAddr, oldAddr []wgcfg.CIDR) bool {
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
func dnsMapsEqual(new, old *controlclient.NetworkMap) bool {
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

// updateDNSMap updates the domain map in the DNS resolver in wgengine
// based on the given netMap and user preferences.
func (b *LocalBackend) updateDNSMap(netMap *controlclient.NetworkMap) {
	if netMap == nil {
		b.logf("dns map: (not ready)")
		return
	}

	nameToIP := make(map[string]netaddr.IP)
	set := func(name string, addrs []wgcfg.CIDR) {
		if len(addrs) == 0 || name == "" {
			return
		}
		nameToIP[name] = netaddr.IPFrom16(addrs[0].IP.Addr)
	}

	for _, peer := range netMap.Peers {
		set(peer.Name, peer.Addresses)
	}
	set(netMap.Name, netMap.Addresses)

	dnsMap := tsdns.NewMap(nameToIP, domainsForProxying(netMap))
	// map diff will be logged in tsdns.Resolver.SetMap.
	b.e.SetDNSMap(dnsMap)
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
func (b *LocalBackend) send(n Notify) {
	b.mu.Lock()
	notify := b.notify
	b.mu.Unlock()

	if notify != nil {
		n.Version = version.Long
		notify(n)
	} else {
		b.logf("nil notify callback; dropping %+v", n)
	}
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
	b.send(Notify{BrowseToURL: &url})
	if b.State() == Running {
		b.enterState(Starting)
	}
}

// initMachineKeyLocked is called to initialize b.machinePrivKey.
//
// b.prefs must already be initialized.
// b.stateKey should be set too, but just for nicer log messages.
// b.mu must be held.
func (b *LocalBackend) initMachineKeyLocked() (err error) {
	if temporarilySetMachineKeyInPersist() {
		defer func() {
			if err != nil {
				return
			}
			if b.prefs != nil && b.prefs.Persist != nil {
				b.prefs.Persist.LegacyFrontendPrivateMachineKey = b.machinePrivKey
			}
		}()
	}

	if !b.machinePrivKey.IsZero() {
		// Already set.
		return nil
	}

	var legacyMachineKey wgcfg.PrivateKey
	if b.prefs.Persist != nil {
		legacyMachineKey = b.prefs.Persist.LegacyFrontendPrivateMachineKey
	}

	keyText, err := b.store.ReadState(MachineKeyStateKey)
	if err == nil {
		if err := b.machinePrivKey.UnmarshalText(keyText); err != nil {
			return fmt.Errorf("invalid key in %s key of %v: %w", MachineKeyStateKey, b.store, err)
		}
		if b.machinePrivKey.IsZero() {
			return fmt.Errorf("invalid zero key stored in %v key of %v", MachineKeyStateKey, b.store)
		}
		if !legacyMachineKey.IsZero() && !bytes.Equal(legacyMachineKey[:], b.machinePrivKey[:]) {
			b.logf("frontend-provided legacy machine key ignored; used value from server state")
		}
		return nil
	}
	if err != ErrStateNotExist {
		return fmt.Errorf("error reading %v key of %v: %w", MachineKeyStateKey, b.store, err)
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
		b.machinePrivKey, err = wgcfg.NewPrivateKey()
		if err != nil {
			return fmt.Errorf("initializing new machine key: %w", err)
		}
	}

	keyText, _ = b.machinePrivKey.MarshalText()
	if err := b.store.WriteState(MachineKeyStateKey, keyText); err != nil {
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
func (b *LocalBackend) writeServerModeStartState(userID string, prefs *Prefs) {
	if userID == "" || prefs == nil {
		return
	}

	if prefs.ForceDaemon {
		stateKey := StateKey("user-" + userID)
		if err := b.store.WriteState(ServerModeStartKey, []byte(stateKey)); err != nil {
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
		if err := b.store.WriteState(ServerModeStartKey, nil); err != nil {
			b.logf("WriteState error: %v", err)
		}
	}
}

// loadStateLocked sets b.prefs and b.stateKey based on a complex
// combination of key, prefs, and legacyPath. b.mu must be held when
// calling.
func (b *LocalBackend) loadStateLocked(key StateKey, prefs *Prefs, legacyPath string) (err error) {
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
		if err := b.initMachineKeyLocked(); err != nil {
			return fmt.Errorf("initMachineKeyLocked: %w", err)
		}
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
	if err != nil {
		if errors.Is(err, ErrStateNotExist) {
			if legacyPath != "" {
				b.prefs, err = LoadPrefs(legacyPath)
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						b.logf("failed to load legacy prefs: %v", err)
					}
					b.prefs = NewPrefs()
				} else {
					b.logf("imported prefs from relaynode for %q: %v", key, b.prefs.Pretty())
				}
			} else {
				b.prefs = NewPrefs()
				b.logf("created empty state for %q: %s", key, b.prefs.Pretty())
			}
			if err := b.initMachineKeyLocked(); err != nil {
				return fmt.Errorf("initMachineKeyLocked: %w", err)
			}
			return nil
		}
		return fmt.Errorf("store.ReadState(%q): %v", key, err)
	}
	b.prefs, err = PrefsFromBytes(bs, false)
	if err != nil {
		return fmt.Errorf("PrefsFromBytes: %v", err)
	}
	b.logf("backend prefs for %q: %s", key, b.prefs.Pretty())
	if err := b.initMachineKeyLocked(); err != nil {
		return fmt.Errorf("initMachineKeyLocked: %w", err)
	}
	return nil
}

// State returns the backend state machine's current state.
func (b *LocalBackend) State() State {
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
func (b *LocalBackend) getEngineStatus() EngineStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.engineStatus
}

// Login implements Backend.
func (b *LocalBackend) Login(token *oauth2.Token) {
	b.mu.Lock()
	b.assertClientLocked()
	c := b.c
	b.mu.Unlock()

	c.Login(token, controlclient.LoginInteractive)
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
	c := b.c
	b.mu.Unlock()
	b.logf("StartLoginInteractive: url=%v", url != "")

	if url != "" {
		b.popBrowserAuthNow()
	} else {
		c.Login(nil, controlclient.LoginInteractive)
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
	b.send(Notify{NetMap: b.netMap})
}

func (b *LocalBackend) Ping(ipStr string) {
	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		b.logf("ignoring Ping request to invalid IP %q", ipStr)
		return
	}
	b.e.Ping(ip, func(pr *ipnstate.PingResult) {
		b.send(Notify{PingResult: pr})
	})
}

// parseWgStatusLocked returns an EngineStatus based on s.
//
// b.mu must be held; mostly because the caller is about to anyway, and doing so
// gives us slightly better guarantees about the two peers stats lines not
// being intermixed if there are concurrent calls to our caller.
func (b *LocalBackend) parseWgStatusLocked(s *wgengine.Status) (ret EngineStatus) {
	var peerStats, peerKeys strings.Builder

	ret.LiveDERPs = s.DERPs
	ret.LivePeers = map[tailcfg.NodeKey]wgengine.PeerStatus{}
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
		b.keyLogf("peer keys: %s", strings.TrimSpace(peerKeys.String()))
		b.statsLogf("v%v peers: %v", version.Long, strings.TrimSpace(peerStats.String()))
	}
	return ret
}

// shieldsAreUp returns whether user preferences currently request
// "shields up" mode, which disallows all inbound connections.
func (b *LocalBackend) shieldsAreUp() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.prefs == nil {
		return true // default to safest setting
	}
	return b.prefs.ShieldsUp
}

func (b *LocalBackend) SetCurrentUserID(uid string) {
	b.mu.Lock()
	b.userID = uid
	b.mu.Unlock()
}

func (b *LocalBackend) SetWantRunning(wantRunning bool) {
	b.mu.Lock()
	new := b.prefs.Clone()
	b.mu.Unlock()
	if new.WantRunning == wantRunning {
		return
	}
	new.WantRunning = wantRunning
	b.logf("SetWantRunning: %v", wantRunning)
	b.SetPrefs(new)
}

// SetPrefs saves new user preferences and propagates them throughout
// the system. Implements Backend.
func (b *LocalBackend) SetPrefs(newp *Prefs) {
	if newp == nil {
		panic("SetPrefs got nil prefs")
	}

	b.mu.Lock()

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
	newHi.RoutableIPs = append([]wgcfg.CIDR(nil), b.prefs.AdvertiseRoutes...)
	applyPrefsToHostinfo(newHi, newp)
	b.hostinfo = newHi
	hostInfoChanged := !oldHi.Equal(newHi)
	userID := b.userID

	b.mu.Unlock()

	if stateKey != "" {
		if err := b.store.WriteState(stateKey, newp.ToBytes()); err != nil {
			b.logf("Failed to save new controlclient state: %v", err)
		}
	}
	b.writeServerModeStartState(userID, newp)

	// [GRINDER STATS LINE] - please don't remove (used for log parsing)
	b.logf("SetPrefs: %v", newp.Pretty())
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

	b.send(Notify{Prefs: newp})
}

// doSetHostinfoFilterServices calls SetHostinfo on the controlclient,
// possibly after mangling the given hostinfo.
//
// TODO(danderson): we shouldn't be mangling hostinfo here after
// painstakingly constructing it in twelvety other places.
func (b *LocalBackend) doSetHostinfoFilterServices(hi *tailcfg.Hostinfo) {
	hi2 := *hi
	if b.shieldsAreUp() {
		// No local services are available, since ShieldsUp will block
		// them all.
		hi2.Services = []tailcfg.Service{}
	}

	b.mu.Lock()
	cli := b.c
	b.mu.Unlock()

	// b.c might not be started yet
	if cli != nil {
		cli.SetHostinfo(&hi2)
	}
}

// NetMap returns the latest cached network map received from
// controlclient, or nil if no network map was received yet.
func (b *LocalBackend) NetMap() *controlclient.NetworkMap {
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

	var flags controlclient.WGConfigFlags
	if uc.RouteAll {
		flags |= controlclient.AllowDefaultRoute
		// TODO(apenwarr): Make subnet routes a different pref?
		flags |= controlclient.AllowSubnetRoutes
	}
	if uc.AllowSingleHosts {
		flags |= controlclient.AllowSingleHosts
	}
	if hasPAC && disableSubnetsIfPAC {
		if flags&controlclient.AllowSubnetRoutes != 0 {
			b.logf("authReconfig: have PAC; disabling subnet routes")
			flags &^= controlclient.AllowSubnetRoutes
		}
	}

	cfg, err := nm.WGCfg(b.logf, flags)
	if err != nil {
		b.logf("wgcfg: %v", err)
		return
	}

	rcfg := routerConfig(cfg, uc)

	// If CorpDNS is false, rcfg.DNS remains the zero value.
	if uc.CorpDNS {
		domains := nm.DNS.Domains
		proxied := nm.DNS.Proxied
		if proxied {
			if len(nm.DNS.Nameservers) == 0 {
				b.logf("[unexpected] dns proxied but no nameservers")
				proxied = false
			} else {
				// Domains for proxying should come first to avoid leaking queries.
				domains = append(domainsForProxying(nm), domains...)
			}
		}
		rcfg.DNS = dns.Config{
			Nameservers: nm.DNS.Nameservers,
			Domains:     domains,
			PerDomain:   nm.DNS.PerDomain,
			Proxied:     proxied,
		}
	}

	err = b.e.Reconfig(cfg, rcfg)
	if err == wgengine.ErrNoChanges {
		return
	}
	b.logf("authReconfig: ra=%v dns=%v 0x%02x: %v", uc.RouteAll, uc.CorpDNS, flags, err)
}

// domainsForProxying produces a list of search domains for proxied DNS.
func domainsForProxying(nm *controlclient.NetworkMap) []string {
	var domains []string
	if idx := strings.IndexByte(nm.Name, '.'); idx != -1 {
		domains = append(domains, nm.Name[idx+1:])
	}
	for _, peer := range nm.Peers {
		idx := strings.IndexByte(peer.Name, '.')
		if idx == -1 {
			continue
		}
		domain := peer.Name[idx+1:]
		seen := false
		// In theory this makes the function O(n^2) worst case,
		// but in practice we expect domains to contain very few elements
		// (only one until invitations are introduced).
		for _, seenDomain := range domains {
			if domain == seenDomain {
				seen = true
			}
		}
		if !seen {
			domains = append(domains, domain)
		}
	}
	return domains
}

// routerConfig produces a router.Config from a wireguard config and IPN prefs.
func routerConfig(cfg *wgcfg.Config, prefs *Prefs) *router.Config {
	var addrs []wgcfg.CIDR
	for _, addr := range cfg.Addresses {
		addrs = append(addrs, wgcfg.CIDR{
			IP:   addr.IP,
			Mask: 32,
		})
	}

	rs := &router.Config{
		LocalAddrs:       wgCIDRsToNetaddr(addrs),
		SubnetRoutes:     wgCIDRsToNetaddr(prefs.AdvertiseRoutes),
		SNATSubnetRoutes: !prefs.NoSNAT,
		NetfilterMode:    prefs.NetfilterMode,
	}

	for _, peer := range cfg.Peers {
		rs.Routes = append(rs.Routes, wgCIDRsToNetaddr(peer.AllowedIPs)...)
	}

	rs.Routes = append(rs.Routes, netaddr.IPPrefix{
		IP:   tsaddr.TailscaleServiceIP(),
		Bits: 32,
	})

	return rs
}

func wgCIDRsToNetaddr(cidrLists ...[]wgcfg.CIDR) (ret []netaddr.IPPrefix) {
	for _, cidrs := range cidrLists {
		for _, cidr := range cidrs {
			ncidr, ok := netaddr.FromStdIPNet(cidr.IPNet())
			if !ok {
				panic(fmt.Sprintf("conversion of %s from wgcfg to netaddr IPNet failed", cidr))
			}
			ncidr.IP = ncidr.IP.Unmap()
			ret = append(ret, ncidr)
		}
	}
	return ret
}

func applyPrefsToHostinfo(hi *tailcfg.Hostinfo, prefs *Prefs) {
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
func (b *LocalBackend) enterState(newState State) {
	b.mu.Lock()
	state := b.state
	b.state = newState
	prefs := b.prefs
	notify := b.notify
	bc := b.c
	networkUp := b.prevIfState.AnyInterfaceUp()
	b.mu.Unlock()

	if state == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v)",
		state, newState, prefs.WantRunning)
	if notify != nil {
		b.send(Notify{State: &newState})
	}

	if bc != nil {
		bc.SetPaused(newState == Stopped || !networkUp)
	}

	switch newState {
	case NeedsLogin:
		b.blockEngineUpdates(true)
		fallthrough
	case Stopped:
		err := b.e.Reconfig(&wgcfg.Config{}, &router.Config{})
		if err != nil {
			b.logf("Reconfig(down): %v", err)
		}
	case Starting, NeedsMachineAuth:
		b.authReconfig()
		// Needed so that UpdateEndpoints can run
		b.e.RequestStatus()
	case Running:
		break
	default:
		b.logf("[unexpected] unknown newState %#v", newState)
	}

}

// nextState returns the state the backend seems to be in, based on
// its internal state.
func (b *LocalBackend) nextState() State {
	b.mu.Lock()
	b.assertClientLocked()
	var (
		c           = b.c
		netMap      = b.netMap
		state       = b.state
		wantRunning = b.prefs.WantRunning
	)
	b.mu.Unlock()

	switch {
	case netMap == nil:
		if c.AuthCantContinue() {
			// Auth was interrupted or waiting for URL visit,
			// so it won't proceed without human help.
			return NeedsLogin
		} else {
			// Auth or map request needs to finish
			return state
		}
	case !wantRunning:
		return Stopped
	case !netMap.Expiry.IsZero() && time.Until(netMap.Expiry) <= 0:
		return NeedsLogin
	case netMap.MachineStatus != tailcfg.MachineAuthorized:
		// TODO(crawshaw): handle tailcfg.MachineInvalid
		return NeedsMachineAuth
	case state == NeedsMachineAuth:
		// (if we get here, we know MachineAuthorized == true)
		return Starting
	case state == Starting:
		if st := b.getEngineStatus(); st.NumLive > 0 || st.LiveDERPs > 0 {
			return Running
		} else {
			return state
		}
	case state == Running:
		return Running
	default:
		return Starting
	}
}

// RequestEngineStatus implements Backend.
func (b *LocalBackend) RequestEngineStatus() {
	b.e.RequestStatus()
}

// RequestStatus implements Backend.
func (b *LocalBackend) RequestStatus() {
	st := b.Status()
	b.send(Notify{Status: st})
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
	b.e.Reconfig(&wgcfg.Config{}, &router.Config{})
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

// Logout tells the controlclient that we want to log out, and transitions the local engine to the logged-out state without waiting for controlclient to be in that state.
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
	c := b.c
	b.setNetMapLocked(nil)
	b.mu.Unlock()

	if c == nil {
		// Double Logout can happen via repeated IPN
		// connections to ipnserver making it repeatedly
		// transition from 1->0 total connections, which on
		// Windows by default ("client mode") causes a Logout
		// on the transition to zero.
		// Previously this crashed when we asserted that c was non-nil
		// here.
		return
	}

	c.Logout()

	b.mu.Lock()
	b.setNetMapLocked(nil)
	b.mu.Unlock()

	b.stateMachine()
}

// assertClientLocked crashes if there is no controlclient in this backend.
func (b *LocalBackend) assertClientLocked() {
	if b.c == nil {
		panic("LocalBackend.assertClient: b.c == nil")
	}
}

// setNetInfo sets b.hostinfo.NetInfo to ni, and passes ni along to the
// controlclient, if one exists.
func (b *LocalBackend) setNetInfo(ni *tailcfg.NetInfo) {
	b.mu.Lock()
	c := b.c
	if b.hostinfo != nil {
		b.hostinfo.NetInfo = ni.Clone()
	}
	b.mu.Unlock()

	if c == nil {
		return
	}
	c.SetNetInfo(ni)
}

func (b *LocalBackend) setNetMapLocked(nm *controlclient.NetworkMap) {
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

// temporarilySetMachineKeyInPersist reports whether we should set
// the machine key in Prefs.Persist.LegacyFrontendPrivateMachineKey
// for the frontend to write out to its preferences for use later.
//
// TODO: remove this in Tailscale 1.3.x (so it effectively always
// returns false). It just exists so users can downgrade from 1.2.x to
// 1.0.x.  But eventually we want to stop sending the machine key to
// clients. We can't do that until 1.0.x is no longer supported.
func temporarilySetMachineKeyInPersist() bool {
	//lint:ignore S1008 for comments
	switch runtime.GOOS {
	case "darwin", "ios", "android":
		// iOS, macOS, Android users can't downgrade anyway.
		return false
	}
	return true
}
