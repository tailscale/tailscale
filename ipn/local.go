// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"inet.af/netaddr"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/policy"
	"tailscale.com/portlist"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/tsdns"
)

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
	e               wgengine.Engine
	store           StateStore
	backendLogID    string
	portpoll        *portlist.Poller // may be nil
	newDecompressor func() (controlclient.Decompressor, error)

	// TODO: these fields are accessed unsafely by concurrent
	// goroutines. They need to be protected.
	serverURL       string // tailcontrol URL
	lastFilterPrint time.Time

	// The mutex protects the following elements.
	mu       sync.Mutex
	notify   func(Notify)
	c        *controlclient.Client
	stateKey StateKey
	prefs    *Prefs
	state    State
	// hostinfo is mutated in-place while mu is held.
	hostinfo *tailcfg.Hostinfo
	// netMap is not mutated in-place once set.
	netMap       *controlclient.NetworkMap
	engineStatus EngineStatus
	endpoints    []string
	blocked      bool
	authURL      string
	interact     int

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
		ctx:          ctx,
		ctxCancel:    cancel,
		logf:         logf,
		keyLogf:      logger.LogOnChange(logf, 5*time.Minute, time.Now),
		e:            e,
		store:        store,
		backendLogID: logid,
		state:        NoState,
		portpoll:     portpoll,
	}
	b.statusChanged = sync.NewCond(&b.statusLock)

	return b, nil
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
				OS:           p.Hostinfo.OS,
				KeepAlive:    p.KeepAlive,
				Created:      p.Created,
				LastSeen:     lastSeen,
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
	if st.LoginFinished != nil {
		// Auth completed, unblock the engine
		b.blockEngineUpdates(false)
		b.authReconfig()
		b.send(Notify{LoginFinished: &empty.Message{}})
	}
	if st.Persist != nil {
		persist := *st.Persist // copy

		b.mu.Lock()
		b.prefs.Persist = &persist
		prefs := b.prefs.Clone()
		stateKey := b.stateKey
		b.mu.Unlock()

		if stateKey != "" {
			if err := b.store.WriteState(stateKey, prefs.ToBytes()); err != nil {
				b.logf("Failed to save new controlclient state: %v", err)
			}
		}
		b.send(Notify{Prefs: prefs})
	}
	if st.NetMap != nil {
		// Netmap is unchanged only when the diff is empty.
		changed := true
		b.mu.Lock()
		if b.netMap != nil {
			diff := st.NetMap.ConciseDiffFrom(b.netMap)
			if strings.TrimSpace(diff) == "" {
				changed = false
				b.logf("netmap diff: (none)")
			} else {
				b.logf("netmap diff:\n%v", diff)
			}
		}
		disableDERP := b.prefs != nil && b.prefs.DisableDERP
		b.netMap = st.NetMap
		b.mu.Unlock()

		b.send(Notify{NetMap: st.NetMap})
		// There is nothing to update if the map hasn't changed.
		if changed {
			b.updateFilter(st.NetMap)
			b.updateDNSMap(st.NetMap)
		}
		if disableDERP {
			b.e.SetDERPMap(nil)
		} else {
			b.e.SetDERPMap(st.NetMap.DERPMap)
		}
	}
	if st.URL != "" {
		b.logf("Received auth URL: %.20v...", st.URL)

		b.mu.Lock()
		interact := b.interact
		b.authURL = st.URL
		b.mu.Unlock()

		if interact > 0 {
			b.popBrowserAuthNow()
		}
	}
	if st.Err != "" {
		// TODO(crawshaw): display in the UI.
		b.logf("Received error: %v", st.Err)
		return
	}
	if st.NetMap != nil {
		b.mu.Lock()
		if b.state == NeedsLogin {
			b.prefs.WantRunning = true
		}
		prefs := b.prefs
		b.mu.Unlock()

		b.SetPrefs(prefs)
	}
	b.stateMachine()
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

	es := b.parseWgStatus(s)

	b.mu.Lock()
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

	b.serverURL = b.prefs.ControlURL
	hostinfo.RoutableIPs = append(hostinfo.RoutableIPs, b.prefs.AdvertiseRoutes...)
	hostinfo.RequestTags = append(hostinfo.RequestTags, b.prefs.AdvertiseTags...)

	b.notify = opts.Notify
	b.netMap = nil
	persist := b.prefs.Persist
	b.mu.Unlock()

	b.updateFilter(nil)

	var discoPublic tailcfg.DiscoKey
	if useDisco, _ := strconv.ParseBool(os.Getenv("TS_DEBUG_USE_DISCO")); useDisco {
		discoPrivate := key.NewPrivate()
		b.e.SetDiscoPrivateKey(discoPrivate)
		discoPublic = tailcfg.DiscoKey(discoPrivate.Public())
	}

	var err error
	if persist == nil {
		// let controlclient initialize it
		persist = &controlclient.Persist{}
	}
	cli, err := controlclient.New(controlclient.Options{
		Logf:            logger.WithPrefix(b.logf, "control: "),
		Persist:         *persist,
		ServerURL:       b.serverURL,
		AuthKey:         opts.AuthKey,
		Hostinfo:        hostinfo,
		KeepAlive:       true,
		NewDecompressor: b.newDecompressor,
		HTTPTestClient:  opts.HTTPTestClient,
		DiscoPublicKey:  discoPublic,
	})
	if err != nil {
		return err
	}

	// At this point, we have finished using hostinfo without synchronization,
	// so it is safe to start readPoller which concurrently writes to it.
	if b.portpoll != nil {
		go b.portpoll.Run(b.ctx)
		go b.readPoller()
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
func (b *LocalBackend) updateFilter(netMap *controlclient.NetworkMap) {
	if netMap == nil {
		// Not configured yet, block everything
		b.logf("netmap packet filter: (not ready yet)")
		b.e.SetFilter(filter.NewAllowNone(b.logf))
		return
	}

	b.mu.Lock()
	advRoutes := b.prefs.AdvertiseRoutes
	b.mu.Unlock()
	localNets := wgCIDRsToFilter(netMap.Addresses, advRoutes)

	if b.shieldsAreUp() {
		// Shields up, block everything
		b.logf("netmap packet filter: (shields up)")
		var prevFilter *filter.Filter // don't reuse old filter state
		b.e.SetFilter(filter.New(filter.Matches{}, localNets, prevFilter, b.logf))
		return
	}

	// TODO(apenwarr): don't replace filter at all if unchanged.
	// TODO(apenwarr): print a diff instead of full filter.
	now := time.Now()
	if now.Sub(b.lastFilterPrint) > 1*time.Minute {
		b.logf("netmap packet filter: %v", netMap.PacketFilter)
		b.lastFilterPrint = now
	} else {
		b.logf("netmap packet filter: (length %d)", len(netMap.PacketFilter))
	}
	b.e.SetFilter(filter.New(netMap.PacketFilter, localNets, b.e.GetFilter(), b.logf))
}

// updateDNSMap updates the domain map in the DNS resolver in wgengine
// based on the given netMap and user preferences.
func (b *LocalBackend) updateDNSMap(netMap *controlclient.NetworkMap) {
	if netMap == nil {
		return
	}
	domainToIP := make(map[string]netaddr.IP)
	for _, peer := range netMap.Peers {
		if len(peer.Addresses) == 0 {
			continue
		}
		domain := peer.Hostinfo.Hostname
		// Like PeerStatus.SimpleHostName()
		domain = strings.TrimSuffix(domain, ".local")
		domain = strings.TrimSuffix(domain, ".localdomain")
		domain = domain + ".ipn.dev"
		domainToIP[domain] = netaddr.IPFrom16(peer.Addresses[0].IP.Addr)
	}
	b.e.SetDNSMap(tsdns.NewMap(domainToIP))
}

// readPoller is a goroutine that receives service lists from
// b.portpoll and propagates them into the controlclient's HostInfo.
func (b *LocalBackend) readPoller() {
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
	}
}

// send delivers n to the connected frontend. If no frontend is
// connected, the notification is dropped without being delivered.
func (b *LocalBackend) send(n Notify) {
	b.mu.Lock()
	notify := b.notify
	b.mu.Unlock()

	if notify != nil {
		n.Version = version.LONG
		notify(n)
	}
}

// popBrowserAuthNow shuts down the data plane and sends an auth URL
// to the connected frontend, if any.
func (b *LocalBackend) popBrowserAuthNow() {
	b.mu.Lock()
	url := b.authURL
	b.interact = 0
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

// loadStateLocked sets b.prefs and b.stateKey based on a complex
// combination of key, prefs, and legacyPath. b.mu must be held when
// calling.
func (b *LocalBackend) loadStateLocked(key StateKey, prefs *Prefs, legacyPath string) error {
	if prefs == nil && key == "" {
		panic("state key and prefs are both unset")
	}

	if key == "" {
		// Frontend fully owns the state, we just need to obey it.
		b.logf("Using frontend prefs")
		b.prefs = prefs.Clone()
		b.stateKey = ""
		return nil
	}

	if prefs != nil {
		// Backend owns the state, but frontend is trying to migrate
		// state into the backend.
		b.logf("Importing frontend prefs into backend store")
		if err := b.store.WriteState(key, prefs.ToBytes()); err != nil {
			return fmt.Errorf("store.WriteState: %v", err)
		}
	}

	b.logf("Using backend prefs")
	bs, err := b.store.ReadState(key)
	if err != nil {
		if errors.Is(err, ErrStateNotExist) {
			if legacyPath != "" {
				b.prefs, err = LoadPrefs(legacyPath, true)
				if err != nil {
					b.logf("Failed to load legacy prefs: %v", err)
					b.prefs = NewPrefs()
				} else {
					b.logf("Imported state from relaynode for %q", key)
				}
			} else {
				b.prefs = NewPrefs()
				b.logf("Created empty state for %q", key)
			}
			b.stateKey = key
			return nil
		}
		return fmt.Errorf("store.ReadState(%q): %v", key, err)
	}
	b.prefs, err = PrefsFromBytes(bs, false)
	if err != nil {
		return fmt.Errorf("PrefsFromBytes: %v", err)
	}
	b.stateKey = key
	return nil
}

// State returns the backend state machine's current state.
func (b *LocalBackend) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.state
}

// getEngineStatus returns a copy of b.engineStatus.
//
// TODO(bradfitz): remove this and use Status() throughout.
func (b *LocalBackend) getEngineStatus() EngineStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.engineStatus
}

// StartLoginInteractive implements Backend. It requests a new
// interactive login from controlclient, unless such a flow is already
// in progress, in which case StartLoginInteractive attempts to pick
// up the in-progress flow where it left off.
func (b *LocalBackend) StartLoginInteractive() {
	b.mu.Lock()
	b.assertClientLocked()
	b.interact++
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
	b.netMap = &mapCopy
	b.send(Notify{NetMap: b.netMap})
}

func (b *LocalBackend) parseWgStatus(s *wgengine.Status) (ret EngineStatus) {
	var (
		peerStats []string
		peerKeys  []string
	)

	ret.LiveDERPs = s.DERPs
	ret.LivePeers = map[tailcfg.NodeKey]wgengine.PeerStatus{}
	for _, p := range s.Peers {
		if !p.LastHandshake.IsZero() {
			peerStats = append(peerStats, fmt.Sprintf("%d/%d", p.RxBytes, p.TxBytes))
			ret.NumLive++
			ret.LivePeers[p.NodeKey] = p

			peerKeys = append(peerKeys, p.NodeKey.ShortString())
		}
		ret.RBytes += p.RxBytes
		ret.WBytes += p.TxBytes
	}
	if len(peerStats) > 0 {
		b.keyLogf("peer keys: %s", strings.Join(peerKeys, " "))
		b.logf("v%v peers: %v", version.LONG, strings.Join(peerStats, " "))
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

// SetPrefs saves new user preferences and propagates them throughout
// the system. Implements Backend.
func (b *LocalBackend) SetPrefs(new *Prefs) {
	if new == nil {
		panic("SetPrefs got nil prefs")
	}

	b.mu.Lock()
	old := b.prefs
	new.Persist = old.Persist // caller isn't allowed to override this
	b.prefs = new
	if b.stateKey != "" {
		if err := b.store.WriteState(b.stateKey, b.prefs.ToBytes()); err != nil {
			b.logf("Failed to save new controlclient state: %v", err)
		}
	}
	oldHi := b.hostinfo
	newHi := oldHi.Clone()
	newHi.RoutableIPs = append([]wgcfg.CIDR(nil), b.prefs.AdvertiseRoutes...)
	if h := new.Hostname; h != "" {
		newHi.Hostname = h
	}
	b.hostinfo = newHi
	b.mu.Unlock()

	b.logf("SetPrefs: %v", new.Pretty())

	if old.ShieldsUp != new.ShieldsUp || !oldHi.Equal(newHi) {
		b.doSetHostinfoFilterServices(newHi)
	}

	b.updateFilter(b.netMap)
	// TODO(dmytro): when Prefs gain an EnableTailscaleDNS toggle, updateDNSMap here.

	turnDERPOff := new.DisableDERP && !old.DisableDERP
	turnDERPOn := !new.DisableDERP && old.DisableDERP
	if turnDERPOff {
		b.e.SetDERPMap(nil)
	} else if turnDERPOn && b.netMap != nil {
		b.e.SetDERPMap(b.netMap.DERPMap)
	}

	if old.WantRunning != new.WantRunning {
		b.stateMachine()
	} else {
		b.authReconfig()
	}

	b.send(Notify{Prefs: new})
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

	uflags := controlclient.UDefault
	if uc.RouteAll {
		uflags |= controlclient.UAllowDefaultRoute
		// TODO(apenwarr): Make subnet routes a different pref?
		uflags |= controlclient.UAllowSubnetRoutes
		// TODO(apenwarr): Remove this once we sort out subnet routes.
		//  Right now default routes are broken in Windows, but
		//  controlclient doesn't properly send subnet routes. So
		//  let's convert a default route into a subnet route in order
		//  to allow experimentation.
		uflags |= controlclient.UHackDefaultRoute
	}
	if uc.AllowSingleHosts {
		uflags |= controlclient.UAllowSingleHosts
	}

	dns := nm.DNS
	dom := nm.DNSDomains
	if !uc.CorpDNS {
		dns = []wgcfg.IP{}
		dom = []string{}
	}
	cfg, err := nm.WGCfg(b.logf, uflags, dns)
	if err != nil {
		b.logf("wgcfg: %v", err)
		return
	}

	err = b.e.Reconfig(cfg, routerConfig(cfg, uc, dom))
	if err == wgengine.ErrNoChanges {
		return
	}
	b.logf("authReconfig: ra=%v dns=%v 0x%02x: %v", uc.RouteAll, uc.CorpDNS, uflags, err)
}

// routerConfig produces a router.Config from a wireguard config,
// IPN prefs, and the dnsDomains pulled from control's network map.
func routerConfig(cfg *wgcfg.Config, prefs *Prefs, dnsDomains []string) *router.Config {
	var addrs []wgcfg.CIDR
	for _, addr := range cfg.Addresses {
		addrs = append(addrs, wgcfg.CIDR{
			IP:   addr.IP,
			Mask: 32,
		})
	}

	rs := &router.Config{
		LocalAddrs:       wgCIDRToNetaddr(addrs),
		DNS:              wgIPToNetaddr(cfg.DNS),
		DNSDomains:       dnsDomains,
		SubnetRoutes:     wgCIDRToNetaddr(prefs.AdvertiseRoutes),
		SNATSubnetRoutes: !prefs.NoSNAT,
		NetfilterMode:    prefs.NetfilterMode,
	}

	for _, peer := range cfg.Peers {
		rs.Routes = append(rs.Routes, wgCIDRToNetaddr(peer.AllowedIPs)...)
	}

	// The Tailscale DNS IP.
	// TODO(dmytro): make this configurable.
	rs.Routes = append(rs.Routes, netaddr.IPPrefix{
		IP:   netaddr.IPv4(100, 100, 100, 100),
		Bits: 32,
	})

	return rs
}

// wgCIDRsToFilter converts lists of wgcfg.CIDR into a single list of
// filter.Net.
func wgCIDRsToFilter(cidrLists ...[]wgcfg.CIDR) (ret []filter.Net) {
	for _, cidrs := range cidrLists {
		for _, cidr := range cidrs {
			if !cidr.IP.Is4() {
				continue
			}
			ret = append(ret, filter.Net{
				IP:   filter.NewIP(cidr.IP.IP()),
				Mask: filter.Netmask(int(cidr.Mask)),
			})
		}
	}
	return ret
}

func wgIPToNetaddr(ips []wgcfg.IP) (ret []netaddr.IP) {
	for _, ip := range ips {
		nip, ok := netaddr.FromStdIP(ip.IP())
		if !ok {
			panic(fmt.Sprintf("conversion of %s from wgcfg to netaddr IP failed", ip))
		}
		ret = append(ret, nip.Unmap())
	}
	return ret
}

func wgCIDRToNetaddr(cidrs []wgcfg.CIDR) (ret []netaddr.IPPrefix) {
	for _, cidr := range cidrs {
		ncidr, ok := netaddr.FromStdIPNet(cidr.IPNet())
		if !ok {
			panic(fmt.Sprintf("conversion of %s from wgcfg to netaddr IPNet failed", cidr))
		}
		ncidr.IP = ncidr.IP.Unmap()
		ret = append(ret, ncidr)
	}
	return ret
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
	b.mu.Unlock()

	if state == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v)",
		state, newState, prefs.WantRunning)
	if notify != nil {
		b.send(Notify{State: &newState})
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
	b.notify(Notify{Status: st})
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
	b.assertClientLocked()
	c := b.c
	b.netMap = nil
	b.mu.Unlock()

	c.Logout()

	b.mu.Lock()
	b.netMap = nil
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

// TestOnlyPublicKeys returns the current machine and node public
// keys. Used in tests only to facilitate automated node authorization
// in the test harness.
func (b *LocalBackend) TestOnlyPublicKeys() (machineKey tailcfg.MachineKey, nodeKey tailcfg.NodeKey) {
	b.mu.Lock()
	prefs := b.prefs
	b.mu.Unlock()

	if prefs == nil {
		return
	}

	mk := prefs.Persist.PrivateMachineKey.Public()
	nk := prefs.Persist.PrivateNodeKey.Public()
	return tailcfg.MachineKey(mk), tailcfg.NodeKey(nk)
}
