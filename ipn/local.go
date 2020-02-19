// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"tailscale.com/control/controlclient"
	"tailscale.com/portlist"
	"tailscale.com/tailcfg"
	"tailscale.com/types/empty"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
)

// LocalBackend is the scaffolding between the Tailscale cloud control
// plane and the local network stack.
type LocalBackend struct {
	logf            logger.Logf
	notify          func(n Notify)
	c               *controlclient.Client
	e               wgengine.Engine
	store           StateStore
	serverURL       string
	backendLogID    string
	portpoll        *portlist.Poller // may be nil
	newDecompressor func() (controlclient.Decompressor, error)
	cmpDiff         func(x, y interface{}) string

	// The mutex protects the following elements.
	mu           sync.Mutex
	stateKey     StateKey
	prefs        Prefs
	state        State
	hiCache      tailcfg.Hostinfo
	netMapCache  *controlclient.NetworkMap
	engineStatus EngineStatus
	endPoints    []string
	blocked      bool
	authURL      string
	interact     int

	// statusLock must be held before calling statusChanged.Lock() or
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
	e.SetFilter(filter.NewAllowNone())

	portpoll, err := portlist.NewPoller()
	if err != nil {
		logf("skipping portlist: %s\n", err)
	}

	b := LocalBackend{
		logf:         logf,
		e:            e,
		store:        store,
		backendLogID: logid,
		state:        NoState,
		portpoll:     portpoll,
	}
	b.statusChanged = sync.NewCond(&b.statusLock)

	if b.portpoll != nil {
		go b.portpoll.Run()
		go b.runPoller()
	}

	return &b, nil
}

func (b *LocalBackend) Shutdown() {
	if b.portpoll != nil {
		b.portpoll.Close()
	}
	b.c.Shutdown()
	b.e.Close()
	b.e.Wait()
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

// SetCmpDiff sets a comparison function used to generate logs of what
// has changed in the network map.
//
// Typically the comparison function comes from go-cmp.
// We don't wire it in directly here because the go-cmp package adds
// 1.77mb to the binary size of the iOS NetworkExtension, which takes
// away from its precious RSS limit.
func (b *LocalBackend) SetCmpDiff(cmpDiff func(x, y interface{}) string) {
	b.cmpDiff = cmpDiff
}

func (b *LocalBackend) Start(opts Options) error {
	if opts.Prefs == nil && opts.StateKey == "" {
		return errors.New("no state key or prefs provided")
	}

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

	if opts.Prefs != nil {
		b.logf("Start: %v\n", opts.Prefs.Pretty())
	} else {
		b.logf("Start\n")
	}

	hi := controlclient.NewHostinfo()
	hi.BackendLogID = b.backendLogID
	hi.FrontendLogID = opts.FrontendLogID

	b.mu.Lock()
	hi.Services = b.hiCache.Services // keep any previous session
	b.hiCache = hi
	b.state = NoState

	if err := b.loadStateWithLock(opts.StateKey, opts.Prefs); err != nil {
		b.mu.Unlock()
		return fmt.Errorf("loading requested state: %v", err)
	}

	b.serverURL = b.prefs.ControlURL
	hi.RoutableIPs = append(hi.RoutableIPs, b.prefs.AdvertiseRoutes...)

	b.notify = opts.Notify
	b.netMapCache = nil
	b.mu.Unlock()

	b.updateFilter()

	var err error
	persist := b.prefs.Persist
	if persist == nil {
		// let controlclient initialize it
		persist = &controlclient.Persist{}
	}
	cli, err := controlclient.New(controlclient.Options{
		Logf: func(fmt string, args ...interface{}) {
			b.logf("control: "+fmt, args...)
		},
		Persist:         *persist,
		ServerURL:       b.serverURL,
		Hostinfo:        &hi,
		KeepAlive:       true,
		NewDecompressor: b.newDecompressor,
	})
	if err != nil {
		return err
	}

	b.mu.Lock()
	b.c = cli
	b.mu.Unlock()

	if b.endPoints != nil {
		cli.UpdateEndpoints(0, b.endPoints)
	}

	cli.SetStatusFunc(func(new controlclient.Status) {
		if new.LoginFinished != nil {
			// Auth completed, unblock the engine
			b.blockEngineUpdates(false)
			b.authReconfig()
			b.send(Notify{LoginFinished: &empty.Message{}})
		}
		if new.Persist != nil {
			persist := *new.Persist // copy
			b.prefs.Persist = &persist
			if b.stateKey != "" {
				if err := b.store.WriteState(b.stateKey, b.prefs.ToBytes()); err != nil {
					b.logf("Failed to save new controlclient state: %v", err)
				}
			}
			np := b.prefs
			b.send(Notify{Prefs: &np})
		}
		if new.NetMap != nil {
			if b.netMapCache != nil && b.cmpDiff != nil {
				s1 := strings.Split(b.netMapCache.Concise(), "\n")
				s2 := strings.Split(new.NetMap.Concise(), "\n")
				b.logf("netmap diff:\n%v\n", b.cmpDiff(s1, s2))
			}
			b.netMapCache = new.NetMap
			b.send(Notify{NetMap: new.NetMap})
			b.updateFilter()
		}
		if new.URL != "" {
			b.logf("Received auth URL: %.20v...\n", new.URL)

			b.mu.Lock()
			interact := b.interact
			b.authURL = new.URL
			b.mu.Unlock()

			if interact > 0 {
				b.popBrowserAuthNow()
			}
		}
		if new.Err != "" {
			// TODO(crawshaw): display in the UI.
			log.Print(new.Err)
			return
		}
		if new.NetMap != nil {
			if b.prefs.WantRunning || b.State() == NeedsLogin {
				b.prefs.WantRunning = true
			}
			b.SetPrefs(b.prefs)
		}
		b.stateMachine()
	})

	b.e.SetStatusCallback(func(s *wgengine.Status, err error) {
		if err != nil {
			b.logf("wgengine status error: %#v", err)
			return
		}
		if s == nil {
			log.Fatalf("weird: non-error wgengine update with status=nil\n")
		}

		b.mu.Lock()
		es := b.parseWgStatus(s)
		b.mu.Unlock()

		b.engineStatus = es

		if b.c != nil {
			b.c.UpdateEndpoints(0, s.LocalAddrs)
		}
		b.endPoints = append([]string{}, s.LocalAddrs...)
		b.stateMachine()

		b.statusLock.Lock()
		b.statusChanged.Broadcast()
		b.statusLock.Unlock()

		b.send(Notify{Engine: &es})
	})

	blid := b.backendLogID
	b.logf("Backend: logs: be:%v fe:%v\n", blid, opts.FrontendLogID)
	b.send(Notify{BackendLogID: &blid})
	nprefs := b.prefs // make a copy
	b.send(Notify{Prefs: &nprefs})

	cli.Login(nil, controlclient.LoginDefault)
	return nil
}

func (b *LocalBackend) updateFilter() {
	if !b.Prefs().UsePacketFilter {
		b.e.SetFilter(filter.NewAllowAll())
	} else if b.netMapCache == nil {
		// Not configured yet, block everything
		b.e.SetFilter(filter.NewAllowNone())
	} else {
		b.logf("netmap packet filter: %v\n", b.netMapCache.PacketFilter)
		b.e.SetFilter(filter.New(b.netMapCache.PacketFilter))
	}
}

func (b *LocalBackend) runPoller() {
	for {
		ports := <-b.portpoll.C
		if ports == nil {
			break
		}
		sl := []tailcfg.Service{}
		for _, p := range ports {
			var proto tailcfg.ServiceProto
			if p.Proto == "tcp" {
				proto = tailcfg.TCP
			} else if p.Proto == "udp" {
				proto = tailcfg.UDP
			}
			if p.Port == 53 || p.Port == 68 ||
				p.Port == 5353 || p.Port == 5355 {
				// uninteresting system services
				continue
			}
			s := tailcfg.Service{
				Proto:       proto,
				Port:        p.Port,
				Description: p.Process,
			}
			sl = append(sl, s)
		}

		b.mu.Lock()
		hi := b.hiCache
		hi.Services = sl
		b.hiCache = hi
		cli := b.c
		b.mu.Unlock()

		// b.c might not be started yet
		if cli != nil {
			cli.SetHostinfo(hi)
		}
	}
}

func (b *LocalBackend) send(n Notify) {
	if b.notify != nil {
		n.Version = version.LONG
		b.notify(n)
	}
}

func (b *LocalBackend) popBrowserAuthNow() {
	b.mu.Lock()
	url := b.authURL
	b.interact = 0
	b.authURL = ""
	b.mu.Unlock()
	b.logf("popBrowserAuthNow: url=%v\n", url != "")

	b.blockEngineUpdates(true)
	b.stopEngineAndWait()
	b.send(Notify{BrowseToURL: &url})
	if b.State() == Running {
		b.enterState(Starting)
	}
}

func (b *LocalBackend) loadStateWithLock(key StateKey, prefs *Prefs) error {
	if prefs == nil && key == "" {
		panic("state key and prefs are both unset")
	}

	if key == "" {
		// Frontend fully owns the state, we just need to obey it.
		b.logf("Using frontend prefs")
		b.prefs = *prefs
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
		if err == ErrStateNotExist {
			b.prefs = NewPrefs()
			b.stateKey = key
			b.logf("Created empty state for %q", key)
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

func (b *LocalBackend) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.state
}

func (b *LocalBackend) EngineStatus() EngineStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.engineStatus
}

func (b *LocalBackend) StartLoginInteractive() {
	b.assertClient()
	b.mu.Lock()
	b.interact++
	url := b.authURL
	b.mu.Unlock()
	b.logf("StartLoginInteractive: url=%v\n", url != "")

	if url != "" {
		b.popBrowserAuthNow()
	} else {
		b.c.Login(nil, controlclient.LoginInteractive)
	}
}

func (b *LocalBackend) FakeExpireAfter(x time.Duration) {
	b.logf("FakeExpireAfter: %v\n", x)
	if b.netMapCache != nil {
		e := b.netMapCache.Expiry
		if e.IsZero() || time.Until(e) > x {
			b.netMapCache.Expiry = time.Now().Add(x)
		}
		b.send(Notify{NetMap: b.netMapCache})
	}
}

func (b *LocalBackend) LocalAddrs() []wgcfg.CIDR {
	if b.netMapCache != nil {
		return b.netMapCache.Addresses
	} else {
		return nil
	}
}

func (b *LocalBackend) Expiry() time.Time {
	if b.netMapCache != nil {
		return b.netMapCache.Expiry
	} else {
		return time.Time{}
	}
}

func (b *LocalBackend) parseWgStatus(s *wgengine.Status) EngineStatus {
	var ss []string
	var rx, tx wgengine.ByteCount
	peers := make(map[tailcfg.NodeKey]wgengine.PeerStatus)

	live := 0
	for _, p := range s.Peers {
		if p.LastHandshake.IsZero() {
			ss = append(ss, "x")
		} else {
			ss = append(ss, fmt.Sprintf("%d/%d", p.RxBytes, p.TxBytes))
			live++
			peers[p.NodeKey] = p
		}
		rx += p.RxBytes
		tx += p.TxBytes
	}
	b.logf("v%v peers: %v\n", version.LONG, strings.Join(ss, " "))
	return EngineStatus{
		RBytes:    rx,
		WBytes:    tx,
		NumLive:   live,
		LivePeers: peers,
	}
}

func (b *LocalBackend) AdminPageURL() string {
	return b.serverURL + "/admin/machines"
}

func (b *LocalBackend) Prefs() Prefs {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.prefs
}

func (b *LocalBackend) SetPrefs(new Prefs) {
	b.mu.Lock()
	old := b.prefs
	new.Persist = old.Persist // caller isn't allowed to override this
	b.prefs = new
	if b.stateKey != "" {
		if err := b.store.WriteState(b.stateKey, b.prefs.ToBytes()); err != nil {
			b.logf("Failed to save new controlclient state: %v", err)
		}
	}
	oldHi := b.hiCache
	newHi := oldHi.Copy()
	newHi.RoutableIPs = append([]wgcfg.CIDR(nil), b.prefs.AdvertiseRoutes...)
	b.hiCache = *newHi
	cli := b.c
	b.mu.Unlock()

	if cli != nil && !oldHi.Equal(newHi) {
		cli.SetHostinfo(*newHi)
	}

	if old.WantRunning != new.WantRunning {
		b.stateMachine()
	} else {
		b.authReconfig()
	}

	b.logf("SetPrefs: %v\n", new.Pretty())
	b.send(Notify{Prefs: &new})
}

// Note: return value may be nil, if we haven't received a netmap yet.
func (b *LocalBackend) NetMap() *controlclient.NetworkMap {
	return b.netMapCache
}

func (b *LocalBackend) blockEngineUpdates(block bool) {
	// TODO(apenwarr): probably need mutex here (and several other places)
	b.logf("blockEngineUpdates(%v)\n", block)

	b.mu.Lock()
	b.blocked = block
	b.mu.Unlock()
}

func (b *LocalBackend) authReconfig() {
	b.mu.Lock()
	blocked := b.blocked
	uc := b.prefs
	nm := b.netMapCache
	b.mu.Unlock()

	if blocked {
		b.logf("authReconfig: blocked, skipping.\n")
		return
	}
	if nm == nil {
		b.logf("authReconfig: netmap not yet valid. Skipping.\n")
		return
	}
	if !uc.WantRunning {
		b.logf("authReconfig: skipping because !WantRunning.\n")
		return
	}
	b.logf("Configuring wireguard connection.\n")

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
	b.logf("reconfig: ra=%v dns=%v 0x%02x\n", uc.RouteAll, uc.CorpDNS, uflags)

	if nm != nil {
		dns := nm.DNS
		dom := nm.DNSDomains
		if !uc.CorpDNS {
			dns = []wgcfg.IP{}
			dom = []string{}
		}
		cfg, err := nm.WGCfg(uflags, dns)
		if err != nil {
			log.Fatalf("WGCfg: %v\n", err)
		}

		err = b.e.Reconfig(cfg, dom)
		if err != nil {
			b.logf("reconfig: %v", err)
		}
	}
}

func (b *LocalBackend) enterState(newState State) {
	b.mu.Lock()
	state := b.state
	prefs := b.prefs
	b.mu.Unlock()

	if state == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v)\n",
		state, newState, prefs.WantRunning)
	if b.notify != nil {
		b.send(Notify{State: &newState})
	}

	b.state = newState
	switch newState {
	case NeedsLogin:
		b.blockEngineUpdates(true)
		fallthrough
	case Stopped:
		err := b.e.Reconfig(&wgcfg.Config{}, nil)
		if err != nil {
			b.logf("Reconfig(down): %v\n", err)
		}
	case Starting, NeedsMachineAuth:
		b.authReconfig()
		// Needed so that UpdateEndpoints can run
		b.e.RequestStatus()
	case Running:
		break
	default:
		b.logf("Weird: unknown newState %#v\n", newState)
	}

}

func (b *LocalBackend) nextState() State {
	b.assertClient()
	state := b.State()

	if b.netMapCache == nil {
		if b.c.AuthCantContinue() {
			// Auth was interrupted or waiting for URL visit,
			// so it won't proceed without human help.
			return NeedsLogin
		} else {
			// Auth or map request needs to finish
			return state
		}
	} else if !b.prefs.WantRunning {
		return Stopped
	} else if e := b.netMapCache.Expiry; !e.IsZero() && time.Until(e) <= 0 {
		return NeedsLogin
	} else if b.netMapCache.MachineStatus != tailcfg.MachineAuthorized {
		// TODO(crawshaw): handle tailcfg.MachineInvalid
		return NeedsMachineAuth
	} else if state == NeedsMachineAuth {
		// (if we get here, we know MachineAuthorized == true)
		return Starting
	} else if state == Starting {
		if b.EngineStatus().NumLive > 0 {
			return Running
		} else {
			return state
		}
	} else if state == Running {
		return Running
	} else {
		return Starting
	}
}

func (b *LocalBackend) RequestEngineStatus() {
	b.e.RequestStatus()
}

// TODO(apenwarr): use a channel or something to prevent re-entrancy?
//  Or maybe just call the state machine from fewer places.
func (b *LocalBackend) stateMachine() {
	b.enterState(b.nextState())
}

func (b *LocalBackend) stopEngineAndWait() {
	b.logf("stopEngineAndWait...\n")
	b.e.Reconfig(&wgcfg.Config{}, nil)
	b.requestEngineStatusAndWait()
	b.logf("stopEngineAndWait: done.\n")
}

// Requests the wgengine status, and does not return until the status
// was delivered (to the usual callback).
func (b *LocalBackend) requestEngineStatusAndWait() {
	b.logf("requestEngineStatusAndWait\n")

	b.statusLock.Lock()
	go b.e.RequestStatus()
	b.logf("requestEngineStatusAndWait: waiting...\n")
	b.statusChanged.Wait() // temporarily releases lock while waiting
	b.logf("requestEngineStatusAndWait: got status update.\n")
	b.statusLock.Unlock()
}

// NOTE(apenwarr): No easy way to persist logged-out status.
//  Maybe that's for the better; if someone logs out accidentally,
//  rebooting will fix it.
func (b *LocalBackend) Logout() {
	b.assertClient()
	b.netMapCache = nil
	b.c.Logout()
	b.netMapCache = nil
	b.stateMachine()
}

func (b *LocalBackend) assertClient() {
	if b.c == nil {
		panic("LocalBackend.assertClient: b.c == nil")
	}
}
