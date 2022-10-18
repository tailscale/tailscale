// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/netipx"
	"golang.org/x/exp/slices"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/control/controlclient"
	"tailscale.com/doctor"
	"tailscale.com/doctor/routetable"
	"tailscale.com/envknob"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/policy"
	"tailscale.com/net/dns"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netutil"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/paths"
	"tailscale.com/portlist"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/types/views"
	"tailscale.com/util/deephash"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
	"tailscale.com/util/osshare"
	"tailscale.com/util/systemd"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
	"tailscale.com/wgengine/wgcfg/nmcfg"
)

var controlDebugFlags = getControlDebugFlags()

func getControlDebugFlags() []string {
	if e := envknob.String("TS_DEBUG_CONTROL_FLAGS"); e != "" {
		return strings.Split(e, ",")
	}
	return nil
}

// SSHServer is the interface of the conditionally linked ssh/tailssh.server.
type SSHServer interface {
	HandleSSHConn(net.Conn) error

	// OnPolicyChange is called when the SSH access policy changes,
	// so that existing sessions can be re-evaluated for validity
	// and closed if they'd no longer be accepted.
	OnPolicyChange()

	// Shutdown is called when tailscaled is shutting down.
	Shutdown()
}

type newSSHServerFunc func(logger.Logf, *LocalBackend) (SSHServer, error)

var newSSHServer newSSHServerFunc // or nil

// RegisterNewSSHServer lets the conditionally linked ssh/tailssh package register itself.
func RegisterNewSSHServer(fn newSSHServerFunc) {
	newSSHServer = fn
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
	dialer                *tsdial.Dialer // non-nil
	backendLogID          string
	unregisterLinkMon     func()
	unregisterHealthWatch func()
	portpoll              *portlist.Poller // may be nil
	portpollOnce          sync.Once        // guards starting readPoller
	gotPortPollRes        chan struct{}    // closed upon first readPoller result
	serverURL             string           // tailcontrol URL
	newDecompressor       func() (controlclient.Decompressor, error)
	varRoot               string // or empty if SetVarRoot never called
	sshAtomicBool         atomic.Bool
	shutdownCalled        bool // if Shutdown has been called

	filterAtomic            atomic.Pointer[filter.Filter]
	containsViaIPFuncAtomic syncs.AtomicValue[func(netip.Addr) bool]

	// The mutex protects the following elements.
	mu             sync.Mutex
	filterHash     deephash.Sum
	httpTestClient *http.Client // for controlclient. nil by default, used by tests.
	ccGen          clientGen    // function for producing controlclient; lazily populated
	sshServer      SSHServer    // or nil, initialized lazily.
	notify         func(ipn.Notify)
	cc             controlclient.Client
	ccAuto         *controlclient.Auto // if cc is of type *controlclient.Auto
	stateKey       ipn.StateKey        // computed in part from user-provided value
	userID         string              // current controlling user ID (for Windows, primarily)
	prefs          *ipn.Prefs
	inServerMode   bool
	machinePrivKey key.MachinePrivate
	nlPrivKey      key.NLPrivate
	tka            *tkaState
	state          ipn.State
	capFileSharing bool // whether netMap contains the file sharing capability
	// hostinfo is mutated in-place while mu is held.
	hostinfo *tailcfg.Hostinfo
	// netMap is not mutated in-place once set.
	netMap           *netmap.NetworkMap
	nodeByAddr       map[netip.Addr]*tailcfg.Node
	activeLogin      string // last logged LoginName from netMap
	engineStatus     ipn.EngineStatus
	endpoints        []tailcfg.Endpoint
	blocked          bool
	keyExpired       bool
	authURL          string // cleared on Notify
	authURLSticky    string // not cleared on Notify
	interact         bool
	egg              bool
	prevIfState      *interfaces.State
	peerAPIServer    *peerAPIServer // or nil
	peerAPIListeners []*peerAPIListener
	loginFlags       controlclient.LoginFlags
	incomingFiles    map[*incomingFile]bool
	lastStatusTime   time.Time // status.AsOf value of the last processed status update
	// directFileRoot, if non-empty, means to write received files
	// directly to this directory, without staging them in an
	// intermediate buffered directory for "pick-up" later. If
	// empty, the files are received in a daemon-owned location
	// and the localapi is used to enumerate, download, and delete
	// them. This is used on macOS where the GUI lifetime is the
	// same as the Network Extension lifetime and we can thus avoid
	// double-copying files by writing them to the right location
	// immediately.
	// It's also used on several NAS platforms (Synology, TrueNAS, etc)
	// but in that case DoFinalRename is also set true, which moves the
	// *.partial file to its final name on completion.
	directFileRoot          string
	directFileDoFinalRename bool // false on macOS, true on several NAS platforms
	componentLogUntil       map[string]componentLogState

	// statusLock must be held before calling statusChanged.Wait() or
	// statusChanged.Broadcast().
	statusLock    sync.Mutex
	statusChanged *sync.Cond

	// dialPlan is any dial plan that we've received from the control
	// server during a previous connection; it is cleared on logout.
	dialPlan atomic.Pointer[tailcfg.ControlDialPlan]

	// tkaSyncLock is used to make tkaSyncIfNeeded an exclusive
	// section. This is needed to stop two map-responses in quick succession
	// from racing each other through TKA sync logic / RPCs.
	//
	// tkaSyncLock MUST be taken before mu (or inversely, mu must not be held
	// at the moment that tkaSyncLock is taken).
	tkaSyncLock sync.Mutex
}

// clientGen is a func that creates a control plane client.
// It's the type used by LocalBackend.SetControlClientGetterForTesting.
type clientGen func(controlclient.Options) (controlclient.Client, error)

// NewLocalBackend returns a new LocalBackend that is ready to run,
// but is not actually running.
//
// If dialer is nil, a new one is made.
func NewLocalBackend(logf logger.Logf, logid string, store ipn.StateStore, dialer *tsdial.Dialer, e wgengine.Engine, loginFlags controlclient.LoginFlags) (*LocalBackend, error) {
	if e == nil {
		panic("ipn.NewLocalBackend: engine must not be nil")
	}

	hi := hostinfo.New()
	logf.JSON(1, "Hostinfo", hi)
	envknob.LogCurrent(logf)
	if dialer == nil {
		dialer = &tsdial.Dialer{Logf: logf}
	}

	osshare.SetFileSharingEnabled(false, logf)

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
		dialer:         dialer,
		backendLogID:   logid,
		state:          ipn.NoState,
		portpoll:       portpoll,
		gotPortPollRes: make(chan struct{}),
		loginFlags:     loginFlags,
	}

	// Default filter blocks everything and logs nothing, until Start() is called.
	b.setFilter(filter.NewAllowNone(logf, &netipx.IPSet{}))

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
		if tunWrap, _, _, ok := ig.GetInternals(); ok {
			tunWrap.PeerAPIPort = b.GetPeerAPIPort
			wiredPeerAPIPort = true
		}
	}
	if !wiredPeerAPIPort {
		b.logf("[unexpected] failed to wire up peer API port for engine %T", e)
	}

	for _, component := range debuggableComponents {
		key := componentStateKey(component)
		if ut, err := ipn.ReadStoreInt(store, key); err == nil {
			if until := time.Unix(ut, 0); until.After(time.Now()) {
				// conditional to avoid log spam at start when off
				b.SetComponentDebugLogging(component, until)
			}
		}
	}

	return b, nil
}

type componentLogState struct {
	until time.Time
	timer *time.Timer // if non-nil, the AfterFunc to disable it
}

var debuggableComponents = []string{
	"magicsock",
}

func componentStateKey(component string) ipn.StateKey {
	return ipn.StateKey("_debug_" + component + "_until")
}

// SetComponentDebugLogging sets component's debug logging enabled until the until time.
// If until is in the past, the component's debug logging is disabled.
//
// The following components are recognized:
//
//   - magicsock
func (b *LocalBackend) SetComponentDebugLogging(component string, until time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var setEnabled func(bool)
	switch component {
	case "magicsock":
		mc, err := b.magicConn()
		if err != nil {
			return err
		}
		setEnabled = mc.SetDebugLoggingEnabled
	}
	if setEnabled == nil || !slices.Contains(debuggableComponents, component) {
		return fmt.Errorf("unknown component %q", component)
	}
	timeUnixOrZero := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Unix()
	}
	ipn.PutStoreInt(b.store, componentStateKey(component), timeUnixOrZero(until))
	now := time.Now()
	on := now.Before(until)
	setEnabled(on)
	var onFor time.Duration
	if on {
		onFor = until.Sub(now)
		b.logf("debugging logging for component %q enabled for %v (until %v)", component, onFor.Round(time.Second), until.UTC().Format(time.RFC3339))
	} else {
		b.logf("debugging logging for component %q disabled", component)
	}
	if oldSt, ok := b.componentLogUntil[component]; ok && oldSt.timer != nil {
		oldSt.timer.Stop()
	}
	newSt := componentLogState{until: until}
	if on {
		newSt.timer = time.AfterFunc(onFor, func() {
			// Turn off logging after the timer fires, as long as the state is
			// unchanged when the timer actually fires.
			b.mu.Lock()
			defer b.mu.Unlock()
			if ls := b.componentLogUntil[component]; ls.until == until {
				setEnabled(false)
				b.logf("debugging logging for component %q disabled (by timer)", component)
			}
		})
	}
	mak.Set(&b.componentLogUntil, component, newSt)
	return nil
}

// GetComponentDebugLogging gets the time that component's debug logging is
// enabled until, or the zero time if component's time is not currently
// enabled.
func (b *LocalBackend) GetComponentDebugLogging(component string) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	ls := b.componentLogUntil[component]
	if ls.until.IsZero() || ls.until.Before(now) {
		return time.Time{}
	}
	return ls.until
}

// Dialer returns the backend's dialer.
func (b *LocalBackend) Dialer() *tsdial.Dialer {
	return b.dialer
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

// SetDirectFileDoFinalRename sets whether the peerapi file server should rename
// a received "name.partial" file to "name" when the download is complete.
//
// This only applies when SetDirectFileRoot is non-empty.
// The default is false.
func (b *LocalBackend) SetDirectFileDoFinalRename(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.directFileDoFinalRename = v
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
	b.updateFilterLocked(b.netMap, b.prefs)

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
	if b.shutdownCalled {
		b.mu.Unlock()
		return
	}
	b.shutdownCalled = true

	if b.loginFlags&controlclient.LoginEphemeral != 0 {
		b.mu.Unlock()
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		defer cancel()
		b.LogoutSync(ctx) // best effort
		b.mu.Lock()
	}
	cc := b.cc
	if b.sshServer != nil {
		b.sshServer.Shutdown()
		b.sshServer = nil
	}
	b.closePeerAPIListenersLocked()
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
		p.Persist.PrivateNodeKey = key.NodePrivate{}
		p.Persist.OldPrivateNodeKey = key.NodePrivate{}
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
			case multierr.Error:
				for _, err := range e.Errors() {
					s.Health = append(s.Health, err.Error())
				}
			default:
				s.Health = append(s.Health, err.Error())
			}
		}
		if m := b.sshOnButUnusableHealthCheckMessageLocked(); m != "" {
			s.Health = append(s.Health, m)
		}
		if b.netMap != nil {
			s.CertDomains = append([]string(nil), b.netMap.DNS.CertDomains...)
			s.MagicDNSSuffix = b.netMap.MagicDNSSuffix()
			if s.CurrentTailnet == nil {
				s.CurrentTailnet = &ipnstate.TailnetStatus{}
			}
			s.CurrentTailnet.MagicDNSSuffix = b.netMap.MagicDNSSuffix()
			s.CurrentTailnet.MagicDNSEnabled = b.netMap.DNS.Proxied
			s.CurrentTailnet.Name = b.netMap.Domain
			if b.prefs != nil && !b.prefs.ExitNodeID.IsZero() {
				if exitPeer, ok := b.netMap.PeerWithStableID(b.prefs.ExitNodeID); ok {
					var online = false
					if exitPeer.Online != nil {
						online = *exitPeer.Online
					}
					s.ExitNodeStatus = &ipnstate.ExitNodeStatus{
						ID:           b.prefs.ExitNodeID,
						Online:       online,
						TailscaleIPs: exitPeer.Addresses,
					}
				}

			}
		}
	})
	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
		ss.Online = health.GetInPollNetMap()
		if b.netMap != nil {
			ss.HostName = b.netMap.Hostinfo.Hostname
			ss.DNSName = b.netMap.Name
			ss.UserID = b.netMap.User
			if sn := b.netMap.SelfNode; sn != nil {
				ss.ID = sn.StableID
				if c := sn.Capabilities; len(c) > 0 {
					ss.Capabilities = append([]string(nil), c...)
				}
			}
		} else {
			ss.HostName, _ = os.Hostname()
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
		var tailscaleIPs = make([]netip.Addr, 0, len(p.Addresses))
		for _, addr := range p.Addresses {
			if addr.IsSingleIP() && tsaddr.IsTailscaleIP(addr.Addr()) {
				tailscaleIPs = append(tailscaleIPs, addr.Addr())
			}
		}
		exitNodeOption := tsaddr.PrefixesContainsFunc(p.AllowedIPs, func(r netip.Prefix) bool {
			return r.Bits() == 0
		})
		var tags *views.Slice[string]
		var primaryRoutes *views.IPPrefixSlice
		if p.Tags != nil {
			v := views.SliceOf(p.Tags)
			tags = &v
		}
		if p.PrimaryRoutes != nil {
			v := views.IPPrefixSliceOf(p.PrimaryRoutes)
			primaryRoutes = &v
		}
		sb.AddPeer(p.Key, &ipnstate.PeerStatus{
			InNetworkMap:   true,
			ID:             p.StableID,
			UserID:         p.User,
			TailscaleIPs:   tailscaleIPs,
			Tags:           tags,
			PrimaryRoutes:  primaryRoutes,
			HostName:       p.Hostinfo.Hostname(),
			DNSName:        p.Name,
			OS:             p.Hostinfo.OS(),
			KeepAlive:      p.KeepAlive,
			Created:        p.Created,
			LastSeen:       lastSeen,
			Online:         p.Online != nil && *p.Online,
			ShareeNode:     p.Hostinfo.ShareeNode(),
			ExitNode:       p.StableID != "" && p.StableID == b.prefs.ExitNodeID,
			ExitNodeOption: exitNodeOption,
			SSH_HostKeys:   p.Hostinfo.SSH_HostKeys().AsSlice(),
		})
	}
}

// WhoIs reports the node and user who owns the node with the given IP:port.
// If the IP address is a Tailscale IP, the provided port may be 0.
// If ok == true, n and u are valid.
func (b *LocalBackend) WhoIs(ipp netip.AddrPort) (n *tailcfg.Node, u tailcfg.UserProfile, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok = b.nodeByAddr[ipp.Addr()]
	if !ok {
		var ip netip.Addr
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

// PeerCaps returns the capabilities that remote src IP has to
// ths current node.
func (b *LocalBackend) PeerCaps(src netip.Addr) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.peerCapsLocked(src)
}

func (b *LocalBackend) peerCapsLocked(src netip.Addr) []string {
	if b.netMap == nil {
		return nil
	}
	filt := b.filterAtomic.Load()
	if filt == nil {
		return nil
	}
	for _, a := range b.netMap.Addresses {
		if !a.IsSingleIP() {
			continue
		}
		dst := a.Addr()
		if dst.BitLen() == src.BitLen() { // match on family
			return filt.AppendCaps(nil, src, dst)
		}
	}
	return nil
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
	if st.Err != nil {
		// TODO(crawshaw): display in the UI.
		if errors.Is(st.Err, io.EOF) {
			b.logf("[v1] Received error: EOF")
			return
		}
		b.logf("Received error: %v", st.Err)
		var uerr controlclient.UserVisibleError
		if errors.As(st.Err, &uerr) {
			s := uerr.UserVisibleError()
			b.send(ipn.Notify{ErrMessage: &s})
		}
		return
	}

	b.mu.Lock()
	wasBlocked := b.blocked
	keyExpiryExtended := false
	if st.NetMap != nil {
		wasExpired := b.keyExpired
		isExpired := !st.NetMap.Expiry.IsZero() && st.NetMap.Expiry.Before(time.Now())
		if wasExpired && !isExpired {
			keyExpiryExtended = true
		}
		b.keyExpired = isExpired
	}
	b.mu.Unlock()

	if keyExpiryExtended && wasBlocked {
		// Key extended, unblock the engine
		b.blockEngineUpdates(false)
	}

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
		b.e.SetNetworkMap(new(netmap.NetworkMap))
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
		b.mu.Unlock() // respect locking rules for tkaSyncIfNeeded
		if err := b.tkaSyncIfNeeded(st.NetMap); err != nil {
			b.logf("[v1] TKA sync error: %v", err)
		}
		b.mu.Lock()

		if !envknob.TKASkipSignatureCheck() {
			b.tkaFilterNetmapLocked(st.NetMap)
		}
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
	if st.NetMap != nil {
		b.updateFilterLocked(st.NetMap, prefs)
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
				b.logf("[v1] netmap diff:\n%v", diff)
			}
		}

		b.e.SetNetworkMap(st.NetMap)
		b.e.SetDERPMap(st.NetMap.DERPMap)

		// Update our cached DERP map
		dnsfallback.UpdateCache(st.NetMap.DERPMap)

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
	if nm == nil {
		// No netmap, can't resolve anything.
		return false
	}

	// If we have a desired IP on file, try to find the corresponding
	// node.
	if !b.prefs.ExitNodeIP.IsValid() {
		return false
	}

	// IP takes precedence over ID, so if both are set, clear ID.
	if b.prefs.ExitNodeID != "" {
		b.prefs.ExitNodeID = ""
		prefsChanged = true
	}

	for _, peer := range nm.Peers {
		for _, addr := range peer.Addresses {
			if !addr.IsSingleIP() || addr.Addr() != b.prefs.ExitNodeIP {
				continue
			}
			// Found the node being referenced, upgrade prefs to
			// reference it directly for next time.
			b.prefs.ExitNodeID = peer.StableID
			b.prefs.ExitNodeIP = netip.Addr{}
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
	if s.AsOf.Before(b.lastStatusTime) {
		// Don't process a status update that is older than the one we have
		// already processed. (corp#2579)
		b.mu.Unlock()
		return
	}
	b.lastStatusTime = s.AsOf
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
			cc.UpdateEndpoints(s.LocalAddrs)
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
// TODO(apenwarr): we shouldn't need this. The state machine is now
// nearly clean enough where it can accept a new connection while in
// any state, not just Running, and on any platform.  We'd want to add
// a few more tests to state_test.go to ensure this continues to work
// as expected.
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
	hostinfo.Userspace.Set(wgengine.IsNetstack(b.e))
	hostinfo.UserspaceRouter.Set(wgengine.IsNetstackRouter(b.e))

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
		hostinfo.Services = b.hostinfo.Services // keep any previous services
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
		b.setAtomicValuesFromPrefs(b.prefs)
	}

	wantRunning := b.prefs.WantRunning
	if wantRunning {
		if err := b.initMachineKeyLocked(); err != nil {
			return fmt.Errorf("initMachineKeyLocked: %w", err)
		}
	}
	if err := b.initNLKeyLocked(); err != nil {
		return fmt.Errorf("initNLKeyLocked: %w", err)
	}

	loggedOut := b.prefs.LoggedOut

	b.inServerMode = b.prefs.ForceDaemon
	b.serverURL = b.prefs.ControlURLOrDefault()
	if b.inServerMode || runtime.GOOS == "windows" {
		b.logf("Start: serverMode=%v", b.inServerMode)
	}
	b.applyPrefsToHostinfo(hostinfo, b.prefs)

	b.setNetMapLocked(nil)
	persistv := b.prefs.Persist
	b.updateFilterLocked(nil, nil)
	b.mu.Unlock()

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
				b.logf("[v1] got initial portlist info in %v", time.Since(t0).Round(time.Millisecond))
				timer.Stop()
			case <-timer.C:
				b.logf("timeout waiting for initial portlist")
			}
		})
	}

	discoPublic := b.e.DiscoPublicKey()

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
		GetNLPublicKey:       b.createGetNLPublicKeyFunc(),
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
		Pinger:               b,
		PopBrowserURL:        b.tellClientToBrowseToURL,
		Dialer:               b.Dialer(),
		Status:               b.setClientStatus,
		C2NHandler:           http.HandlerFunc(b.handleC2N),
		DialPlan:             &b.dialPlan, // pointer because it can't be copied

		// Don't warn about broken Linux IP forwarding when
		// netstack is being used.
		SkipIPForwardingCheck: isNetstack,
	})
	if err != nil {
		return err
	}

	b.mu.Lock()
	b.cc = cc
	b.ccAuto, _ = cc.(*controlclient.Auto)
	endpoints := b.endpoints
	b.mu.Unlock()

	if endpoints != nil {
		cc.UpdateEndpoints(endpoints)
	}

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

// updateFilterLocked updates the packet filter in wgengine based on the
// given netMap and user preferences.
//
// b.mu must be held.
func (b *LocalBackend) updateFilterLocked(netMap *netmap.NetworkMap, prefs *ipn.Prefs) {
	// NOTE(danderson): keep change detection as the first thing in
	// this function. Don't try to optimize by returning early, more
	// likely than not you'll just end up breaking the change
	// detection and end up with the wrong filter installed. This is
	// quite hard to debug, so save yourself the trouble.
	var (
		haveNetmap   = netMap != nil
		addrs        []netip.Prefix
		packetFilter []filter.Match
		localNetsB   netipx.IPSetBuilder
		logNetsB     netipx.IPSetBuilder
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
				localInterfaceRoutes, hostIPs, err := interfaceRoutes()
				if err != nil {
					b.logf("getting local interface routes: %v", err)
					continue
				}
				s, err := shrinkDefaultRoute(r, localInterfaceRoutes, hostIPs)
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
	var sshPol tailcfg.SSHPolicy
	if haveNetmap && netMap.SSHPolicy != nil {
		sshPol = *netMap.SSHPolicy
	}

	changed := deephash.Update(&b.filterHash, &struct {
		HaveNetmap  bool
		Addrs       []netip.Prefix
		FilterMatch []filter.Match
		LocalNets   []netipx.IPRange
		LogNets     []netipx.IPRange
		ShieldsUp   bool
		SSHPolicy   tailcfg.SSHPolicy
	}{haveNetmap, addrs, packetFilter, localNets.Ranges(), logNets.Ranges(), shieldsUp, sshPol})
	if !changed {
		return
	}

	if !haveNetmap {
		b.logf("[v1] netmap packet filter: (not ready yet)")
		b.setFilter(filter.NewAllowNone(b.logf, logNets))
		return
	}

	oldFilter := b.e.GetFilter()
	if shieldsUp {
		b.logf("[v1] netmap packet filter: (shields up)")
		b.setFilter(filter.NewShieldsUpFilter(localNets, logNets, oldFilter, b.logf))
	} else {
		b.logf("[v1] netmap packet filter: %v filters", len(packetFilter))
		b.setFilter(filter.New(packetFilter, localNets, logNets, oldFilter, b.logf))
	}

	if b.sshServer != nil {
		go b.sshServer.OnPolicyChange()
	}
}

func (b *LocalBackend) setFilter(f *filter.Filter) {
	b.filterAtomic.Store(f)
	b.e.SetFilter(f)
}

var removeFromDefaultRoute = []netip.Prefix{
	// RFC1918 LAN ranges
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("10.0.0.0/8"),
	// IPv4 link-local
	netip.MustParsePrefix("169.254.0.0/16"),
	// IPv4 multicast
	netip.MustParsePrefix("224.0.0.0/4"),
	// Tailscale IPv4 range
	tsaddr.CGNATRange(),
	// IPv6 Link-local addresses
	netip.MustParsePrefix("fe80::/10"),
	// IPv6 multicast
	netip.MustParsePrefix("ff00::/8"),
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
func internalAndExternalInterfaces() (internal, external []netip.Prefix, err error) {
	il, err := interfaces.GetList()
	if err != nil {
		return nil, nil, err
	}
	return internalAndExternalInterfacesFrom(il, runtime.GOOS)
}

func internalAndExternalInterfacesFrom(il interfaces.List, goos string) (internal, external []netip.Prefix, err error) {
	// We use an IPSetBuilder here to canonicalize the prefixes
	// and to remove any duplicate entries.
	var internalBuilder, externalBuilder netipx.IPSetBuilder
	if err := il.ForeachInterfaceAddress(func(iface interfaces.Interface, pfx netip.Prefix) {
		if tsaddr.IsTailscaleIP(pfx.Addr()) {
			return
		}
		if pfx.IsSingleIP() {
			return
		}
		if iface.IsLoopback() {
			internalBuilder.AddPrefix(pfx)
			return
		}
		if goos == "windows" {
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
				internalBuilder.AddPrefix(pfx)
				return
			}
		}
		externalBuilder.AddPrefix(pfx)
	}); err != nil {
		return nil, nil, err
	}
	iSet, err := internalBuilder.IPSet()
	if err != nil {
		return nil, nil, err
	}
	eSet, err := externalBuilder.IPSet()
	if err != nil {
		return nil, nil, err
	}

	return iSet.Prefixes(), eSet.Prefixes(), nil
}

func interfaceRoutes() (ips *netipx.IPSet, hostIPs []netip.Addr, err error) {
	var b netipx.IPSetBuilder
	if err := interfaces.ForeachInterfaceAddress(func(_ interfaces.Interface, pfx netip.Prefix) {
		if tsaddr.IsTailscaleIP(pfx.Addr()) {
			return
		}
		if pfx.IsSingleIP() {
			return
		}
		hostIPs = append(hostIPs, pfx.Addr())
		b.AddPrefix(pfx)
	}); err != nil {
		return nil, nil, err
	}

	ipSet, _ := b.IPSet()
	return ipSet, hostIPs, nil
}

// shrinkDefaultRoute returns an IPSet representing the IPs in route,
// minus those in removeFromDefaultRoute and localInterfaceRoutes,
// plus the IPs in hostIPs.
func shrinkDefaultRoute(route netip.Prefix, localInterfaceRoutes *netipx.IPSet, hostIPs []netip.Addr) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	// Add the default route.
	b.AddPrefix(route)
	// Remove the local interface routes.
	b.RemoveSet(localInterfaceRoutes)

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
func dnsCIDRsEqual(newAddr, oldAddr []netip.Prefix) bool {
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

	if apiSrv.hasFilesWaiting() {
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
	b.tellClientToBrowseToURL(url)
	if b.State() == ipn.Running {
		b.enterState(ipn.Starting)
	}
}

func (b *LocalBackend) tellClientToBrowseToURL(url string) {
	if url != "" {
		b.send(ipn.Notify{BrowseToURL: &url})
	}
}

// For testing lazy machine key generation.
var panicOnMachineKeyGeneration = envknob.RegisterBool("TS_DEBUG_PANIC_MACHINE_KEY")

func (b *LocalBackend) createGetMachinePrivateKeyFunc() func() (key.MachinePrivate, error) {
	var cache syncs.AtomicValue[key.MachinePrivate]
	return func() (key.MachinePrivate, error) {
		if panicOnMachineKeyGeneration() {
			panic("machine key generated")
		}
		if v, ok := cache.LoadOk(); ok {
			return v, nil
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if v, ok := cache.LoadOk(); ok {
			return v, nil
		}
		if err := b.initMachineKeyLocked(); err != nil {
			return key.MachinePrivate{}, err
		}
		cache.Store(b.machinePrivKey)
		return b.machinePrivKey, nil
	}
}

func (b *LocalBackend) createGetNLPublicKeyFunc() func() (key.NLPublic, error) {
	var cache syncs.AtomicValue[key.NLPublic]
	return func() (key.NLPublic, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if v, ok := cache.LoadOk(); ok {
			return v, nil
		}

		pub := b.nlPrivKey.Public()
		cache.Store(pub)
		return pub, nil
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

// initNLKeyLocked is called to initialize b.nlPrivKey.
//
// b.prefs must already be initialized.
// b.stateKey should be set too, but just for nicer log messages.
// b.mu must be held.
func (b *LocalBackend) initNLKeyLocked() (err error) {
	if !b.nlPrivKey.IsZero() {
		// Already set.
		return nil
	}

	keyText, err := b.store.ReadState(ipn.NLKeyStateKey)
	if err == nil {
		if err := b.nlPrivKey.UnmarshalText(keyText); err != nil {
			return fmt.Errorf("invalid key in %s key of %v: %w", ipn.NLKeyStateKey, b.store, err)
		}
		if b.nlPrivKey.IsZero() {
			return fmt.Errorf("invalid zero key stored in %v key of %v", ipn.NLKeyStateKey, b.store)
		}
		return nil
	}
	if err != ipn.ErrStateNotExist {
		return fmt.Errorf("error reading %v key of %v: %w", ipn.NLKeyStateKey, b.store, err)
	}

	// If we didn't find one already on disk, generate a new one.
	b.logf("generating new network-lock key")
	b.nlPrivKey = key.NewNLPrivate()

	keyText, _ = b.nlPrivKey.MarshalText()
	if err := b.store.WriteState(ipn.NLKeyStateKey, keyText); err != nil {
		b.logf("error writing network-lock key to store: %v", err)
		return err
	}

	b.logf("network-lock key written to store")
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

	bs, err := b.store.ReadState(key)
	switch {
	case errors.Is(err, ipn.ErrStateNotExist):
		b.prefs = ipn.NewPrefs()
		b.prefs.WantRunning = false
		b.logf("using backend prefs; created empty state for %q: %s", key, b.prefs.Pretty())
		return nil
	case err != nil:
		return fmt.Errorf("backend prefs: store.ReadState(%q): %v", key, err)
	}
	b.prefs, err = ipn.PrefsFromBytes(bs)
	if err != nil {
		b.logf("using backend prefs for %q", key)
		return fmt.Errorf("PrefsFromBytes: %v", err)
	}

	// Ignore any old stored preferences for https://login.tailscale.com
	// as the control server that would override the new default of
	// controlplane.tailscale.com.
	// This makes sure that mobile clients go through the new
	// frontends where we're (2021-10-02) doing battery
	// optimization work ahead of turning down the old backends.
	if b.prefs != nil && b.prefs.ControlURL != "" &&
		b.prefs.ControlURL != ipn.DefaultControlURL &&
		ipn.IsLoginServerSynonym(b.prefs.ControlURL) {
		b.prefs.ControlURL = ""
	}

	b.logf("using backend prefs for %q: %s", key, b.prefs.Pretty())

	b.setAtomicValuesFromPrefs(b.prefs)

	return nil
}

// setAtomicValuesFromPrefs populates sshAtomicBool and containsViaIPFuncAtomic
// from the prefs p, which may be nil.
func (b *LocalBackend) setAtomicValuesFromPrefs(p *ipn.Prefs) {
	b.sshAtomicBool.Store(p != nil && p.RunSSH && envknob.CanSSHD())

	if p == nil {
		b.containsViaIPFuncAtomic.Store(tsaddr.NewContainsIPFunc(nil))
	} else {
		b.containsViaIPFuncAtomic.Store(tsaddr.NewContainsIPFunc(tsaddr.FilterPrefixesCopy(p.AdvertiseRoutes, tsaddr.IsViaPrefix)))
	}
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
// As of 2022-02-17, this is only exists for tests.
func (b *LocalBackend) Login(token *tailcfg.Oauth2Token) {
	b.mu.Lock()
	b.assertClientLocked()
	cc := b.cc
	b.mu.Unlock()

	cc.Login(token, b.loginFlags|controlclient.LoginInteractive)
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
		cc.Login(nil, b.loginFlags|controlclient.LoginInteractive)
	}
}

func (b *LocalBackend) Ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType) (*ipnstate.PingResult, error) {
	if pingType == tailcfg.PingPeerAPI {
		t0 := time.Now()
		node, base, err := b.pingPeerAPI(ctx, ip)
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		d := time.Since(t0)
		pr := &ipnstate.PingResult{
			IP:             ip.String(),
			NodeIP:         ip.String(),
			LatencySeconds: d.Seconds(),
			PeerAPIURL:     base,
		}
		if err != nil {
			pr.Err = err.Error()
		}
		if node != nil {
			pr.NodeName = node.Name
		}
		return pr, nil
	}
	ch := make(chan *ipnstate.PingResult, 1)
	b.e.Ping(ip, pingType, func(pr *ipnstate.PingResult) {
		select {
		case ch <- pr:
		default:
		}
	})
	select {
	case pr := <-ch:
		return pr, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *LocalBackend) pingPeerAPI(ctx context.Context, ip netip.Addr) (peer *tailcfg.Node, peerBase string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nm := b.NetMap()
	if nm == nil {
		return nil, "", errors.New("no netmap")
	}
	peer, ok := nm.PeerByTailscaleIP(ip)
	if !ok {
		return nil, "", fmt.Errorf("no peer found with Tailscale IP %v", ip)
	}
	base := peerAPIBase(nm, peer)
	if base == "" {
		return nil, "", fmt.Errorf("no peer API base found for peer %v (%v)", peer.ID, ip)
	}
	outReq, err := http.NewRequestWithContext(ctx, "HEAD", base, nil)
	if err != nil {
		return nil, "", err
	}
	tr := b.Dialer().PeerAPITransport()
	res, err := tr.RoundTrip(outReq)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close() // but unnecessary on HEAD responses
	if res.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP status %v", res.Status)
	}
	return peer, base, nil
}

// parseWgStatusLocked returns an EngineStatus based on s.
//
// b.mu must be held; mostly because the caller is about to anyway, and doing so
// gives us slightly better guarantees about the two peers stats lines not
// being intermixed if there are concurrent calls to our caller.
func (b *LocalBackend) parseWgStatusLocked(s *wgengine.Status) (ret ipn.EngineStatus) {
	var peerStats, peerKeys strings.Builder

	ret.LiveDERPs = s.DERPs
	ret.LivePeers = map[key.NodePublic]ipnstate.PeerStatusLite{}
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

func (b *LocalBackend) CheckPrefs(p *ipn.Prefs) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checkPrefsLocked(p)
}

func (b *LocalBackend) checkPrefsLocked(p *ipn.Prefs) error {
	var errs []error
	if p.Hostname == "badhostname.tailscale." {
		// Keep this one just for testing.
		errs = append(errs, errors.New("bad hostname [test]"))
	}
	if err := b.checkSSHPrefsLocked(p); err != nil {
		errs = append(errs, err)
	}
	return multierr.New(errs...)
}

func (b *LocalBackend) checkSSHPrefsLocked(p *ipn.Prefs) error {
	if !p.RunSSH {
		return nil
	}
	switch runtime.GOOS {
	case "linux":
		if distro.Get() == distro.Synology && !envknob.UseWIPCode() {
			return errors.New("The Tailscale SSH server does not run on Synology.")
		}
		if distro.Get() == distro.QNAP && !envknob.UseWIPCode() {
			return errors.New("The Tailscale SSH server does not run on QNAP.")
		}
		// otherwise okay
	case "darwin":
		// okay only in tailscaled mode for now.
		if version.IsSandboxedMacOS() {
			return errors.New("The Tailscale SSH server does not run in sandboxed Tailscale GUI builds.")
		}
		if !envknob.UseWIPCode() {
			return errors.New("The Tailscale SSH server is disabled on macOS tailscaled by default. To try, set env TAILSCALE_USE_WIP_CODE=1")
		}
	default:
		return errors.New("The Tailscale SSH server is not supported on " + runtime.GOOS)
	}
	if !envknob.CanSSHD() {
		return errors.New("The Tailscale SSH server has been administratively disabled.")
	}
	if envknob.SSHIgnoreTailnetPolicy() || envknob.SSHPolicyFile() != "" {
		return nil
	}
	if b.netMap != nil {
		if !hasCapability(b.netMap, tailcfg.CapabilitySSH) {
			if b.isDefaultServerLocked() {
				return errors.New("Unable to enable local Tailscale SSH server; not enabled on Tailnet. See https://tailscale.com/s/ssh")
			}
			return errors.New("Unable to enable local Tailscale SSH server; not enabled on Tailnet.")
		}
	}
	return nil
}

func (b *LocalBackend) sshOnButUnusableHealthCheckMessageLocked() (healthMessage string) {
	if b.prefs == nil || !b.prefs.RunSSH {
		return ""
	}
	if envknob.SSHIgnoreTailnetPolicy() || envknob.SSHPolicyFile() != "" {
		return "development SSH policy in use"
	}
	nm := b.netMap
	if nm == nil {
		return ""
	}
	if nm.SSHPolicy != nil && len(nm.SSHPolicy.Rules) > 0 {
		return ""
	}
	isDefault := b.isDefaultServerLocked()
	isAdmin := hasCapability(nm, tailcfg.CapabilityAdmin)

	if !isAdmin {
		return "Tailscale SSH enabled, but access controls don't allow anyone to access this device. Ask your admin to update your tailnet's ACLs to allow access."
	}
	if !isDefault {
		return "Tailscale SSH enabled, but access controls don't allow anyone to access this device. Update your tailnet's ACLs to allow access."
	}
	return "Tailscale SSH enabled, but access controls don't allow anyone to access this device. Update your tailnet's ACLs at https://tailscale.com/s/ssh-policy"
}

func (b *LocalBackend) isDefaultServerLocked() bool {
	if b.prefs == nil {
		return true // assume true until set otherwise
	}
	return b.prefs.ControlURLOrDefault() == ipn.DefaultControlURL
}

func (b *LocalBackend) EditPrefs(mp *ipn.MaskedPrefs) (*ipn.Prefs, error) {
	b.mu.Lock()
	if mp.EggSet {
		mp.EggSet = false
		b.egg = true
		go b.doSetHostinfoFilterServices(b.hostinfo.Clone())
	}
	p0 := b.prefs.Clone()
	p1 := b.prefs.Clone()
	p1.ApplyEdits(mp)
	if err := b.checkPrefsLocked(p1); err != nil {
		b.mu.Unlock()
		b.logf("EditPrefs check error: %v", err)
		return nil, err
	}
	if p1.RunSSH && !envknob.CanSSHD() {
		b.mu.Unlock()
		b.logf("EditPrefs requests SSH, but disabled by envknob; returning error")
		return nil, errors.New("Tailscale SSH server administratively disabled.")
	}
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
// unlocks b.mu when done. newp ownership passes to this function.
func (b *LocalBackend) setPrefsLockedOnEntry(caller string, newp *ipn.Prefs) {
	netMap := b.netMap
	stateKey := b.stateKey

	b.setAtomicValuesFromPrefs(newp)

	oldp := b.prefs
	newp.Persist = oldp.Persist // caller isn't allowed to override this
	b.prefs = newp
	// findExitNodeIDLocked returns whether it updated b.prefs, but
	// everything in this function treats b.prefs as completely new
	// anyway. No-op if no exit node resolution is needed.
	b.findExitNodeIDLocked(netMap)
	b.inServerMode = newp.ForceDaemon
	// We do this to avoid holding the lock while doing everything else.
	newp = b.prefs.Clone()

	oldHi := b.hostinfo
	newHi := oldHi.Clone()
	b.applyPrefsToHostinfo(newHi, newp)
	b.hostinfo = newHi
	hostInfoChanged := !oldHi.Equal(newHi)
	userID := b.userID
	cc := b.cc

	// [GRINDER STATS LINE] - please don't remove (used for log parsing)
	if caller == "SetPrefs" {
		b.logf("SetPrefs: %v", newp.Pretty())
	}
	b.updateFilterLocked(netMap, newp)

	if oldp.ShouldSSHBeRunning() && !newp.ShouldSSHBeRunning() {
		if b.sshServer != nil {
			go b.sshServer.Shutdown()
			b.sshServer = nil
		}
	}
	b.mu.Unlock()

	if stateKey != "" {
		if err := b.store.WriteState(stateKey, newp.ToBytes()); err != nil {
			b.logf("failed to save new controlclient state: %v", err)
		}
	}
	b.writeServerModeStartState(userID, newp)

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
				b.logf("active login: %q ([unexpected] corp#461, not %q)", newp.Persist.LoginName, login)
			}
		}
	}

	if oldp.ShieldsUp != newp.ShieldsUp || hostInfoChanged {
		b.doSetHostinfoFilterServices(newHi)
	}

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

// GetPeerAPIPort returns the port number for the peerapi server
// running on the provided IP.
func (b *LocalBackend) GetPeerAPIPort(ip netip.Addr) (port uint16, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, pln := range b.peerAPIListeners {
		if pln.ip == ip {
			return uint16(pln.port), true
		}
	}
	return 0, false
}

// ServePeerAPIConnection serves an already-accepted connection c.
//
// The remote parameter is the remote address.
// The local parameter is the local address (either a Tailscale IPv4
// or IPv6 IP and the peerapi port for that address).
//
// The connection will be closed by ServePeerAPIConnection.
func (b *LocalBackend) ServePeerAPIConnection(remote, local netip.AddrPort, c net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, pln := range b.peerAPIListeners {
		if pln.ip == local.Addr() {
			go pln.ServeConn(remote, c)
			return
		}
	}
	b.logf("[unexpected] no peerAPI listener found for %v", local)
	c.Close()
	return
}

func (b *LocalBackend) peerAPIServicesLocked() (ret []tailcfg.Service) {
	for _, pln := range b.peerAPIListeners {
		proto := tailcfg.PeerAPI4
		if pln.ip.Is6() {
			proto = tailcfg.PeerAPI6
		}
		ret = append(ret, tailcfg.Service{
			Proto: proto,
			Port:  uint16(pln.port),
		})
	}
	switch runtime.GOOS {
	case "linux", "freebsd", "openbsd", "illumos", "darwin", "windows":
		// These are the platforms currently supported by
		// net/dns/resolver/tsdns.go:Resolver.HandleExitNodeDNSQuery.
		ret = append(ret, tailcfg.Service{
			Proto: tailcfg.PeerAPIDNS,
			Port:  1, // version
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
	if b.egg {
		peerAPIServices = append(peerAPIServices, tailcfg.Service{Proto: "egg", Port: 1})
	}
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

func (b *LocalBackend) isEngineBlocked() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocked
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
		b.logf("[v1] authReconfig: blocked, skipping.")
		return
	}
	if nm == nil {
		b.logf("[v1] authReconfig: netmap not yet valid. Skipping.")
		return
	}
	if !prefs.WantRunning {
		b.logf("[v1] authReconfig: skipping because !WantRunning.")
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

	// Keep the dialer updated about whether we're supposed to use
	// an exit node's DNS server (so SOCKS5/HTTP outgoing dials
	// can use it for name resolution)
	if dohURL, ok := exitNodeCanProxyDNS(nm, prefs.ExitNodeID); ok {
		b.dialer.SetExitDNSDoH(dohURL)
	} else {
		b.dialer.SetExitDNSDoH("")
	}

	cfg, err := nmcfg.WGCfg(nm, b.logf, flags, prefs.ExitNodeID)
	if err != nil {
		b.logf("wgcfg: %v", err)
		return
	}

	oneCGNATRoute := shouldUseOneCGNATRoute(nm, b.logf, version.OS())
	rcfg := b.routerConfig(cfg, prefs, oneCGNATRoute)
	dcfg := dnsConfigForNetmap(nm, prefs, b.logf, version.OS())

	err = b.e.Reconfig(cfg, rcfg, dcfg, nm.Debug)
	if err == wgengine.ErrNoChanges {
		return
	}
	b.logf("[v1] authReconfig: ra=%v dns=%v 0x%02x: %v", prefs.RouteAll, prefs.CorpDNS, flags, err)

	b.initPeerAPIListener()
}

// shouldUseOneCGNATRoute reports whether we should prefer to make one big
// CGNAT /10 route rather than a /32 per peer.
//
// The versionOS is a Tailscale-style version ("iOS", "macOS") and not
// a runtime.GOOS.
func shouldUseOneCGNATRoute(nm *netmap.NetworkMap, logf logger.Logf, versionOS string) bool {
	// Explicit enabling or disabling always take precedence.
	if nm.Debug != nil {
		if v, ok := nm.Debug.OneCGNATRoute.Get(); ok {
			logf("[v1] shouldUseOneCGNATRoute: explicit=%v", v)
			return v
		}
	}
	// Also prefer to do this on the Mac, so that we don't need to constantly
	// update the network extension configuration (which is disruptive to
	// Chrome, see https://github.com/tailscale/tailscale/issues/3102). Only
	// use fine-grained routes if another interfaces is also using the CGNAT
	// IP range.
	if versionOS == "macOS" {
		hasCGNATInterface, err := interfaces.HasCGNATInterface()
		if err != nil {
			logf("shouldUseOneCGNATRoute: Could not determine if any interfaces use CGNAT: %v", err)
			return false
		}
		logf("[v1] shouldUseOneCGNATRoute: macOS automatic=%v", !hasCGNATInterface)
		if !hasCGNATInterface {
			return true
		}
	}
	return false
}

// dnsConfigForNetmap returns a *dns.Config for the given netmap,
// prefs, client OS version, and cloud hosting environment.
//
// The versionOS is a Tailscale-style version ("iOS", "macOS") and not
// a runtime.GOOS.
func dnsConfigForNetmap(nm *netmap.NetworkMap, prefs *ipn.Prefs, logf logger.Logf, versionOS string) *dns.Config {
	dcfg := &dns.Config{
		Routes: map[dnsname.FQDN][]*dnstype.Resolver{},
		Hosts:  map[dnsname.FQDN][]netip.Addr{},
	}

	// selfV6Only is whether we only have IPv6 addresses ourselves.
	selfV6Only := tsaddr.PrefixesContainsFunc(nm.Addresses, tsaddr.PrefixIs6) &&
		!tsaddr.PrefixesContainsFunc(nm.Addresses, tsaddr.PrefixIs4)
	dcfg.OnlyIPv6 = selfV6Only

	// Populate MagicDNS records. We do this unconditionally so that
	// quad-100 can always respond to MagicDNS queries, even if the OS
	// isn't configured to make MagicDNS resolution truly
	// magic. Details in
	// https://github.com/tailscale/tailscale/issues/1886.
	set := func(name string, addrs []netip.Prefix) {
		if len(addrs) == 0 || name == "" {
			return
		}
		fqdn, err := dnsname.ToFQDN(name)
		if err != nil {
			return // TODO: propagate error?
		}
		have4 := tsaddr.PrefixesContainsFunc(addrs, tsaddr.PrefixIs4)
		var ips []netip.Addr
		for _, addr := range addrs {
			if selfV6Only {
				if addr.Addr().Is6() {
					ips = append(ips, addr.Addr())
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
			if addr.Addr().Is6() && have4 {
				continue
			}
			ips = append(ips, addr.Addr())
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
		ip, err := netip.ParseAddr(rec.Value)
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

	addDefault := func(resolvers []*dnstype.Resolver) {
		for _, r := range resolvers {
			dcfg.DefaultResolvers = append(dcfg.DefaultResolvers, r)
		}
	}

	// If we're using an exit node and that exit node is new enough (1.19.x+)
	// to run a DoH DNS proxy, then send all our DNS traffic through it.
	if dohURL, ok := exitNodeCanProxyDNS(nm, prefs.ExitNodeID); ok {
		addDefault([]*dnstype.Resolver{{Addr: dohURL}})
		return dcfg
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
		dcfg.Routes[fqdn] = make([]*dnstype.Resolver, 0, len(resolvers))

		for _, r := range resolvers {
			dcfg.Routes[fqdn] = append(dcfg.Routes[fqdn], r)
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
	}

	return dcfg
}

// SetTailnetKeyAuthority sets the key authority which should be
// used for locked tailnets.
//
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetTailnetKeyAuthority(a *tka.Authority, storage *tka.FS) {
	b.tka = &tkaState{
		authority: a,
		storage:   storage,
	}
}

// SetVarRoot sets the root directory of Tailscale's writable
// storage area . (e.g. "/var/lib/tailscale")
//
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetVarRoot(dir string) {
	b.varRoot = dir
}

// TailscaleVarRoot returns the root directory of Tailscale's writable
// storage area. (e.g. "/var/lib/tailscale")
//
// It returns an empty string if there's no configured or discovered
// location.
func (b *LocalBackend) TailscaleVarRoot() string {
	if b.varRoot != "" {
		return b.varRoot
	}
	switch runtime.GOOS {
	case "ios", "android", "darwin":
		return paths.AppSharedDir.Load()
	}
	return ""
}

func (b *LocalBackend) fileRootLocked(uid tailcfg.UserID) string {
	if v := b.directFileRoot; v != "" {
		return v
	}
	varRoot := b.TailscaleVarRoot()
	if varRoot == "" {
		b.logf("Taildrop disabled; no state directory")
		return ""
	}
	baseDir := fmt.Sprintf("%s-uid-%d",
		strings.ReplaceAll(b.activeLogin, "@", "-"),
		uid)
	dir := filepath.Join(varRoot, "files", baseDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		b.logf("Taildrop disabled; error making directory: %v", err)
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
	if b.shutdownCalled {
		return
	}

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
			if pln.ip != b.netMap.Addresses[i].Addr() {
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
		b.logf("peerapi starting without Taildrop directory configured")
	}

	ps := &peerAPIServer{
		b:                       b,
		rootDir:                 fileRoot,
		selfNode:                selfNode,
		directFileMode:          b.directFileRoot != "",
		directFileDoFinalRename: b.directFileDoFinalRename,
	}
	if re, ok := b.e.(wgengine.ResolvingEngine); ok {
		if r, ok := re.GetResolver(); ok {
			ps.resolver = r
		}
	}
	b.peerAPIServer = ps

	isNetstack := wgengine.IsNetstack(b.e)
	for i, a := range b.netMap.Addresses {
		var ln net.Listener
		var err error
		skipListen := i > 0 && isNetstack
		if !skipListen {
			ln, err = ps.listen(a.Addr(), b.prevIfState)
			if err != nil {
				if peerAPIListenAsync {
					// Expected. But we fix it later in linkChange
					// ("peerAPIListeners too low").
					continue
				}
				b.logf("[unexpected] peerapi listen(%q) error: %v", a.Addr(), err)
				continue
			}
		}
		pln := &peerAPIListener{
			ps: ps,
			ip: a.Addr(),
			ln: ln, // nil for 2nd+ on netstack
			lb: b,
		}
		if skipListen {
			pln.port = b.peerAPIListeners[0].port
		} else {
			pln.port = ln.Addr().(*net.TCPAddr).Port
		}
		pln.urlStr = "http://" + net.JoinHostPort(a.Addr().String(), strconv.Itoa(pln.port))
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
	ipv4Default = netip.MustParsePrefix("0.0.0.0/0")
	ipv6Default = netip.MustParsePrefix("::/0")
)

// peerRoutes returns the routerConfig.Routes to access peers.
// If there are over cgnatThreshold CGNAT routes, one big CGNAT route
// is used instead.
func peerRoutes(peers []wgcfg.Peer, cgnatThreshold int) (routes []netip.Prefix) {
	tsULA := tsaddr.TailscaleULARange()
	cgNAT := tsaddr.CGNATRange()
	var didULA bool
	var cgNATIPs []netip.Prefix
	for _, peer := range peers {
		for _, aip := range peer.AllowedIPs {
			aip = unmapIPPrefix(aip)
			// Only add the Tailscale IPv6 ULA once, if we see anybody using part of it.
			if aip.Addr().Is6() && aip.IsSingleIP() && tsULA.Contains(aip.Addr()) {
				if !didULA {
					didULA = true
					routes = append(routes, tsULA)
				}
				continue
			}
			if aip.IsSingleIP() && cgNAT.Contains(aip.Addr()) {
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

	sort.Slice(routes, func(i, j int) bool {
		return ipPrefixLess(routes[i], routes[j])
	})
	return routes
}

func ipPrefixLess(ri, rj netip.Prefix) bool {
	if ri.Addr() == rj.Addr() {
		return ri.Bits() < rj.Bits()
	}
	return ri.Addr().Less(rj.Addr())
}

// routerConfig produces a router.Config from a wireguard config and IPN prefs.
func (b *LocalBackend) routerConfig(cfg *wgcfg.Config, prefs *ipn.Prefs, oneCGNATRoute bool) *router.Config {
	singleRouteThreshold := 10_000
	if oneCGNATRoute {
		singleRouteThreshold = 1
	}
	rs := &router.Config{
		LocalAddrs:       unmapIPPrefixes(cfg.Addresses),
		SubnetRoutes:     unmapIPPrefixes(prefs.AdvertiseRoutes),
		SNATSubnetRoutes: !prefs.NoSNAT,
		NetfilterMode:    prefs.NetfilterMode,
		Routes:           peerRoutes(cfg.Peers, singleRouteThreshold),
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
	if prefs.ExitNodeID != "" || prefs.ExitNodeIP.IsValid() {
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
			} else {
				// Explicitly add routes to the local network so that we do not
				// leak any traffic.
				rs.Routes = append(rs.Routes, externalIPs...)
			}
			b.logf("allowing exit node access to local IPs: %v", rs.LocalRoutes)
		}
	}

	if tsaddr.PrefixesContainsFunc(rs.LocalAddrs, tsaddr.PrefixIs4) {
		rs.Routes = append(rs.Routes, netip.PrefixFrom(tsaddr.TailscaleServiceIP(), 32))
	}

	return rs
}

func unmapIPPrefix(ipp netip.Prefix) netip.Prefix {
	return netip.PrefixFrom(ipp.Addr().Unmap(), ipp.Bits())
}

func unmapIPPrefixes(ippsList ...[]netip.Prefix) (ret []netip.Prefix) {
	for _, ipps := range ippsList {
		for _, ipp := range ipps {
			ret = append(ret, unmapIPPrefix(ipp))
		}
	}
	return ret
}

// Warning: b.mu might be held. Currently (2022-02-17) both callers hold it.
func (b *LocalBackend) applyPrefsToHostinfo(hi *tailcfg.Hostinfo, prefs *ipn.Prefs) {
	if h := prefs.Hostname; h != "" {
		hi.Hostname = h
	}
	hi.RoutableIPs = append(prefs.AdvertiseRoutes[:0:0], prefs.AdvertiseRoutes...)
	hi.RequestTags = append(prefs.AdvertiseTags[:0:0], prefs.AdvertiseTags...)
	hi.ShieldsUp = prefs.ShieldsUp

	var sshHostKeys []string
	if prefs.RunSSH && envknob.CanSSHD() {
		// TODO(bradfitz): this is called with b.mu held. Not ideal.
		// If the filesystem gets wedged or something we could block for
		// a long time. But probably fine.
		sshHostKeys = b.getSSHHostKeyPublicStrings()
	}
	hi.SSH_HostKeys = sshHostKeys
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

	// prefs may change irrespective of state; WantRunning should be explicitly
	// set before potential early return even if the state is unchanged.
	health.SetIPNState(newState.String(), prefs.WantRunning)
	if oldState == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)",
		oldState, newState, prefs.WantRunning, netMap != nil)
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
			addrs = append(addrs, addr.Addr().String())
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
		keyExpired  = b.keyExpired
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
	case keyExpired:
		// NetMap must be non-nil for us to get here.
		// The node key expired, need to relogin.
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
// TODO(apenwarr): use a channel or something to prevent reentrancy?
// Or maybe just call the state machine from fewer places.
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
	b.keyExpired = false
	b.authURL = ""
	b.authURLSticky = ""
	b.activeLogin = ""
	b.setAtomicValuesFromPrefs(nil)
}

func (b *LocalBackend) ShouldRunSSH() bool { return b.sshAtomicBool.Load() && envknob.CanSSHD() }

// ShouldHandleViaIP reports whether ip is an IPv6 address in the
// Tailscale ULA's v6 "via" range embedding an IPv4 address to be forwarded to
// by Tailscale.
func (b *LocalBackend) ShouldHandleViaIP(ip netip.Addr) bool {
	if f, ok := b.containsViaIPFuncAtomic.LoadOk(); ok {
		return f(ip)
	}
	return false
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

	// Clear any previous dial plan(s), if set.
	b.dialPlan.Store(nil)

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
	b.dialer.SetNetMap(nm)
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
		b.nodeByAddr = map[netip.Addr]*tailcfg.Node{}
	}
	// First pass, mark everything unwanted.
	for k := range b.nodeByAddr {
		b.nodeByAddr[k] = nil
	}
	addNode := func(n *tailcfg.Node) {
		for _, ipp := range n.Addresses {
			if ipp.IsSingleIP() {
				b.nodeByAddr[ipp.Addr()] = n
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

// operatorUserName returns the current pref's OperatorUser's name, or the
// empty string if none.
func (b *LocalBackend) operatorUserName() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.prefs == nil {
		return ""
	}
	return b.prefs.OperatorUser
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
func (b *LocalBackend) TestOnlyPublicKeys() (machineKey key.MachinePublic, nodeKey key.NodePublic) {
	b.mu.Lock()
	prefs := b.prefs
	machinePrivKey := b.machinePrivKey
	b.mu.Unlock()

	if prefs == nil || machinePrivKey.IsZero() {
		return
	}

	mk := machinePrivKey.Public()
	nk := prefs.Persist.PrivateNodeKey.Public()
	return mk, nk
}

func (b *LocalBackend) WaitingFiles() ([]apitype.WaitingFile, error) {
	b.mu.Lock()
	apiSrv := b.peerAPIServer
	b.mu.Unlock()
	return apiSrv.WaitingFiles()
}

func (b *LocalBackend) DeleteFile(name string) error {
	b.mu.Lock()
	apiSrv := b.peerAPIServer
	b.mu.Unlock()
	return apiSrv.DeleteFile(name)
}

func (b *LocalBackend) OpenFile(name string) (rc io.ReadCloser, size int64, err error) {
	b.mu.Lock()
	apiSrv := b.peerAPIServer
	b.mu.Unlock()
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
		return nil, errors.New("not connected to the tailnet")
	}
	if !b.capFileSharing {
		return nil, errors.New("file sharing not enabled by Tailscale admin")
	}
	for _, p := range nm.Peers {
		if !b.peerIsTaildropTargetLocked(p) {
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

// peerIsTaildropTargetLocked reports whether p is a valid Taildrop file
// recipient from this node according to its ownership and the capabilities in
// the netmap.
//
// b.mu must be locked.
func (b *LocalBackend) peerIsTaildropTargetLocked(p *tailcfg.Node) bool {
	if b.netMap == nil || p == nil {
		return false
	}
	if b.netMap.User == p.User {
		return true
	}
	if len(p.Addresses) > 0 &&
		b.peerHasCapLocked(p.Addresses[0].Addr(), tailcfg.CapabilityFileSharingTarget) {
		// Explicitly noted in the netmap ACL caps as a target.
		return true
	}
	return false
}

func (b *LocalBackend) peerHasCapLocked(addr netip.Addr, wantCap string) bool {
	for _, hasCap := range b.peerCapsLocked(addr) {
		if hasCap == wantCap {
			return true
		}
	}
	return false
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
		Version: 1, // TODO(bradfitz,maisem): use tailcfg.CurrentCapabilityVersion when using the Noise transport
		Type:    "TXT",
		Name:    name,
		Value:   value,
	}

	b.mu.Lock()
	cc := b.ccAuto
	if prefs := b.prefs; prefs != nil {
		req.NodeKey = prefs.Persist.PrivateNodeKey.Public()
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
	if nm == nil || peer == nil || !peer.Hostinfo.Valid() {
		return ""
	}

	var have4, have6 bool
	for _, a := range nm.Addresses {
		if !a.IsSingleIP() {
			continue
		}
		switch {
		case a.Addr().Is4():
			have4 = true
		case a.Addr().Is6():
			have6 = true
		}
	}
	var p4, p6 uint16
	svcs := peer.Hostinfo.Services()
	for i, n := 0, svcs.Len(); i < n; i++ {
		s := svcs.At(i)
		switch s.Proto {
		case tailcfg.PeerAPI4:
			p4 = s.Port
		case tailcfg.PeerAPI6:
			p6 = s.Port
		}
	}
	var ipp netip.AddrPort
	switch {
	case have4 && p4 != 0:
		ipp = netip.AddrPortFrom(nodeIP(peer, netip.Addr.Is4), p4)
	case have6 && p6 != 0:
		ipp = netip.AddrPortFrom(nodeIP(peer, netip.Addr.Is6), p6)
	}
	if !ipp.Addr().IsValid() {
		return ""
	}
	return fmt.Sprintf("http://%v", ipp)
}

func nodeIP(n *tailcfg.Node, pred func(netip.Addr) bool) netip.Addr {
	for _, a := range n.Addresses {
		if a.IsSingleIP() && pred(a.Addr()) {
			return a.Addr()
		}
	}
	return netip.Addr{}
}

func (b *LocalBackend) CheckIPForwarding() error {
	if wgengine.IsNetstackRouter(b.e) {
		return nil
	}

	// TODO: let the caller pass in the ranges.
	warn, err := netutil.CheckIPForwarding(tsaddr.ExitRoutes(), nil)
	if err != nil {
		return err
	}
	return warn
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

// OfferingExitNode reports whether b is currently offering exit node
// access.
func (b *LocalBackend) OfferingExitNode() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.prefs == nil {
		return false
	}
	var def4, def6 bool
	for _, r := range b.prefs.AdvertiseRoutes {
		if r.Bits() != 0 {
			continue
		}
		if r.Addr().Is4() {
			def4 = true
		} else if r.Addr().Is6() {
			def6 = true
		}
	}
	return def4 && def6
}

// allowExitNodeDNSProxyToServeName reports whether the Exit Node DNS
// proxy is allowed to serve responses for the provided DNS name.
func (b *LocalBackend) allowExitNodeDNSProxyToServeName(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	nm := b.netMap
	if nm == nil {
		return false
	}
	name = strings.ToLower(name)
	for _, bad := range nm.DNS.ExitNodeFilteredSet {
		if bad == "" {
			// Invalid, ignore.
			continue
		}
		if bad[0] == '.' {
			// Entries beginning with a dot are suffix matches.
			if dnsname.HasSuffix(name, bad) {
				return false
			}
			continue
		}
		// Otherwise entries are exact matches. They're
		// guaranteed to be lowercase already.
		if name == bad {
			return false
		}
	}
	return true
}

// SetExpiry updates the expiry of the current node key to t, as long as it's
// only sooner than the old expiry.
//
// If t is in the past, the key is expired immediately.
// If t is after the current expiry, an error is returned.
func (b *LocalBackend) SetExpirySooner(ctx context.Context, expiry time.Time) error {
	b.mu.Lock()
	cc := b.ccAuto
	b.mu.Unlock()
	if cc == nil {
		return errors.New("not running")
	}
	return cc.SetExpirySooner(ctx, expiry)
}

// exitNodeCanProxyDNS reports the DoH base URL ("http://foo/dns-query") without query parameters
// to exitNodeID's DoH service, if available.
//
// If exitNodeID is the zero valid, it returns "", false.
func exitNodeCanProxyDNS(nm *netmap.NetworkMap, exitNodeID tailcfg.StableNodeID) (dohURL string, ok bool) {
	if exitNodeID.IsZero() {
		return "", false
	}
	for _, p := range nm.Peers {
		if p.StableID != exitNodeID {
			continue
		}
		services := p.Hostinfo.Services()
		for i, n := 0, services.Len(); i < n; i++ {
			s := services.At(i)
			if s.Proto == tailcfg.PeerAPIDNS && s.Port >= 1 {
				return peerAPIBase(nm, p) + "/dns-query", true
			}
		}
	}
	return "", false
}

func (b *LocalBackend) DebugRebind() error {
	mc, err := b.magicConn()
	if err != nil {
		return err
	}
	mc.Rebind()
	return nil
}

func (b *LocalBackend) DebugReSTUN() error {
	mc, err := b.magicConn()
	if err != nil {
		return err
	}
	mc.ReSTUN("explicit-debug")
	return nil
}

func (b *LocalBackend) magicConn() (*magicsock.Conn, error) {
	ig, ok := b.e.(wgengine.InternalsGetter)
	if !ok {
		return nil, errors.New("engine isn't InternalsGetter")
	}
	_, mc, _, ok := ig.GetInternals()
	if !ok {
		return nil, errors.New("failed to get internals")
	}
	return mc, nil
}

// DoNoiseRequest sends a request to URL over the control plane
// Noise connection.
func (b *LocalBackend) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	b.mu.Lock()
	cc := b.ccAuto
	b.mu.Unlock()
	if cc == nil {
		return nil, errors.New("no client")
	}
	return cc.DoNoiseRequest(req)
}

// tailscaleSSHEnabled reports whether Tailscale SSH is currently enabled based
// on prefs. It returns false if there are no prefs set.
func (b *LocalBackend) tailscaleSSHEnabled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.prefs == nil {
		return false
	}
	return b.prefs.RunSSH
}

func (b *LocalBackend) sshServerOrInit() (_ SSHServer, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sshServer != nil {
		return b.sshServer, nil
	}
	if newSSHServer == nil {
		return nil, errors.New("no SSH server support")
	}
	b.sshServer, err = newSSHServer(b.logf, b)
	if err != nil {
		return nil, fmt.Errorf("newSSHServer: %w", err)
	}
	return b.sshServer, nil
}

func (b *LocalBackend) HandleSSHConn(c net.Conn) (err error) {
	s, err := b.sshServerOrInit()
	if err != nil {
		return err
	}
	return s.HandleSSHConn(c)
}

// HandleQuad100Port80Conn serves http://100.100.100.100/ on port 80 (and
// the equivalent tsaddr.TailscaleServiceIPv6 address).
func (b *LocalBackend) HandleQuad100Port80Conn(c net.Conn) {
	var s http.Server
	s.Handler = http.HandlerFunc(b.handleQuad100Port80Conn)
	s.Serve(netutil.NewOneConnListener(c, nil))
}

func (b *LocalBackend) handleQuad100Port80Conn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self';")
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	io.WriteString(w, "<h1>Tailscale</h1>\n")
	if b.netMap == nil {
		io.WriteString(w, "No netmap.\n")
		return
	}
	if len(b.netMap.Addresses) == 0 {
		io.WriteString(w, "No local addresses.\n")
		return
	}
	io.WriteString(w, "<p>Local addresses:</p><ul>\n")
	for _, ipp := range b.netMap.Addresses {
		fmt.Fprintf(w, "<li>%v</li>\n", ipp.Addr())
	}
	io.WriteString(w, "</ul>\n")
}

func (b *LocalBackend) Doctor(ctx context.Context, logf logger.Logf) {
	var checks []doctor.Check

	checks = append(checks, routetable.Check{})

	// TODO(andrew): more

	numChecks := len(checks)
	checks = append(checks, doctor.CheckFunc("numchecks", func(_ context.Context, log logger.Logf) error {
		log("%d checks", numChecks)
		return nil
	}))

	doctor.RunChecks(ctx, logf, checks...)
}
