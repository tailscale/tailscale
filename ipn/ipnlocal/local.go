// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnlocal is the heart of the Tailscale node agent that controls
// all the other misc pieces of the Tailscale node.
package ipnlocal

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go4.org/mem"
	"go4.org/netipx"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/appc"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/control/controlclient"
	"tailscale.com/control/controlknobs"
	"tailscale.com/drive"
	"tailscale.com/envknob"
	"tailscale.com/envknob/featureknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/health/healthmsg"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/log/sockstatlog"
	"tailscale.com/logpolicy"
	"tailscale.com/net/dns"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/ipset"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netkernelconf"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/netutil"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/paths"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstime"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/empty"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/preftype"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	"tailscale.com/util/checkchange"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/goroutines"
	"tailscale.com/util/mak"
	"tailscale.com/util/osuser"
	"tailscale.com/util/rands"
	"tailscale.com/util/set"
	"tailscale.com/util/slicesx"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/syspolicy/ptype"
	"tailscale.com/util/testenv"
	"tailscale.com/util/usermetric"
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

	// NumActiveConns returns the number of connections passed to HandleSSHConn
	// that are still active.
	NumActiveConns() int

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

// watchSession represents a WatchNotifications channel,
// an [ipnauth.Actor] that owns it (e.g., a connected GUI/CLI),
// and sessionID as required to close targeted buses.
type watchSession struct {
	ch        chan *ipn.Notify
	owner     ipnauth.Actor // or nil
	sessionID string
	cancel    context.CancelFunc // to shut down the session
}

var (
	// errShutdown indicates that the [LocalBackend.Shutdown] was called.
	errShutdown = errors.New("shutting down")

	// errNodeContextChanged indicates that [LocalBackend] has switched
	// to a different [localNodeContext], usually due to a profile change.
	// It is used as a context cancellation cause for the old context
	// and can be returned when an operation is performed on it.
	errNodeContextChanged = errors.New("profile changed")

	// errManagedByPolicy indicates the operation is blocked
	// because the target state is managed by a GP/MDM policy.
	errManagedByPolicy = errors.New("managed by policy")
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
	ctx       context.Context         // canceled by [LocalBackend.Shutdown]
	ctxCancel context.CancelCauseFunc // cancels ctx
	logf      logger.Logf             // general logging
	keyLogf   logger.Logf             // for printing list of peers on change
	statsLogf logger.Logf             // for printing peers stats on change
	sys       *tsd.System
	eventSubs eventbus.Monitor

	health                   *health.Tracker     // always non-nil
	polc                     policyclient.Client // always non-nil
	metrics                  metrics
	e                        wgengine.Engine // non-nil; TODO(bradfitz): remove; use sys
	store                    ipn.StateStore  // non-nil; TODO(bradfitz): remove; use sys
	dialer                   *tsdial.Dialer  // non-nil; TODO(bradfitz): remove; use sys
	pushDeviceToken          syncs.AtomicValue[string]
	backendLogID             logid.PublicID // or zero value if logging not in use
	unregisterSysPolicyWatch func()
	varRoot                  string         // or empty if SetVarRoot never called
	logFlushFunc             func()         // or nil if SetLogFlusher wasn't called
	em                       *expiryManager // non-nil; TODO(nickkhyl): move to nodeBackend
	sshAtomicBool            atomic.Bool    // TODO(nickkhyl): move to nodeBackend
	// webClientAtomicBool controls whether the web client is running. This should
	// be true unless the disable-web-client node attribute has been set.
	webClientAtomicBool atomic.Bool // TODO(nickkhyl): move to nodeBackend
	// exposeRemoteWebClientAtomicBool controls whether the web client is exposed over
	// Tailscale on port 5252.
	exposeRemoteWebClientAtomicBool atomic.Bool // TODO(nickkhyl): move to nodeBackend
	shutdownCalled                  bool        // if Shutdown has been called
	debugSink                       packet.CaptureSink
	sockstatLogger                  *sockstatlog.Logger

	// getTCPHandlerForFunnelFlow returns a handler for an incoming TCP flow for
	// the provided srcAddr and dstPort if one exists.
	//
	// srcAddr is the source address of the flow, not the address of the Funnel
	// node relaying the flow.
	// dstPort is the destination port of the flow.
	//
	// It returns nil if there is no known handler for this flow.
	//
	// This is specifically used to handle TCP flows for Funnel connections to tsnet
	// servers.
	//
	// It is set once during initialization, and can be nil if SetTCPHandlerForFunnelFlow
	// is never called.
	getTCPHandlerForFunnelFlow func(srcAddr netip.AddrPort, dstPort uint16) (handler func(net.Conn))

	containsViaIPFuncAtomic                 syncs.AtomicValue[func(netip.Addr) bool]     // TODO(nickkhyl): move to nodeBackend
	shouldInterceptTCPPortAtomic            syncs.AtomicValue[func(uint16) bool]         // TODO(nickkhyl): move to nodeBackend
	shouldInterceptVIPServicesTCPPortAtomic syncs.AtomicValue[func(netip.AddrPort) bool] // TODO(nickkhyl): move to nodeBackend
	numClientStatusCalls                    atomic.Uint32                                // TODO(nickkhyl): move to nodeBackend

	// goTracker accounts for all goroutines started by LocalBacked, primarily
	// for testing and graceful shutdown purposes.
	goTracker goroutines.Tracker

	startOnce sync.Once // protects the one‑time initialization in [LocalBackend.Start]

	// extHost is the bridge between [LocalBackend] and the registered [ipnext.Extension]s.
	// It may be nil in tests that use direct composite literal initialization of [LocalBackend]
	// instead of calling [NewLocalBackend]. A nil pointer is a valid, no-op host.
	// It can be used with or without b.mu held, but is typically used with it held
	// to prevent state changes while invoking callbacks.
	extHost *ExtensionHost

	// The mutex protects the following elements.
	mu sync.Mutex

	// currentNodeAtomic is the current node context. It is always non-nil.
	// It must be re-created when [LocalBackend] switches to a different profile/node
	// (see tailscale/corp#28014 for a bug), but can be mutated in place (via its methods)
	// while [LocalBackend] represents the same node.
	//
	// It is safe for reading with or without holding b.mu, but mutating it in place
	// or creating a new one must be done with b.mu held. If both mutexes must be held,
	// the LocalBackend's mutex must be acquired first before acquiring the nodeBackend's mutex.
	//
	// We intend to relax this in the future and only require holding b.mu when replacing it,
	// but that requires a better (strictly ordered?) state machine and better management
	// of [LocalBackend]'s own state that is not tied to the node context.
	currentNodeAtomic atomic.Pointer[nodeBackend]

	conf             *conffile.Config // latest parsed config, or nil if not in declarative mode
	pm               *profileManager  // mu guards access
	lastFilterInputs *filterInputs
	httpTestClient   *http.Client       // for controlclient. nil by default, used by tests.
	ccGen            clientGen          // function for producing controlclient; lazily populated
	sshServer        SSHServer          // or nil, initialized lazily.
	appConnector     *appc.AppConnector // or nil, initialized when configured.
	// notifyCancel cancels notifications to the current SetNotifyCallback.
	notifyCancel   context.CancelFunc
	cc             controlclient.Client // TODO(nickkhyl): move to nodeBackend
	ccAuto         *controlclient.Auto  // if cc is of type *controlclient.Auto; TODO(nickkhyl): move to nodeBackend
	machinePrivKey key.MachinePrivate
	tka            *tkaState // TODO(nickkhyl): move to nodeBackend
	state          ipn.State // TODO(nickkhyl): move to nodeBackend
	capTailnetLock bool      // whether netMap contains the tailnet lock capability
	// hostinfo is mutated in-place while mu is held.
	hostinfo          *tailcfg.Hostinfo      // TODO(nickkhyl): move to nodeBackend
	nmExpiryTimer     tstime.TimerController // for updating netMap on node expiry; can be nil; TODO(nickkhyl): move to nodeBackend
	activeLogin       string                 // last logged LoginName from netMap; TODO(nickkhyl): move to nodeBackend (or remove? it's in [ipn.LoginProfile]).
	engineStatus      ipn.EngineStatus
	endpoints         []tailcfg.Endpoint
	blocked           bool
	keyExpired        bool          // TODO(nickkhyl): move to nodeBackend
	authURL           string        // non-empty if not Running; TODO(nickkhyl): move to nodeBackend
	authURLTime       time.Time     // when the authURL was received from the control server; TODO(nickkhyl): move to nodeBackend
	authActor         ipnauth.Actor // an actor who called [LocalBackend.StartLoginInteractive] last, or nil; TODO(nickkhyl): move to nodeBackend
	egg               bool
	prevIfState       *netmon.State
	peerAPIServer     *peerAPIServer // or nil
	peerAPIListeners  []*peerAPIListener
	loginFlags        controlclient.LoginFlags
	notifyWatchers    map[string]*watchSession // by session ID
	lastStatusTime    time.Time                // status.AsOf value of the last processed status update
	componentLogUntil map[string]componentLogState
	currentUser       ipnauth.Actor

	// capForcedNetfilter is the netfilter that control instructs Linux clients
	// to use, unless overridden locally.
	capForcedNetfilter string // TODO(nickkhyl): move to nodeBackend

	// ServeConfig fields. (also guarded by mu)
	lastServeConfJSON mem.RO                   // last JSON that was parsed into serveConfig
	serveConfig       ipn.ServeConfigView      // or !Valid if none
	ipVIPServiceMap   netmap.IPServiceMappings // map of VIPService IPs to their corresponding service names; TODO(nickkhyl): move to nodeBackend

	webClient          webClient
	webClientListeners map[netip.AddrPort]*localListener // listeners for local web client traffic

	serveListeners     map[netip.AddrPort]*localListener // listeners for local serve traffic
	serveProxyHandlers sync.Map                          // string (HTTPHandler.Proxy) => *reverseProxy

	// mu must be held before calling statusChanged.Wait() or
	// statusChanged.Broadcast().
	statusChanged *sync.Cond

	// dialPlan is any dial plan that we've received from the control
	// server during a previous connection; it is cleared on logout.
	dialPlan atomic.Pointer[tailcfg.ControlDialPlan] // TODO(nickkhyl): maybe move to nodeBackend?

	// tkaSyncLock is used to make tkaSyncIfNeeded an exclusive
	// section. This is needed to stop two map-responses in quick succession
	// from racing each other through TKA sync logic / RPCs.
	//
	// tkaSyncLock MUST be taken before mu (or inversely, mu must not be held
	// at the moment that tkaSyncLock is taken).
	tkaSyncLock sync.Mutex
	clock       tstime.Clock

	// Last ClientVersion received in MapResponse, guarded by mu.
	lastClientVersion *tailcfg.ClientVersion

	// lastNotifiedDriveSharesMu guards lastNotifiedDriveShares
	lastNotifiedDriveSharesMu sync.Mutex

	// lastNotifiedDriveShares keeps track of the last set of shares that we
	// notified about.
	lastNotifiedDriveShares *views.SliceView[*drive.Share, drive.ShareView]

	// lastSuggestedExitNode stores the last suggested exit node suggestion to
	// avoid unnecessary churn between multiple equally-good options.
	lastSuggestedExitNode tailcfg.StableNodeID

	// allowedSuggestedExitNodes is a set of exit nodes permitted by the most recent
	// [pkey.AllowedSuggestedExitNodes] value. The allowedSuggestedExitNodesMu
	// mutex guards access to this set.
	allowedSuggestedExitNodesMu sync.Mutex
	allowedSuggestedExitNodes   set.Set[tailcfg.StableNodeID]

	// refreshAutoExitNode indicates if the exit node should be recomputed when the next netcheck report is available.
	refreshAutoExitNode bool // guarded by mu

	// captiveCtx and captiveCancel are used to control captive portal
	// detection. They are protected by 'mu' and can be changed during the
	// lifetime of a LocalBackend.
	//
	// captiveCtx will always be non-nil, though it might be a canceled
	// context. captiveCancel is non-nil if checkCaptivePortalLoop is
	// running, and is set to nil after being canceled.
	captiveCtx    context.Context
	captiveCancel context.CancelFunc
	// needsCaptiveDetection is a channel that is used to signal either
	// that captive portal detection is required (sending true) or that the
	// backend is healthy and captive portal detection is not required
	// (sending false).
	needsCaptiveDetection chan bool

	// overrideAlwaysOn is whether [pkey.AlwaysOn] is overridden by the user
	// and should have no impact on the WantRunning state until the policy changes,
	// or the user re-connects manually, switches to a different profile, etc.
	// Notably, this is true when [pkey.AlwaysOnOverrideWithReason] is enabled,
	// and the user has disconnected with a reason.
	// See tailscale/corp#26146.
	overrideAlwaysOn bool

	// reconnectTimer is used to schedule a reconnect by setting [ipn.Prefs.WantRunning]
	// to true after a delay, or nil if no reconnect is scheduled.
	reconnectTimer tstime.TimerController

	// overrideExitNodePolicy is whether the user has overridden the exit node policy
	// by manually selecting an exit node, as allowed by [pkey.AllowExitNodeOverride].
	//
	// If true, the [pkey.ExitNodeID] and [pkey.ExitNodeIP] policy settings are ignored,
	// and the suggested exit node is not applied automatically.
	//
	// It is cleared when the user switches back to the state required by policy (typically, auto:any),
	// or when switching profiles, connecting/disconnecting Tailscale, restarting the client,
	// or on similar events.
	//
	// See tailscale/corp#29969.
	overrideExitNodePolicy bool

	// hardwareAttested is whether backend should use a hardware-backed key to
	// bind the node identity to this device.
	hardwareAttested atomic.Bool
}

// SetHardwareAttested enables hardware attestation key signatures in map
// requests, if supported on this platform. SetHardwareAttested should be called
// before Start.
func (b *LocalBackend) SetHardwareAttested() {
	b.hardwareAttested.Store(true)
}

// HardwareAttested reports whether hardware-backed attestation keys should be
// used to bind the node's identity to this device.
func (b *LocalBackend) HardwareAttested() bool {
	return b.hardwareAttested.Load()
}

// HealthTracker returns the health tracker for the backend.
func (b *LocalBackend) HealthTracker() *health.Tracker { return b.health }

// Logger returns the logger for the backend.
func (b *LocalBackend) Logger() logger.Logf { return b.logf }

// UserMetricsRegistry returns the usermetrics registry for the backend
func (b *LocalBackend) UserMetricsRegistry() *usermetric.Registry {
	return b.sys.UserMetricsRegistry()
}

// NetMon returns the network monitor for the backend.
func (b *LocalBackend) NetMon() *netmon.Monitor {
	return b.sys.NetMon.Get()
}

// PolicyClient returns the policy client for the backend.
func (b *LocalBackend) PolicyClient() policyclient.Client { return b.polc }

type metrics struct {
	// advertisedRoutes is a metric that reports the number of network routes that are advertised by the local node.
	// This informs the user of how many routes are being advertised by the local node, excluding exit routes.
	advertisedRoutes *usermetric.Gauge

	// approvedRoutes is a metric that reports the number of network routes served by the local node and approved
	// by the control server.
	approvedRoutes *usermetric.Gauge
}

// clientGen is a func that creates a control plane client.
// It's the type used by LocalBackend.SetControlClientGetterForTesting.
type clientGen func(controlclient.Options) (controlclient.Client, error)

// NewLocalBackend returns a new LocalBackend that is ready to run,
// but is not actually running.
//
// If dialer is nil, a new one is made.
//
// The logID may be the zero value if logging is not in use.
func NewLocalBackend(logf logger.Logf, logID logid.PublicID, sys *tsd.System, loginFlags controlclient.LoginFlags) (_ *LocalBackend, err error) {
	e := sys.Engine.Get()
	store := sys.StateStore.Get()
	dialer := sys.Dialer.Get()
	if dialer == nil {
		return nil, errors.New("dialer to NewLocalBackend must be set")
	}
	if dialer.NetMon() == nil {
		return nil, errors.New("dialer to NewLocalBackend must have a NetMon")
	}
	mConn := sys.MagicSock.Get()

	goos := envknob.GOOS()
	if loginFlags&controlclient.LocalBackendStartKeyOSNeutral != 0 {
		goos = ""
	}
	pm, err := newProfileManagerWithGOOS(store, logf, sys.HealthTracker.Get(), goos)
	if err != nil {
		return nil, err
	}
	if sds, ok := store.(ipn.StateStoreDialerSetter); ok {
		sds.SetDialer(dialer.SystemDial)
	}

	envknob.LogCurrent(logf)

	ctx, cancel := context.WithCancelCause(context.Background())
	clock := tstime.StdClock{}

	// Until we transition to a Running state, use a canceled context for
	// our captive portal detection.
	captiveCtx, captiveCancel := context.WithCancel(ctx)
	captiveCancel()

	m := metrics{
		advertisedRoutes: sys.UserMetricsRegistry().NewGauge(
			"tailscaled_advertised_routes", "Number of advertised network routes (e.g. by a subnet router)"),
		approvedRoutes: sys.UserMetricsRegistry().NewGauge(
			"tailscaled_approved_routes", "Number of approved network routes (e.g. by a subnet router)"),
	}

	b := &LocalBackend{
		ctx:                   ctx,
		ctxCancel:             cancel,
		logf:                  logf,
		keyLogf:               logger.LogOnChange(logf, 5*time.Minute, clock.Now),
		statsLogf:             logger.LogOnChange(logf, 5*time.Minute, clock.Now),
		sys:                   sys,
		polc:                  sys.PolicyClientOrDefault(),
		health:                sys.HealthTracker.Get(),
		metrics:               m,
		e:                     e,
		dialer:                dialer,
		store:                 store,
		pm:                    pm,
		backendLogID:          logID,
		state:                 ipn.NoState,
		em:                    newExpiryManager(logf, sys.Bus.Get()),
		loginFlags:            loginFlags,
		clock:                 clock,
		captiveCtx:            captiveCtx,
		captiveCancel:         nil, // so that we start checkCaptivePortalLoop when Running
		needsCaptiveDetection: make(chan bool),
	}

	nb := newNodeBackend(ctx, b.logf, b.sys.Bus.Get())
	b.currentNodeAtomic.Store(nb)
	nb.ready()

	mConn.SetNetInfoCallback(b.setNetInfo)

	if sys.InitialConfig != nil {
		if err := b.initPrefsFromConfig(sys.InitialConfig); err != nil {
			return nil, err
		}
	}

	if b.extHost, err = NewExtensionHost(logf, b); err != nil {
		return nil, fmt.Errorf("failed to create extension host: %w", err)
	}
	b.pm.SetExtensionHost(b.extHost)

	if b.unregisterSysPolicyWatch, err = b.registerSysPolicyWatch(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			b.unregisterSysPolicyWatch()
		}
	}()

	netMon := sys.NetMon.Get()
	b.sockstatLogger, err = sockstatlog.NewLogger(logpolicy.LogsDir(logf), logf, logID, netMon, sys.HealthTracker.Get(), sys.Bus.Get())
	if err != nil {
		log.Printf("error setting up sockstat logger: %v", err)
	}
	// Enable sockstats logs only on non-mobile unstable builds
	if version.IsUnstableBuild() && !version.IsMobile() && b.sockstatLogger != nil {
		b.sockstatLogger.SetLoggingEnabled(true)
	}

	// Default filter blocks everything and logs nothing, until Start() is called.
	noneFilter := filter.NewAllowNone(logf, &netipx.IPSet{})
	b.setFilter(noneFilter)
	b.e.SetJailedFilter(noneFilter)

	b.setTCPPortsIntercepted(nil)

	b.statusChanged = sync.NewCond(&b.mu)
	b.e.SetStatusCallback(b.setWgengineStatus)

	b.prevIfState = netMon.InterfaceState()
	// Call our linkChange code once with the current state.
	// Following changes are triggered via the eventbus.
	b.linkChange(&netmon.ChangeDelta{New: netMon.InterfaceState()})

	if buildfeatures.HasPeerAPIServer {
		if tunWrap, ok := b.sys.Tun.GetOK(); ok {
			tunWrap.PeerAPIPort = b.GetPeerAPIPort
		} else {
			b.logf("[unexpected] failed to wire up PeerAPI port for engine %T", e)
		}
	}

	if buildfeatures.HasDebug {
		for _, component := range ipn.DebuggableComponents {
			key := componentStateKey(component)
			if ut, err := ipn.ReadStoreInt(pm.Store(), key); err == nil {
				if until := time.Unix(ut, 0); until.After(b.clock.Now()) {
					// conditional to avoid log spam at start when off
					b.SetComponentDebugLogging(component, until)
				}
			}
		}
	}

	// Start the event bus late, once all the assignments above are done.
	// (See previous race in tailscale/tailscale#17252)
	ec := b.Sys().Bus.Get().Client("ipnlocal.LocalBackend")
	b.eventSubs = ec.Monitor(b.consumeEventbusTopics(ec))

	return b, nil
}

// consumeEventbusTopics consumes events from all relevant
// [eventbus.Subscriber]'s and passes them to their related handler. Events are
// always handled in the order they are received, i.e. the next event is not
// read until the previous event's handler has returned. It returns when the
// [eventbus.Client] is closed.
func (b *LocalBackend) consumeEventbusTopics(ec *eventbus.Client) func(*eventbus.Client) {
	clientVersionSub := eventbus.Subscribe[tailcfg.ClientVersion](ec)
	autoUpdateSub := eventbus.Subscribe[controlclient.AutoUpdate](ec)

	var healthChange <-chan health.Change
	if buildfeatures.HasHealth {
		healthChangeSub := eventbus.Subscribe[health.Change](ec)
		healthChange = healthChangeSub.Events()
	}
	changeDeltaSub := eventbus.Subscribe[netmon.ChangeDelta](ec)
	routeUpdateSub := eventbus.Subscribe[appctype.RouteUpdate](ec)
	storeRoutesSub := eventbus.Subscribe[appctype.RouteInfo](ec)

	var portlist <-chan PortlistServices
	if buildfeatures.HasPortList {
		portlistSub := eventbus.Subscribe[PortlistServices](ec)
		portlist = portlistSub.Events()
	}

	return func(ec *eventbus.Client) {
		for {
			select {
			case <-ec.Done():
				return
			case clientVersion := <-clientVersionSub.Events():
				b.onClientVersion(&clientVersion)
			case au := <-autoUpdateSub.Events():
				b.onTailnetDefaultAutoUpdate(au.Value)
			case change := <-healthChange:
				b.onHealthChange(change)
			case changeDelta := <-changeDeltaSub.Events():
				b.linkChange(&changeDelta)

			case pl := <-portlist:
				if buildfeatures.HasPortList { // redundant, but explicit for linker deadcode and humans
					b.setPortlistServices(pl)
				}
			case ru := <-routeUpdateSub.Events():
				// TODO(creachadair, 2025-10-02): It is currently possible for updates produced under
				// one profile to arrive and be applied after a switch to another profile.
				// We need to find a way to ensure that changes to the backend state are applied
				// consistently in the presnce of profile changes, which currently may not happen in
				// a single atomic step.  See: https://github.com/tailscale/tailscale/issues/17414
				if err := b.AdvertiseRoute(ru.Advertise...); err != nil {
					b.logf("appc: failed to advertise routes: %v: %v", ru.Advertise, err)
				}
				if err := b.UnadvertiseRoute(ru.Unadvertise...); err != nil {
					b.logf("appc: failed to unadvertise routes: %v: %v", ru.Unadvertise, err)
				}
			case ri := <-storeRoutesSub.Events():
				// Whether or not routes should be stored can change over time.
				shouldStoreRoutes := b.ControlKnobs().AppCStoreRoutes.Load()
				if shouldStoreRoutes {
					if err := b.storeRouteInfo(ri); err != nil {
						b.logf("appc: failed to store route info: %v", err)
					}
				}
			}
		}
	}
}

func (b *LocalBackend) Clock() tstime.Clock { return b.clock }
func (b *LocalBackend) Sys() *tsd.System    { return b.sys }

// NodeBackend returns the current node's NodeBackend interface.
func (b *LocalBackend) NodeBackend() ipnext.NodeBackend {
	return b.currentNode()
}

func (b *LocalBackend) currentNode() *nodeBackend {
	if v := b.currentNodeAtomic.Load(); v != nil || !testenv.InTest() {
		return v
	}
	v := newNodeBackend(cmp.Or(b.ctx, context.Background()), b.logf, b.sys.Bus.Get())
	if b.currentNodeAtomic.CompareAndSwap(nil, v) {
		v.ready()
	}
	return b.currentNodeAtomic.Load()
}

// FindExtensionByName returns an active extension with the given name,
// or nil if no such extension exists.
func (b *LocalBackend) FindExtensionByName(name string) any {
	return b.extHost.Extensions().FindExtensionByName(name)
}

// FindMatchingExtension finds the first active extension that matches target,
// and if one is found, sets target to that extension and returns true.
// Otherwise, it returns false.
//
// It panics if target is not a non-nil pointer to either a type
// that implements [ipnext.Extension], or to any interface type.
func (b *LocalBackend) FindMatchingExtension(target any) bool {
	return b.extHost.Extensions().FindMatchingExtension(target)
}

type componentLogState struct {
	until time.Time
	timer tstime.TimerController // if non-nil, the AfterFunc to disable it
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
//   - sockstats
func (b *LocalBackend) SetComponentDebugLogging(component string, until time.Time) error {
	if !buildfeatures.HasDebug {
		return feature.ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	var setEnabled func(bool)
	switch component {
	case "magicsock":
		setEnabled = b.MagicConn().SetDebugLoggingEnabled
	case "sockstats":
		if b.sockstatLogger != nil {
			setEnabled = func(v bool) {
				b.sockstatLogger.SetLoggingEnabled(v)
				// Flush (and thus upload) logs when the enabled period ends,
				// so that the logs are available for debugging.
				if !v {
					b.sockstatLogger.Flush()
				}
			}
		}
	case "syspolicy":
		setEnabled = b.polc.SetDebugLoggingEnabled
	}
	if setEnabled == nil || !slices.Contains(ipn.DebuggableComponents, component) {
		return fmt.Errorf("unknown component %q", component)
	}
	timeUnixOrZero := func(t time.Time) int64 {
		if t.IsZero() {
			return 0
		}
		return t.Unix()
	}
	ipn.PutStoreInt(b.store, componentStateKey(component), timeUnixOrZero(until))
	now := b.clock.Now()
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
		newSt.timer = b.clock.AfterFunc(onFor, func() {
			// Turn off logging after the timer fires, as long as the state is
			// unchanged when the timer actually fires.
			b.mu.Lock()
			defer b.mu.Unlock()
			if ls := b.componentLogUntil[component]; ls.until.Equal(until) {
				setEnabled(false)
				b.logf("debugging logging for component %q disabled (by timer)", component)
			}
		})
	}
	mak.Set(&b.componentLogUntil, component, newSt)
	return nil
}

// GetDNSOSConfig returns the base OS DNS configuration, as seen by the DNS manager.
func (b *LocalBackend) GetDNSOSConfig() (dns.OSConfig, error) {
	if !buildfeatures.HasDNS {
		panic("unreachable")
	}
	manager, ok := b.sys.DNSManager.GetOK()
	if !ok {
		return dns.OSConfig{}, errors.New("DNS manager not available")
	}
	return manager.GetBaseConfig()
}

// QueryDNS performs a DNS query for name and queryType using the built-in DNS resolver, and returns
// the raw DNS response and the resolvers that are were able to handle the query (the internal forwarder
// may race multiple resolvers).
func (b *LocalBackend) QueryDNS(name string, queryType dnsmessage.Type) (res []byte, resolvers []*dnstype.Resolver, err error) {
	if !buildfeatures.HasDNS {
		return nil, nil, feature.ErrUnavailable
	}
	manager, ok := b.sys.DNSManager.GetOK()
	if !ok {
		return nil, nil, errors.New("DNS manager not available")
	}
	fqdn, err := dnsname.ToFQDN(name)
	if err != nil {
		b.logf("DNSQuery: failed to parse FQDN %q: %v", name, err)
		return nil, nil, err
	}
	n, err := dnsmessage.NewName(fqdn.WithTrailingDot())
	if err != nil {
		b.logf("DNSQuery: failed to parse name %q: %v", name, err)
		return nil, nil, err
	}
	from := netip.MustParseAddrPort("127.0.0.1:0")
	db := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		OpCode:           0,
		RecursionDesired: true,
		ID:               1,
	})
	db.StartQuestions()
	db.Question(dnsmessage.Question{
		Name:  n,
		Type:  queryType,
		Class: dnsmessage.ClassINET,
	})
	q, err := db.Finish()
	if err != nil {
		b.logf("DNSQuery: failed to build query: %v", err)
		return nil, nil, err
	}
	res, err = manager.Query(b.ctx, q, "tcp", from)
	if err != nil {
		b.logf("DNSQuery: failed to query %q: %v", name, err)
		return nil, nil, err
	}
	rr := manager.Resolver().GetUpstreamResolvers(fqdn)
	return res, rr, nil
}

// GetComponentDebugLogging gets the time that component's debug logging is
// enabled until, or the zero time if component's time is not currently
// enabled.
func (b *LocalBackend) GetComponentDebugLogging(component string) time.Time {
	if !buildfeatures.HasDebug {
		return time.Time{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.clock.Now()
	ls := b.componentLogUntil[component]
	if ls.until.IsZero() || ls.until.Before(now) {
		return time.Time{}
	}
	return ls.until
}

// Dialer returns the backend's dialer.
// It is always non-nil.
func (b *LocalBackend) Dialer() *tsdial.Dialer {
	return b.dialer
}

// ReloadConfig reloads the backend's config from disk.
//
// It returns (false, nil) if not running in declarative mode, (true, nil) on
// success, or (false, error) on failure.
func (b *LocalBackend) ReloadConfig() (ok bool, err error) {
	unlock := b.lockAndGetUnlock()
	defer unlock()
	if b.conf == nil {
		return false, nil
	}
	conf, err := conffile.Load(b.conf.Path)
	if err != nil {
		return false, err
	}
	if err := b.setConfigLockedOnEntry(conf, unlock); err != nil {
		return false, fmt.Errorf("error setting config: %w", err)
	}

	return true, nil
}

// initPrefsFromConfig initializes the backend's prefs from the provided config.
// This should only be called once, at startup. For updates at runtime, use
// [LocalBackend.setConfigLocked].
func (b *LocalBackend) initPrefsFromConfig(conf *conffile.Config) error {
	// TODO(maisem,bradfitz): combine this with setConfigLocked. This is called
	// before anything is running, so there's no need to lock and we don't
	// update any subsystems. At runtime, we both need to lock and update
	// subsystems with the new prefs.
	p := b.pm.CurrentPrefs().AsStruct()
	mp, err := conf.Parsed.ToPrefs()
	if err != nil {
		return fmt.Errorf("error parsing config to prefs: %w", err)
	}
	p.ApplyEdits(&mp)
	if err := b.pm.SetPrefs(p.View(), ipn.NetworkProfile{}); err != nil {
		return err
	}
	b.setStaticEndpointsFromConfigLocked(conf)
	b.conf = conf
	return nil
}

func (b *LocalBackend) setStaticEndpointsFromConfigLocked(conf *conffile.Config) {
	if conf.Parsed.StaticEndpoints == nil && (b.conf == nil || b.conf.Parsed.StaticEndpoints == nil) {
		return
	}

	// Ensure that magicsock conn has the up to date static wireguard
	// endpoints. Setting the endpoints here triggers an asynchronous update
	// of the node's advertised endpoints.
	if b.conf == nil && len(conf.Parsed.StaticEndpoints) != 0 || !reflect.DeepEqual(conf.Parsed.StaticEndpoints, b.conf.Parsed.StaticEndpoints) {
		ms, ok := b.sys.MagicSock.GetOK()
		if !ok {
			b.logf("[unexpected] ReloadConfig: MagicSock not set")
		} else {
			ms.SetStaticEndpoints(views.SliceOf(conf.Parsed.StaticEndpoints))
		}
	}
}

func (b *LocalBackend) setStateLocked(state ipn.State) {
	if b.state == state {
		return
	}
	b.state = state
	for _, f := range b.extHost.Hooks().BackendStateChange {
		f(state)
	}
}

// setConfigLockedOnEntry uses the provided config to update the backend's prefs
// and other state.
func (b *LocalBackend) setConfigLockedOnEntry(conf *conffile.Config, unlock unlockOnce) error {
	defer unlock()
	p := b.pm.CurrentPrefs().AsStruct()
	mp, err := conf.Parsed.ToPrefs()
	if err != nil {
		return fmt.Errorf("error parsing config to prefs: %w", err)
	}
	p.ApplyEdits(&mp)
	b.setStaticEndpointsFromConfigLocked(conf)
	b.setPrefsLockedOnEntry(p, unlock)

	b.conf = conf
	return nil
}

var assumeNetworkUpdateForTest = envknob.RegisterBool("TS_ASSUME_NETWORK_UP_FOR_TEST")

// pauseOrResumeControlClientLocked pauses b.cc if there is no network available
// or if the LocalBackend is in Stopped state with a valid NetMap. In all other
// cases, it unpauses it. It is a no-op if b.cc is nil.
//
// b.mu must be held.
func (b *LocalBackend) pauseOrResumeControlClientLocked() {
	if b.cc == nil {
		return
	}
	networkUp := b.prevIfState.AnyInterfaceUp()
	b.cc.SetPaused((b.state == ipn.Stopped && b.NetMap() != nil) || (!networkUp && !testenv.InTest() && !assumeNetworkUpdateForTest()))
}

// DisconnectControl shuts down control client. This can be run before node shutdown to force control to consider this ndoe
// inactive. This can be used to ensure that nodes that are HA subnet router or app connector replicas are shutting
// down, clients switch over to other replicas whilst the existing connections are kept alive for some period of time.
func (b *LocalBackend) DisconnectControl() {
	b.mu.Lock()
	defer b.mu.Unlock()
	cc := b.resetControlClientLocked()
	if cc == nil {
		return
	}
	cc.Shutdown()
}

// linkChange is our network monitor callback, called whenever the network changes.
func (b *LocalBackend) linkChange(delta *netmon.ChangeDelta) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ifst := delta.New
	hadPAC := b.prevIfState.HasPAC()
	b.prevIfState = ifst
	b.pauseOrResumeControlClientLocked()
	prefs := b.pm.CurrentPrefs()
	if delta.Major && prefs.AutoExitNode().IsSet() {
		b.refreshAutoExitNode = true
	}

	var needReconfig bool
	// If the network changed and we're using an exit node and allowing LAN access, we may need to reconfigure.
	if delta.Major && prefs.ExitNodeID() != "" && prefs.ExitNodeAllowLANAccess() {
		b.logf("linkChange: in state %v; updating LAN routes", b.state)
		needReconfig = true
	}
	// If the PAC-ness of the network changed, reconfig wireguard+route to add/remove subnets.
	if hadPAC != ifst.HasPAC() {
		b.logf("linkChange: in state %v; PAC changed from %v->%v", b.state, hadPAC, ifst.HasPAC())
		needReconfig = true
	}
	if needReconfig {
		switch b.state {
		case ipn.NoState, ipn.Stopped:
			// Do nothing.
		default:
			// TODO(raggi,tailscale/corp#22574): authReconfig should be refactored such that we can call the
			// necessary operations here and avoid the need for asynchronous behavior that is racy and hard
			// to test here, and do less extra work in these conditions.
			b.goTracker.Go(b.authReconfig)
		}
	}

	// If the local network configuration has changed, our filter may
	// need updating to tweak default routes.
	b.updateFilterLocked(prefs)
	updateExitNodeUsageWarning(prefs, delta.New, b.health)

	if buildfeatures.HasPeerAPIServer {
		cn := b.currentNode()
		nm := cn.NetMap()
		if peerAPIListenAsync && nm != nil && b.state == ipn.Running {
			want := nm.GetAddresses().Len()
			have := len(b.peerAPIListeners)
			b.logf("[v1] linkChange: have %d peerAPIListeners, want %d", have, want)
			if have < want {
				b.logf("linkChange: peerAPIListeners too low; trying again")
				b.goTracker.Go(b.initPeerAPIListener)
			}
		}
	}
}

// Captive portal detection hooks.
var (
	hookCaptivePortalHealthChange feature.Hook[func(*LocalBackend, *health.State)]
	hookCheckCaptivePortalLoop    feature.Hook[func(*LocalBackend, context.Context)]
)

func (b *LocalBackend) onHealthChange(change health.Change) {
	if !buildfeatures.HasHealth {
		return
	}
	if change.WarnableChanged {
		w := change.Warnable
		us := change.UnhealthyState
		if us == nil {
			b.logf("health(warnable=%s): ok", w.Code)
		} else {
			b.logf("health(warnable=%s): error: %s", w.Code, us.Text)
		}
	}

	// Whenever health changes, send the current health state to the frontend.
	state := b.health.CurrentState()
	b.send(ipn.Notify{
		Health: state,
	})

	if f, ok := hookCaptivePortalHealthChange.GetOk(); ok {
		f(b, state)
	}
}

// GetOrSetCaptureSink returns the current packet capture sink, creating it
// with the provided newSink function if it does not already exist.
func (b *LocalBackend) GetOrSetCaptureSink(newSink func() packet.CaptureSink) packet.CaptureSink {
	if !buildfeatures.HasCapture {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.debugSink != nil {
		return b.debugSink
	}
	s := newSink()
	b.debugSink = s
	b.e.InstallCaptureHook(s.CaptureCallback())
	return s
}

func (b *LocalBackend) ClearCaptureSink() {
	if !buildfeatures.HasCapture {
		return
	}
	// Shut down & uninstall the sink if there are no longer
	// any outputs on it.
	b.mu.Lock()
	defer b.mu.Unlock()

	select {
	case <-b.ctx.Done():
		return
	default:
	}
	if b.debugSink != nil && b.debugSink.NumOutputs() == 0 {
		s := b.debugSink
		b.e.InstallCaptureHook(nil)
		b.debugSink = nil
		s.Close()
	}
}

// Shutdown halts the backend and all its sub-components. The backend
// can no longer be used after Shutdown returns.
func (b *LocalBackend) Shutdown() {
	// Close the [eventbus.Client] and wait for LocalBackend.consumeEventbusTopics
	// to return. Do this before acquiring b.mu:
	//  1. LocalBackend.consumeEventbusTopics event handlers also acquire b.mu,
	//     they can deadlock with c.Shutdown().
	//  2. LocalBackend.consumeEventbusTopics event handlers may not guard against
	//     undesirable post/in-progress LocalBackend.Shutdown() behaviors.
	b.eventSubs.Close()

	b.em.close()

	b.mu.Lock()
	if b.shutdownCalled {
		b.mu.Unlock()
		return
	}
	b.shutdownCalled = true

	if buildfeatures.HasCaptivePortal && b.captiveCancel != nil {
		b.logf("canceling captive portal context")
		b.captiveCancel()
	}

	b.stopReconnectTimerLocked()

	if b.loginFlags&controlclient.LoginEphemeral != 0 {
		b.mu.Unlock()
		ctx, cancel := context.WithTimeout(b.ctx, 5*time.Second)
		defer cancel()
		t0 := time.Now()
		err := b.Logout(ctx, ipnauth.Self) // best effort
		td := time.Since(t0).Round(time.Millisecond)
		if err != nil {
			b.logf("failed to log out ephemeral node on shutdown after %v: %v", td, err)
		} else {
			b.logf("logged out ephemeral node on shutdown")
		}
		b.mu.Lock()
	}
	cc := b.cc
	if b.sshServer != nil {
		b.sshServer.Shutdown()
		b.sshServer = nil
	}
	b.closePeerAPIListenersLocked()
	if b.debugSink != nil {
		b.e.InstallCaptureHook(nil)
		b.debugSink.Close()
		b.debugSink = nil
	}
	if b.notifyCancel != nil {
		b.notifyCancel()
	}
	b.appConnector.Close()
	b.mu.Unlock()
	b.webClientShutdown()

	if b.sockstatLogger != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		b.sockstatLogger.Shutdown(ctx)
	}

	b.unregisterSysPolicyWatch()
	if cc != nil {
		cc.Shutdown()
	}
	b.ctxCancel(errShutdown)
	b.currentNode().shutdown(errShutdown)
	b.extHost.Shutdown()
	b.e.Close()
	<-b.e.Done()
	b.awaitNoGoroutinesInTest()
}

func (b *LocalBackend) awaitNoGoroutinesInTest() {
	if !buildfeatures.HasDebug || !testenv.InTest() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	ch := make(chan bool, 1)
	defer b.goTracker.AddDoneCallback(func() { ch <- true })()

	for {
		n := b.goTracker.RunningGoroutines()
		if n == 0 {
			return
		}
		select {
		case <-ctx.Done():
			// TODO(bradfitz): pass down some TB-like failer interface from
			// tests, without depending on testing from here?
			// But this is fine in tests too:
			panic(fmt.Sprintf("timeout waiting for %d goroutines to stop", n))
		case <-ch:
		}
	}
}

func stripKeysFromPrefs(p ipn.PrefsView) ipn.PrefsView {
	if !p.Valid() || !p.Persist().Valid() {
		return p
	}

	p2 := p.AsStruct()
	p2.Persist.PrivateNodeKey = key.NodePrivate{}
	p2.Persist.OldPrivateNodeKey = key.NodePrivate{}
	p2.Persist.NetworkLockKey = key.NLPrivate{}
	p2.Persist.AttestationKey = nil
	return p2.View()
}

// Prefs returns a copy of b's current prefs, with any private keys removed.
func (b *LocalBackend) Prefs() ipn.PrefsView {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sanitizedPrefsLocked()
}

func (b *LocalBackend) sanitizedPrefsLocked() ipn.PrefsView {
	return stripKeysFromPrefs(b.pm.CurrentPrefs())
}

// unsanitizedPersist returns the current PersistView, including any private keys.
func (b *LocalBackend) unsanitizedPersist() persist.PersistView {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.CurrentPrefs().Persist()
}

// Status returns the latest status of the backend and its
// sub-components.
func (b *LocalBackend) Status() *ipnstate.Status {
	sb := &ipnstate.StatusBuilder{WantPeers: true}
	b.UpdateStatus(sb)
	return sb.Status()
}

// StatusWithoutPeers is like Status but omits any details
// of peers.
func (b *LocalBackend) StatusWithoutPeers() *ipnstate.Status {
	sb := &ipnstate.StatusBuilder{WantPeers: false}
	b.UpdateStatus(sb)
	return sb.Status()
}

// UpdateStatus implements ipnstate.StatusUpdater.
func (b *LocalBackend) UpdateStatus(sb *ipnstate.StatusBuilder) {
	b.e.UpdateStatus(sb) // does wireguard + magicsock status

	b.mu.Lock()
	defer b.mu.Unlock()

	cn := b.currentNode()
	nm := cn.NetMap()
	sb.MutateStatus(func(s *ipnstate.Status) {
		s.Version = version.Long()
		s.TUN = !b.sys.IsNetstack()
		s.BackendState = b.state.String()
		s.AuthURL = b.authURL
		if prefs := b.pm.CurrentPrefs(); prefs.Valid() && prefs.AutoUpdate().Check {
			s.ClientVersion = b.lastClientVersion
		}
		s.Health = b.health.Strings()
		s.HaveNodeKey = b.hasNodeKeyLocked()

		// TODO(bradfitz): move this health check into a health.Warnable
		// and remove from here.
		if m := b.sshOnButUnusableHealthCheckMessageLocked(); m != "" {
			s.Health = append(s.Health, m)
		}
		if nm != nil {
			s.CertDomains = append([]string(nil), nm.DNS.CertDomains...)
			s.MagicDNSSuffix = nm.MagicDNSSuffix()
			if s.CurrentTailnet == nil {
				s.CurrentTailnet = &ipnstate.TailnetStatus{}
			}
			s.CurrentTailnet.MagicDNSSuffix = nm.MagicDNSSuffix()
			s.CurrentTailnet.MagicDNSEnabled = nm.DNS.Proxied
			s.CurrentTailnet.Name = nm.Domain
			if prefs := b.pm.CurrentPrefs(); prefs.Valid() {
				if !prefs.RouteAll() && nm.AnyPeersAdvertiseRoutes() {
					s.Health = append(s.Health, healthmsg.WarnAcceptRoutesOff)
				}
				if !prefs.ExitNodeID().IsZero() {
					if exitPeer, ok := nm.PeerWithStableID(prefs.ExitNodeID()); ok {
						s.ExitNodeStatus = &ipnstate.ExitNodeStatus{
							ID:           prefs.ExitNodeID(),
							Online:       exitPeer.Online().Get(),
							TailscaleIPs: exitPeer.Addresses().AsSlice(),
						}
					}
				}
			}
		}
	})

	var tailscaleIPs []netip.Addr
	if nm != nil {
		addrs := nm.GetAddresses()
		for i := range addrs.Len() {
			if addr := addrs.At(i); addr.IsSingleIP() {
				sb.AddTailscaleIP(addr.Addr())
				tailscaleIPs = append(tailscaleIPs, addr.Addr())
			}
		}
	}

	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
		ss.OS = version.OS()
		ss.Online = b.health.GetInPollNetMap()
		if nm != nil {
			ss.InNetworkMap = true
			if hi := nm.SelfNode.Hostinfo(); hi.Valid() {
				ss.HostName = hi.Hostname()
			}
			ss.DNSName = nm.Name
			ss.UserID = nm.User()
			if sn := nm.SelfNode; sn.Valid() {
				peerStatusFromNode(ss, sn)
				if cm := sn.CapMap(); cm.Len() > 0 {
					ss.Capabilities = make([]tailcfg.NodeCapability, 1, cm.Len()+1)
					ss.Capabilities[0] = "HTTPS://TAILSCALE.COM/s/DEPRECATED-NODE-CAPS#see-https://github.com/tailscale/tailscale/issues/11508"
					ss.CapMap = make(tailcfg.NodeCapMap, sn.CapMap().Len())
					for k, v := range cm.All() {
						ss.CapMap[k] = v.AsSlice()
						ss.Capabilities = append(ss.Capabilities, k)
					}
					slices.Sort(ss.Capabilities[1:])
				}
			}
			for _, addr := range tailscaleIPs {
				ss.TailscaleIPs = append(ss.TailscaleIPs, addr)
			}

		} else {
			ss.HostName, _ = hostinfo.Hostname()
		}
		for _, pln := range b.peerAPIListeners {
			ss.PeerAPIURL = append(ss.PeerAPIURL, pln.urlStr)
		}
	})
	// TODO: hostinfo, and its networkinfo
	// TODO: EngineStatus copy (and deprecate it?)

	if sb.WantPeers {
		b.populatePeerStatusLocked(sb)
	}
}

func (b *LocalBackend) populatePeerStatusLocked(sb *ipnstate.StatusBuilder) {
	cn := b.currentNode()
	nm := cn.NetMap()
	if nm == nil {
		return
	}
	for id, up := range nm.UserProfiles {
		sb.AddUser(id, up)
	}
	exitNodeID := b.pm.CurrentPrefs().ExitNodeID()
	for _, p := range cn.Peers() {
		tailscaleIPs := make([]netip.Addr, 0, p.Addresses().Len())
		for i := range p.Addresses().Len() {
			addr := p.Addresses().At(i)
			if addr.IsSingleIP() && tsaddr.IsTailscaleIP(addr.Addr()) {
				tailscaleIPs = append(tailscaleIPs, addr.Addr())
			}
		}
		ps := &ipnstate.PeerStatus{
			InNetworkMap:    true,
			UserID:          p.User(),
			AltSharerUserID: p.Sharer(),
			TailscaleIPs:    tailscaleIPs,
			HostName:        p.Hostinfo().Hostname(),
			DNSName:         p.Name(),
			OS:              p.Hostinfo().OS(),
			LastSeen:        p.LastSeen().Get(),
			Online:          p.Online().Get(),
			ShareeNode:      p.Hostinfo().ShareeNode(),
			ExitNode:        p.StableID() != "" && p.StableID() == exitNodeID,
			SSH_HostKeys:    p.Hostinfo().SSH_HostKeys().AsSlice(),
			Location:        p.Hostinfo().Location().AsStruct(),
			Capabilities:    p.Capabilities().AsSlice(),
		}
		for _, f := range b.extHost.Hooks().SetPeerStatus {
			f(ps, p, cn)
		}
		if cm := p.CapMap(); cm.Len() > 0 {
			ps.CapMap = make(tailcfg.NodeCapMap, cm.Len())
			for k, v := range cm.All() {
				ps.CapMap[k] = v.AsSlice()
			}
		}
		peerStatusFromNode(ps, p)

		p4, p6 := peerAPIPorts(p)
		if u := peerAPIURL(nodeIP(p, netip.Addr.Is4), p4); u != "" {
			ps.PeerAPIURL = append(ps.PeerAPIURL, u)
		}
		if u := peerAPIURL(nodeIP(p, netip.Addr.Is6), p6); u != "" {
			ps.PeerAPIURL = append(ps.PeerAPIURL, u)
		}
		sb.AddPeer(p.Key(), ps)
	}
}

// peerStatusFromNode copies fields that exist in the Node struct for
// current node and peers into the provided PeerStatus.
func peerStatusFromNode(ps *ipnstate.PeerStatus, n tailcfg.NodeView) {
	ps.PublicKey = n.Key()
	ps.ID = n.StableID()
	ps.Created = n.Created()
	ps.ExitNodeOption = buildfeatures.HasUseExitNode && tsaddr.ContainsExitRoutes(n.AllowedIPs())
	if n.Tags().Len() != 0 {
		v := n.Tags()
		ps.Tags = &v
	}
	if n.PrimaryRoutes().Len() != 0 {
		v := n.PrimaryRoutes()
		ps.PrimaryRoutes = &v
	}
	if n.AllowedIPs().Len() != 0 {
		v := n.AllowedIPs()
		ps.AllowedIPs = &v
	}

	if n.Expired() {
		ps.Expired = true
	}
	if t := n.KeyExpiry(); !t.IsZero() {
		t = t.Round(time.Second)
		ps.KeyExpiry = &t
	}
}

func profileFromView(v tailcfg.UserProfileView) tailcfg.UserProfile {
	if v.Valid() {
		return tailcfg.UserProfile{
			ID:            v.ID(),
			LoginName:     v.LoginName(),
			DisplayName:   v.DisplayName(),
			ProfilePicURL: v.ProfilePicURL(),
		}
	}
	return tailcfg.UserProfile{}
}

// WhoIsNodeKey returns the peer info of given public key, if it exists.
func (b *LocalBackend) WhoIsNodeKey(k key.NodePublic) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	cn := b.currentNode()
	if nid, ok := cn.NodeByKey(k); ok {
		if n, ok := cn.NodeByID(nid); ok {
			up, ok := cn.NetMap().UserProfiles[n.User()]
			u = profileFromView(up)
			return n, u, ok
		}
	}
	return n, u, false
}

var debugWhoIs = envknob.RegisterBool("TS_DEBUG_WHOIS")

// WhoIs reports the node and user who owns the node with the given IP:port.
// If the IP address is a Tailscale IP, the provided port may be 0.
//
// The 'proto' is used when looking up the IP:port in our proxy mapper; it
// tracks which local IP:ports correspond to connections proxied by tailscaled,
// and since tailscaled proxies both TCP and UDP, the 'proto' is needed to look
// up the correct IP:port based on the connection's protocol. If not provided,
// the lookup will be done for TCP and then UDP, in that order.
//
// If ok == true, n and u are valid.
func (b *LocalBackend) WhoIs(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	var zero tailcfg.NodeView
	b.mu.Lock()
	defer b.mu.Unlock()

	failf := func(format string, args ...any) (tailcfg.NodeView, tailcfg.UserProfile, bool) {
		if debugWhoIs() {
			args = append([]any{proto, ipp}, args...)
			b.logf("whois(%q, %v) :"+format, args...)
		}
		return zero, u, false
	}

	cn := b.currentNode()
	nid, ok := cn.NodeByAddr(ipp.Addr())
	if !ok && buildfeatures.HasNetstack {
		var ip netip.Addr
		if ipp.Port() != 0 {
			var protos []string
			if proto != "" {
				protos = []string{proto}
			} else {
				// If the user didn't specify a protocol, try all of them
				protos = []string{"tcp", "udp"}
			}

			for _, tryproto := range protos {
				ip, ok = b.sys.ProxyMapper().WhoIsIPPort(tryproto, ipp)
				if ok {
					break
				}
			}
		}
		if !ok {
			return failf("no IP found in ProxyMapper for %v", ipp)
		}
		nid, ok = cn.NodeByAddr(ip)
		if !ok {
			return failf("no node for proxymapped IP %v", ip)
		}
	}
	nm := cn.NetMap()
	if nm == nil {
		return failf("no netmap")
	}
	n, ok = cn.NodeByID(nid)
	if !ok {
		return zero, u, false
	}
	up, ok := cn.UserByID(n.User())
	if !ok {
		return failf("no userprofile for node %v", n.Key())
	}
	return n, profileFromView(up), true
}

// PeerCaps returns the capabilities that remote src IP has to
// ths current node.
func (b *LocalBackend) PeerCaps(src netip.Addr) tailcfg.PeerCapMap {
	return b.currentNode().PeerCaps(src)
}

func (b *LocalBackend) GetFilterForTest() *filter.Filter {
	testenv.AssertInTest()
	nb := b.currentNode()
	return nb.filterAtomic.Load()
}

// SetControlClientStatus is the callback invoked by the control client whenever it posts a new status.
// Among other things, this is where we update the netmap, packet filters, DNS and DERP maps.
func (b *LocalBackend) SetControlClientStatus(c controlclient.Client, st controlclient.Status) {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	if b.cc != c {
		b.logf("Ignoring SetControlClientStatus from old client")
		return
	}
	if st.Err != nil {
		// The following do not depend on any data for which we need b locked.
		unlock.UnlockEarly()
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

	// Track the number of calls
	currCall := b.numClientStatusCalls.Add(1)

	// Handle node expiry in the netmap
	if st.NetMap != nil {
		now := b.clock.Now()
		b.em.flagExpiredPeers(st.NetMap, now)

		// Always stop the existing netmap timer if we have a netmap;
		// it's possible that we have no nodes expiring, so we should
		// always cancel the timer and then possibly restart it below.
		if b.nmExpiryTimer != nil {
			// Ignore if we can't stop; the atomic check in the
			// AfterFunc (below) will skip running.
			b.nmExpiryTimer.Stop()

			// Nil so we don't attempt to stop on the next netmap
			b.nmExpiryTimer = nil
		}

		// Figure out when the next node in the netmap is expiring so we can
		// start a timer to reconfigure at that point.
		nextExpiry := b.em.nextPeerExpiry(st.NetMap, now)
		if !nextExpiry.IsZero() {
			tmrDuration := nextExpiry.Sub(now) + 10*time.Second
			b.nmExpiryTimer = b.clock.AfterFunc(tmrDuration, func() {
				// Skip if the world has moved on past the
				// saved call (e.g. if we race stopping this
				// timer).
				if b.numClientStatusCalls.Load() != currCall {
					return
				}

				b.logf("setClientStatus: netmap expiry timer triggered after %v", tmrDuration)

				// Call ourselves with the current status again; the logic in
				// setClientStatus will take care of updating the expired field
				// of peers in the netmap.
				b.SetControlClientStatus(c, st)
			})
		}
	}

	wasBlocked := b.blocked
	authWasInProgress := b.authURL != ""
	keyExpiryExtended := false
	if st.NetMap != nil {
		wasExpired := b.keyExpired
		isExpired := !st.NetMap.Expiry.IsZero() && st.NetMap.Expiry.Before(b.clock.Now())
		if wasExpired && !isExpired {
			keyExpiryExtended = true
		}
		b.keyExpired = isExpired
	}

	unlock.UnlockEarly()

	if keyExpiryExtended && wasBlocked {
		// Key extended, unblock the engine
		b.blockEngineUpdates(false)
	}

	if st.LoginFinished() && (wasBlocked || authWasInProgress) {
		if wasBlocked {
			// Auth completed, unblock the engine
			b.blockEngineUpdates(false)
		}
		b.authReconfig()
		b.send(ipn.Notify{LoginFinished: &empty.Message{}})
	}

	// Lock b again and do only the things that require locking.
	b.mu.Lock()

	prefsChanged := false
	cn := b.currentNode()
	prefs := b.pm.CurrentPrefs().AsStruct()
	oldNetMap := cn.NetMap()
	curNetMap := st.NetMap
	if curNetMap == nil {
		// The status didn't include a netmap update, so the old one is still
		// current.
		curNetMap = oldNetMap
	}

	if prefs.ControlURL == "" {
		// Once we get a message from the control plane, set
		// our ControlURL pref explicitly. This causes a
		// future "tailscale up" to start checking for
		// implicit setting reverts, which it doesn't do when
		// ControlURL is blank.
		prefs.ControlURL = prefs.ControlURLOrDefault(b.polc)
		prefsChanged = true
	}
	if st.Persist.Valid() {
		if !prefs.Persist.View().Equals(st.Persist) {
			prefsChanged = true
			prefs.Persist = st.Persist.AsStruct()
		}
	}
	if st.LoginFinished() {
		if b.authURL != "" {
			b.resetAuthURLLocked()
			// Interactive login finished successfully (URL visited).
			// After an interactive login, the user always wants
			// WantRunning.
			if !prefs.WantRunning {
				prefs.WantRunning = true
				prefsChanged = true
			}
		}
		if prefs.LoggedOut {
			prefs.LoggedOut = false
			prefsChanged = true
		}
	}
	// We primarily need this to apply syspolicy to the prefs if an implicit profile
	// switch is about to happen.
	// TODO(nickkhyl): remove this once we improve handling of implicit profile switching
	// in tailscale/corp#28014 and we apply syspolicy when the switch actually happens.
	if b.reconcilePrefsLocked(prefs) {
		prefsChanged = true
	}

	// Until recently, we did not store the account's tailnet name. So check if this is the case,
	// and backfill it on incoming status update.
	if b.pm.requiresBackfill() && st.NetMap != nil && st.NetMap.Domain != "" {
		prefsChanged = true
	}

	// If the tailnet's display name has changed, update prefs.
	if st.NetMap != nil && st.NetMap.TailnetDisplayName() != b.pm.CurrentProfile().NetworkProfile().DisplayName {
		prefsChanged = true
	}

	// Perform all mutations of prefs based on the netmap here.
	if prefsChanged {
		// Prefs will be written out if stale; this is not safe unless locked or cloned.
		if err := b.pm.SetPrefs(prefs.View(), ipn.NetworkProfile{
			MagicDNSName: curNetMap.MagicDNSSuffix(),
			DomainName:   curNetMap.DomainName(),
			DisplayName:  curNetMap.TailnetDisplayName(),
		}); err != nil {
			b.logf("Failed to save new controlclient state: %v", err)
		}

		b.sendToLocked(ipn.Notify{Prefs: ptr.To(prefs.View())}, allClients)
	}

	// initTKALocked is dependent on CurrentProfile.ID, which is initialized
	// (for new profiles) on the first call to b.pm.SetPrefs.
	if err := b.initTKALocked(); err != nil {
		b.logf("initTKALocked: %v", err)
	}

	// Perform all reconfiguration based on the netmap here.
	if st.NetMap != nil {
		b.capTailnetLock = st.NetMap.HasCap(tailcfg.CapabilityTailnetLock)
		b.setWebClientAtomicBoolLocked(st.NetMap)

		b.mu.Unlock() // respect locking rules for tkaSyncIfNeeded
		if err := b.tkaSyncIfNeeded(st.NetMap, prefs.View()); err != nil {
			b.logf("[v1] TKA sync error: %v", err)
		}
		b.mu.Lock()
		// As we stepped outside of the lock, it's possible for b.cc
		// to now be nil.
		if b.cc != nil {
			if b.tka != nil {
				head, err := b.tka.authority.Head().MarshalText()
				if err != nil {
					b.logf("[v1] error marshalling tka head: %v", err)
				} else {
					b.cc.SetTKAHead(string(head))
				}
			} else {
				b.cc.SetTKAHead("")
			}
		}

		if !envknob.TKASkipSignatureCheck() {
			b.tkaFilterNetmapLocked(st.NetMap)
		}
		b.setNetMapLocked(st.NetMap)
		b.updateFilterLocked(prefs.View())
	}
	b.mu.Unlock()

	// Now complete the lock-free parts of what we started while locked.
	if st.NetMap != nil {
		if envknob.NoLogsNoSupport() && st.NetMap.HasCap(tailcfg.CapabilityDataPlaneAuditLogs) {
			msg := "tailnet requires logging to be enabled. Remove --no-logs-no-support from tailscaled command line."
			b.health.SetLocalLogConfigHealth(errors.New(msg))
			// Connecting to this tailnet without logging is forbidden; boot us outta here.
			b.mu.Lock()
			// Get the current prefs again, since we unlocked above.
			prefs := b.pm.CurrentPrefs().AsStruct()
			prefs.WantRunning = false
			p := prefs.View()
			if err := b.pm.SetPrefs(p, ipn.NetworkProfile{
				MagicDNSName: st.NetMap.MagicDNSSuffix(),
				DomainName:   st.NetMap.DomainName(),
				DisplayName:  st.NetMap.TailnetDisplayName(),
			}); err != nil {
				b.logf("Failed to save new controlclient state: %v", err)
			}
			b.mu.Unlock()
			b.send(ipn.Notify{ErrMessage: &msg, Prefs: &p})
			return
		}
		if oldNetMap != nil {
			diff := st.NetMap.ConciseDiffFrom(oldNetMap)
			if strings.TrimSpace(diff) == "" {
				b.logf("[v1] netmap diff: (none)")
			} else {
				b.logf("[v1] netmap diff:\n%v", diff)
			}
		}

		b.e.SetNetworkMap(st.NetMap)
		b.MagicConn().SetDERPMap(st.NetMap.DERPMap)
		b.MagicConn().SetOnlyTCP443(st.NetMap.HasCap(tailcfg.NodeAttrOnlyTCP443))

		// Update our cached DERP map
		dnsfallback.UpdateCache(st.NetMap.DERPMap, b.logf)

		// Update the DERP map in the health package, which uses it for health notifications
		b.health.SetDERPMap(st.NetMap.DERPMap)

		b.send(ipn.Notify{NetMap: st.NetMap})

		// The error here is unimportant as is the result.  This will recalculate the suggested exit node
		// cache the value and push any changes to the IPN bus.
		b.SuggestExitNode()

		// Check and update the exit node if needed, now that we have a new netmap.
		//
		// This must happen after the netmap change is sent via [ipn.Notify],
		// so the GUI can correctly display the exit node if it has changed
		// since the last netmap was sent.
		//
		// Otherwise, it might briefly show the exit node as offline and display a warning,
		// if the node wasn't online or wasn't advertising default routes in the previous netmap.
		b.RefreshExitNode()
	}
	if st.URL != "" {
		b.logf("Received auth URL: %.20v...", st.URL)
		b.setAuthURL(st.URL)
	}
	b.stateMachine()
	// This is currently (2020-07-28) necessary; conditionally disabling it is fragile!
	// This is where netmap information gets propagated to router and magicsock.
	b.authReconfig()
}

type preferencePolicyInfo struct {
	key pkey.Key
	get func(ipn.PrefsView) bool
	set func(*ipn.Prefs, bool)
}

var preferencePolicies = []preferencePolicyInfo{
	{
		key: pkey.EnableIncomingConnections,
		// Allow Incoming (used by the UI) is the negation of ShieldsUp (used by the
		// backend), so this has to convert between the two conventions.
		get: func(p ipn.PrefsView) bool { return !p.ShieldsUp() },
		set: func(p *ipn.Prefs, v bool) { p.ShieldsUp = !v },
	},
	{
		key: pkey.EnableServerMode,
		get: func(p ipn.PrefsView) bool { return p.ForceDaemon() },
		set: func(p *ipn.Prefs, v bool) { p.ForceDaemon = v },
	},
	{
		key: pkey.ExitNodeAllowLANAccess,
		get: func(p ipn.PrefsView) bool { return p.ExitNodeAllowLANAccess() },
		set: func(p *ipn.Prefs, v bool) { p.ExitNodeAllowLANAccess = v },
	},
	{
		key: pkey.EnableTailscaleDNS,
		get: func(p ipn.PrefsView) bool { return p.CorpDNS() },
		set: func(p *ipn.Prefs, v bool) { p.CorpDNS = v },
	},
	{
		key: pkey.EnableTailscaleSubnets,
		get: func(p ipn.PrefsView) bool { return p.RouteAll() },
		set: func(p *ipn.Prefs, v bool) { p.RouteAll = v },
	},
	{
		key: pkey.CheckUpdates,
		get: func(p ipn.PrefsView) bool { return p.AutoUpdate().Check },
		set: func(p *ipn.Prefs, v bool) { p.AutoUpdate.Check = v },
	},
	{
		key: pkey.ApplyUpdates,
		get: func(p ipn.PrefsView) bool { v, _ := p.AutoUpdate().Apply.Get(); return v },
		set: func(p *ipn.Prefs, v bool) { p.AutoUpdate.Apply.Set(v) },
	},
	{
		key: pkey.EnableRunExitNode,
		get: func(p ipn.PrefsView) bool { return p.AdvertisesExitNode() },
		set: func(p *ipn.Prefs, v bool) { p.SetAdvertiseExitNode(v) },
	},
}

// applySysPolicyLocked overwrites configured preferences with policies that may be
// configured by the system administrator in an OS-specific way.
//
// b.mu must be held.
func (b *LocalBackend) applySysPolicyLocked(prefs *ipn.Prefs) (anyChange bool) {
	if !buildfeatures.HasSystemPolicy {
		return false
	}
	if controlURL, err := b.polc.GetString(pkey.ControlURL, prefs.ControlURL); err == nil && prefs.ControlURL != controlURL {
		prefs.ControlURL = controlURL
		anyChange = true
	}

	const sentinel = "HostnameDefaultValue"
	hostnameFromPolicy, _ := b.polc.GetString(pkey.Hostname, sentinel)
	switch hostnameFromPolicy {
	case sentinel:
		// An empty string for this policy value means that the admin wants to delete
		// the hostname stored in the ipn.Prefs. To make that work, we need to
		// distinguish between an empty string and a policy that was not set.
		// We cannot do that with the current implementation of syspolicy.GetString.
		// It currently does not return an error if a policy was not configured.
		// Instead, it returns the default value provided as the second argument.
		// This behavior makes it impossible to distinguish between a policy that
		// was not set and a policy that was set to an empty default value.
		// Checking for sentinel here is a workaround to distinguish between
		// the two cases. If we get it, we do nothing because the policy was not set.
		//
		// TODO(angott,nickkhyl): clean up this behavior once syspolicy.GetString starts
		// properly returning errors.
	case "":
		// The policy was set to an empty string, which means the admin intends
		// to clear the hostname stored in preferences.
		prefs.Hostname = ""
		anyChange = true
	default:
		// The policy was set to a non-empty string, which means the admin wants
		// to override the hostname stored in preferences.
		if prefs.Hostname != hostnameFromPolicy {
			prefs.Hostname = hostnameFromPolicy
			anyChange = true
		}
	}

	// Only apply the exit node policy if the user hasn't overridden it.
	if !b.overrideExitNodePolicy && b.applyExitNodeSysPolicyLocked(prefs) {
		anyChange = true
	}

	if alwaysOn, _ := b.polc.GetBoolean(pkey.AlwaysOn, false); alwaysOn && !b.overrideAlwaysOn && !prefs.WantRunning {
		prefs.WantRunning = true
		anyChange = true
	}

	for _, opt := range preferencePolicies {
		if po, err := b.polc.GetPreferenceOption(opt.key, ptype.ShowChoiceByPolicy); err == nil {
			curVal := opt.get(prefs.View())
			newVal := po.ShouldEnable(curVal)
			if curVal != newVal {
				opt.set(prefs, newVal)
				anyChange = true
			}
		}
	}

	return anyChange
}

// applyExitNodeSysPolicyLocked applies the exit node policy settings to prefs
// and reports whether any change was made.
//
// b.mu must be held.
func (b *LocalBackend) applyExitNodeSysPolicyLocked(prefs *ipn.Prefs) (anyChange bool) {
	if !buildfeatures.HasUseExitNode {
		return false
	}
	if exitNodeIDStr, _ := b.polc.GetString(pkey.ExitNodeID, ""); exitNodeIDStr != "" {
		exitNodeID := tailcfg.StableNodeID(exitNodeIDStr)

		// Try to parse the policy setting value as an "auto:"-prefixed [ipn.ExitNodeExpression],
		// and update prefs if it differs from the current one.
		// This includes cases where it was previously an expression but no longer is,
		// or where it wasn't before but now is.
		autoExitNode, useAutoExitNode := ipn.ParseAutoExitNodeString(exitNodeID)
		if prefs.AutoExitNode != autoExitNode {
			prefs.AutoExitNode = autoExitNode
			anyChange = true
		}
		// Additionally, if the specified exit node ID is an expression,
		// meaning an exit node is required but we don't yet have a valid exit node ID,
		// we should set exitNodeID to a value that is never a valid [tailcfg.StableNodeID],
		// to install a blackhole route and prevent accidental non-exit-node usage
		// until the expression is evaluated and an actual exit node is selected.
		// We use "auto:any" for this purpose, primarily for compatibility with
		// older clients (in case a user downgrades to an earlier version)
		// and GUIs/CLIs that have special handling for it.
		if useAutoExitNode {
			exitNodeID = unresolvedExitNodeID
		}

		// If the current exit node ID doesn't match the one enforced by the policy setting,
		// and the policy either requires a specific exit node ID,
		// or requires an auto exit node ID and the current one isn't allowed,
		// then update the exit node ID.
		if prefs.ExitNodeID != exitNodeID {
			if !useAutoExitNode || !isAllowedAutoExitNodeID(b.polc, prefs.ExitNodeID) {
				prefs.ExitNodeID = exitNodeID
				anyChange = true
			}
		}

		// If the exit node IP is set, clear it. When ExitNodeIP is set in the prefs,
		// it takes precedence over the ExitNodeID.
		if prefs.ExitNodeIP.IsValid() {
			prefs.ExitNodeIP = netip.Addr{}
			anyChange = true
		}
	} else if exitNodeIPStr, _ := b.polc.GetString(pkey.ExitNodeIP, ""); exitNodeIPStr != "" {
		if prefs.AutoExitNode != "" {
			prefs.AutoExitNode = "" // mutually exclusive with ExitNodeIP
			anyChange = true
		}
		if exitNodeIP, err := netip.ParseAddr(exitNodeIPStr); err == nil {
			if prefs.ExitNodeID != "" || prefs.ExitNodeIP != exitNodeIP {
				anyChange = true
			}
			prefs.ExitNodeID = ""
			prefs.ExitNodeIP = exitNodeIP
		}
	}

	return anyChange
}

// registerSysPolicyWatch subscribes to syspolicy change notifications
// and immediately applies the effective syspolicy settings to the current profile.
func (b *LocalBackend) registerSysPolicyWatch() (unregister func(), err error) {
	if unregister, err = b.polc.RegisterChangeCallback(b.sysPolicyChanged); err != nil {
		return nil, fmt.Errorf("syspolicy: LocalBacked failed to register policy change callback: %v", err)
	}
	if prefs, anyChange := b.reconcilePrefs(); anyChange {
		b.logf("syspolicy: changed initial profile prefs: %v", prefs.Pretty())
	}
	b.refreshAllowedSuggestions()
	return unregister, nil
}

// reconcilePrefs overwrites the current profile's preferences with policies
// that may be configured by the system administrator in an OS-specific way.
//
// b.mu must not be held.
func (b *LocalBackend) reconcilePrefs() (_ ipn.PrefsView, anyChange bool) {
	unlock := b.lockAndGetUnlock()
	prefs := b.pm.CurrentPrefs().AsStruct()
	if !b.reconcilePrefsLocked(prefs) {
		unlock.UnlockEarly()
		return prefs.View(), false
	}
	return b.setPrefsLockedOnEntry(prefs, unlock), true
}

// sysPolicyChanged is a callback triggered by syspolicy when it detects
// a change in one or more syspolicy settings.
func (b *LocalBackend) sysPolicyChanged(policy policyclient.PolicyChange) {
	if policy.HasChangedAnyOf(pkey.AlwaysOn, pkey.AlwaysOnOverrideWithReason) {
		// If the AlwaysOn or the AlwaysOnOverrideWithReason policy has changed,
		// we should reset the overrideAlwaysOn flag, as the override might
		// no longer be valid.
		b.mu.Lock()
		b.overrideAlwaysOn = false
		b.mu.Unlock()
	}

	if policy.HasChangedAnyOf(pkey.ExitNodeID, pkey.ExitNodeIP, pkey.AllowExitNodeOverride) {
		// Reset the exit node override if a policy that enforces exit node usage
		// or allows the user to override automatic exit node selection has changed.
		b.mu.Lock()
		b.overrideExitNodePolicy = false
		b.mu.Unlock()
	}

	if buildfeatures.HasUseExitNode && policy.HasChanged(pkey.AllowedSuggestedExitNodes) {
		b.refreshAllowedSuggestions()
		// Re-evaluate exit node suggestion now that the policy setting has changed.
		if _, err := b.SuggestExitNode(); err != nil && !errors.Is(err, ErrNoPreferredDERP) {
			b.logf("failed to select auto exit node: %v", err)
		}
		// If [pkey.ExitNodeID] is set to `auto:any`, the suggested exit node ID
		// will be used when [applySysPolicy] updates the current profile's prefs.
	}

	if prefs, anyChange := b.reconcilePrefs(); anyChange {
		b.logf("syspolicy: changed profile prefs: %v", prefs.Pretty())
	}
}

var _ controlclient.NetmapDeltaUpdater = (*LocalBackend)(nil)

// UpdateNetmapDelta implements controlclient.NetmapDeltaUpdater.
func (b *LocalBackend) UpdateNetmapDelta(muts []netmap.NodeMutation) (handled bool) {
	var notify *ipn.Notify // non-nil if we need to send a Notify
	defer func() {
		if notify != nil {
			b.send(*notify)
		}
	}()
	b.mu.Lock()
	defer b.mu.Unlock()

	cn := b.currentNode()
	cn.UpdateNetmapDelta(muts)

	// If auto exit nodes are enabled and our exit node went offline,
	// we need to schedule picking a new one.
	// TODO(nickkhyl): move the auto exit node logic to a feature package.
	if prefs := b.pm.CurrentPrefs(); prefs.AutoExitNode().IsSet() {
		exitNodeID := prefs.ExitNodeID()
		for _, m := range muts {
			mo, ok := m.(netmap.NodeMutationOnline)
			if !ok || mo.Online {
				continue
			}
			n, ok := cn.NodeByID(m.NodeIDBeingMutated())
			if !ok || n.StableID() != exitNodeID {
				continue
			}
			b.goTracker.Go(b.RefreshExitNode)
			break
		}
	}

	if cn.NetMap() != nil && mutationsAreWorthyOfRecalculatingSuggestedExitNode(muts, cn, b.lastSuggestedExitNode) {
		// Recompute the suggested exit node
		b.suggestExitNodeLocked()
	}

	if cn.NetMap() != nil && mutationsAreWorthyOfTellingIPNBus(muts) {

		nm := cn.netMapWithPeers()
		notify = &ipn.Notify{NetMap: nm}
	} else if testenv.InTest() {
		// In tests, send an empty Notify as a wake-up so end-to-end
		// integration tests in another repo can check on the status of
		// LocalBackend after processing deltas.
		notify = new(ipn.Notify)
	}
	return true
}

// mustationsAreWorthyOfRecalculatingSuggestedExitNode reports whether any mutation type in muts is
// worthy of recalculating the suggested exit node.
func mutationsAreWorthyOfRecalculatingSuggestedExitNode(muts []netmap.NodeMutation, cn *nodeBackend, sid tailcfg.StableNodeID) bool {
	if !buildfeatures.HasUseExitNode {
		return false
	}
	for _, m := range muts {
		n, ok := cn.NodeByID(m.NodeIDBeingMutated())
		if !ok {
			// The node being mutated is not in the netmap.
			continue
		}

		// The previously suggested exit node itself is being mutated.
		if sid != "" && n.StableID() == sid {
			return true
		}

		allowed := n.AllowedIPs().AsSlice()
		isExitNode := slices.Contains(allowed, tsaddr.AllIPv4()) || slices.Contains(allowed, tsaddr.AllIPv6())
		// The node being mutated is not an exit node.  We don't care about it - unless
		// it was our previously suggested exit node which we catch above.
		if !isExitNode {
			continue
		}

		// Some exit node is being mutated.  We care about it if it's online
		// or offline state has changed.  We *might* eventually care about it for other reasons
		// but for the sake of finding a "better" suggested exit node, this is probably
		// sufficient.
		switch m.(type) {
		case netmap.NodeMutationOnline:
			return true
		}
	}
	return false
}

// mutationsAreWorthyOfTellingIPNBus reports whether any mutation type in muts is
// worthy of spamming the IPN bus (the Windows & Mac GUIs, basically) to tell them
// about the update.
func mutationsAreWorthyOfTellingIPNBus(muts []netmap.NodeMutation) bool {
	for _, m := range muts {
		switch m.(type) {
		case netmap.NodeMutationLastSeen,
			netmap.NodeMutationOnline:
			// The GUI clients might render peers differently depending on whether
			// they're online.
			return true
		}
	}
	return false
}

// resolveAutoExitNodeLocked computes a suggested exit node and updates prefs
// to use it if AutoExitNode is enabled, and reports whether prefs was mutated.
//
// b.mu must be held.
func (b *LocalBackend) resolveAutoExitNodeLocked(prefs *ipn.Prefs) (prefsChanged bool) {
	if !buildfeatures.HasUseExitNode {
		return false
	}
	// As of 2025-07-08, the only supported auto exit node expression is [ipn.AnyExitNode].
	//
	// However, to maintain forward compatibility with future auto exit node expressions,
	// we treat any non-empty AutoExitNode as [ipn.AnyExitNode].
	//
	// If and when we support additional auto exit node expressions, this method should be updated
	// to handle them appropriately, while still falling back to [ipn.AnyExitNode] or a more appropriate
	// default for unknown (or partially supported) expressions.
	if !prefs.AutoExitNode.IsSet() {
		return false
	}
	if _, err := b.suggestExitNodeLocked(); err != nil && !errors.Is(err, ErrNoPreferredDERP) {
		b.logf("failed to select auto exit node: %v", err) // non-fatal, see below
	}
	var newExitNodeID tailcfg.StableNodeID
	if !b.lastSuggestedExitNode.IsZero() {
		// If we have a suggested exit node, use it.
		newExitNodeID = b.lastSuggestedExitNode
	} else if isAllowedAutoExitNodeID(b.polc, prefs.ExitNodeID) {
		// If we don't have a suggested exit node, but the prefs already
		// specify an allowed auto exit node ID, retain it.
		newExitNodeID = prefs.ExitNodeID
	} else {
		// Otherwise, use [unresolvedExitNodeID] to install a blackhole route,
		// preventing traffic from leaking to the local network until an actual
		// exit node is selected.
		newExitNodeID = unresolvedExitNodeID
	}
	if prefs.ExitNodeID != newExitNodeID {
		prefs.ExitNodeID = newExitNodeID
		prefsChanged = true
	}
	if prefs.ExitNodeIP.IsValid() {
		prefs.ExitNodeIP = netip.Addr{}
		prefsChanged = true
	}
	return prefsChanged
}

// resolveExitNodeIPLocked updates prefs to reference an exit node by ID, rather
// than by IP. It returns whether prefs was mutated.
//
// b.mu must be held.
func (b *LocalBackend) resolveExitNodeIPLocked(prefs *ipn.Prefs) (prefsChanged bool) {
	if !buildfeatures.HasUseExitNode {
		return false
	}
	// If we have a desired IP on file, try to find the corresponding node.
	if !prefs.ExitNodeIP.IsValid() {
		return false
	}

	// IP takes precedence over ID, so if both are set, clear ID.
	if prefs.ExitNodeID != "" {
		prefs.ExitNodeID = ""
		prefsChanged = true
	}

	cn := b.currentNode()
	if nid, ok := cn.NodeByAddr(prefs.ExitNodeIP); ok {
		if node, ok := cn.NodeByID(nid); ok {
			// Found the node being referenced, upgrade prefs to
			// reference it directly for next time.
			prefs.ExitNodeID = node.StableID()
			prefs.ExitNodeIP = netip.Addr{}
			// Cleared ExitNodeIP, so prefs changed
			// even if the ID stayed the same.
			prefsChanged = true

		}
	}
	return prefsChanged
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
	needUpdateEndpoints := !slices.Equal(s.LocalAddrs, b.endpoints)
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

// broadcastStatusChanged must not be called with b.mu held.
func (b *LocalBackend) broadcastStatusChanged() {
	// The sync.Cond docs say: "It is allowed but not required for the caller to hold c.L during the call."
	// In this particular case, we must acquire b.mu. Otherwise we might broadcast before
	// the waiter (in requestEngineStatusAndWait) starts to wait, in which case
	// the waiter can get stuck indefinitely. See PR 2865.
	b.mu.Lock()
	b.statusChanged.Broadcast()
	b.mu.Unlock()
}

// SetNotifyCallback sets the function to call when the backend has something to
// notify the frontend about. Only one callback can be set at a time, so calling
// this function will replace the previous callback.
func (b *LocalBackend) SetNotifyCallback(notify func(ipn.Notify)) {
	ctx, cancel := context.WithCancel(b.ctx)
	b.mu.Lock()
	prevCancel := b.notifyCancel
	b.notifyCancel = cancel
	b.mu.Unlock()
	if prevCancel != nil {
		prevCancel()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go b.WatchNotifications(ctx, 0, wg.Done, func(n *ipn.Notify) bool {
		notify(*n)
		return true
	})
	wg.Wait()
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

// PeersForTest returns all the current peers, sorted by Node.ID,
// for integration tests in another repo.
func (b *LocalBackend) PeersForTest() []tailcfg.NodeView {
	testenv.AssertInTest()
	return b.currentNode().PeersForTest()
}

func (b *LocalBackend) getNewControlClientFuncLocked() clientGen {
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

// initOnce is called on the first call to [LocalBackend.Start].
func (b *LocalBackend) initOnce() {
	b.extHost.Init()
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
	b.logf("Start")

	b.startOnce.Do(b.initOnce)

	var clientToShutdown controlclient.Client
	defer func() {
		if clientToShutdown != nil {
			clientToShutdown.Shutdown()
		}
	}()
	unlock := b.lockAndGetUnlock()
	defer unlock()

	if opts.UpdatePrefs != nil {
		if err := b.checkPrefsLocked(opts.UpdatePrefs); err != nil {
			return err
		}
	}
	if b.state != ipn.Running && b.conf != nil && b.conf.Parsed.AuthKey != nil && opts.AuthKey == "" {
		v := *b.conf.Parsed.AuthKey
		if filename, ok := strings.CutPrefix(v, "file:"); ok {
			b, err := os.ReadFile(filename)
			if err != nil {
				return fmt.Errorf("error reading config file authKey: %w", err)
			}
			v = strings.TrimSpace(string(b))
		}
		opts.AuthKey = v
	}

	if b.state != ipn.Running && b.conf == nil && opts.AuthKey == "" {
		sysak, _ := b.polc.GetString(pkey.AuthKey, "")
		if sysak != "" {
			b.logf("Start: setting opts.AuthKey by syspolicy, len=%v", len(sysak))
			opts.AuthKey = strings.TrimSpace(sysak)
		}
	}

	hostinfo := hostinfo.New()
	applyConfigToHostinfo(hostinfo, b.conf)
	hostinfo.BackendLogID = b.backendLogID.String()
	hostinfo.FrontendLogID = opts.FrontendLogID
	hostinfo.Userspace.Set(b.sys.IsNetstack())
	hostinfo.UserspaceRouter.Set(b.sys.IsNetstackRouter())
	hostinfo.AppConnector.Set(b.appConnector != nil)
	hostinfo.StateEncrypted = b.stateEncrypted()
	b.logf.JSON(1, "Hostinfo", hostinfo)

	// TODO(apenwarr): avoid the need to reinit controlclient.
	// This will trigger a full relogin/reconfigure cycle every
	// time a Handle reconnects to the backend. Ideally, we
	// would send the new Prefs and everything would get back
	// into sync with the minimal changes. But that's not how it
	// is right now, which is a sign that the code is still too
	// complicated.
	clientToShutdown = b.resetControlClientLocked()
	httpTestClient := b.httpTestClient

	if b.hostinfo != nil {
		hostinfo.Services = b.hostinfo.Services // keep any previous services
	}
	b.hostinfo = hostinfo
	b.setStateLocked(ipn.NoState)

	cn := b.currentNode()

	prefsChanged := false
	newPrefs := b.pm.CurrentPrefs().AsStruct()
	if opts.UpdatePrefs != nil {
		newPrefs = opts.UpdatePrefs.Clone()
		prefsChanged = true
	}
	// Apply any syspolicy overrides, resolve exit node ID, etc.
	// As of 2025-07-03, this is primarily needed in two cases:
	//  - when opts.UpdatePrefs is not nil
	//  - when Always Mode is enabled and we need to set WantRunning to true
	if b.reconcilePrefsLocked(newPrefs) {
		prefsChanged = true
	}

	// neither UpdatePrefs or reconciliation should change Persist
	newPrefs.Persist = b.pm.CurrentPrefs().Persist().AsStruct()

	if buildfeatures.HasTPM {
		if genKey, ok := feature.HookGenerateAttestationKeyIfEmpty.GetOk(); ok {
			newKey, err := genKey(newPrefs.Persist, b.logf)
			if err != nil {
				b.logf("failed to populate attestation key from TPM: %v", err)
			}
			if newKey {
				prefsChanged = true
			}
		}
	}

	if prefsChanged {
		if err := b.pm.SetPrefs(newPrefs.View(), cn.NetworkProfile()); err != nil {
			b.logf("failed to save updated and reconciled prefs: %v", err)
		}
	}
	prefs := newPrefs.View()

	// Reset the always-on override whenever Start is called.
	b.resetAlwaysOnOverrideLocked()
	b.setAtomicValuesFromPrefsLocked(prefs)

	wantRunning := prefs.WantRunning()
	if wantRunning {
		if err := b.initMachineKeyLocked(); err != nil {
			return fmt.Errorf("initMachineKeyLocked: %w", err)
		}
	}

	loggedOut := prefs.LoggedOut()

	serverURL := prefs.ControlURLOrDefault(b.polc)
	if inServerMode := prefs.ForceDaemon(); inServerMode || runtime.GOOS == "windows" {
		b.logf("Start: serverMode=%v", inServerMode)
	}
	b.applyPrefsToHostinfoLocked(hostinfo, prefs)

	persistv := prefs.Persist().AsStruct()
	if persistv == nil {
		persistv = new(persist.Persist)
	}

	discoPublic := b.MagicConn().DiscoPublicKey()

	isNetstack := b.sys.IsNetstackRouter()
	debugFlags := controlDebugFlags
	if isNetstack {
		debugFlags = append([]string{"netstack"}, debugFlags...)
	}

	var ccShutdownCbs []func()
	ccShutdown := func() {
		for _, cb := range ccShutdownCbs {
			cb()
		}
	}

	var c2nHandler http.Handler
	if buildfeatures.HasC2N {
		c2nHandler = http.HandlerFunc(b.handleC2N)
	}

	// TODO(apenwarr): The only way to change the ServerURL is to
	// re-run b.Start, because this is the only place we create a
	// new controlclient. EditPrefs allows you to overwrite ServerURL,
	// but it won't take effect until the next Start.
	cc, err := b.getNewControlClientFuncLocked()(controlclient.Options{
		GetMachinePrivateKey: b.createGetMachinePrivateKeyFunc(),
		Logf:                 logger.WithPrefix(b.logf, "control: "),
		Persist:              *persistv,
		ServerURL:            serverURL,
		AuthKey:              opts.AuthKey,
		Hostinfo:             hostinfo,
		HTTPTestClient:       httpTestClient,
		DiscoPublicKey:       discoPublic,
		DebugFlags:           debugFlags,
		HealthTracker:        b.health,
		PolicyClient:         b.sys.PolicyClientOrDefault(),
		Pinger:               b,
		PopBrowserURL:        b.tellClientToBrowseToURL,
		Dialer:               b.Dialer(),
		Observer:             b,
		C2NHandler:           c2nHandler,
		DialPlan:             &b.dialPlan, // pointer because it can't be copied
		ControlKnobs:         b.sys.ControlKnobs(),
		Shutdown:             ccShutdown,
		Bus:                  b.sys.Bus.Get(),

		// Don't warn about broken Linux IP forwarding when
		// netstack is being used.
		SkipIPForwardingCheck: isNetstack,
	})
	if err != nil {
		return err
	}
	ccShutdownCbs = b.extHost.NotifyNewControlClient(cc, b.pm.CurrentProfile())

	b.setControlClientLocked(cc)
	endpoints := b.endpoints

	if err := b.initTKALocked(); err != nil {
		b.logf("initTKALocked: %v", err)
	}
	var tkaHead string
	if b.tka != nil {
		head, err := b.tka.authority.Head().MarshalText()
		if err != nil {
			return fmt.Errorf("marshalling tka head: %w", err)
		}
		tkaHead = string(head)
	}
	confWantRunning := b.conf != nil && wantRunning

	if endpoints != nil {
		cc.UpdateEndpoints(endpoints)
	}
	cc.SetTKAHead(tkaHead)

	blid := b.backendLogID.String()
	b.logf("Backend: logs: be:%v fe:%v", blid, opts.FrontendLogID)
	b.sendToLocked(ipn.Notify{Prefs: &prefs}, allClients)

	// initialize Taildrive shares from saved state
	if fs, ok := b.sys.DriveForRemote.GetOK(); ok {
		currentShares := b.pm.CurrentPrefs().DriveShares()
		var shares []*drive.Share
		for _, share := range currentShares.All() {
			shares = append(shares, share.AsStruct())
		}
		fs.SetShares(shares)
	}

	if !loggedOut && (b.hasNodeKeyLocked() || confWantRunning) {
		// If we know that we're either logged in or meant to be
		// running, tell the controlclient that it should also assume
		// that we need to be logged in.
		//
		// Without this, the state machine transitions to "NeedsLogin" implying
		// that user interaction is required, which is not the case and can
		// regress tsnet.Server restarts.
		cc.Login(controlclient.LoginDefault)
	}
	b.stateMachineLockedOnEntry(unlock)

	return nil
}

// addServiceIPs adds the IP addresses of any VIP Services sent from the
// coordination server to the list of addresses that we expect to handle.
func addServiceIPs(localNetsB *netipx.IPSetBuilder, selfNode tailcfg.NodeView) error {
	if !selfNode.Valid() {
		return nil
	}

	serviceMap, err := tailcfg.UnmarshalNodeCapViewJSON[tailcfg.ServiceIPMappings](selfNode.CapMap(), tailcfg.NodeAttrServiceHost)
	if err != nil {
		return err
	}

	for _, sm := range serviceMap { // typically there will be exactly one of these
		for _, serviceAddrs := range sm {
			for _, addr := range serviceAddrs { // typically there will be exactly two of these
				localNetsB.Add(addr)
			}
		}
	}

	return nil
}

// invalidPacketFilterWarnable is a Warnable to warn the user that the control server sent an invalid packet filter.
var invalidPacketFilterWarnable = health.Register(&health.Warnable{
	Code:     "invalid-packet-filter",
	Title:    "Invalid packet filter",
	Severity: health.SeverityHigh,
	Text:     health.StaticMessage("The coordination server sent an invalid packet filter permitting traffic to unlocked nodes; rejecting all packets for safety"),
})

// filterInputs holds the inputs to the packet filter.
//
// Any field changes or additions here should be accompanied by a change to
// [filterInputs.Equal] and [filterInputs.Clone] if necessary. (e.g. non-view
// and non-value fields)
type filterInputs struct {
	HaveNetmap  bool
	Addrs       views.Slice[netip.Prefix]
	FilterMatch views.Slice[filter.Match]
	LocalNets   views.Slice[netipx.IPRange]
	LogNets     views.Slice[netipx.IPRange]
	ShieldsUp   bool
	SSHPolicy   tailcfg.SSHPolicyView
}

func (fi *filterInputs) Equal(o *filterInputs) bool {
	if fi == nil || o == nil {
		return fi == o
	}
	return reflect.DeepEqual(fi, o)
}

func (fi *filterInputs) Clone() *filterInputs {
	if fi == nil {
		return nil
	}
	v := *fi // all fields are shallow copyable
	return &v
}

// updateFilterLocked updates the packet filter in wgengine based on the
// given netMap and user preferences.
//
// b.mu must be held.
func (b *LocalBackend) updateFilterLocked(prefs ipn.PrefsView) {
	// TODO(nickkhyl) split this into two functions:
	// - (*nodeBackend).RebuildFilters() (normalFilter, jailedFilter *filter.Filter, changed bool),
	//   which would return packet filters for the current state and whether they changed since the last call.
	// - (*LocalBackend).updateFilters(), which would use the above to update the engine with the new filters,
	//    notify b.sshServer, etc.
	//
	// For this, we would need to plumb a few more things into the [nodeBackend]. Most importantly,
	// the current [ipn.PrefsView]), but also maybe also a b.logf and a b.health?
	//
	// NOTE(danderson): keep change detection as the first thing in
	// this function. Don't try to optimize by returning early, more
	// likely than not you'll just end up breaking the change
	// detection and end up with the wrong filter installed. This is
	// quite hard to debug, so save yourself the trouble.
	var (
		cn           = b.currentNode()
		netMap       = cn.NetMap()
		haveNetmap   = netMap != nil
		addrs        views.Slice[netip.Prefix]
		packetFilter []filter.Match
		localNetsB   netipx.IPSetBuilder
		logNetsB     netipx.IPSetBuilder
		shieldsUp    = !prefs.Valid() || prefs.ShieldsUp() // Be conservative when not ready
	)
	// Log traffic for Tailscale IPs.
	logNetsB.AddPrefix(tsaddr.CGNATRange())
	logNetsB.AddPrefix(tsaddr.TailscaleULARange())
	logNetsB.RemovePrefix(tsaddr.ChromeOSVMRange())
	if haveNetmap {
		addrs = netMap.GetAddresses()
		for i := range addrs.Len() {
			localNetsB.AddPrefix(addrs.At(i))
		}
		packetFilter = netMap.PacketFilter

		if cn.unlockedNodesPermitted(packetFilter) {
			b.health.SetUnhealthy(invalidPacketFilterWarnable, nil)
			packetFilter = nil
		} else {
			b.health.SetHealthy(invalidPacketFilterWarnable)
		}

		if err := addServiceIPs(&localNetsB, netMap.SelfNode); err != nil {
			b.logf("addServiceIPs: %v", err)
		}
	}
	if prefs.Valid() {
		if buildfeatures.HasAdvertiseRoutes {
			for _, r := range prefs.AdvertiseRoutes().All() {
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

		// App connectors handle DNS requests for app domains over PeerAPI (corp#11961),
		// but a safety check verifies the requesting peer has at least permission
		// to send traffic to 0.0.0.0:53 (or 2000:: for IPv6) before handling the DNS
		// request (see peerAPIHandler.replyToDNSQueries in peerapi.go).
		// The correct filter rules are synthesized by the coordination server
		// and sent down, but the address needs to be part of the 'local net' for the
		// filter package to even bother checking the filter rules, so we set them here.
		if buildfeatures.HasAppConnectors && prefs.AppConnector().Advertise {
			localNetsB.Add(netip.MustParseAddr("0.0.0.0"))
			localNetsB.Add(netip.MustParseAddr("::0"))
		}
	}
	localNets, _ := localNetsB.IPSet()
	logNets, _ := logNetsB.IPSet()
	var sshPol tailcfg.SSHPolicyView
	if buildfeatures.HasSSH && haveNetmap && netMap.SSHPolicy != nil {
		sshPol = netMap.SSHPolicy.View()
	}

	changed := checkchange.Update(&b.lastFilterInputs, &filterInputs{
		HaveNetmap:  haveNetmap,
		Addrs:       addrs,
		FilterMatch: views.SliceOf(packetFilter),
		LocalNets:   views.SliceOf(localNets.Ranges()),
		LogNets:     views.SliceOf(logNets.Ranges()),
		ShieldsUp:   shieldsUp,
		SSHPolicy:   sshPol,
	})
	if !changed {
		return
	}

	if !haveNetmap {
		b.logf("[v1] netmap packet filter: (not ready yet)")
		noneFilter := filter.NewAllowNone(b.logf, logNets)
		b.setFilter(noneFilter)
		b.e.SetJailedFilter(noneFilter)
		return
	}

	oldFilter := b.e.GetFilter()
	if shieldsUp {
		b.logf("[v1] netmap packet filter: (shields up)")
		b.setFilter(filter.NewShieldsUpFilter(localNets, logNets, oldFilter, b.logf))
	} else {
		b.logf("[v1] netmap packet filter: %v filters", len(packetFilter))
		b.setFilter(filter.New(packetFilter, b.srcIPHasCapForFilter, localNets, logNets, oldFilter, b.logf))
	}
	// The filter for a jailed node is the exact same as a ShieldsUp filter.
	oldJailedFilter := b.e.GetJailedFilter()
	b.e.SetJailedFilter(filter.NewShieldsUpFilter(localNets, logNets, oldJailedFilter, b.logf))

	if b.sshServer != nil {
		b.goTracker.Go(b.sshServer.OnPolicyChange)
	}
}

// packetFilterPermitsUnlockedNodes reports any peer in peers with the
// UnsignedPeerAPIOnly bool set true has any of its allowed IPs in the packet
// filter.
//
// If this reports true, the packet filter is invalid (the server is either broken
// or malicious) and should be ignored for safety.
func packetFilterPermitsUnlockedNodes(peers map[tailcfg.NodeID]tailcfg.NodeView, packetFilter []filter.Match) bool {
	var b netipx.IPSetBuilder
	var numUnlocked int
	for _, p := range peers {
		if !p.UnsignedPeerAPIOnly() {
			continue
		}
		numUnlocked++
		for _, pfx := range p.AllowedIPs().All() { // not only addresses!
			b.AddPrefix(pfx)
		}
	}
	if numUnlocked == 0 {
		return false
	}
	s, err := b.IPSet()
	if err != nil {
		// Shouldn't happen, but if it does, fail closed.
		return true
	}
	for _, m := range packetFilter {
		for _, r := range m.Srcs {
			if !s.OverlapsPrefix(r) {
				continue
			}
			if len(m.Dsts) != 0 {
				return true
			}
		}
	}
	return false
}

// TODO(nickkhyl): this should be non-existent with a proper [LocalBackend.updateFilterLocked].
// See the comment in that function for more details.
func (b *LocalBackend) setFilter(f *filter.Filter) {
	b.currentNode().setFilter(f)
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
	il, err := netmon.GetInterfaceList()
	if err != nil {
		return nil, nil, err
	}
	return internalAndExternalInterfacesFrom(il, runtime.GOOS)
}

func internalAndExternalInterfacesFrom(il netmon.InterfaceList, goos string) (internal, external []netip.Prefix, err error) {
	// We use an IPSetBuilder here to canonicalize the prefixes
	// and to remove any duplicate entries.
	var internalBuilder, externalBuilder netipx.IPSetBuilder
	if err := il.ForeachInterfaceAddress(func(iface netmon.Interface, pfx netip.Prefix) {
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
	if err := netmon.ForeachInterfaceAddress(func(_ netmon.Interface, pfx netip.Prefix) {
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

// GetPushDeviceToken returns the push notification device token.
func (b *LocalBackend) GetPushDeviceToken() string {
	return b.pushDeviceToken.Load()
}

// SetPushDeviceToken sets the push notification device token and informs the
// controlclient of the new value.
func (b *LocalBackend) SetPushDeviceToken(tk string) {
	old := b.pushDeviceToken.Swap(tk)
	if old == tk {
		return
	}
	b.doSetHostinfoFilterServices()
}

func applyConfigToHostinfo(hi *tailcfg.Hostinfo, c *conffile.Config) {
	if c == nil {
		return
	}
	if c.Parsed.Hostname != nil {
		hi.Hostname = *c.Parsed.Hostname
	}
}

// WatchNotifications subscribes to the ipn.Notify message bus notification
// messages.
//
// WatchNotifications blocks until ctx is done.
//
// The provided onWatchAdded, if non-nil, will be called once the watcher
// is installed.
//
// The provided fn will be called for each notification. It will only be
// called with non-nil pointers. The caller must not modify roNotify. If
// fn returns false, the watch also stops.
//
// Failure to consume many notifications in a row will result in dropped
// notifications. There is currently (2022-11-22) no mechanism provided to
// detect when a message has been dropped.
func (b *LocalBackend) WatchNotifications(ctx context.Context, mask ipn.NotifyWatchOpt, onWatchAdded func(), fn func(roNotify *ipn.Notify) (keepGoing bool)) {
	b.WatchNotificationsAs(ctx, nil, mask, onWatchAdded, fn)
}

// WatchNotificationsAs is like [LocalBackend.WatchNotifications] but takes an [ipnauth.Actor]
// as an additional parameter. If non-nil, the specified callback is invoked
// only for notifications relevant to this actor.
func (b *LocalBackend) WatchNotificationsAs(ctx context.Context, actor ipnauth.Actor, mask ipn.NotifyWatchOpt, onWatchAdded func(), fn func(roNotify *ipn.Notify) (keepGoing bool)) {
	ch := make(chan *ipn.Notify, 128)
	sessionID := rands.HexString(16)
	if mask&ipn.NotifyNoPrivateKeys != 0 {
		fn = filterPrivateKeys(fn)
	}
	if mask&ipn.NotifyHealthActions == 0 {
		// if UI does not support PrimaryAction in health warnings, append
		// action URLs to the warning text instead.
		fn = appendHealthActions(fn)
	}

	var ini *ipn.Notify

	b.mu.Lock()

	const initialBits = ipn.NotifyInitialState | ipn.NotifyInitialPrefs | ipn.NotifyInitialNetMap | ipn.NotifyInitialDriveShares | ipn.NotifyInitialSuggestedExitNode
	if mask&initialBits != 0 {
		cn := b.currentNode()
		ini = &ipn.Notify{Version: version.Long()}
		if mask&ipn.NotifyInitialState != 0 {
			ini.SessionID = sessionID
			ini.State = ptr.To(b.state)
			if b.state == ipn.NeedsLogin && b.authURL != "" {
				ini.BrowseToURL = ptr.To(b.authURL)
			}
		}
		if mask&ipn.NotifyInitialPrefs != 0 {
			ini.Prefs = ptr.To(b.sanitizedPrefsLocked())
		}
		if mask&ipn.NotifyInitialNetMap != 0 {
			ini.NetMap = cn.NetMap()
		}
		if mask&ipn.NotifyInitialDriveShares != 0 && b.DriveSharingEnabled() {
			ini.DriveShares = b.pm.prefs.DriveShares()
		}
		if mask&ipn.NotifyInitialHealthState != 0 {
			ini.Health = b.HealthTracker().CurrentState()
		}
		if mask&ipn.NotifyInitialSuggestedExitNode != 0 {
			if en, err := b.suggestExitNodeLocked(); err == nil {
				ini.SuggestedExitNode = &en.ID
			}
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	session := &watchSession{
		ch:        ch,
		owner:     actor,
		sessionID: sessionID,
		cancel:    cancel,
	}
	mak.Set(&b.notifyWatchers, sessionID, session)
	b.mu.Unlock()

	metricCurrentWatchIPNBus.Add(1)
	defer metricCurrentWatchIPNBus.Add(-1)

	defer func() {
		b.mu.Lock()
		delete(b.notifyWatchers, sessionID)
		b.mu.Unlock()
	}()

	if onWatchAdded != nil {
		onWatchAdded()
	}

	if ini != nil {
		if !fn(ini) {
			return
		}
	}

	// The GUI clients want to know when peers become active or inactive.
	// They've historically got this information by polling for it, which is
	// wasteful. As a step towards making it efficient, they now set this
	// NotifyWatchEngineUpdates bit to ask for us to send it to them only on
	// change. That's not yet (as of 2022-11-26) plumbed everywhere in
	// tailscaled yet, so just do the polling here. This ends up causing all IPN
	// bus watchers to get the notification every 2 seconds instead of just the
	// GUI client's bus watcher, but in practice there's only 1 total connection
	// anyway. And if we're polling, at least the client isn't making a new HTTP
	// request every 2 seconds.
	// TODO(bradfitz): plumb this further and only send a Notify on change.
	if mask&ipn.NotifyWatchEngineUpdates != 0 {
		b.goTracker.Go(func() { b.pollRequestEngineStatus(ctx) })
	}

	// TODO(marwan-at-work): streaming background logs?
	defer b.DeleteForegroundSession(sessionID)

	sender := &rateLimitingBusSender{fn: fn}
	defer sender.close()

	if mask&ipn.NotifyRateLimit != 0 {
		sender.interval = 3 * time.Second
	}

	sender.Run(ctx, ch)
}

// filterPrivateKeys returns an IPN listener func that wraps the supplied IPN
// listener and zeroes out the PrivateKey in the NetMap passed to the wrapped
// listener.
func filterPrivateKeys(fn func(roNotify *ipn.Notify) (keepGoing bool)) func(*ipn.Notify) bool {
	return func(n *ipn.Notify) bool {
		redacted, changed := redactNetmapPrivateKeys(n.NetMap)
		if !changed {
			return fn(n)
		}

		// The netmap in n is shared across all watchers, so to mutate it for a
		// single watcher we have to clone the notify and the netmap. We can
		// make shallow clones, at least.
		n2 := *n
		n2.NetMap = redacted
		return fn(&n2)
	}
}

// redactNetmapPrivateKeys returns a copy of nm with private keys zeroed out.
// If no change was needed, it returns nm unmodified.
func redactNetmapPrivateKeys(nm *netmap.NetworkMap) (redacted *netmap.NetworkMap, changed bool) {
	if nm == nil || nm.PrivateKey.IsZero() {
		return nm, false
	}

	// The netmap might be shared across watchers, so make at least a shallow
	// clone before mutating it.
	nm2 := *nm
	nm2.PrivateKey = key.NodePrivate{}
	return &nm2, true
}

// appendHealthActions returns an IPN listener func that wraps the supplied IPN
// listener func and transforms health messages passed to the wrapped listener.
// If health messages with PrimaryActions are present, it appends the label &
// url in the PrimaryAction to the text of the message. For use for clients that
// do not process the PrimaryAction.
func appendHealthActions(fn func(roNotify *ipn.Notify) (keepGoing bool)) func(*ipn.Notify) bool {
	return func(n *ipn.Notify) bool {
		if n.Health == nil || len(n.Health.Warnings) == 0 {
			return fn(n)
		}

		// Shallow clone the notify and health so we can mutate them
		h2 := *n.Health
		n2 := *n
		n2.Health = &h2
		n2.Health.Warnings = make(map[health.WarnableCode]health.UnhealthyState, len(n.Health.Warnings))
		for k, v := range n.Health.Warnings {
			if v.PrimaryAction != nil {
				v.Text = fmt.Sprintf("%s %s: %s", v.Text, v.PrimaryAction.Label, v.PrimaryAction.URL)
				v.PrimaryAction = nil
			}
			n2.Health.Warnings[k] = v
		}
		return fn(&n2)
	}
}

// pollRequestEngineStatus calls b.e.RequestStatus every 2 seconds until ctx
// is done.
func (b *LocalBackend) pollRequestEngineStatus(ctx context.Context) {
	ticker, tickerChannel := b.clock.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-tickerChannel:
			b.e.RequestStatus()
		case <-ctx.Done():
			return
		}
	}
}

// DebugNotify injects a fake notify message to clients.
//
// It should only be used via the LocalAPI's debug handler.
func (b *LocalBackend) DebugNotify(n ipn.Notify) {
	b.send(n)
}

// DebugNotifyLastNetMap injects a fake notify message to clients,
// repeating whatever the last netmap was.
//
// It should only be used via the LocalAPI's debug handler.
func (b *LocalBackend) DebugNotifyLastNetMap() {
	if nm := b.currentNode().NetMap(); nm != nil {
		b.send(ipn.Notify{NetMap: nm})
	}
}

// DebugForceNetmapUpdate forces a full no-op netmap update of the current
// netmap in all the various subsystems (wireguard, magicsock, LocalBackend).
//
// It exists for load testing reasons (for issue 1909), doing what would happen
// if a new MapResponse came in from the control server that couldn't be handled
// incrementally.
func (b *LocalBackend) DebugForceNetmapUpdate() {
	b.mu.Lock()
	defer b.mu.Unlock()
	// TODO(nickkhyl): this all should be done in [LocalBackend.setNetMapLocked].
	nm := b.currentNode().NetMap()
	b.e.SetNetworkMap(nm)
	if nm != nil {
		b.MagicConn().SetDERPMap(nm.DERPMap)
	}
	b.setNetMapLocked(nm)
}

// DebugPickNewDERP forwards to magicsock.Conn.DebugPickNewDERP.
// See its docs.
func (b *LocalBackend) DebugPickNewDERP() error {
	return b.sys.MagicSock.Get().DebugPickNewDERP()
}

// DebugForcePreferDERP forwards to netcheck.DebugForcePreferDERP.
// See its docs.
func (b *LocalBackend) DebugForcePreferDERP(n int) {
	b.sys.MagicSock.Get().DebugForcePreferDERP(n)
}

// send delivers n to the connected frontend and any API watchers from
// LocalBackend.WatchNotifications (via the LocalAPI).
//
// If no frontend is connected or API watchers are backed up, the notification
// is dropped without being delivered.
//
// If n contains Prefs, those will be sanitized before being delivered.
//
// b.mu must not be held.
func (b *LocalBackend) send(n ipn.Notify) {
	b.sendTo(n, allClients)
}

// SendNotify sends a notification to the IPN bus,
// typically to the GUI client.
func (b *LocalBackend) SendNotify(n ipn.Notify) {
	b.send(n)
}

// notificationTarget describes a notification recipient.
// A zero value is valid and indicate that the notification
// should be broadcast to all active [watchSession]s.
type notificationTarget struct {
	// userID is the OS-specific UID of the target user.
	// If empty, the notification is not user-specific and
	// will be broadcast to all connected users.
	// TODO(nickkhyl): make this field cross-platform rather
	// than Windows-specific.
	userID ipn.WindowsUserID
	// clientID identifies a client that should be the exclusive recipient
	// of the notification. A zero value indicates that notification should
	// be sent to all sessions of the specified user.
	clientID ipnauth.ClientID
}

var allClients = notificationTarget{} // broadcast to all connected clients

// toNotificationTarget returns a [notificationTarget] that matches only actors
// representing the same user as the specified actor. If the actor represents
// a specific connected client, the [ipnauth.ClientID] must also match.
// If the actor is nil, the [notificationTarget] matches all actors.
func toNotificationTarget(actor ipnauth.Actor) notificationTarget {
	t := notificationTarget{}
	if actor != nil {
		t.userID = actor.UserID()
		t.clientID, _ = actor.ClientID()
	}
	return t
}

// match reports whether the specified actor should receive notifications
// targeting t. If the actor is nil, it should only receive notifications
// intended for all users.
func (t notificationTarget) match(actor ipnauth.Actor) bool {
	if t == allClients {
		return true
	}
	if actor == nil {
		return false
	}
	if t.userID != "" && t.userID != actor.UserID() {
		return false
	}
	if t.clientID != ipnauth.NoClientID {
		clientID, ok := actor.ClientID()
		if !ok || clientID != t.clientID {
			return false
		}
	}
	return true
}

// sendTo is like [LocalBackend.send] but allows specifying a recipient.
func (b *LocalBackend) sendTo(n ipn.Notify, recipient notificationTarget) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sendToLocked(n, recipient)
}

// sendToLocked is like [LocalBackend.sendTo], but assumes b.mu is already held.
func (b *LocalBackend) sendToLocked(n ipn.Notify, recipient notificationTarget) {
	if n.Prefs != nil {
		n.Prefs = ptr.To(stripKeysFromPrefs(*n.Prefs))
	}
	if n.Version == "" {
		n.Version = version.Long()
	}

	for _, f := range b.extHost.Hooks().MutateNotifyLocked {
		f(&n)
	}

	for _, sess := range b.notifyWatchers {
		if recipient.match(sess.owner) {
			select {
			case sess.ch <- &n:
			default:
				// Drop the notification if the channel is full.
			}
		}
	}
}

// setAuthURL sets the authURL and triggers [LocalBackend.popBrowserAuthNow] if the URL has changed.
// This method is called when a new authURL is received from the control plane, meaning that either a user
// has started a new interactive login (e.g., by running `tailscale login` or clicking Login in the GUI),
// or the control plane was unable to authenticate this node non-interactively (e.g., due to key expiration).
// A non-nil b.authActor indicates that an interactive login is in progress and was initiated by the specified actor.
// If url is "", it is equivalent to calling [LocalBackend.resetAuthURLLocked] with b.mu held.
func (b *LocalBackend) setAuthURL(url string) {
	var popBrowser, keyExpired bool
	var recipient ipnauth.Actor

	b.mu.Lock()
	switch {
	case url == "":
		b.resetAuthURLLocked()
		b.mu.Unlock()
		return
	case b.authURL != url:
		b.authURL = url
		b.authURLTime = b.clock.Now()
		// Always open the browser if the URL has changed.
		// This includes the transition from no URL -> some URL.
		popBrowser = true
	default:
		// Otherwise, only open it if the user explicitly requests interactive login.
		popBrowser = b.authActor != nil
	}
	keyExpired = b.keyExpired
	recipient = b.authActor // or nil
	// Consume the StartLoginInteractive call, if any, that caused the control
	// plane to send us this URL.
	b.authActor = nil
	b.mu.Unlock()

	if popBrowser {
		b.popBrowserAuthNow(url, keyExpired, recipient)
	}
}

// popBrowserAuthNow shuts down the data plane and sends the URL to the recipient's
// [watchSession]s if the recipient is non-nil; otherwise, it sends the URL to all watchSessions.
// keyExpired is the value of b.keyExpired upon entry and indicates
// whether the node's key has expired.
// It must not be called with b.mu held.
func (b *LocalBackend) popBrowserAuthNow(url string, keyExpired bool, recipient ipnauth.Actor) {
	b.logf("popBrowserAuthNow(%q): url=%v, key-expired=%v, seamless-key-renewal=%v", maybeUsernameOf(recipient), url != "", keyExpired, b.seamlessRenewalEnabled())

	// Deconfigure the local network data plane if:
	// - seamless key renewal is not enabled;
	// - key is expired (in which case tailnet connectivity is down anyway).
	if !b.seamlessRenewalEnabled() || keyExpired {
		b.blockEngineUpdates(true)
		b.stopEngineAndWait()

		if b.State() == ipn.Running {
			b.enterState(ipn.Starting)
		}
	}
	b.tellRecipientToBrowseToURL(url, toNotificationTarget(recipient))
}

// validPopBrowserURL reports whether urlStr is a valid value for a
// control server to send in a *URL field.
//
// b.mu must *not* be held.
func (b *LocalBackend) validPopBrowserURL(urlStr string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.validPopBrowserURLLocked(urlStr)
}

// validPopBrowserURLLocked reports whether urlStr is a valid value for a
// control server to send in a *URL field.
//
// b.mu must be held.
func (b *LocalBackend) validPopBrowserURLLocked(urlStr string) bool {
	if urlStr == "" {
		return false
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	serverURL := b.sanitizedPrefsLocked().ControlURLOrDefault(b.polc)
	if ipn.IsLoginServerSynonym(serverURL) {
		// When connected to the official Tailscale control plane, only allow
		// URLs from tailscale.com or its subdomains.
		if h := u.Hostname(); h != "tailscale.com" && !strings.HasSuffix(u.Hostname(), ".tailscale.com") {
			return false
		}
		// When using a different ControlURL, we cannot be sure what legitimate
		// PopBrowserURLs they will send. Allow any domain there to avoid
		// breaking existing user setups.
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		// If the control server is using plain HTTP (likely a dev server),
		// then permit http://.
		return strings.HasPrefix(serverURL, "http://")
	}
	return false
}

func (b *LocalBackend) tellClientToBrowseToURL(url string) {
	b.tellRecipientToBrowseToURL(url, allClients)
}

// tellRecipientToBrowseToURL is like tellClientToBrowseToURL but allows specifying a recipient.
func (b *LocalBackend) tellRecipientToBrowseToURL(url string, recipient notificationTarget) {
	if b.validPopBrowserURL(url) {
		b.sendTo(ipn.Notify{BrowseToURL: &url}, recipient)
	}
}

// onClientVersion is called on MapResponse updates when a MapResponse contains
// a non-nil ClientVersion message.
func (b *LocalBackend) onClientVersion(v *tailcfg.ClientVersion) {
	b.mu.Lock()
	b.lastClientVersion = v
	b.health.SetLatestVersion(v)
	b.mu.Unlock()
	b.send(ipn.Notify{ClientVersion: v})
}

func (b *LocalBackend) onTailnetDefaultAutoUpdate(au bool) {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	prefs := b.pm.CurrentPrefs()
	if !prefs.Valid() {
		b.logf("[unexpected]: received tailnet default auto-update callback but current prefs are nil")
		return
	}
	if _, ok := prefs.AutoUpdate().Apply.Get(); ok {
		// Apply was already set from a previous default or manually by the
		// user. Tailnet default should not affect us, even if it changes.
		return
	}
	if au && b.hostinfo != nil && b.hostinfo.Container.EqualBool(true) {
		// This is a containerized node, which is usually meant to be
		// immutable. Do not enable auto-updates if the tailnet does. But users
		// can still manually enable auto-updates on this node.
		return
	}
	if buildfeatures.HasClientUpdate && feature.CanAutoUpdate() {
		b.logf("using tailnet default auto-update setting: %v", au)
		prefsClone := prefs.AsStruct()
		prefsClone.AutoUpdate.Apply = opt.NewBool(au)
		_, err := b.editPrefsLockedOnEntry(
			ipnauth.Self,
			&ipn.MaskedPrefs{
				Prefs: *prefsClone,
				AutoUpdateSet: ipn.AutoUpdatePrefsMask{
					ApplySet: true,
				},
			}, unlock)
		if err != nil {
			b.logf("failed to apply tailnet-wide default for auto-updates (%v): %v", au, err)
			return
		}
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

	keyText, err := b.store.ReadState(ipn.MachineKeyStateKey)
	if err == nil {
		if err := b.machinePrivKey.UnmarshalText(keyText); err != nil {
			return fmt.Errorf("invalid key in %s key of %v: %w", ipn.MachineKeyStateKey, b.store, err)
		}
		if b.machinePrivKey.IsZero() {
			return fmt.Errorf("invalid zero key stored in %v key of %v", ipn.MachineKeyStateKey, b.store)
		}
		return nil
	}
	if err != ipn.ErrStateNotExist {
		return fmt.Errorf("error reading %v key of %v: %w", ipn.MachineKeyStateKey, b.store, err)
	}

	// If we didn't find one already on disk and the prefs already
	// have a legacy machine key, use that. Otherwise generate a
	// new one.
	b.logf("generating new machine key")
	b.machinePrivKey = key.NewMachine()

	keyText, _ = b.machinePrivKey.MarshalText()
	if err := ipn.WriteState(b.store, ipn.MachineKeyStateKey, keyText); err != nil {
		b.logf("error writing machine key to store: %v", err)
		return err
	}

	b.logf("machine key written to store")
	return nil
}

// clearMachineKeyLocked is called to clear the persisted and in-memory
// machine key, so that initMachineKeyLocked (called as part of starting)
// generates a new machine key.
//
// b.mu must be held.
func (b *LocalBackend) clearMachineKeyLocked() error {
	if err := ipn.WriteState(b.store, ipn.MachineKeyStateKey, nil); err != nil {
		return err
	}
	b.machinePrivKey = key.MachinePrivate{}
	b.logf("machine key cleared")
	return nil
}

func generateInterceptTCPPortFunc(ports []uint16) func(uint16) bool {
	slices.Sort(ports)
	ports = slices.Compact(ports)
	var f func(uint16) bool
	switch len(ports) {
	case 0:
		f = func(uint16) bool { return false }
	case 1:
		f = func(p uint16) bool { return ports[0] == p }
	case 2:
		f = func(p uint16) bool { return ports[0] == p || ports[1] == p }
	case 3:
		f = func(p uint16) bool { return ports[0] == p || ports[1] == p || ports[2] == p }
	default:
		if len(ports) > 16 {
			m := map[uint16]bool{}
			for _, p := range ports {
				m[p] = true
			}
			f = func(p uint16) bool { return m[p] }
		} else {
			f = func(p uint16) bool {
				for _, x := range ports {
					if p == x {
						return true
					}
				}
				return false
			}
		}
	}
	return f
}

// setTCPPortsIntercepted populates b.shouldInterceptTCPPortAtomic with an
// efficient func for ShouldInterceptTCPPort to use, which is called on every
// incoming packet.
func (b *LocalBackend) setTCPPortsIntercepted(ports []uint16) {
	b.shouldInterceptTCPPortAtomic.Store(generateInterceptTCPPortFunc(ports))
}

func generateInterceptVIPServicesTCPPortFunc(svcAddrPorts map[netip.Addr]func(uint16) bool) func(netip.AddrPort) bool {
	return func(ap netip.AddrPort) bool {
		if f, ok := svcAddrPorts[ap.Addr()]; ok {
			return f(ap.Port())
		}
		return false
	}
}

// setAtomicValuesFromPrefsLocked populates sshAtomicBool, containsViaIPFuncAtomic,
// shouldInterceptTCPPortAtomic, and exposeRemoteWebClientAtomicBool from the prefs p,
// which may be !Valid().
func (b *LocalBackend) setAtomicValuesFromPrefsLocked(p ipn.PrefsView) {
	b.sshAtomicBool.Store(p.Valid() && p.RunSSH() && envknob.CanSSHD())
	b.setExposeRemoteWebClientAtomicBoolLocked(p)

	if !p.Valid() {
		b.containsViaIPFuncAtomic.Store(ipset.FalseContainsIPFunc())
		b.setTCPPortsIntercepted(nil)
		if f, ok := hookServeClearVIPServicesTCPPortsInterceptedLocked.GetOk(); ok {
			f(b)
		}
		b.lastServeConfJSON = mem.B(nil)
		b.serveConfig = ipn.ServeConfigView{}
	} else {
		filtered := tsaddr.FilterPrefixesCopy(p.AdvertiseRoutes(), tsaddr.IsViaPrefix)
		b.containsViaIPFuncAtomic.Store(ipset.NewContainsIPFunc(views.SliceOf(filtered)))
		b.setTCPPortsInterceptedFromNetmapAndPrefsLocked(p)
	}
}

// State returns the backend state machine's current state.
func (b *LocalBackend) State() ipn.State {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.state
}

// CheckIPNConnectionAllowed returns an error if the specified actor should not
// be allowed to connect or make requests to the LocalAPI currently.
//
// Currently (as of 2024-08-26), this is only used on Windows.
// We plan to remove it as part of the multi-user and unattended mode improvements
// as we progress on tailscale/corp#18342.
func (b *LocalBackend) CheckIPNConnectionAllowed(actor ipnauth.Actor) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pm.CurrentUserID() == "" {
		// There's no "current user" yet; allow the connection.
		return nil
	}
	// Always allow Windows SYSTEM user to connect,
	// even if Tailscale is currently being used by another user.
	if actor.IsLocalSystem() {
		return nil
	}

	uid := actor.UserID()
	if uid == "" {
		return errors.New("empty user uid in connection identity")
	}
	if uid == b.pm.CurrentUserID() {
		// The connection is from the current user; allow it.
		return nil
	}

	// The connection is from a different user; block it.
	var reason string
	if b.pm.CurrentPrefs().ForceDaemon() {
		reason = "running in server mode"
	} else {
		reason = "already in use"
	}
	return fmt.Errorf("Tailscale %s (%q); connection from %q not allowed",
		reason, b.tryLookupUserName(string(b.pm.CurrentUserID())),
		b.tryLookupUserName(string(uid)))
}

// tryLookupUserName tries to look up the username for the uid.
// It returns the username on success, or the UID on failure.
func (b *LocalBackend) tryLookupUserName(uid string) string {
	u, err := ipnauth.LookupUserFromID(b.logf, uid)
	if err != nil {
		return uid
	}
	return u.Username
}

// StartLoginInteractive requests a new interactive login from controlclient,
// unless such a flow is already in progress, in which case
// StartLoginInteractive attempts to pick up the in-progress flow where it left
// off.
func (b *LocalBackend) StartLoginInteractive(ctx context.Context) error {
	return b.StartLoginInteractiveAs(ctx, nil)
}

// StartLoginInteractiveAs is like StartLoginInteractive but takes an [ipnauth.Actor]
// as an additional parameter. If non-nil, the specified user is expected to complete
// the interactive login, and therefore will receive the BrowseToURL notification once
// the control plane sends us one. Otherwise, the notification will be delivered to all
// active [watchSession]s.
func (b *LocalBackend) StartLoginInteractiveAs(ctx context.Context, user ipnauth.Actor) error {
	b.mu.Lock()
	if b.cc == nil {
		panic("LocalBackend.assertClient: b.cc == nil")
	}
	url := b.authURL
	keyExpired := b.keyExpired
	timeSinceAuthURLCreated := b.clock.Since(b.authURLTime)
	// Only use an authURL if it was sent down from control in the last
	// 6 days and 23 hours. Avoids using a stale URL that is no longer valid
	// server-side. Server-side URLs expire after 7 days.
	hasValidURL := url != "" && timeSinceAuthURLCreated < ((7*24*time.Hour)-(1*time.Hour))
	if !hasValidURL {
		// A user wants to log in interactively, but we don't have a valid authURL.
		// Remember the user who initiated the login, so that we can notify them
		// once the authURL is available.
		b.authActor = user
	}
	cc := b.cc
	b.mu.Unlock()

	b.logf("StartLoginInteractiveAs(%q): url=%v", maybeUsernameOf(user), hasValidURL)

	if hasValidURL {
		b.popBrowserAuthNow(url, keyExpired, user)
	} else {
		cc.Login(b.loginFlags | controlclient.LoginInteractive)
	}
	return nil
}

func (b *LocalBackend) Ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType, size int) (*ipnstate.PingResult, error) {
	if pingType == tailcfg.PingPeerAPI {
		t0 := b.clock.Now()
		node, base, err := b.pingPeerAPI(ctx, ip)
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		d := b.clock.Since(t0)
		pr := &ipnstate.PingResult{
			IP:             ip.String(),
			NodeIP:         ip.String(),
			LatencySeconds: d.Seconds(),
			PeerAPIURL:     base,
		}
		if err != nil {
			pr.Err = err.Error()
		}
		if node.Valid() {
			pr.NodeName = node.Name()
		}
		return pr, nil
	}
	ch := make(chan *ipnstate.PingResult, 1)
	b.e.Ping(ip, pingType, size, func(pr *ipnstate.PingResult) {
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

func (b *LocalBackend) pingPeerAPI(ctx context.Context, ip netip.Addr) (peer tailcfg.NodeView, peerBase string, err error) {
	if !buildfeatures.HasPeerAPIClient {
		return peer, peerBase, feature.ErrUnavailable
	}
	var zero tailcfg.NodeView
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nm := b.NetMap()
	if nm == nil {
		return zero, "", errors.New("no netmap")
	}
	peer, ok := nm.PeerByTailscaleIP(ip)
	if !ok {
		return zero, "", fmt.Errorf("no peer found with Tailscale IP %v", ip)
	}
	if peer.Expired() {
		return zero, "", errors.New("peer's node key has expired")
	}
	base := peerAPIBase(nm, peer)
	if base == "" {
		return zero, "", fmt.Errorf("no PeerAPI base found for peer %v (%v)", peer.ID(), ip)
	}
	outReq, err := http.NewRequestWithContext(ctx, "HEAD", base, nil)
	if err != nil {
		return zero, "", err
	}
	tr := b.Dialer().PeerAPITransport()
	res, err := tr.RoundTrip(outReq)
	if err != nil {
		return zero, "", err
	}
	defer res.Body.Close() // but unnecessary on HEAD responses
	if res.StatusCode != http.StatusOK {
		return zero, "", fmt.Errorf("HTTP status %v", res.Status)
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
		b.statsLogf("[v1] v%v peers: %v", version.Long(), strings.TrimSpace(peerStats.String()))
	}
	return ret
}

// SetCurrentUser is used to implement support for multi-user systems (only
// Windows 2022-11-25). On such systems, the actor is used to determine which
// user's state should be used. The current user is maintained by active
// connections open to the backend.
//
// When the backend initially starts it will typically start with no user. Then,
// the first connection to the backend from the GUI frontend will set the
// current user. Once set, the current user cannot be changed until all previous
// connections are closed. The user is also used to determine which
// LoginProfiles are accessible.
//
// In unattended mode, the backend will start with the user which enabled
// unattended mode. The user must disable unattended mode before the user can be
// changed.
//
// On non-multi-user systems, the actor should be set to nil.
func (b *LocalBackend) SetCurrentUser(actor ipnauth.Actor) {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	var userIdentifier string
	if user := cmp.Or(actor, b.currentUser); user != nil {
		maybeUsername, _ := user.Username()
		userIdentifier = cmp.Or(maybeUsername, string(user.UserID()))
	}

	if actor != b.currentUser {
		if c, ok := b.currentUser.(ipnauth.ActorCloser); ok {
			c.Close()
		}
		b.currentUser = actor
	}

	var action string
	if actor == nil {
		action = "disconnected"
	} else {
		action = "connected"
	}
	reason := fmt.Sprintf("client %s (%s)", action, userIdentifier)
	b.switchToBestProfileLockedOnEntry(reason, unlock)
}

// SwitchToBestProfile selects the best profile to use,
// as reported by [LocalBackend.resolveBestProfileLocked], and switches
// to it, unless it's already the current profile. The reason indicates
// why the profile is being switched, such as due to a client connecting
// or disconnecting, or a change in the desktop session state, and is used
// for logging.
func (b *LocalBackend) SwitchToBestProfile(reason string) {
	b.switchToBestProfileLockedOnEntry(reason, b.lockAndGetUnlock())
}

// switchToBestProfileLockedOnEntry is like [LocalBackend.SwitchToBestProfile],
// but b.mu must held on entry. It is released on exit.
func (b *LocalBackend) switchToBestProfileLockedOnEntry(reason string, unlock unlockOnce) {
	defer unlock()
	oldControlURL := b.pm.CurrentPrefs().ControlURLOrDefault(b.polc)
	profile, background := b.resolveBestProfileLocked()
	cp, switched, err := b.pm.SwitchToProfile(profile)
	switch {
	case !switched && cp.ID() == "":
		if err != nil {
			b.logf("%s: an error occurred; staying on empty profile: %v", reason, err)
		} else {
			b.logf("%s: staying on empty profile", reason)
		}
	case !switched:
		if err != nil {
			b.logf("%s: an error occurred; staying on profile %q (%s): %v", reason, cp.UserProfile().LoginName, cp.ID(), err)
		} else {
			b.logf("%s: staying on profile %q (%s)", reason, cp.UserProfile().LoginName, cp.ID())
		}
	case cp.ID() == "":
		b.logf("%s: disconnecting Tailscale", reason)
	case background:
		b.logf("%s: switching to background profile %q (%s)", reason, cp.UserProfile().LoginName, cp.ID())
	default:
		b.logf("%s: switching to profile %q (%s)", reason, cp.UserProfile().LoginName, cp.ID())
	}
	if !switched {
		return
	}
	// As an optimization, only reset the dialPlan if the control URL changed.
	if newControlURL := b.pm.CurrentPrefs().ControlURLOrDefault(b.polc); oldControlURL != newControlURL {
		b.resetDialPlan()
	}
	if err := b.resetForProfileChangeLockedOnEntry(unlock); err != nil {
		// TODO(nickkhyl): The actual reset cannot fail. However,
		// the TKA initialization or [LocalBackend.Start] can fail.
		// These errors are not critical as far as we're concerned.
		// But maybe we should post a notification to the API watchers?
		b.logf("failed switching profile to %q: %v", profile.ID(), err)
	}
}

// resolveBestProfileLocked returns the best profile to use based on the current
// state of the backend, such as whether a GUI/CLI client is connected, whether
// the unattended mode is enabled, the current state of the desktop sessions,
// and other factors.
//
// It returns a read-only view of the profile and whether it is considered
// a background profile. A background profile is used when no OS user is actively
// using Tailscale, such as when no GUI/CLI client is connected and Unattended Mode
// is enabled (see also [LocalBackend.getBackgroundProfileLocked]).
//
// An invalid view indicates no profile, meaning Tailscale should disconnect
// and remain idle until a GUI or CLI client connects.
// A valid profile view with an empty [ipn.ProfileID] indicates a new profile that
// has not been persisted yet.
//
// b.mu must be held.
func (b *LocalBackend) resolveBestProfileLocked() (_ ipn.LoginProfileView, isBackground bool) {
	// TODO(nickkhyl): delegate all of this to the extensions and remove the distinction
	// between "foreground" and "background" profiles as we migrate away from the concept
	// of a single "current user" on Windows. See tailscale/corp#18342.
	//
	// If a GUI/CLI client is connected, use the connected user's profile, which means
	// either the current profile if owned by the user, or their default profile.
	if b.currentUser != nil {
		profile := b.pm.CurrentProfile()
		// TODO(nickkhyl): check if the current profile is allowed on the device,
		// such as when [pkey.Tailnet] policy setting requires a specific Tailnet.
		// See tailscale/corp#26249.
		if uid := b.currentUser.UserID(); profile.LocalUserID() != uid {
			profile = b.pm.DefaultUserProfile(uid)
		}
		return profile, false
	}

	// Otherwise, if on Windows, use the background profile if one is set.
	// This includes staying on the current profile if Unattended Mode is enabled
	// or if AlwaysOn mode is enabled and the current user is still signed in.
	// If the returned background profileID is "", Tailscale will disconnect
	// and remain idle until a GUI or CLI client connects.
	if goos := envknob.GOOS(); goos == "windows" {
		// If Unattended Mode is enabled for the current profile, keep using it.
		if b.pm.CurrentPrefs().ForceDaemon() {
			return b.pm.CurrentProfile(), true
		}
		// Otherwise, use the profile returned by the extension.
		profile := b.extHost.DetermineBackgroundProfile(b.pm)
		return profile, true
	}

	// On other platforms, however, Tailscale continues to run in the background
	// using the current profile.
	//
	// TODO(nickkhyl): check if the current profile is allowed on the device,
	// such as when [pkey.Tailnet] policy setting requires a specific Tailnet.
	// See tailscale/corp#26249.
	return b.pm.CurrentProfile(), false
}

// CurrentUserForTest returns the current user and the associated WindowsUserID.
// It is used for testing only, and will be removed along with the rest of the
// "current user" functionality as we progress on the multi-user improvements (tailscale/corp#18342).
func (b *LocalBackend) CurrentUserForTest() (ipn.WindowsUserID, ipnauth.Actor) {
	testenv.AssertInTest()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.CurrentUserID(), b.currentUser
}

func (b *LocalBackend) CheckPrefs(p *ipn.Prefs) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checkPrefsLocked(p)
}

// isConfigLocked_Locked reports whether the parsed config file is locked.
// b.mu must be held.
func (b *LocalBackend) isConfigLocked_Locked() bool {
	// TODO(bradfitz,maisem): make this more fine-grained, permit changing
	// some things if they're not explicitly set in the config. But for now
	// (2023-10-16), just blanket disable everything.
	return b.conf != nil && !b.conf.Parsed.Locked.EqualBool(false)
}

func (b *LocalBackend) checkPrefsLocked(p *ipn.Prefs) error {
	if b.isConfigLocked_Locked() {
		return errors.New("can't reconfigure tailscaled when using a config file; config file is locked")
	}
	var errs []error
	if p.Hostname == "badhostname.tailscale." {
		// Keep this one just for testing.
		errs = append(errs, errors.New("bad hostname [test]"))
	}
	if err := b.checkProfileNameLocked(p); err != nil {
		errs = append(errs, err)
	}
	if err := b.checkSSHPrefsLocked(p); err != nil {
		errs = append(errs, err)
	}
	if err := b.checkExitNodePrefsLocked(p); err != nil {
		errs = append(errs, err)
	}
	if err := b.checkFunnelEnabledLocked(p); err != nil {
		errs = append(errs, err)
	}
	if err := b.checkAutoUpdatePrefsLocked(p); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (b *LocalBackend) checkSSHPrefsLocked(p *ipn.Prefs) error {
	if !p.RunSSH {
		return nil
	}
	if err := featureknob.CanRunTailscaleSSH(); err != nil {
		return err
	}
	if runtime.GOOS == "linux" {
		b.updateSELinuxHealthWarning()
	}
	if envknob.SSHIgnoreTailnetPolicy() || envknob.SSHPolicyFile() != "" {
		return nil
	}
	// Assume that we do have the SSH capability if don't have a netmap yet.
	if !b.currentNode().SelfHasCapOr(tailcfg.CapabilitySSH, true) {
		if b.isDefaultServerLocked() {
			return errors.New("Unable to enable local Tailscale SSH server; not enabled on Tailnet. See https://tailscale.com/s/ssh")
		}
		return errors.New("Unable to enable local Tailscale SSH server; not enabled on Tailnet.")
	}
	return nil
}

func (b *LocalBackend) sshOnButUnusableHealthCheckMessageLocked() (healthMessage string) {
	if p := b.pm.CurrentPrefs(); !p.Valid() || !p.RunSSH() {
		return ""
	}
	if envknob.SSHIgnoreTailnetPolicy() || envknob.SSHPolicyFile() != "" {
		return "development SSH policy in use"
	}
	nm := b.currentNode().NetMap()
	if nm == nil {
		return ""
	}
	if nm.SSHPolicy != nil && len(nm.SSHPolicy.Rules) > 0 {
		return ""
	}
	isDefault := b.isDefaultServerLocked()

	if !nm.HasCap(tailcfg.CapabilityAdmin) {
		return healthmsg.TailscaleSSHOnBut + "access controls don't allow anyone to access this device. Ask your admin to update your tailnet's ACLs to allow access."
	}
	if !isDefault {
		return healthmsg.TailscaleSSHOnBut + "access controls don't allow anyone to access this device. Update your tailnet's ACLs to allow access."
	}
	return healthmsg.TailscaleSSHOnBut + "access controls don't allow anyone to access this device. Update your tailnet's ACLs at https://tailscale.com/s/ssh-policy"
}

func (b *LocalBackend) isDefaultServerLocked() bool {
	prefs := b.pm.CurrentPrefs()
	if !prefs.Valid() {
		return true // assume true until set otherwise
	}
	return prefs.ControlURLOrDefault(b.polc) == ipn.DefaultControlURL
}

var exitNodeMisconfigurationWarnable = health.Register(&health.Warnable{
	Code:     "exit-node-misconfiguration",
	Title:    "Exit node misconfiguration",
	Severity: health.SeverityMedium,
	Text: func(args health.Args) string {
		return "Exit node misconfiguration: " + args[health.ArgError]
	},
})

// updateExitNodeUsageWarning updates a warnable meant to notify users of
// configuration issues that could break exit node usage.
func updateExitNodeUsageWarning(p ipn.PrefsView, state *netmon.State, healthTracker *health.Tracker) {
	if !buildfeatures.HasUseExitNode {
		return
	}
	var msg string
	if p.ExitNodeIP().IsValid() || p.ExitNodeID() != "" {
		warn, _ := netutil.CheckReversePathFiltering(state)
		if len(warn) > 0 {
			msg = fmt.Sprintf("%s: %v, %s", healthmsg.WarnExitNodeUsage, warn, healthmsg.DisableRPFilter)
		}
	}
	if len(msg) > 0 {
		healthTracker.SetUnhealthy(exitNodeMisconfigurationWarnable, health.Args{health.ArgError: msg})
	} else {
		healthTracker.SetHealthy(exitNodeMisconfigurationWarnable)
	}
}

func (b *LocalBackend) checkExitNodePrefsLocked(p *ipn.Prefs) error {
	tryingToUseExitNode := p.ExitNodeIP.IsValid() || p.ExitNodeID != ""
	if !tryingToUseExitNode {
		return nil
	}
	if !buildfeatures.HasUseExitNode {
		return feature.ErrUnavailable
	}

	if err := featureknob.CanUseExitNode(); err != nil {
		return err
	}

	if p.AdvertisesExitNode() {
		return errors.New("Cannot advertise an exit node and use an exit node at the same time.")
	}
	return nil
}

func (b *LocalBackend) checkFunnelEnabledLocked(p *ipn.Prefs) error {
	if p.ShieldsUp && b.serveConfig.IsFunnelOn() {
		return errors.New("Cannot enable shields-up when Funnel is enabled.")
	}
	return nil
}

func (b *LocalBackend) checkAutoUpdatePrefsLocked(p *ipn.Prefs) error {
	if !buildfeatures.HasClientUpdate {
		if p.AutoUpdate.Apply.EqualBool(true) {
			return errors.New("Auto-update support is disabled in this build")
		}
	}
	if p.AutoUpdate.Apply.EqualBool(true) && !feature.CanAutoUpdate() {
		return errors.New("Auto-updates are not supported on this platform.")
	}
	return nil
}

// SetUseExitNodeEnabled turns on or off the most recently selected exit node.
//
// On success, it returns the resulting prefs (or current prefs, in the case of no change).
// Setting the value to false when use of an exit node is already false is not an error,
// nor is true when the exit node is already in use.
func (b *LocalBackend) SetUseExitNodeEnabled(actor ipnauth.Actor, v bool) (ipn.PrefsView, error) {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	p0 := b.pm.CurrentPrefs()
	if !buildfeatures.HasUseExitNode {
		return p0, nil
	}
	if v && p0.ExitNodeID() != "" {
		// Already on.
		return p0, nil
	}
	if !v && p0.ExitNodeID() == "" {
		// Already off.
		return p0, nil
	}

	var zero ipn.PrefsView
	if v && p0.InternalExitNodePrior() == "" {
		if !p0.ExitNodeIP().IsValid() {
			return zero, errors.New("no exit node IP to enable & prior exit node IP was never resolved an a node")
		}
		return zero, errors.New("no prior exit node to enable")
	}

	mp := &ipn.MaskedPrefs{}
	if v {
		mp.ExitNodeIDSet = true
		mp.ExitNodeID = p0.InternalExitNodePrior()
		if expr, ok := ipn.ParseAutoExitNodeString(mp.ExitNodeID); ok {
			mp.AutoExitNodeSet = true
			mp.AutoExitNode = expr
			mp.ExitNodeID = unresolvedExitNodeID
		}
	} else {
		mp.ExitNodeIDSet = true
		mp.ExitNodeID = ""
		mp.AutoExitNodeSet = true
		mp.AutoExitNode = ""
		mp.InternalExitNodePriorSet = true
		if p0.AutoExitNode().IsSet() {
			mp.InternalExitNodePrior = tailcfg.StableNodeID(ipn.AutoExitNodePrefix + p0.AutoExitNode())
		} else {
			mp.InternalExitNodePrior = p0.ExitNodeID()
		}
	}
	return b.editPrefsLockedOnEntry(actor, mp, unlock)
}

// MaybeClearAppConnector clears the routes from any AppConnector if
// AdvertiseRoutes has been set in the MaskedPrefs.
func (b *LocalBackend) MaybeClearAppConnector(mp *ipn.MaskedPrefs) error {
	if !buildfeatures.HasAppConnectors {
		return nil
	}
	var err error
	if ac := b.AppConnector(); ac != nil && mp.AdvertiseRoutesSet {
		err = ac.ClearRoutes()
		if err != nil {
			b.logf("appc: clear routes error: %v", err)
		}
	}
	return err
}

// EditPrefs applies the changes in mp to the current prefs,
// acting as the tailscaled itself rather than a specific user.
func (b *LocalBackend) EditPrefs(mp *ipn.MaskedPrefs) (ipn.PrefsView, error) {
	return b.EditPrefsAs(mp, ipnauth.Self)
}

// EditPrefsAs is like EditPrefs, but makes the change as the specified actor.
// It returns an error if the actor is not allowed to make the change.
func (b *LocalBackend) EditPrefsAs(mp *ipn.MaskedPrefs, actor ipnauth.Actor) (ipn.PrefsView, error) {
	if mp.SetsInternal() {
		return ipn.PrefsView{}, errors.New("can't set Internal fields")
	}

	return b.editPrefsLockedOnEntry(actor, mp, b.lockAndGetUnlock())
}

// checkEditPrefsAccessLocked checks whether the current user has access
// to apply the changes in mp to the given prefs.
//
// It returns an error if the user is not allowed, or nil otherwise.
//
// b.mu must be held.
func (b *LocalBackend) checkEditPrefsAccessLocked(actor ipnauth.Actor, prefs ipn.PrefsView, mp *ipn.MaskedPrefs) error {
	var errs []error

	if mp.RunSSHSet && mp.RunSSH && !envknob.CanSSHD() {
		errs = append(errs, errors.New("Tailscale SSH server administratively disabled"))
	}

	// Check if the user is allowed to disconnect Tailscale.
	if mp.WantRunningSet && !mp.WantRunning && b.pm.CurrentPrefs().WantRunning() {
		if err := actor.CheckProfileAccess(b.pm.CurrentProfile(), ipnauth.Disconnect, b.extHost.AuditLogger()); err != nil {
			errs = append(errs, err)
		}
	}

	// Prevent users from changing exit node preferences
	// when exit node usage is managed by policy.
	if mp.ExitNodeIDSet || mp.ExitNodeIPSet || mp.AutoExitNodeSet {
		isManaged, err := b.polc.HasAnyOf(pkey.ExitNodeID, pkey.ExitNodeIP)
		if err != nil {
			err = fmt.Errorf("policy check failed: %w", err)
		} else if isManaged {
			// Allow users to override ExitNode policy settings and select an exit node manually
			// if permitted by [pkey.AllowExitNodeOverride].
			//
			// Disabling exit node usage entirely is not allowed.
			allowExitNodeOverride, _ := b.polc.GetBoolean(pkey.AllowExitNodeOverride, false)
			if !allowExitNodeOverride || b.changeDisablesExitNodeLocked(prefs, mp) {
				err = errManagedByPolicy
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("exit node cannot be changed: %w", err))
		}
	}

	return errors.Join(errs...)
}

// changeDisablesExitNodeLocked reports whether applying the change
// to the given prefs would disable exit node usage.
//
// In other words, it returns true if prefs.ExitNodeID is non-empty
// initially, but would become empty after applying the given change.
//
// It applies the same adjustments and resolves the exit node in the prefs
// as done during actual edits. While not optimal performance-wise,
// changing the exit node via LocalAPI isn't a hot path, and reusing
// the same logic ensures consistency and simplifies maintenance.
//
// b.mu must be held.
func (b *LocalBackend) changeDisablesExitNodeLocked(prefs ipn.PrefsView, change *ipn.MaskedPrefs) bool {
	if !buildfeatures.HasUseExitNode {
		return false
	}
	if !change.AutoExitNodeSet && !change.ExitNodeIDSet && !change.ExitNodeIPSet {
		// The change does not affect exit node usage.
		return false
	}

	if prefs.ExitNodeID() == "" {
		// Exit node usage is already disabled.
		// Note that we do not check for ExitNodeIP here.
		// If ExitNodeIP hasn't been resolved to a node,
		// it's not enabled yet.
		return false
	}

	// First, apply the adjustments to a copy of the changes,
	// e.g., clear AutoExitNode if ExitNodeID is set.
	tmpChange := ptr.To(*change)
	tmpChange.Prefs = *change.Prefs.Clone()
	b.adjustEditPrefsLocked(prefs, tmpChange)

	// Then apply the adjusted changes to a copy of the current prefs,
	// and resolve the exit node in the prefs.
	tmpPrefs := prefs.AsStruct()
	tmpPrefs.ApplyEdits(tmpChange)
	b.resolveExitNodeInPrefsLocked(tmpPrefs)

	// If ExitNodeID is empty after applying the changes,
	// but wasn't empty before, then the change disables
	// exit node usage.
	return tmpPrefs.ExitNodeID == ""
}

// adjustEditPrefsLocked applies additional changes to mp if necessary,
// such as zeroing out mutually exclusive fields.
//
// It must not assume that the changes in mp will actually be applied.
//
// b.mu must be held.
func (b *LocalBackend) adjustEditPrefsLocked(prefs ipn.PrefsView, mp *ipn.MaskedPrefs) {
	// Zeroing the ExitNodeID via localAPI must also zero the prior exit node.
	if mp.ExitNodeIDSet && mp.ExitNodeID == "" && !mp.InternalExitNodePriorSet {
		mp.InternalExitNodePrior = ""
		mp.InternalExitNodePriorSet = true
	}

	// Clear ExitNodeID if AutoExitNode is disabled and ExitNodeID is still unresolved.
	if mp.AutoExitNodeSet && mp.AutoExitNode == "" && prefs.ExitNodeID() == unresolvedExitNodeID {
		mp.ExitNodeIDSet = true
		mp.ExitNodeID = ""
	}

	// Disable automatic exit node selection if the user explicitly sets
	// ExitNodeID or ExitNodeIP.
	if (mp.ExitNodeIDSet || mp.ExitNodeIPSet) && !mp.AutoExitNodeSet {
		mp.AutoExitNodeSet = true
		mp.AutoExitNode = ""
	}
}

// onEditPrefsLocked is called when prefs are edited (typically, via LocalAPI),
// just before the changes in newPrefs are set for the current profile.
//
// The changes in mp have been allowed, but the resulting [ipn.Prefs]
// have not yet been applied and may be subject to reconciliation
// by [LocalBackend.reconcilePrefsLocked], either before or after being set.
//
// This method handles preference edits, typically initiated by the user,
// as opposed to reconfiguring the backend when the final prefs are set.
//
// b.mu must be held; mp must not be mutated by this method.
func (b *LocalBackend) onEditPrefsLocked(_ ipnauth.Actor, mp *ipn.MaskedPrefs, oldPrefs, newPrefs ipn.PrefsView) {
	if mp.WantRunningSet && !mp.WantRunning && oldPrefs.WantRunning() {
		// If a user has enough rights to disconnect, such as when [pkey.AlwaysOn]
		// is disabled, or [pkey.AlwaysOnOverrideWithReason] is also set and the user
		// provides a reason for disconnecting, then we should not force the "always on"
		// mode on them until the policy changes, they switch to a different profile, etc.
		b.overrideAlwaysOn = true

		if reconnectAfter, _ := b.polc.GetDuration(pkey.ReconnectAfter, 0); reconnectAfter > 0 {
			b.startReconnectTimerLocked(reconnectAfter)
		}
	}

	if oldPrefs.WantRunning() != newPrefs.WantRunning() {
		// Connecting to or disconnecting from Tailscale clears the override,
		// unless the user is also explicitly changing the exit node (see below).
		b.overrideExitNodePolicy = false
	}
	if mp.AutoExitNodeSet || mp.ExitNodeIDSet || mp.ExitNodeIPSet {
		if allowExitNodeOverride, _ := b.polc.GetBoolean(pkey.AllowExitNodeOverride, false); allowExitNodeOverride {
			// If applying exit node policy settings to the new prefs results in no change,
			// the user is not overriding the policy. Otherwise, it is an override.
			b.overrideExitNodePolicy = b.applyExitNodeSysPolicyLocked(newPrefs.AsStruct())
		} else {
			// Overrides are not allowed; clear the override flag.
			b.overrideExitNodePolicy = false
		}
	}

	// This is recorded here in the EditPrefs path, not the setPrefs path on purpose.
	// recordForEdit records metrics related to edits and changes, not the final state.
	// If, in the future, we want to record gauge-metrics related to the state of prefs,
	// that should be done in the setPrefs path.
	e := prefsMetricsEditEvent{
		change:                mp,
		pNew:                  newPrefs,
		pOld:                  oldPrefs,
		node:                  b.currentNode(),
		lastSuggestedExitNode: b.lastSuggestedExitNode,
	}
	e.record()
}

// startReconnectTimerLocked sets a timer to automatically set WantRunning to true
// after the specified duration.
func (b *LocalBackend) startReconnectTimerLocked(d time.Duration) {
	if b.reconnectTimer != nil {
		// Stop may return false if the timer has already fired,
		// and the function has been called in its own goroutine,
		// but lost the race to acquire b.mu. In this case, it'll
		// end up as a no-op due to a reconnectTimer mismatch
		// once it manages to acquire the lock. This is fine, and we
		// don't need to check the return value.
		b.reconnectTimer.Stop()
	}
	profileID := b.pm.CurrentProfile().ID()
	var reconnectTimer tstime.TimerController
	reconnectTimer = b.clock.AfterFunc(d, func() {
		unlock := b.lockAndGetUnlock()
		defer unlock()

		if b.reconnectTimer != reconnectTimer {
			// We're either not the most recent timer, or we lost the race when
			// the timer was stopped. No need to reconnect.
			return
		}
		b.reconnectTimer = nil

		cp := b.pm.CurrentProfile()
		if cp.ID() != profileID {
			// The timer fired before the profile changed but we lost the race
			// and acquired the lock shortly after.
			// No need to reconnect.
			return
		}

		mp := &ipn.MaskedPrefs{WantRunningSet: true, Prefs: ipn.Prefs{WantRunning: true}}
		if _, err := b.editPrefsLockedOnEntry(ipnauth.Self, mp, unlock); err != nil {
			b.logf("failed to automatically reconnect as %q after %v: %v", cp.Name(), d, err)
		} else {
			b.logf("automatically reconnected as %q after %v", cp.Name(), d)
		}
	})
	b.reconnectTimer = reconnectTimer
	b.logf("reconnect for %q has been scheduled and will be performed in %v", b.pm.CurrentProfile().Name(), d)
}

func (b *LocalBackend) resetAlwaysOnOverrideLocked() {
	b.overrideAlwaysOn = false
	b.stopReconnectTimerLocked()
}

func (b *LocalBackend) stopReconnectTimerLocked() {
	if b.reconnectTimer != nil {
		// Stop may return false if the timer has already fired,
		// and the function has been called in its own goroutine,
		// but lost the race to acquire b.mu.
		// In this case, it'll end up as a no-op due to a reconnectTimer
		// mismatch (see [LocalBackend.startReconnectTimerLocked])
		// once it manages to acquire the lock. This is fine, and we
		// don't need to check the return value.
		b.reconnectTimer.Stop()
		b.reconnectTimer = nil
	}
}

// Warning: b.mu must be held on entry, but it unlocks it on the way out.
// TODO(bradfitz): redo the locking on all these weird methods like this.
func (b *LocalBackend) editPrefsLockedOnEntry(actor ipnauth.Actor, mp *ipn.MaskedPrefs, unlock unlockOnce) (ipn.PrefsView, error) {
	defer unlock() // for error paths

	p0 := b.pm.CurrentPrefs()

	// Check if the changes in mp are allowed.
	if err := b.checkEditPrefsAccessLocked(actor, p0, mp); err != nil {
		b.logf("EditPrefs(%v): %v", mp.Pretty(), err)
		return ipn.PrefsView{}, err
	}

	// Apply additional changes to mp if necessary,
	// such as clearing mutually exclusive fields.
	b.adjustEditPrefsLocked(p0, mp)

	if mp.EggSet {
		mp.EggSet = false
		b.egg = true
		b.goTracker.Go(b.doSetHostinfoFilterServices)
	}

	p1 := b.pm.CurrentPrefs().AsStruct()
	p1.ApplyEdits(mp)

	if err := b.checkPrefsLocked(p1); err != nil {
		b.logf("EditPrefs check error: %v", err)
		return ipn.PrefsView{}, err
	}

	if p1.View().Equals(p0) {
		return stripKeysFromPrefs(p0), nil
	}

	b.logf("EditPrefs: %v", mp.Pretty())

	// Perform any actions required when prefs are edited (typically by a user),
	// before the modified prefs are actually set for the current profile.
	b.onEditPrefsLocked(actor, mp, p0, p1.View())

	newPrefs := b.setPrefsLockedOnEntry(p1, unlock)

	// Note: don't perform any actions for the new prefs here. Not
	// every prefs change goes through EditPrefs. Put your actions
	// in setPrefsLocksOnEntry instead.

	// This should return the public prefs, not the private ones.
	return stripKeysFromPrefs(newPrefs), nil
}

func (b *LocalBackend) checkProfileNameLocked(p *ipn.Prefs) error {
	if p.ProfileName == "" {
		// It is always okay to clear the profile name.
		return nil
	}
	id := b.pm.ProfileIDForName(p.ProfileName)
	if id == "" {
		// No profile with that name exists. That's fine.
		return nil
	}
	if id != b.pm.CurrentProfile().ID() {
		// Name is already in use by another profile.
		return fmt.Errorf("profile name %q already in use", p.ProfileName)
	}
	return nil
}

// setPrefsLockedOnEntry requires b.mu be held to call it, but it
// unlocks b.mu when done. newp ownership passes to this function.
// It returns a read-only copy of the new prefs.
func (b *LocalBackend) setPrefsLockedOnEntry(newp *ipn.Prefs, unlock unlockOnce) ipn.PrefsView {
	defer unlock()

	cn := b.currentNode()
	netMap := cn.NetMap()
	b.setAtomicValuesFromPrefsLocked(newp.View())

	oldp := b.pm.CurrentPrefs()
	if oldp.Valid() {
		newp.Persist = oldp.Persist().AsStruct() // caller isn't allowed to override this
	}
	// Apply reconciliation to the prefs, such as policy overrides,
	// exit node resolution, and so on. The call returns whether it updated
	// newp, but everything in this function treats newp as completely new
	// anyway, so its return value can be ignored here.
	b.reconcilePrefsLocked(newp)

	// We do this to avoid holding the lock while doing everything else.

	oldHi := b.hostinfo
	newHi := oldHi.Clone()
	if newHi == nil {
		newHi = new(tailcfg.Hostinfo)
	}
	b.applyPrefsToHostinfoLocked(newHi, newp.View())
	b.hostinfo = newHi
	hostInfoChanged := !oldHi.Equal(newHi)
	cc := b.cc

	b.updateFilterLocked(newp.View())

	if buildfeatures.HasSSH && oldp.ShouldSSHBeRunning() && !newp.ShouldSSHBeRunning() {
		if b.sshServer != nil {
			b.goTracker.Go(b.sshServer.Shutdown)
			b.sshServer = nil
		}
	}
	if netMap != nil {
		newProfile := profileFromView(netMap.UserProfiles[netMap.User()])
		if newLoginName := newProfile.LoginName; newLoginName != "" {
			if !oldp.Persist().Valid() {
				b.logf("active login: %s", newLoginName)
			} else {
				oldLoginName := oldp.Persist().UserProfile().LoginName
				if oldLoginName != newLoginName {
					b.logf("active login: %q (changed from %q)", newLoginName, oldLoginName)
				}
				newp.Persist.UserProfile = newProfile
			}
		}
	}

	prefs := newp.View()
	np := cmp.Or(cn.NetworkProfile(), b.pm.CurrentProfile().NetworkProfile())
	if err := b.pm.SetPrefs(prefs, np); err != nil {
		b.logf("failed to save new controlclient state: %v", err)
	} else if prefs.WantRunning() {
		// Reset the always-on override if WantRunning is true in the new prefs,
		// such as when the user toggles the Connected switch in the GUI
		// or runs `tailscale up`.
		b.resetAlwaysOnOverrideLocked()
	}

	unlock.UnlockEarly()

	if oldp.ShieldsUp() != newp.ShieldsUp || hostInfoChanged {
		b.doSetHostinfoFilterServices()
	}

	if netMap != nil {
		b.MagicConn().SetDERPMap(netMap.DERPMap)
	}

	if !oldp.WantRunning() && newp.WantRunning && cc != nil {
		b.logf("transitioning to running; doing Login...")
		cc.Login(controlclient.LoginDefault)
	}

	if oldp.WantRunning() != newp.WantRunning {
		b.stateMachine()
	} else {
		b.authReconfig()
	}

	b.send(ipn.Notify{Prefs: &prefs})
	return prefs
}

// GetPeerAPIPort returns the port number for the peerapi server
// running on the provided IP.
func (b *LocalBackend) GetPeerAPIPort(ip netip.Addr) (port uint16, ok bool) {
	if !buildfeatures.HasPeerAPIServer {
		return 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, pln := range b.peerAPIListeners {
		if pln.ip == ip {
			return uint16(pln.port), true
		}
	}
	return 0, false
}

// handlePeerAPIConn serves an already-accepted connection c.
//
// The remote parameter is the remote address.
// The local parameter is the local address (either a Tailscale IPv4
// or IPv6 IP and the peerapi port for that address).
//
// The connection will be closed by handlePeerAPIConn.
func (b *LocalBackend) handlePeerAPIConn(remote, local netip.AddrPort, c net.Conn) {
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

func (b *LocalBackend) isLocalIP(ip netip.Addr) bool {
	nm := b.NetMap()
	return nm != nil && views.SliceContains(nm.GetAddresses(), netip.PrefixFrom(ip, ip.BitLen()))
}

var (
	magicDNSIP   = tsaddr.TailscaleServiceIP()
	magicDNSIPv6 = tsaddr.TailscaleServiceIPv6()
)

// Hook exclusively for serve.
var (
	hookServeTCPHandlerForVIPService                     feature.Hook[func(b *LocalBackend, dst netip.AddrPort, src netip.AddrPort) (handler func(c net.Conn) error)]
	hookTCPHandlerForServe                               feature.Hook[func(b *LocalBackend, dport uint16, srcAddr netip.AddrPort, f *funnelFlow) (handler func(net.Conn) error)]
	hookServeUpdateServeTCPPortNetMapAddrListenersLocked feature.Hook[func(b *LocalBackend, ports []uint16)]

	hookServeSetTCPPortsInterceptedFromNetmapAndPrefsLocked feature.Hook[func(b *LocalBackend, prefs ipn.PrefsView) (handlePorts []uint16)]
	hookServeClearVIPServicesTCPPortsInterceptedLocked      feature.Hook[func(*LocalBackend)]
)

func (b *LocalBackend) handleDriveConn(conn net.Conn) error {
	fs, ok := b.sys.DriveForLocal.GetOK()
	if !ok || !b.DriveAccessEnabled() {
		conn.Close()
		return nil
	}
	return fs.HandleConn(conn, conn.RemoteAddr())
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
	case "linux", "freebsd", "openbsd", "illumos", "solaris", "darwin", "windows", "android", "ios":
		// These are the platforms currently supported by
		// net/dns/resolver/tsdns.go:Resolver.HandleExitNodeDNSQuery.
		ret = append(ret, tailcfg.Service{
			Proto: tailcfg.PeerAPIDNS,
			Port:  1, // version
		})
	}
	return ret
}

// PortlistServices is an eventbus topic for the portlist extension
// to advertise the running services on the host.
type PortlistServices []tailcfg.Service

func (b *LocalBackend) setPortlistServices(sl []tailcfg.Service) {
	if !buildfeatures.HasPortList { // redundant, but explicit for linker deadcode and humans
		return
	}

	b.mu.Lock()
	if b.hostinfo == nil {
		b.hostinfo = new(tailcfg.Hostinfo)
	}
	b.hostinfo.Services = sl
	b.mu.Unlock()

	b.doSetHostinfoFilterServices()
}

// doSetHostinfoFilterServices calls SetHostinfo on the controlclient,
// possibly after mangling the given hostinfo.
//
// TODO(danderson): we shouldn't be mangling hostinfo here after
// painstakingly constructing it in twelvety other places.
func (b *LocalBackend) doSetHostinfoFilterServices() {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	cc := b.cc
	if cc == nil {
		// Control client isn't up yet.
		return
	}
	if b.hostinfo == nil {
		b.logf("[unexpected] doSetHostinfoFilterServices with nil hostinfo")
		return
	}
	peerAPIServices := b.peerAPIServicesLocked()
	if b.egg {
		peerAPIServices = append(peerAPIServices, tailcfg.Service{Proto: "egg", Port: 1})
	}

	// TODO(maisem,bradfitz): store hostinfo as a view, not as a mutable struct.
	hi := *b.hostinfo // shallow copy

	// Make a shallow copy of hostinfo so we can mutate
	// at the Service field.
	if f, ok := b.extHost.Hooks().ShouldUploadServices.GetOk(); !ok || !f() {
		hi.Services = []tailcfg.Service{}
	}

	unlock.UnlockEarly()

	// Don't mutate hi.Service's underlying array. Append to
	// the slice with no free capacity.
	c := len(hi.Services)
	hi.Services = append(hi.Services[:c:c], peerAPIServices...)
	hi.PushDeviceToken = b.pushDeviceToken.Load()

	// Compare the expected ports from peerAPIServices to the actual ports in hi.Services.
	expectedPorts := extractPeerAPIPorts(peerAPIServices)
	actualPorts := extractPeerAPIPorts(hi.Services)
	if expectedPorts != actualPorts {
		b.logf("Hostinfo peerAPI ports changed: expected %v, got %v", expectedPorts, actualPorts)
	}

	cc.SetHostinfo(&hi)
}

type portPair struct {
	v4, v6 uint16
}

func extractPeerAPIPorts(services []tailcfg.Service) portPair {
	var p portPair
	for _, s := range services {
		switch s.Proto {
		case "peerapi4":
			p.v4 = s.Port
		case "peerapi6":
			p.v6 = s.Port
		}
	}
	return p
}

// NetMap returns the latest cached network map received from
// controlclient, or nil if no network map was received yet.
func (b *LocalBackend) NetMap() *netmap.NetworkMap {
	return b.currentNode().NetMap()
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

// reconfigAppConnectorLocked updates the app connector state based on the
// current network map and preferences.
// b.mu must be held.
func (b *LocalBackend) reconfigAppConnectorLocked(nm *netmap.NetworkMap, prefs ipn.PrefsView) {
	if !buildfeatures.HasAppConnectors {
		return
	}
	const appConnectorCapName = "tailscale.com/app-connectors"
	defer func() {
		if b.hostinfo != nil {
			b.hostinfo.AppConnector.Set(b.appConnector != nil)
		}
	}()

	// App connectors have been disabled.
	if !prefs.AppConnector().Advertise {
		b.appConnector.Close() // clean up a previous connector (safe on nil)
		b.appConnector = nil
		return
	}

	// We don't (yet) have an app connector configured, or the configured
	// connector has a different route persistence setting.
	shouldStoreRoutes := b.ControlKnobs().AppCStoreRoutes.Load()
	if b.appConnector == nil || (shouldStoreRoutes != b.appConnector.ShouldStoreRoutes()) {
		ri, err := b.readRouteInfoLocked()
		if err != nil && err != ipn.ErrStateNotExist {
			b.logf("Unsuccessful Read RouteInfo: %v", err)
		}
		b.appConnector.Close() // clean up a previous connector (safe on nil)
		b.appConnector = appc.NewAppConnector(appc.Config{
			Logf:            b.logf,
			EventBus:        b.sys.Bus.Get(),
			RouteInfo:       ri,
			HasStoredRoutes: shouldStoreRoutes,
		})
	}
	if nm == nil {
		return
	}

	attrs, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](nm.SelfNode.CapMap(), appConnectorCapName)
	if err != nil {
		b.logf("[unexpected] error parsing app connector mapcap: %v", err)
		return
	}

	// Geometric cost, assumes that the number of advertised tags is small
	selfHasTag := func(attrTags []string) bool {
		return nm.SelfNode.Tags().ContainsFunc(func(tag string) bool {
			return slices.Contains(attrTags, tag)
		})
	}

	var (
		domains []string
		routes  []netip.Prefix
	)
	for _, attr := range attrs {
		if slices.Contains(attr.Connectors, "*") || selfHasTag(attr.Connectors) {
			domains = append(domains, attr.Domains...)
			routes = append(routes, attr.Routes...)
		}
	}
	slices.Sort(domains)
	slices.SortFunc(routes, func(i, j netip.Prefix) int { return i.Addr().Compare(j.Addr()) })
	domains = slices.Compact(domains)
	routes = slices.Compact(routes)
	b.appConnector.UpdateDomainsAndRoutes(domains, routes)
}

func (b *LocalBackend) readvertiseAppConnectorRoutes() {
	// Note: we should never call b.appConnector methods while holding b.mu.
	// This can lead to a deadlock, like
	// https://github.com/tailscale/corp/issues/25965.
	//
	// Grab a copy of the field, since b.mu only guards access to the
	// b.appConnector field itself.
	appConnector := b.AppConnector()

	if appConnector == nil {
		return
	}
	domainRoutes := appConnector.DomainRoutes()
	if domainRoutes == nil {
		return
	}

	// Re-advertise the stored routes, in case stored state got out of
	// sync with previously advertised routes in prefs.
	var prefixes []netip.Prefix
	for _, ips := range domainRoutes {
		for _, ip := range ips {
			prefixes = append(prefixes, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	// Note: AdvertiseRoute will trim routes that are already
	// advertised, so if everything is already being advertised this is
	// a noop.
	if err := b.AdvertiseRoute(prefixes...); err != nil {
		b.logf("error advertising stored app connector routes: %v", err)
	}
}

// authReconfig pushes a new configuration into wgengine, if engine
// updates are not currently blocked, based on the cached netmap and
// user prefs.
func (b *LocalBackend) authReconfig() {
	// Wait for magicsock to process pending [eventbus] events,
	// such as netmap updates. This should be completed before
	// wireguard-go is reconfigured. See tailscale/tailscale#16369.
	b.MagicConn().Synchronize()

	b.mu.Lock()
	blocked := b.blocked
	prefs := b.pm.CurrentPrefs()
	cn := b.currentNode()
	nm := cn.NetMap()
	hasPAC := b.prevIfState.HasPAC()
	disableSubnetsIfPAC := cn.SelfHasCap(tailcfg.NodeAttrDisableSubnetsIfPAC)
	dohURL, dohURLOK := cn.exitNodeCanProxyDNS(prefs.ExitNodeID())
	dcfg := cn.dnsConfigForNetmap(prefs, b.keyExpired, version.OS())
	// If the current node is an app connector, ensure the app connector machine is started
	b.reconfigAppConnectorLocked(nm, prefs)
	closing := b.shutdownCalled
	b.mu.Unlock()

	if closing {
		b.logf("[v1] authReconfig: skipping because in shutdown")
		return
	}

	if blocked {
		b.logf("[v1] authReconfig: blocked, skipping.")
		return
	}
	if nm == nil {
		b.logf("[v1] authReconfig: netmap not yet valid. Skipping.")
		return
	}
	if !prefs.WantRunning() {
		b.logf("[v1] authReconfig: skipping because !WantRunning.")
		return
	}

	var flags netmap.WGConfigFlags
	if prefs.RouteAll() {
		flags |= netmap.AllowSubnetRoutes
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
	if buildfeatures.HasUseExitNode {
		if dohURLOK {
			b.dialer.SetExitDNSDoH(dohURL)
		} else {
			b.dialer.SetExitDNSDoH("")
		}
	}

	cfg, err := nmcfg.WGCfg(nm, b.logf, flags, prefs.ExitNodeID())
	if err != nil {
		b.logf("wgcfg: %v", err)
		return
	}

	oneCGNATRoute := shouldUseOneCGNATRoute(b.logf, b.sys.NetMon.Get(), b.sys.ControlKnobs(), version.OS())
	rcfg := b.routerConfig(cfg, prefs, oneCGNATRoute)

	err = b.e.Reconfig(cfg, rcfg, dcfg)
	if err == wgengine.ErrNoChanges {
		return
	}
	b.logf("[v1] authReconfig: ra=%v dns=%v 0x%02x: %v", prefs.RouteAll(), prefs.CorpDNS(), flags, err)

	b.initPeerAPIListener()
	if buildfeatures.HasAppConnectors {
		b.readvertiseAppConnectorRoutes()
	}
}

// shouldUseOneCGNATRoute reports whether we should prefer to make one big
// CGNAT /10 route rather than a /32 per peer.
//
// The versionOS is a Tailscale-style version ("iOS", "macOS") and not
// a runtime.GOOS.
func shouldUseOneCGNATRoute(logf logger.Logf, mon *netmon.Monitor, controlKnobs *controlknobs.Knobs, versionOS string) bool {
	if controlKnobs != nil {
		// Explicit enabling or disabling always take precedence.
		if v, ok := controlKnobs.OneCGNAT.Load().Get(); ok {
			logf("[v1] shouldUseOneCGNATRoute: explicit=%v", v)
			return v
		}
	}

	if versionOS == "plan9" {
		// Just temporarily during plan9 bringup to have fewer routes to debug.
		return true
	}

	// Also prefer to do this on the Mac, so that we don't need to constantly
	// update the network extension configuration (which is disruptive to
	// Chrome, see https://github.com/tailscale/tailscale/issues/3102). Only
	// use fine-grained routes if another interfaces is also using the CGNAT
	// IP range.
	if versionOS == "macOS" {
		hasCGNATInterface, err := mon.HasCGNATInterface()
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

// SetTCPHandlerForFunnelFlow sets the TCP handler for Funnel flows.
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetTCPHandlerForFunnelFlow(h func(src netip.AddrPort, dstPort uint16) (handler func(net.Conn))) {
	b.getTCPHandlerForFunnelFlow = h
}

// SetVarRoot sets the root directory of Tailscale's writable
// storage area . (e.g. "/var/lib/tailscale")
//
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetVarRoot(dir string) {
	b.varRoot = dir
}

// SetLogFlusher sets a func to be called to flush log uploads.
//
// It should only be called before the LocalBackend is used.
func (b *LocalBackend) SetLogFlusher(flushFunc func()) {
	if !buildfeatures.HasLogTail {
		return
	}
	b.logFlushFunc = flushFunc
}

// TryFlushLogs calls the log flush function. It returns false if a log flush
// function was never initialized with SetLogFlusher.
//
// TryFlushLogs should not block.
func (b *LocalBackend) TryFlushLogs() bool {
	if !buildfeatures.HasLogTail || b.logFlushFunc == nil {
		return false
	}
	b.logFlushFunc()
	return true
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
	case "linux":
		if distro.Get() == distro.Gokrazy {
			return "/perm/tailscaled"
		}
	}
	return ""
}

// closePeerAPIListenersLocked closes any existing PeerAPI listeners
// and clears out the PeerAPI server state.
//
// It does not kick off any Hostinfo update with new services.
//
// b.mu must be held.
func (b *LocalBackend) closePeerAPIListenersLocked() {
	if !buildfeatures.HasPeerAPIServer {
		return
	}
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
	if !buildfeatures.HasPeerAPIServer {
		return
	}
	b.logf("[v1] initPeerAPIListener: entered")
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.shutdownCalled {
		b.logf("[v1] initPeerAPIListener: shutting down")
		return
	}

	cn := b.currentNode()
	nm := cn.NetMap()
	if nm == nil {
		// We're called from authReconfig which checks that
		// netMap is non-nil, but if a concurrent Logout,
		// ResetForClientDisconnect, or Start happens when its
		// mutex was released, the netMap could be
		// nil'ed out (Issue 1996). Bail out early here if so.
		b.logf("[v1] initPeerAPIListener: no netmap")
		return
	}

	addrs := nm.GetAddresses()
	if addrs.Len() == len(b.peerAPIListeners) {
		allSame := true
		for i, pln := range b.peerAPIListeners {
			if pln.ip != addrs.At(i).Addr() {
				allSame = false
				break
			}
		}
		if allSame {
			// Nothing to do.
			b.logf("[v1] initPeerAPIListener: %d netmap addresses match existing listeners", addrs.Len())
			return
		}
	}

	b.closePeerAPIListenersLocked()

	selfNode := nm.SelfNode
	if !selfNode.Valid() || nm.GetAddresses().Len() == 0 {
		b.logf("[v1] initPeerAPIListener: no addresses in netmap")
		return
	}

	ps := &peerAPIServer{
		b: b,
	}
	if dm, ok := b.sys.DNSManager.GetOK(); ok {
		ps.resolver = dm.Resolver()
	}
	b.peerAPIServer = ps

	isNetstack := b.sys.IsNetstack()
	for i, a := range addrs.All() {
		var ln net.Listener
		var err error
		skipListen := i > 0 && isNetstack
		if !skipListen {
			ln, err = ps.listen(a.Addr(), b.prevIfState)
			if err != nil {
				if peerAPIListenAsync {
					b.logf("[v1] possibly transient peerapi listen(%q) error, will try again on linkChange: %v", a.Addr(), err)
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

	b.goTracker.Go(b.doSetHostinfoFilterServices)
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

// peerRoutes returns the routerConfig.Routes to access peers.
// If there are over cgnatThreshold CGNAT routes, one big CGNAT route
// is used instead.
func peerRoutes(logf logger.Logf, peers []wgcfg.Peer, cgnatThreshold int) (routes []netip.Prefix) {
	tsULA := tsaddr.TailscaleULARange()
	cgNAT := tsaddr.CGNATRange()
	var didULA bool
	var cgNATIPs []netip.Prefix
	for _, peer := range peers {
		for _, aip := range peer.AllowedIPs {
			aip = unmapIPPrefix(aip)

			// Ensure that we're only accepting properly-masked
			// prefixes; the control server should be masking
			// these, so if we get them, skip.
			if mm := aip.Masked(); aip != mm {
				// To avoid a DoS where a peer could cause all
				// reconfigs to fail by sending a bad prefix, we just
				// skip, but don't error, on an unmasked route.
				logf("advertised route %s from %s has non-address bits set; expected %s", aip, peer.PublicKey.ShortString(), mm)
				continue
			}

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

	tsaddr.SortPrefixes(routes)
	return routes
}

// routerConfig produces a router.Config from a wireguard config and IPN prefs.
func (b *LocalBackend) routerConfig(cfg *wgcfg.Config, prefs ipn.PrefsView, oneCGNATRoute bool) *router.Config {
	singleRouteThreshold := 10_000
	if oneCGNATRoute {
		singleRouteThreshold = 1
	}

	b.mu.Lock()
	netfilterKind := b.capForcedNetfilter // protected by b.mu
	b.mu.Unlock()

	if prefs.NetfilterKind() != "" {
		if netfilterKind != "" {
			b.logf("nodeattr netfilter preference %s overridden by c2n pref %s", netfilterKind, prefs.NetfilterKind())
		}
		netfilterKind = prefs.NetfilterKind()
	}

	var doStatefulFiltering bool
	if v, ok := prefs.NoStatefulFiltering().Get(); ok && !v {
		// The preferences explicitly "do stateful filtering" is turned
		// off, or to expand the double negative, to do stateful
		// filtering. Do so.
		doStatefulFiltering = true
	}

	rs := &router.Config{
		LocalAddrs:        unmapIPPrefixes(cfg.Addresses),
		SubnetRoutes:      unmapIPPrefixes(prefs.AdvertiseRoutes().AsSlice()),
		SNATSubnetRoutes:  !prefs.NoSNAT(),
		StatefulFiltering: doStatefulFiltering,
		NetfilterMode:     prefs.NetfilterMode(),
		Routes:            peerRoutes(b.logf, cfg.Peers, singleRouteThreshold),
		NetfilterKind:     netfilterKind,
	}

	if buildfeatures.HasSynology && distro.Get() == distro.Synology {
		// Issue 1995: we don't use iptables on Synology.
		rs.NetfilterMode = preftype.NetfilterOff
	}

	// Sanity check: we expect the control server to program both a v4
	// and a v6 default route, if default routing is on. Fill in
	// blackhole routes appropriately if we're missing some. This is
	// likely to break some functionality, but if the user expressed a
	// preference for routing remotely, we want to avoid leaking
	// traffic at the expense of functionality.
	if buildfeatures.HasUseExitNode && (prefs.ExitNodeID() != "" || prefs.ExitNodeIP().IsValid()) {
		var default4, default6 bool
		for _, route := range rs.Routes {
			switch route {
			case tsaddr.AllIPv4():
				default4 = true
			case tsaddr.AllIPv6():
				default6 = true
			}
			if default4 && default6 {
				break
			}
		}
		if !default4 {
			rs.Routes = append(rs.Routes, tsaddr.AllIPv4())
		}
		if !default6 {
			rs.Routes = append(rs.Routes, tsaddr.AllIPv6())
		}
		internalIPs, externalIPs, err := internalAndExternalInterfaces()
		if err != nil {
			b.logf("failed to discover interface ips: %v", err)
		}
		switch runtime.GOOS {
		case "linux", "windows", "darwin", "ios", "android":
			rs.LocalRoutes = internalIPs // unconditionally allow access to guest VM networks
			if prefs.ExitNodeAllowLANAccess() {
				rs.LocalRoutes = append(rs.LocalRoutes, externalIPs...)
			} else {
				// Explicitly add routes to the local network so that we do not
				// leak any traffic.
				rs.Routes = append(rs.Routes, externalIPs...)
			}
			b.logf("allowing exit node access to local IPs: %v", rs.LocalRoutes)
		default:
			if prefs.ExitNodeAllowLANAccess() {
				b.logf("warning: ExitNodeAllowLANAccess has no effect on " + runtime.GOOS)
			}
		}
	}

	if slices.ContainsFunc(rs.LocalAddrs, tsaddr.PrefixIs4) {
		rs.Routes = append(rs.Routes, netip.PrefixFrom(tsaddr.TailscaleServiceIP(), 32))
	}
	if slices.ContainsFunc(rs.LocalAddrs, tsaddr.PrefixIs6) {
		rs.Routes = append(rs.Routes, netip.PrefixFrom(tsaddr.TailscaleServiceIPv6(), 128))
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

// b.mu must be held.
func (b *LocalBackend) applyPrefsToHostinfoLocked(hi *tailcfg.Hostinfo, prefs ipn.PrefsView) {
	if h := prefs.Hostname(); h != "" {
		hi.Hostname = h
	}
	hi.RoutableIPs = prefs.AdvertiseRoutes().AsSlice()
	hi.RequestTags = prefs.AdvertiseTags().AsSlice()
	hi.ShieldsUp = prefs.ShieldsUp()
	hi.AllowsUpdate = buildfeatures.HasClientUpdate && (envknob.AllowsRemoteUpdate() || prefs.AutoUpdate().Apply.EqualBool(true))

	if buildfeatures.HasAdvertiseRoutes {
		b.metrics.advertisedRoutes.Set(float64(tsaddr.WithoutExitRoute(prefs.AdvertiseRoutes()).Len()))
	}

	var sshHostKeys []string
	if buildfeatures.HasSSH && prefs.RunSSH() && envknob.CanSSHD() {
		// TODO(bradfitz): this is called with b.mu held. Not ideal.
		// If the filesystem gets wedged or something we could block for
		// a long time. But probably fine.
		var err error
		sshHostKeys, err = b.getSSHHostKeyPublicStrings()
		if err != nil {
			b.logf("warning: unable to get SSH host keys, SSH will appear as disabled for this node: %v", err)
		}
	}
	hi.SSH_HostKeys = sshHostKeys

	hi.ServicesHash = b.vipServiceHash(b.vipServicesFromPrefsLocked(prefs))

	// The Hostinfo.IngressEnabled field is used to communicate to control whether
	// the node has funnel enabled.
	hi.IngressEnabled = b.hasIngressEnabledLocked()
	// The Hostinfo.WantIngress field tells control whether the user intends
	// to use funnel with this node even though it is not currently enabled.
	// This is an optimization to control- Funnel requires creation of DNS
	// records and because DNS propagation can take time, we want to ensure
	// that the records exist for any node that intends to use funnel even
	// if it's not enabled. If hi.IngressEnabled is true, control knows that
	// DNS records are needed, so we can save bandwidth and not send
	// WireIngress.
	hi.WireIngress = b.shouldWireInactiveIngressLocked()

	if buildfeatures.HasAppConnectors {
		hi.AppConnector.Set(prefs.AppConnector().Advertise)
	}

	// The [tailcfg.Hostinfo.ExitNodeID] field tells control which exit node
	// was selected, if any.
	//
	// If auto exit node is enabled (via [ipn.Prefs.AutoExitNode] or
	// [pkey.ExitNodeID]), or an exit node is specified by ExitNodeIP
	// instead of ExitNodeID , and we don't yet have enough info to resolve
	// it (usually due to missing netmap or net report), then ExitNodeID in
	// the prefs may be invalid (typically, [unresolvedExitNodeID]) until
	// the netmap is available.
	//
	// In this case, we shouldn't update the Hostinfo with the bogus
	// ExitNodeID here; [LocalBackend.ResolveExitNode] will be called once
	// the netmap and/or net report have been received to both pick the exit
	// node and notify control of the change.
	if buildfeatures.HasUseExitNode {
		if sid := prefs.ExitNodeID(); sid != unresolvedExitNodeID {
			hi.ExitNodeID = prefs.ExitNodeID()
		}
	}
}

// enterState transitions the backend into newState, updating internal
// state and propagating events out as needed.
//
// TODO(danderson): while this isn't a lie, exactly, a ton of other
// places twiddle IPN internal state without going through here, so
// really this is more "one of several places in which random things
// happen".
func (b *LocalBackend) enterState(newState ipn.State) {
	unlock := b.lockAndGetUnlock()
	b.enterStateLockedOnEntry(newState, unlock)
}

// enterStateLockedOnEntry is like enterState but requires b.mu be held to call
// it, but it unlocks b.mu when done (via unlock, a once func).
func (b *LocalBackend) enterStateLockedOnEntry(newState ipn.State, unlock unlockOnce) {
	cn := b.currentNode()
	oldState := b.state
	b.setStateLocked(newState)
	prefs := b.pm.CurrentPrefs()

	// Some temporary (2024-05-05) debugging code to help us catch
	// https://github.com/tailscale/tailscale/issues/11962 in the act.
	if prefs.WantRunning() &&
		prefs.ControlURLOrDefault(b.polc) == ipn.DefaultControlURL &&
		envknob.Bool("TS_PANIC_IF_HIT_MAIN_CONTROL") {
		panic("[unexpected] use of main control server in integration test")
	}

	netMap := cn.NetMap()
	activeLogin := b.activeLogin
	authURL := b.authURL
	if newState == ipn.Running {
		// TODO(zofrex): Is this needed? As of 2025-10-03 it doesn't seem to be
		// necessary when logging in or authenticating. When do we need to reset it
		// here, rather than the other places it is reset? We should test if it is
		// necessary and add unit tests to cover those cases, or remove it.
		if oldState != ipn.Running {
			b.resetAuthURLLocked()
		}

		// Start a captive portal detection loop if none has been
		// started. Create a new context if none is present, since it
		// can be shut down if we transition away from Running.
		if buildfeatures.HasCaptivePortal {
			if b.captiveCancel == nil {
				captiveCtx, captiveCancel := context.WithCancel(b.ctx)
				b.captiveCtx, b.captiveCancel = captiveCtx, captiveCancel
				b.goTracker.Go(func() { hookCheckCaptivePortalLoop.Get()(b, captiveCtx) })
			}
		}
	} else if oldState == ipn.Running {
		// Transitioning away from running.
		b.closePeerAPIListenersLocked()

		// Stop any existing captive portal detection loop.
		if buildfeatures.HasCaptivePortal && b.captiveCancel != nil {
			b.captiveCancel()
			b.captiveCancel = nil

			// NOTE: don't set captiveCtx to nil here, to ensure
			// that we always have a (canceled) context to wait on
			// in onHealthChange.
		}
	}
	b.pauseOrResumeControlClientLocked()

	unlock.UnlockEarly()

	// prefs may change irrespective of state; WantRunning should be explicitly
	// set before potential early return even if the state is unchanged.
	b.health.SetIPNState(newState.String(), prefs.Valid() && prefs.WantRunning())
	if oldState == newState {
		return
	}
	b.logf("Switching ipn state %v -> %v (WantRunning=%v, nm=%v)",
		oldState, newState, prefs.WantRunning(), netMap != nil)
	b.send(ipn.Notify{State: &newState})

	switch newState {
	case ipn.NeedsLogin:
		feature.SystemdStatus("Needs login: %s", authURL)
		// always block updates on NeedsLogin even if seamless renewal is enabled,
		// to prevent calls to authReconfig from reconfiguring the engine when our
		// key has expired and we're waiting to authenticate to use the new key.
		b.blockEngineUpdates(true)
		fallthrough
	case ipn.Stopped, ipn.NoState:
		// Unconfigure the engine if it has stopped (WantRunning is set to false)
		// or if we've switched to a different profile and the state is unknown.
		err := b.e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{})
		if err != nil {
			b.logf("Reconfig(down): %v", err)
		}

		if newState == ipn.Stopped && authURL == "" {
			feature.SystemdStatus("Stopped; run 'tailscale up' to log in")
		}
	case ipn.Starting, ipn.NeedsMachineAuth:
		b.authReconfig()
		// Needed so that UpdateEndpoints can run
		b.e.RequestStatus()
	case ipn.Running:
		var addrStrs []string
		addrs := netMap.GetAddresses()
		for _, p := range addrs.All() {
			addrStrs = append(addrStrs, p.Addr().String())
		}
		feature.SystemdStatus("Connected; %s; %s", activeLogin, strings.Join(addrStrs, " "))
	default:
		b.logf("[unexpected] unknown newState %#v", newState)
	}
}

func (b *LocalBackend) hasNodeKeyLocked() bool {
	// we can't use b.Prefs(), because it strips the keys, oops!
	p := b.pm.CurrentPrefs()
	return p.Valid() && p.Persist().Valid() && !p.Persist().PrivateNodeKey().IsZero()
}

// NodeKey returns the public node key.
func (b *LocalBackend) NodeKey() key.NodePublic {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.hasNodeKeyLocked() {
		return key.NodePublic{}
	}
	return b.pm.CurrentPrefs().Persist().PublicNodeKey()
}

// nextStateLocked returns the state the backend seems to be in, based on
// its internal state.
//
// b.mu must be held
func (b *LocalBackend) nextStateLocked() ipn.State {
	var (
		cc         = b.cc
		cn         = b.currentNode()
		netMap     = cn.NetMap()
		state      = b.state
		blocked    = b.blocked
		st         = b.engineStatus
		keyExpired = b.keyExpired

		wantRunning = false
		loggedOut   = false
	)
	if p := b.pm.CurrentPrefs(); p.Valid() {
		wantRunning = p.WantRunning()
		loggedOut = p.LoggedOut()
	}

	switch {
	case !wantRunning && !loggedOut && !blocked && b.hasNodeKeyLocked():
		return ipn.Stopped
	case netMap == nil:
		if (cc != nil && cc.AuthCantContinue()) || loggedOut {
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
	case netMap.GetMachineStatus() != tailcfg.MachineAuthorized:
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

// stateMachine updates the state machine state based on other things
// that have happened. It is invoked from the various callbacks that
// feed events into LocalBackend.
//
// TODO(apenwarr): use a channel or something to prevent reentrancy?
// Or maybe just call the state machine from fewer places.
func (b *LocalBackend) stateMachine() {
	unlock := b.lockAndGetUnlock()
	b.stateMachineLockedOnEntry(unlock)
}

// stateMachineLockedOnEntry is like stateMachine but requires b.mu be held to
// call it, but it unlocks b.mu when done (via unlock, a once func).
func (b *LocalBackend) stateMachineLockedOnEntry(unlock unlockOnce) {
	b.enterStateLockedOnEntry(b.nextStateLocked(), unlock)
}

// lockAndGetUnlock locks b.mu and returns a sync.OnceFunc function that will
// unlock it at most once.
//
// This is all very unfortunate but exists as a guardrail against the
// unfortunate "lockedOnEntry" methods in this package (primarily
// enterStateLockedOnEntry) that require b.mu held to be locked on entry to the
// function but unlock the mutex on their way out. As a stepping stone to
// cleaning things up (as of 2024-04-06), we at least pass the unlock func
// around now and defer unlock in the caller to avoid missing unlocks and double
// unlocks. TODO(bradfitz,maisem): make the locking in this package more
// traditional (simple). See https://github.com/tailscale/tailscale/issues/11649
func (b *LocalBackend) lockAndGetUnlock() (unlock unlockOnce) {
	b.mu.Lock()
	var unlocked atomic.Bool
	return func() bool {
		if unlocked.CompareAndSwap(false, true) {
			b.mu.Unlock()
			return true
		}
		return false
	}
}

// unlockOnce is a func that unlocks only b.mu the first time it's called.
// Therefore it can be safely deferred to catch error paths, without worrying
// about double unlocks if a different point in the code later needs to explicitly
// unlock it first as well. It reports whether it was unlocked.
type unlockOnce func() bool

// UnlockEarly unlocks the LocalBackend.mu. It panics if u returns false,
// indicating that this unlocker was already used.
//
// We're using this method to help us document & find the places that have
// atypical locking patterns. See
// https://github.com/tailscale/tailscale/issues/11649 for background.
//
// A normal unlock is a deferred one or an explicit b.mu.Unlock a few lines
// after the lock, without lots of control flow in-between. An "early" unlock is
// one that happens in weird places, like in various "LockedOnEntry" methods in
// this package that require the mutex to be locked on entry but unlock it
// somewhere in the middle (maybe several calls away) and then sometimes proceed
// to lock it again.
//
// The reason UnlockeEarly panics if already called is because these are the
// points at which it's assumed that the mutex is already held and it now needs
// to be released. If somebody already released it, that invariant was violated.
// On the other hand, simply calling u only returns false instead of panicking
// so you can defer it without care, confident you got all the error return
// paths which were previously done by hand.
func (u unlockOnce) UnlockEarly() {
	if !u() {
		panic("Unlock on already-called unlockOnce")
	}
}

// stopEngineAndWait deconfigures the local network data plane, and
// waits for it to deliver a status update indicating it has stopped
// before returning.
func (b *LocalBackend) stopEngineAndWait() {
	b.logf("stopEngineAndWait...")
	b.e.Reconfig(&wgcfg.Config{}, &router.Config{}, &dns.Config{})
	b.requestEngineStatusAndWaitForStopped()
	b.logf("stopEngineAndWait: done.")
}

// Requests the wgengine status, and does not return until a status was
// delivered (to the usual callback) that indicates the engine is stopped.
func (b *LocalBackend) requestEngineStatusAndWaitForStopped() {
	b.logf("requestEngineStatusAndWaitForStopped")

	b.mu.Lock()
	defer b.mu.Unlock()

	b.goTracker.Go(b.e.RequestStatus)
	b.logf("requestEngineStatusAndWaitForStopped: waiting...")
	for {
		b.statusChanged.Wait() // temporarily releases lock while waiting

		if !b.blocked {
			b.logf("requestEngineStatusAndWaitForStopped: engine is no longer blocked, must have stopped and started again, not safe to wait.")
			break
		}
		if b.engineStatus.NumLive == 0 && b.engineStatus.LiveDERPs == 0 {
			b.logf("requestEngineStatusAndWaitForStopped: engine is stopped.")
			break
		}
		b.logf("requestEngineStatusAndWaitForStopped: engine is still running. Waiting...")
	}
}

// setControlClientLocked sets the control client to cc,
// which may be nil.
//
// b.mu must be held.
func (b *LocalBackend) setControlClientLocked(cc controlclient.Client) {
	b.cc = cc
	b.ccAuto, _ = cc.(*controlclient.Auto)
}

// resetControlClientLocked sets b.cc to nil and returns the old value. If the
// returned value is non-nil, the caller must call Shutdown on it after
// releasing b.mu.
func (b *LocalBackend) resetControlClientLocked() controlclient.Client {
	if b.cc == nil {
		return nil
	}

	b.resetAuthURLLocked()

	// When we clear the control client, stop any outstanding netmap expiry
	// timer; synthesizing a new netmap while we don't have a control
	// client will break things.
	//
	// See https://github.com/tailscale/tailscale/issues/7392
	if b.nmExpiryTimer != nil {
		b.nmExpiryTimer.Stop()
		b.nmExpiryTimer = nil

		// Also bump the epoch to ensure that if the timer started, it
		// will abort.
		b.numClientStatusCalls.Add(1)
	}
	prev := b.cc
	b.setControlClientLocked(nil)
	return prev
}

// resetAuthURLLocked resets authURL, canceling any pending interactive login.
func (b *LocalBackend) resetAuthURLLocked() {
	b.authURL = ""
	b.authURLTime = time.Time{}
	b.authActor = nil
}

func (b *LocalBackend) ShouldRunSSH() bool { return b.sshAtomicBool.Load() && envknob.CanSSHD() }

// ShouldRunWebClient reports whether the web client is being run
// within this tailscaled instance. ShouldRunWebClient is safe to
// call regardless of whether b.mu is held or not.
func (b *LocalBackend) ShouldRunWebClient() bool { return b.webClientAtomicBool.Load() }

// ShouldExposeRemoteWebClient reports whether the web client should
// accept connections via [tailscale IP]:5252 in addition to the default
// behaviour of accepting local connections over 100.100.100.100.
//
// This function checks both the web client user pref via
// exposeRemoteWebClientAtomicBool and the disable-web-client node attr
// via ShouldRunWebClient to determine whether the web client should be
// exposed.
func (b *LocalBackend) ShouldExposeRemoteWebClient() bool {
	return b.ShouldRunWebClient() && b.exposeRemoteWebClientAtomicBool.Load()
}

// setWebClientAtomicBoolLocked sets webClientAtomicBool based on whether
// tailcfg.NodeAttrDisableWebClient has been set in the netmap.NetworkMap.
//
// b.mu must be held.
func (b *LocalBackend) setWebClientAtomicBoolLocked(nm *netmap.NetworkMap) {
	shouldRun := !nm.HasCap(tailcfg.NodeAttrDisableWebClient)
	wasRunning := b.webClientAtomicBool.Swap(shouldRun)
	if wasRunning && !shouldRun {
		b.goTracker.Go(b.webClientShutdown) // stop web client
	}
}

// setExposeRemoteWebClientAtomicBoolLocked sets exposeRemoteWebClientAtomicBool
// based on whether the RunWebClient pref is set.
//
// b.mu must be held.
func (b *LocalBackend) setExposeRemoteWebClientAtomicBoolLocked(prefs ipn.PrefsView) {
	if !buildfeatures.HasWebClient {
		return
	}
	shouldExpose := prefs.Valid() && prefs.RunWebClient()
	b.exposeRemoteWebClientAtomicBool.Store(shouldExpose)
}

// ShouldHandleViaIP reports whether ip is an IPv6 address in the
// Tailscale ULA's v6 "via" range embedding an IPv4 address to be forwarded to
// by Tailscale.
func (b *LocalBackend) ShouldHandleViaIP(ip netip.Addr) bool {
	if f, ok := b.containsViaIPFuncAtomic.LoadOk(); ok {
		return f(ip)
	}
	return false
}

// Logout logs out the current profile, if any, and waits for the logout to
// complete.
func (b *LocalBackend) Logout(ctx context.Context, actor ipnauth.Actor) error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	if !b.hasNodeKeyLocked() {
		// Already logged out.
		return nil
	}
	cc := b.cc

	// Grab the current profile before we unlock the mutex, so that we can
	// delete it later.
	profile := b.pm.CurrentProfile()

	_, err := b.editPrefsLockedOnEntry(
		actor,
		&ipn.MaskedPrefs{
			WantRunningSet: true,
			LoggedOutSet:   true,
			Prefs:          ipn.Prefs{WantRunning: false, LoggedOut: true},
		}, unlock)
	if err != nil {
		return err
	}
	// b.mu is now unlocked, after editPrefsLockedOnEntry.

	// Clear any previous dial plan(s), if set.
	b.resetDialPlan()

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

	if err := cc.Logout(ctx); err != nil {
		return err
	}

	unlock = b.lockAndGetUnlock()
	defer unlock()

	if err := b.pm.DeleteProfile(profile.ID()); err != nil {
		b.logf("error deleting profile: %v", err)
		return err
	}
	return b.resetForProfileChangeLockedOnEntry(unlock)
}

// setNetInfo sets b.hostinfo.NetInfo to ni, and passes ni along to the
// controlclient, if one exists.
func (b *LocalBackend) setNetInfo(ni *tailcfg.NetInfo) {
	b.mu.Lock()
	cc := b.cc
	var refresh bool
	if b.MagicConn().DERPs() > 0 || testenv.InTest() {
		// When b.refreshAutoExitNode is set, we recently observed a link change
		// that indicates we have switched networks. After switching networks,
		// the previously selected automatic exit node is no longer as likely
		// to be a good choice and connectivity will already be broken due to
		// the network switch. Therefore, it is a good time to switch to a new
		// exit node because the network is already disrupted.
		//
		// Unfortunately, at the time of the link change, no information is
		// known about the new network's latency or location, so the necessary
		// details are not available to make a new choice. Instead, it sets
		// b.refreshAutoExitNode to signal that a new decision should be made
		// when we have an updated netcheck report. ni is that updated report.
		//
		// However, during testing we observed that often the first ni is
		// inconclusive because it was running during the link change or the
		// link was otherwise not stable yet. b.MagicConn().updateEndpoints()
		// can detect when the netcheck failed and trigger a rebind, but the
		// required information is not available here, and moderate additional
		// plumbing is required to pass that in. Instead, checking for an active
		// DERP link offers an easy approximation. We will continue to refine
		// this over time.
		refresh = b.refreshAutoExitNode
		b.refreshAutoExitNode = false
	}
	b.mu.Unlock()

	if cc == nil {
		return
	}
	cc.SetNetInfo(ni)
	if refresh {
		b.RefreshExitNode()
	}
}

// RefreshExitNode determines which exit node to use based on the current
// prefs and netmap and switches to it if needed.
func (b *LocalBackend) RefreshExitNode() {
	if !buildfeatures.HasUseExitNode {
		return
	}
	if b.resolveExitNode() {
		b.authReconfig()
	}
}

// resolveExitNode determines which exit node to use based on the current prefs
// and netmap. It updates the exit node ID in the prefs if needed, updates the
// exit node ID in the hostinfo if needed, sends a notification to clients, and
// returns true if the exit node has changed.
//
// It is the caller's responsibility to reconfigure routes and actually
// start using the selected exit node, if needed.
//
// b.mu must not be held.
func (b *LocalBackend) resolveExitNode() (changed bool) {
	if !buildfeatures.HasUseExitNode {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	nm := b.currentNode().NetMap()
	prefs := b.pm.CurrentPrefs().AsStruct()
	if !b.resolveExitNodeInPrefsLocked(prefs) {
		return
	}

	if err := b.pm.SetPrefs(prefs.View(), ipn.NetworkProfile{
		MagicDNSName: nm.MagicDNSSuffix(),
		DomainName:   nm.DomainName(),
		DisplayName:  nm.TailnetDisplayName(),
	}); err != nil {
		b.logf("failed to save exit node changes: %v", err)
	}

	// Send the resolved exit node to control via [tailcfg.Hostinfo].
	// [LocalBackend.applyPrefsToHostinfoLocked] usually sets the Hostinfo,
	// but it deferred until this point because there was a bogus ExitNodeID
	// in the prefs.
	//
	// TODO(sfllaw): Mutating b.hostinfo here is undesirable, mutating
	// in-place doubly so.
	sid := prefs.ExitNodeID
	if sid != unresolvedExitNodeID && b.hostinfo.ExitNodeID != sid {
		b.hostinfo.ExitNodeID = sid
		b.goTracker.Go(b.doSetHostinfoFilterServices)
	}

	b.sendToLocked(ipn.Notify{Prefs: ptr.To(prefs.View())}, allClients)
	return true
}

// reconcilePrefsLocked applies policy overrides, exit node resolution,
// and other post-processing to the prefs, and reports whether the prefs
// were modified as a result.
//
// It must not perform any reconfiguration, as the prefs are not yet effective.
//
// b.mu must be held.
func (b *LocalBackend) reconcilePrefsLocked(prefs *ipn.Prefs) (changed bool) {
	if buildfeatures.HasSystemPolicy && b.applySysPolicyLocked(prefs) {
		changed = true
	}
	if buildfeatures.HasUseExitNode && b.resolveExitNodeInPrefsLocked(prefs) {
		changed = true
	}
	if changed {
		b.logf("prefs reconciled: %v", prefs.Pretty())
	}
	return changed
}

// resolveExitNodeInPrefsLocked determines which exit node to use
// based on the specified prefs and netmap. It updates the exit node ID
// in the prefs if needed, and returns true if the exit node has changed.
//
// b.mu must be held.
func (b *LocalBackend) resolveExitNodeInPrefsLocked(prefs *ipn.Prefs) (changed bool) {
	if !buildfeatures.HasUseExitNode {
		return false
	}
	if b.resolveAutoExitNodeLocked(prefs) {
		changed = true
	}
	if b.resolveExitNodeIPLocked(prefs) {
		changed = true
	}
	return changed
}

// setNetMapLocked updates the LocalBackend state to reflect the newly
// received nm. If nm is nil, it resets all configuration as though
// Tailscale is turned off.
func (b *LocalBackend) setNetMapLocked(nm *netmap.NetworkMap) {
	oldSelf := b.currentNode().NetMap().SelfNodeOrZero()

	b.dialer.SetNetMap(nm)
	if ns, ok := b.sys.Netstack.GetOK(); ok {
		ns.UpdateNetstackIPs(nm)
	}
	var login string
	if nm != nil {
		login = cmp.Or(profileFromView(nm.UserProfiles[nm.User()]).LoginName, "<missing-profile>")
	}
	b.currentNode().SetNetMap(nm)
	if login != b.activeLogin {
		b.logf("active login: %v", login)
		b.activeLogin = login
	}
	b.pauseOrResumeControlClientLocked()

	if nm != nil {
		messages := make(map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage)
		for id, msg := range nm.DisplayMessages {
			if msg.PrimaryAction != nil && !b.validPopBrowserURLLocked(msg.PrimaryAction.URL) {
				msg.PrimaryAction = nil
			}
			messages[id] = msg
		}
		b.health.SetControlHealth(messages)
	} else {
		b.health.SetControlHealth(nil)
	}

	if runtime.GOOS == "linux" && buildfeatures.HasOSRouter {
		if nm.HasCap(tailcfg.NodeAttrLinuxMustUseIPTables) {
			b.capForcedNetfilter = "iptables"
		} else if nm.HasCap(tailcfg.NodeAttrLinuxMustUseNfTables) {
			b.capForcedNetfilter = "nftables"
		} else {
			b.capForcedNetfilter = "" // empty string means client can auto-detect
		}
	}

	b.MagicConn().SetSilentDisco(b.ControlKnobs().SilentDisco.Load())
	b.MagicConn().SetProbeUDPLifetime(b.ControlKnobs().ProbeUDPLifetime.Load())

	if buildfeatures.HasDebug {
		b.setDebugLogsByCapabilityLocked(nm)
	}

	// See the netns package for documentation on what this capability does.
	netns.SetBindToInterfaceByRoute(nm.HasCap(tailcfg.CapabilityBindToInterfaceByRoute))
	netns.SetDisableBindConnToInterface(nm.HasCap(tailcfg.CapabilityDebugDisableBindConnToInterface))

	b.setTCPPortsInterceptedFromNetmapAndPrefsLocked(b.pm.CurrentPrefs())
	if buildfeatures.HasServe {
		b.ipVIPServiceMap = nm.GetIPVIPServiceMap()
	}

	if !oldSelf.Equal(nm.SelfNodeOrZero()) {
		for _, f := range b.extHost.Hooks().OnSelfChange {
			f(nm.SelfNode)
		}
	}

	if buildfeatures.HasAdvertiseRoutes {
		if nm == nil {
			// If there is no netmap, the client is going into a "turned off"
			// state so reset the metrics.
			b.metrics.approvedRoutes.Set(0)
		} else if nm.SelfNode.Valid() {
			var approved float64
			for _, route := range nm.SelfNode.AllowedIPs().All() {
				if !views.SliceContains(nm.SelfNode.Addresses(), route) && !tsaddr.IsExitRoute(route) {
					approved++
				}
			}
			b.metrics.approvedRoutes.Set(approved)
		}
	}

	if buildfeatures.HasDrive && nm != nil {
		if f, ok := hookSetNetMapLockedDrive.GetOk(); ok {
			f(b, nm)
		}
	}
}

var hookSetNetMapLockedDrive feature.Hook[func(*LocalBackend, *netmap.NetworkMap)]

// roundTraffic rounds bytes. This is used to preserve user privacy within logs.
func roundTraffic(bytes int64) float64 {
	var x float64
	switch {
	case bytes <= 5:
		return float64(bytes)
	case bytes < 1000:
		x = 10
	case bytes < 10_000:
		x = 100
	case bytes < 100_000:
		x = 1000
	case bytes < 1_000_000:
		x = 10_000
	case bytes < 10_000_000:
		x = 100_000
	case bytes < 100_000_000:
		x = 1_000_000
	case bytes < 1_000_000_000:
		x = 10_000_000
	default:
		x = 100_000_000
	}
	return math.Round(float64(bytes)/x) * x
}

// setDebugLogsByCapabilityLocked sets debug logging based on the self node's
// capabilities in the provided NetMap.
func (b *LocalBackend) setDebugLogsByCapabilityLocked(nm *netmap.NetworkMap) {
	// These are sufficiently cheap (atomic bools) that we don't need to
	// store state and compare.
	if nm.HasCap(tailcfg.CapabilityDebugTSDNSResolution) {
		dnscache.SetDebugLoggingEnabled(true)
	} else {
		dnscache.SetDebugLoggingEnabled(false)
	}
}

// setTCPPortsInterceptedFromNetmapAndPrefsLocked calls setTCPPortsIntercepted with
// the ports that tailscaled should handle as a function of b.netMap and b.prefs.
//
// b.mu must be held.
func (b *LocalBackend) setTCPPortsInterceptedFromNetmapAndPrefsLocked(prefs ipn.PrefsView) {
	handlePorts := make([]uint16, 0, 4)

	if prefs.Valid() && prefs.RunSSH() && envknob.CanSSHD() {
		handlePorts = append(handlePorts, 22)
	}
	if b.ShouldExposeRemoteWebClient() {
		handlePorts = append(handlePorts, webClientPort)

		// don't listen on netmap addresses if we're in userspace mode
		if !b.sys.IsNetstack() {
			b.updateWebClientListenersLocked()
		}
	}

	if f, ok := hookServeSetTCPPortsInterceptedFromNetmapAndPrefsLocked.GetOk(); ok {
		v := f(b, prefs)
		handlePorts = append(handlePorts, v...)
	}

	// Update funnel and service hash info in hostinfo and kick off control update if needed.
	b.updateIngressAndServiceHashLocked(prefs)
	b.setTCPPortsIntercepted(handlePorts)
}

// updateIngressAndServiceHashLocked updates the hostinfo.ServicesHash, hostinfo.WireIngress and
// hostinfo.IngressEnabled fields and kicks off a Hostinfo update if the values have changed.
//
// b.mu must be held.
func (b *LocalBackend) updateIngressAndServiceHashLocked(prefs ipn.PrefsView) {
	if b.hostinfo == nil {
		return
	}
	hostInfoChanged := false
	if ie := b.hasIngressEnabledLocked(); b.hostinfo.IngressEnabled != ie {
		b.logf("Hostinfo.IngressEnabled changed to %v", ie)
		b.hostinfo.IngressEnabled = ie
		hostInfoChanged = true
	}
	if wire := b.shouldWireInactiveIngressLocked(); b.hostinfo.WireIngress != wire {
		b.logf("Hostinfo.WireIngress changed to %v", wire)
		b.hostinfo.WireIngress = wire
		hostInfoChanged = true
	}
	latestHash := b.vipServiceHash(b.vipServicesFromPrefsLocked(prefs))
	if b.hostinfo.ServicesHash != latestHash {
		b.hostinfo.ServicesHash = latestHash
		hostInfoChanged = true
	}
	// Kick off a Hostinfo update to control if ingress status has changed.
	if hostInfoChanged {
		b.goTracker.Go(b.doSetHostinfoFilterServices)
	}
}

// operatorUserName returns the current pref's OperatorUser's name, or the
// empty string if none.
func (b *LocalBackend) operatorUserName() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	prefs := b.pm.CurrentPrefs()
	if !prefs.Valid() {
		return ""
	}
	return prefs.OperatorUser()
}

// OperatorUserID returns the current pref's OperatorUser's ID (in
// os/user.User.Uid string form), or the empty string if none.
func (b *LocalBackend) OperatorUserID() string {
	opUserName := b.operatorUserName()
	if opUserName == "" {
		return ""
	}
	u, err := osuser.LookupByUsername(opUserName)
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
	machinePrivKey := b.machinePrivKey
	prefs := b.pm.CurrentPrefs()
	b.mu.Unlock()

	if !prefs.Valid() || machinePrivKey.IsZero() {
		return
	}

	mk := machinePrivKey.Public()
	nk := prefs.Persist().PublicNodeKey()
	return mk, nk
}

// SetDNS adds a DNS record for the given domain name & TXT record
// value.
//
// It's meant for use with dns-01 ACME (LetsEncrypt) challenges.
//
// This is the low-level interface. Other layers will provide more
// friendly options to get HTTPS certs.
func (b *LocalBackend) SetDNS(ctx context.Context, name, value string) error {
	if !buildfeatures.HasACME {
		return feature.ErrUnavailable
	}
	req := &tailcfg.SetDNSRequest{
		Version: 1, // TODO(bradfitz,maisem): use tailcfg.CurrentCapabilityVersion when using the Noise transport
		Type:    "TXT",
		Name:    name,
		Value:   value,
	}

	b.mu.Lock()
	cc := b.ccAuto
	if prefs := b.pm.CurrentPrefs(); prefs.Valid() && prefs.Persist().Valid() {
		req.NodeKey = prefs.Persist().PrivateNodeKey().Public()
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

func peerAPIPorts(peer tailcfg.NodeView) (p4, p6 uint16) {
	svcs := peer.Hostinfo().Services()
	for _, s := range svcs.All() {
		switch s.Proto {
		case tailcfg.PeerAPI4:
			p4 = s.Port
		case tailcfg.PeerAPI6:
			p6 = s.Port
		}
	}
	return
}

func (b *LocalBackend) CheckIPForwarding() error {
	if !buildfeatures.HasAdvertiseRoutes {
		return nil
	}
	if b.sys.IsNetstackRouter() {
		return nil
	}

	// TODO: let the caller pass in the ranges.
	warn, err := netutil.CheckIPForwarding(tsaddr.ExitRoutes(), b.sys.NetMon.Get().InterfaceState())
	if err != nil {
		return err
	}
	return warn
}

// CheckUDPGROForwarding checks if the machine is optimally configured to
// forward UDP packets between the default route and Tailscale TUN interfaces.
// It returns an error if the check fails or if suboptimal configuration is
// detected. No error is returned if we are unable to gather the interface
// names from the relevant subsystems.
func (b *LocalBackend) CheckUDPGROForwarding() error {
	if b.sys.IsNetstackRouter() {
		return nil
	}
	// We return nil when the interface name or subsystem it's tied to can't be
	// fetched. This is intentional as answering the question "are netdev
	// features optimal for performance?" is a low priority in that situation.
	tunSys, ok := b.sys.Tun.GetOK()
	if !ok {
		return nil
	}
	tunInterface, err := tunSys.Name()
	if err != nil {
		return nil
	}
	netmonSys, ok := b.sys.NetMon.GetOK()
	if !ok {
		return nil
	}
	state := netmonSys.InterfaceState()
	if state == nil {
		return nil
	}
	// We return warn or err. If err is non-nil there was a problem
	// communicating with the kernel via ethtool semantics/ioctl. ethtool ioctl
	// errors are interesting for our future selves as we consider tweaking
	// netdev features automatically using similar API infra.
	warn, err := netkernelconf.CheckUDPGROForwarding(tunInterface, state.DefaultRouteInterface)
	if err != nil {
		return err
	}
	return warn
}

// SetUDPGROForwarding enables UDP GRO forwarding for the default network
// interface of this machine. It can be done to improve performance for nodes
// acting as Tailscale subnet routers or exit nodes. Currently (9/5/2024) this
// functionality is considered experimental and only safe to use via explicit
// user opt-in for ephemeral devices, such as containers.
// https://tailscale.com/kb/1320/performance-best-practices#linux-optimizations-for-subnet-routers-and-exit-nodes
func (b *LocalBackend) SetUDPGROForwarding() error {
	if b.sys.IsNetstackRouter() {
		return errors.New("UDP GRO forwarding cannot be enabled in userspace mode")
	}
	tunSys, ok := b.sys.Tun.GetOK()
	if !ok {
		return errors.New("[unexpected] unable to retrieve tun device configuration")
	}
	tunInterface, err := tunSys.Name()
	if err != nil {
		return errors.New("[unexpected] unable to determine name of the tun device")
	}
	netmonSys, ok := b.sys.NetMon.GetOK()
	if !ok {
		return errors.New("[unexpected] unable to retrieve tailscale netmon configuration")
	}
	state := netmonSys.InterfaceState()
	if state == nil {
		return errors.New("[unexpected] unable to retrieve machine's network interface state")
	}
	if err := netkernelconf.SetUDPGROForwarding(tunInterface, state.DefaultRouteInterface); err != nil {
		return fmt.Errorf("error enabling UDP GRO forwarding: %w", err)
	}
	return nil
}

// DERPMap returns the current DERPMap in use, or nil if not connected.
func (b *LocalBackend) DERPMap() *tailcfg.DERPMap {
	return b.currentNode().DERPMap()
}

// OfferingExitNode reports whether b is currently offering exit node
// access.
func (b *LocalBackend) OfferingExitNode() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.pm.CurrentPrefs().Valid() {
		return false
	}
	var def4, def6 bool
	ar := b.pm.CurrentPrefs().AdvertiseRoutes()
	for i := range ar.Len() {
		r := ar.At(i)
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

// OfferingAppConnector reports whether b is currently offering app
// connector services.
func (b *LocalBackend) OfferingAppConnector() bool {
	if !buildfeatures.HasAppConnectors {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.appConnector != nil
}

// AppConnector returns the current AppConnector, or nil if not configured.
//
// TODO(nickkhyl): move app connectors to [nodeBackend], or perhaps a feature package?
func (b *LocalBackend) AppConnector() *appc.AppConnector {
	if !buildfeatures.HasAppConnectors {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.appConnector
}

// allowExitNodeDNSProxyToServeName reports whether the Exit Node DNS
// proxy is allowed to serve responses for the provided DNS name.
func (b *LocalBackend) allowExitNodeDNSProxyToServeName(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	nm := b.NetMap()
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

// SetDeviceAttrs does a synchronous call to the control plane to update
// the node's attributes.
//
// See docs on [tailcfg.SetDeviceAttributesRequest] for background.
func (b *LocalBackend) SetDeviceAttrs(ctx context.Context, attrs tailcfg.AttrUpdate) error {
	b.mu.Lock()
	cc := b.ccAuto
	b.mu.Unlock()
	if cc == nil {
		return errors.New("not running")
	}
	return cc.SetDeviceAttrs(ctx, attrs)
}

// exitNodeCanProxyDNS reports the DoH base URL ("http://foo/dns-query") without query parameters
// to exitNodeID's DoH service, if available.
//
// If exitNodeID is the zero valid, it returns "", false.
func exitNodeCanProxyDNS(nm *netmap.NetworkMap, peers map[tailcfg.NodeID]tailcfg.NodeView, exitNodeID tailcfg.StableNodeID) (dohURL string, ok bool) {
	if !buildfeatures.HasUseExitNode {
		return "", false
	}
	if exitNodeID.IsZero() {
		return "", false
	}
	for _, p := range peers {
		if p.StableID() == exitNodeID && peerCanProxyDNS(p) {
			return peerAPIBase(nm, p) + "/dns-query", true
		}
	}
	return "", false
}

// wireguardExitNodeDNSResolvers returns the DNS resolvers to use for a
// WireGuard-only exit node, if it has resolver addresses.
func wireguardExitNodeDNSResolvers(nm *netmap.NetworkMap, peers map[tailcfg.NodeID]tailcfg.NodeView, exitNodeID tailcfg.StableNodeID) ([]*dnstype.Resolver, bool) {
	if exitNodeID.IsZero() {
		return nil, false
	}

	for _, p := range peers {
		if p.StableID() == exitNodeID {
			if p.IsWireGuardOnly() {
				resolvers := p.ExitNodeDNSResolvers()
				if !resolvers.IsNil() && resolvers.Len() > 0 {
					copies := make([]*dnstype.Resolver, resolvers.Len())
					for i, r := range resolvers.All() {
						copies[i] = r.AsStruct()
					}
					return copies, true
				}
			}
			return nil, false
		}
	}

	return nil, false
}

func peerCanProxyDNS(p tailcfg.NodeView) bool {
	if p.Cap() >= 26 {
		// Actually added at 25
		// (https://github.com/tailscale/tailscale/blob/3ae6f898cfdb58fd0e30937147dd6ce28c6808dd/tailcfg/tailcfg.go#L51)
		// so anything >= 26 can do it.
		return true
	}
	// If p.Cap is not populated (e.g. older control server), then do the old
	// thing of searching through services.
	services := p.Hostinfo().Services()
	for _, s := range services.All() {
		if s.Proto == tailcfg.PeerAPIDNS && s.Port >= 1 {
			return true
		}
	}
	return false
}

func (b *LocalBackend) DebugRebind() error {
	b.MagicConn().Rebind()
	return nil
}

func (b *LocalBackend) DebugReSTUN() error {
	b.MagicConn().ReSTUN("explicit-debug")
	return nil
}

func (b *LocalBackend) DebugPeerRelayServers() set.Set[netip.Addr] {
	return b.MagicConn().PeerRelays()
}

// ControlKnobs returns the node's control knobs.
func (b *LocalBackend) ControlKnobs() *controlknobs.Knobs {
	return b.sys.ControlKnobs()
}

// EventBus returns the node's event bus.
func (b *LocalBackend) EventBus() *eventbus.Bus {
	return b.sys.Bus.Get()
}

// MagicConn returns the backend's *magicsock.Conn.
func (b *LocalBackend) MagicConn() *magicsock.Conn {
	return b.sys.MagicSock.Get()
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

// ActiveSSHConns returns the number of active SSH connections,
// or 0 if SSH is not linked into the binary or available on the platform.
func (b *LocalBackend) ActiveSSHConns() int {
	if b.sshServer == nil {
		return 0
	}
	return b.sshServer.NumActiveConns()
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

var warnSSHSELinuxWarnable = health.Register(&health.Warnable{
	Code:     "ssh-unavailable-selinux-enabled",
	Title:    "Tailscale SSH and SELinux",
	Severity: health.SeverityLow,
	Text:     health.StaticMessage("SELinux is enabled; Tailscale SSH may not work. See https://tailscale.com/s/ssh-selinux"),
})

func (b *LocalBackend) updateSELinuxHealthWarning() {
	if hostinfo.IsSELinuxEnforcing() {
		b.health.SetUnhealthy(warnSSHSELinuxWarnable, nil)
	} else {
		b.health.SetHealthy(warnSSHSELinuxWarnable)
	}
}

func (b *LocalBackend) handleSSHConn(c net.Conn) (err error) {
	s, err := b.sshServerOrInit()
	if err != nil {
		return err
	}
	b.updateSELinuxHealthWarning()
	return s.HandleSSHConn(c)
}

// HandleQuad100Port80Conn serves http://100.100.100.100/ on port 80 (and
// the equivalent tsaddr.TailscaleServiceIPv6 address).
func (b *LocalBackend) HandleQuad100Port80Conn(c net.Conn) error {
	var s http.Server
	s.Handler = http.HandlerFunc(b.handleQuad100Port80Conn)
	return s.Serve(netutil.NewOneConnListener(c, nil))
}

func validQuad100Host(h string) bool {
	switch h {
	case "",
		tsaddr.TailscaleServiceIPString,
		tsaddr.TailscaleServiceIPv6String,
		"[" + tsaddr.TailscaleServiceIPv6String + "]":
		return true
	}
	return false
}

func (b *LocalBackend) handleQuad100Port80Conn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self';")
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validQuad100Host(r.Host) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	io.WriteString(w, "<h1>Tailscale</h1>\n")
	nm := b.currentNode().NetMap()
	if nm == nil {
		io.WriteString(w, "No netmap.\n")
		return
	}
	addrs := nm.GetAddresses()
	if addrs.Len() == 0 {
		io.WriteString(w, "No local addresses.\n")
		return
	}
	io.WriteString(w, "<p>Local addresses:</p><ul>\n")
	for i := range addrs.Len() {
		fmt.Fprintf(w, "<li>%v</li>\n", addrs.At(i).Addr())
	}
	io.WriteString(w, "</ul>\n")
}

// HookDoctor is an optional hook for the "doctor" problem diagnosis feature.
var HookDoctor feature.Hook[func(context.Context, *LocalBackend, logger.Logf)]

// SetDevStateStore updates the LocalBackend's state storage to the provided values.
//
// It's meant only for development.
func (b *LocalBackend) SetDevStateStore(key, value string) error {
	if b.store == nil {
		return errors.New("no state store")
	}
	err := ipn.WriteState(b.store, ipn.StateKey(key), []byte(value))
	b.logf("SetDevStateStore(%q, %q) = %v", key, value, err)

	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.setTCPPortsInterceptedFromNetmapAndPrefsLocked(b.pm.CurrentPrefs())

	return nil
}

// ShouldInterceptTCPPort reports whether the given TCP port number to a
// Tailscale IP (not a subnet router, service IP, etc) should be intercepted by
// Tailscaled and handled in-process.
func (b *LocalBackend) ShouldInterceptTCPPort(port uint16) bool {
	return b.shouldInterceptTCPPortAtomic.Load()(port)
}

// ShouldInterceptVIPServiceTCPPort reports whether the given TCP port number
// to a VIP service should be intercepted by Tailscaled and handled in-process.
func (b *LocalBackend) ShouldInterceptVIPServiceTCPPort(ap netip.AddrPort) bool {
	if !buildfeatures.HasServe {
		return false
	}
	f := b.shouldInterceptVIPServicesTCPPortAtomic.Load()
	if f == nil {
		return false
	}
	return f(ap)
}

// SwitchProfile switches to the profile with the given id.
// It will restart the backend on success.
// If the profile is not known, it returns an errProfileNotFound.
func (b *LocalBackend) SwitchProfile(profile ipn.ProfileID) error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	oldControlURL := b.pm.CurrentPrefs().ControlURLOrDefault(b.polc)
	if _, changed, err := b.pm.SwitchToProfileByID(profile); !changed || err != nil {
		return err // nil if we're already on the target profile
	}

	// As an optimization, only reset the dialPlan if the control URL changed.
	if newControlURL := b.pm.CurrentPrefs().ControlURLOrDefault(b.polc); oldControlURL != newControlURL {
		b.resetDialPlan()
	}

	return b.resetForProfileChangeLockedOnEntry(unlock)
}

// resetDialPlan resets the dialPlan for this LocalBackend. It will log if
// anything is reset.
//
// It is safe to call this concurrently, with or without b.mu held.
func (b *LocalBackend) resetDialPlan() {
	old := b.dialPlan.Swap(nil)
	if old != nil {
		b.logf("resetDialPlan: did reset")
	}
}

// resetForProfileChangeLockedOnEntry resets the backend for a profile change.
//
// b.mu must held on entry. It is released on exit.
func (b *LocalBackend) resetForProfileChangeLockedOnEntry(unlock unlockOnce) error {
	defer unlock()

	if b.shutdownCalled {
		// Prevent a call back to Start during Shutdown, which calls Logout for
		// ephemeral nodes, which can then call back here. But we're shutting
		// down, so no need to do any work.
		return nil
	}
	newNode := newNodeBackend(b.ctx, b.logf, b.sys.Bus.Get())
	if oldNode := b.currentNodeAtomic.Swap(newNode); oldNode != nil {
		oldNode.shutdown(errNodeContextChanged)
	}
	defer newNode.ready()
	b.setNetMapLocked(nil) // Reset netmap.
	b.updateFilterLocked(ipn.PrefsView{})
	// Reset the NetworkMap in the engine
	b.e.SetNetworkMap(new(netmap.NetworkMap))
	if prevCC := b.resetControlClientLocked(); prevCC != nil {
		// Needs to happen without b.mu held.
		defer prevCC.Shutdown()
	}
	// TKA errors should not prevent resetting the backend state.
	// However, we should still return the error to the caller.
	tkaErr := b.initTKALocked()
	b.lastServeConfJSON = mem.B(nil)
	b.serveConfig = ipn.ServeConfigView{}
	b.lastSuggestedExitNode = ""
	b.keyExpired = false
	b.overrideExitNodePolicy = false
	b.resetAlwaysOnOverrideLocked()
	b.extHost.NotifyProfileChange(b.pm.CurrentProfile(), b.pm.CurrentPrefs(), false)
	b.setAtomicValuesFromPrefsLocked(b.pm.CurrentPrefs())
	b.enterStateLockedOnEntry(ipn.NoState, unlock) // Reset state; releases b.mu
	b.health.SetLocalLogConfigHealth(nil)
	if tkaErr != nil {
		return tkaErr
	}
	return b.Start(ipn.Options{})
}

// DeleteProfile deletes a profile with the given ID.
// If the profile is not known, it is a no-op.
func (b *LocalBackend) DeleteProfile(p ipn.ProfileID) error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	needToRestart := b.pm.CurrentProfile().ID() == p
	if err := b.pm.DeleteProfile(p); err != nil {
		if err == errProfileNotFound {
			return nil
		}
		return err
	}
	if !needToRestart {
		return nil
	}
	return b.resetForProfileChangeLockedOnEntry(unlock)
}

// CurrentProfile returns the current LoginProfile.
// The value may be zero if the profile is not persisted.
func (b *LocalBackend) CurrentProfile() ipn.LoginProfileView {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.CurrentProfile()
}

// NewProfile creates and switches to the new profile.
func (b *LocalBackend) NewProfile() error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	b.pm.SwitchToNewProfile()

	// The new profile doesn't yet have a ControlURL because it hasn't been
	// set. Conservatively reset the dialPlan.
	b.resetDialPlan()

	return b.resetForProfileChangeLockedOnEntry(unlock)
}

// ListProfiles returns a list of all LoginProfiles.
func (b *LocalBackend) ListProfiles() []ipn.LoginProfileView {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.Profiles()
}

// ResetAuth resets the authentication state, including persisted keys. Also
// has the side effect of removing all profiles and reseting preferences. The
// backend is left with a new profile, ready for StartLoginInterative to be
// called to register it as new node.
func (b *LocalBackend) ResetAuth() error {
	unlock := b.lockAndGetUnlock()
	defer unlock()

	prevCC := b.resetControlClientLocked()
	if prevCC != nil {
		defer prevCC.Shutdown() // call must happen after release b.mu
	}
	if err := b.clearMachineKeyLocked(); err != nil {
		return err
	}
	if err := b.pm.DeleteAllProfilesForUser(); err != nil {
		return err
	}
	b.resetDialPlan() // always reset if we're removing everything
	return b.resetForProfileChangeLockedOnEntry(unlock)
}

func (b *LocalBackend) GetPeerEndpointChanges(ctx context.Context, ip netip.Addr) ([]magicsock.EndpointChange, error) {
	pip, ok := b.e.PeerForIP(ip)
	if !ok {
		return nil, fmt.Errorf("no matching peer")
	}
	if pip.IsSelf {
		return nil, fmt.Errorf("%v is local Tailscale IP", ip)
	}
	peer := pip.Node

	chs, err := b.MagicConn().GetEndpointChanges(peer)
	if err != nil {
		return nil, fmt.Errorf("getting endpoint changes: %w", err)
	}
	return chs, nil
}

var breakTCPConns func() error

func (b *LocalBackend) DebugBreakTCPConns() error {
	if breakTCPConns == nil {
		return errors.New("TCP connection breaking not available on this platform")
	}
	return breakTCPConns()
}

func (b *LocalBackend) DebugBreakDERPConns() error {
	return b.MagicConn().DebugBreakDERPConns()
}

// ObserveDNSResponse passes a DNS response from the PeerAPI DNS server to the
// App Connector to enable route discovery.
func (b *LocalBackend) ObserveDNSResponse(res []byte) error {
	if !buildfeatures.HasAppConnectors {
		return nil
	}
	var appConnector *appc.AppConnector
	b.mu.Lock()
	if b.appConnector == nil {
		b.mu.Unlock()
		return nil
	}
	appConnector = b.appConnector
	b.mu.Unlock()

	return appConnector.ObserveDNSResponse(res)
}

// ErrDisallowedAutoRoute is returned by AdvertiseRoute when a route that is not allowed is requested.
var ErrDisallowedAutoRoute = errors.New("route is not allowed")

// AdvertiseRoute implements the appctype.RouteAdvertiser interface. It sets a
// new route advertisement if one is not already present in the existing
// routes.  If the route is disallowed, ErrDisallowedAutoRoute is returned.
func (b *LocalBackend) AdvertiseRoute(ipps ...netip.Prefix) error {
	finalRoutes := b.Prefs().AdvertiseRoutes().AsSlice()
	var newRoutes []netip.Prefix

	for _, ipp := range ipps {
		if !allowedAutoRoute(ipp) {
			continue
		}
		if slices.Contains(finalRoutes, ipp) {
			continue
		}

		// If the new prefix is already contained by existing routes, skip it.
		if coveredRouteRangeNoDefault(finalRoutes, ipp) {
			continue
		}

		finalRoutes = append(finalRoutes, ipp)
		newRoutes = append(newRoutes, ipp)
	}

	if len(newRoutes) == 0 {
		return nil
	}

	b.logf("advertising new app connector routes: %v", newRoutes)
	_, err := b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: finalRoutes,
		},
		AdvertiseRoutesSet: true,
	})
	return err
}

// coveredRouteRangeNoDefault checks if a route is already included in a slice of
// prefixes, ignoring default routes in the range.
func coveredRouteRangeNoDefault(finalRoutes []netip.Prefix, ipp netip.Prefix) bool {
	for _, r := range finalRoutes {
		if r == tsaddr.AllIPv4() || r == tsaddr.AllIPv6() {
			continue
		}
		if ipp.IsSingleIP() {
			if r.Contains(ipp.Addr()) {
				return true
			}
		} else {
			if r.Contains(ipp.Addr()) && r.Contains(netipx.PrefixLastIP(ipp)) {
				return true
			}
		}
	}
	return false
}

// UnadvertiseRoute implements the appctype.RouteAdvertiser interface. It
// removes a route advertisement if one is present in the existing routes.
func (b *LocalBackend) UnadvertiseRoute(toRemove ...netip.Prefix) error {
	currentRoutes := b.Prefs().AdvertiseRoutes().AsSlice()
	finalRoutes := currentRoutes[:0]

	for _, ipp := range currentRoutes {
		if slices.Contains(toRemove, ipp) {
			continue
		}
		finalRoutes = append(finalRoutes, ipp)
	}

	_, err := b.EditPrefs(&ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			AdvertiseRoutes: finalRoutes,
		},
		AdvertiseRoutesSet: true,
	})
	return err
}

// namespace a key with the profile manager's current profile key, if any
func namespaceKeyForCurrentProfile(pm *profileManager, key ipn.StateKey) ipn.StateKey {
	return pm.CurrentProfile().Key() + "||" + key
}

const routeInfoStateStoreKey ipn.StateKey = "_routeInfo"

func (b *LocalBackend) storeRouteInfo(ri appctype.RouteInfo) error {
	if !buildfeatures.HasAppConnectors {
		return feature.ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pm.CurrentProfile().ID() == "" {
		return nil
	}
	key := namespaceKeyForCurrentProfile(b.pm, routeInfoStateStoreKey)
	bs, err := json.Marshal(ri)
	if err != nil {
		return err
	}
	return b.pm.WriteState(key, bs)
}

func (b *LocalBackend) readRouteInfoLocked() (*appctype.RouteInfo, error) {
	if !buildfeatures.HasAppConnectors {
		return nil, feature.ErrUnavailable
	}
	if b.pm.CurrentProfile().ID() == "" {
		return &appctype.RouteInfo{}, nil
	}
	key := namespaceKeyForCurrentProfile(b.pm, routeInfoStateStoreKey)
	bs, err := b.pm.Store().ReadState(key)
	ri := &appctype.RouteInfo{}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(bs, ri); err != nil {
		return nil, err
	}
	return ri, nil
}

// ReadRouteInfo returns the app connector route information that is
// stored in prefs to be consistent across restarts. It should be up
// to date with the RouteInfo in memory being used by appc.
func (b *LocalBackend) ReadRouteInfo() (*appctype.RouteInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.readRouteInfoLocked()
}

// seamlessRenewalEnabled reports whether seamless key renewals are enabled.
//
// As of 2025-09-11, this is the default behaviour unless nodes receive
// [tailcfg.NodeAttrDisableSeamlessKeyRenewal] in their netmap.
func (b *LocalBackend) seamlessRenewalEnabled() bool {
	return b.ControlKnobs().SeamlessKeyRenewal.Load()
}

var (
	disallowedAddrs = []netip.Addr{
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("::"),
		netip.MustParseAddr("0.0.0.0"),
	}
	disallowedRanges = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// allowedAutoRoute determines if the route being added via AdvertiseRoute (the app connector featuge) should be allowed.
func allowedAutoRoute(ipp netip.Prefix) bool {
	// Note: blocking the addrs for globals, not solely the prefixes.
	for _, addr := range disallowedAddrs {
		if ipp.Addr() == addr {
			return false
		}
	}
	for _, pfx := range disallowedRanges {
		if pfx.Overlaps(ipp) {
			return false
		}
	}
	// TODO(raggi): exclude tailscale service IPs and so on as well.
	return true
}

var ErrNoPreferredDERP = errors.New("no preferred DERP, try again later")

// suggestExitNodeLocked computes a suggestion based on the current netmap and
// other optional factors. If there are multiple equally good options, one may
// be selected at random, so the result is not stable. To be eligible for
// consideration, the peer must have NodeAttrSuggestExitNode in its CapMap.
//
// b.mu.lock() must be held.
func (b *LocalBackend) suggestExitNodeLocked() (response apitype.ExitNodeSuggestionResponse, err error) {
	if !buildfeatures.HasUseExitNode {
		return response, feature.ErrUnavailable
	}
	lastReport := b.MagicConn().GetLastNetcheckReport(b.ctx)
	prevSuggestion := b.lastSuggestedExitNode

	res, err := suggestExitNode(lastReport, b.currentNode(), prevSuggestion, randomRegion, randomNode, b.getAllowedSuggestions())
	if err != nil {
		return res, err
	}
	if prevSuggestion != res.ID {
		// Notify the clients via the IPN bus if the exit node suggestion has changed.
		b.sendToLocked(ipn.Notify{SuggestedExitNode: &res.ID}, allClients)
	}
	b.lastSuggestedExitNode = res.ID

	return res, err
}

func (b *LocalBackend) SuggestExitNode() (response apitype.ExitNodeSuggestionResponse, err error) {
	if !buildfeatures.HasUseExitNode {
		return response, feature.ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.suggestExitNodeLocked()
}

// getAllowedSuggestions returns a set of exit nodes permitted by the most recent
// [pkey.AllowedSuggestedExitNodes] value. Callers must not mutate the returned set.
func (b *LocalBackend) getAllowedSuggestions() set.Set[tailcfg.StableNodeID] {
	b.allowedSuggestedExitNodesMu.Lock()
	defer b.allowedSuggestedExitNodesMu.Unlock()
	return b.allowedSuggestedExitNodes
}

// refreshAllowedSuggestions rebuilds the set of permitted exit nodes
// from the current [pkey.AllowedSuggestedExitNodes] value.
func (b *LocalBackend) refreshAllowedSuggestions() {
	if !buildfeatures.HasUseExitNode {
		return
	}
	b.allowedSuggestedExitNodesMu.Lock()
	defer b.allowedSuggestedExitNodesMu.Unlock()
	b.allowedSuggestedExitNodes = fillAllowedSuggestions(b.polc)
}

// selectRegionFunc returns a DERP region from the slice of candidate regions.
// The value is returned, not the slice index.
type selectRegionFunc func(views.Slice[int]) int

// selectNodeFunc returns a node from the slice of candidate nodes. The last
// selected node is provided for when that information is needed to make a better
// choice.
type selectNodeFunc func(nodes views.Slice[tailcfg.NodeView], last tailcfg.StableNodeID) tailcfg.NodeView

func fillAllowedSuggestions(polc policyclient.Client) set.Set[tailcfg.StableNodeID] {
	nodes, err := polc.GetStringArray(pkey.AllowedSuggestedExitNodes, nil)
	if err != nil {
		log.Printf("fillAllowedSuggestions: unable to look up %q policy: %v", pkey.AllowedSuggestedExitNodes, err)
		return nil
	}
	if nodes == nil {
		return nil
	}
	s := make(set.Set[tailcfg.StableNodeID], len(nodes))
	for _, n := range nodes {
		s.Add(tailcfg.StableNodeID(n))
	}
	return s
}

// suggestExitNode returns a suggestion for reasonably good exit node based on
// the current netmap and the previous suggestion.
func suggestExitNode(report *netcheck.Report, nb *nodeBackend, prevSuggestion tailcfg.StableNodeID, selectRegion selectRegionFunc, selectNode selectNodeFunc, allowList set.Set[tailcfg.StableNodeID]) (res apitype.ExitNodeSuggestionResponse, err error) {
	switch {
	case nb.SelfHasCap(tailcfg.NodeAttrTrafficSteering):
		// The traffic-steering feature flag is enabled on this tailnet.
		return suggestExitNodeUsingTrafficSteering(nb, allowList)
	default:
		return suggestExitNodeUsingDERP(report, nb, prevSuggestion, selectRegion, selectNode, allowList)
	}
}

// suggestExitNodeUsingDERP is the classic algorithm used to suggest exit nodes,
// before traffic steering was implemented. This handles the plain failover
// case, in addition to the optional Regional Routing.
//
// It computes a suggestion based on the current netmap and last netcheck
// report. If there are multiple equally good options, one is selected at
// random, so the result is not stable. To be eligible for consideration, the
// peer must have NodeAttrSuggestExitNode in its CapMap.
//
// Currently, peers with a DERP home are preferred over those without (typically
// this means Mullvad). Peers are selected based on having a DERP home that is
// the lowest latency to this device. For peers without a DERP home, we look for
// geographic proximity to this device's DERP home.
func suggestExitNodeUsingDERP(report *netcheck.Report, nb *nodeBackend, prevSuggestion tailcfg.StableNodeID, selectRegion selectRegionFunc, selectNode selectNodeFunc, allowList set.Set[tailcfg.StableNodeID]) (res apitype.ExitNodeSuggestionResponse, err error) {
	// TODO(sfllaw): Context needs to be plumbed down here to support
	// reachability testing.
	ctx := context.TODO()

	netMap := nb.NetMap()
	if report == nil || report.PreferredDERP == 0 || netMap == nil || netMap.DERPMap == nil {
		return res, ErrNoPreferredDERP
	}
	// Use [nodeBackend.AppendMatchingPeers] instead of the netmap directly,
	// since the netmap doesn't include delta updates (e.g., home DERP or Online
	// status changes) from the control plane since the last full update.
	candidates := nb.AppendMatchingPeers(nil, func(peer tailcfg.NodeView) bool {
		if !peer.Valid() || !nb.PeerIsReachable(ctx, peer) {
			return false
		}
		if allowList != nil && !allowList.Contains(peer.StableID()) {
			return false
		}
		return peer.CapMap().Contains(tailcfg.NodeAttrSuggestExitNode) && tsaddr.ContainsExitRoutes(peer.AllowedIPs())
	})
	if len(candidates) == 0 {
		return res, nil
	}
	if len(candidates) == 1 {
		peer := candidates[0]
		if hi := peer.Hostinfo(); hi.Valid() {
			if loc := hi.Location(); loc.Valid() {
				res.Location = loc
			}
		}
		res.ID = peer.StableID()
		res.Name = peer.Name()
		return res, nil
	}

	candidatesByRegion := make(map[int][]tailcfg.NodeView, len(netMap.DERPMap.Regions))
	preferredDERP, ok := netMap.DERPMap.Regions[report.PreferredDERP]
	if !ok {
		return res, ErrNoPreferredDERP
	}
	var minDistance float64 = math.MaxFloat64
	type nodeDistance struct {
		nv       tailcfg.NodeView
		distance float64 // in meters, approximately
	}
	distances := make([]nodeDistance, 0, len(candidates))
	for _, c := range candidates {
		if regionID := c.HomeDERP(); regionID != 0 {
			candidatesByRegion[regionID] = append(candidatesByRegion[regionID], c)
			continue
		}
		if len(candidatesByRegion) > 0 {
			// Since a candidate exists that does have a DERP home, skip this candidate. We never select
			// a candidate without a DERP home if there is a candidate available with a DERP home.
			continue
		}
		// This candidate does not have a DERP home.
		// Use geographic distance from our DERP home to estimate how good this candidate is.
		hi := c.Hostinfo()
		if !hi.Valid() {
			continue
		}
		loc := hi.Location()
		if !loc.Valid() {
			continue
		}
		distance := longLatDistance(preferredDERP.Latitude, preferredDERP.Longitude, loc.Latitude(), loc.Longitude())
		if distance < minDistance {
			minDistance = distance
		}
		distances = append(distances, nodeDistance{nv: c, distance: distance})
	}
	// First, try to select an exit node that has the closest DERP home, based on lastReport's DERP latency.
	// If there are no latency values, it returns an arbitrary region
	if len(candidatesByRegion) > 0 {
		minRegion := minLatencyDERPRegion(slicesx.MapKeys(candidatesByRegion), report)
		if minRegion == 0 {
			minRegion = selectRegion(views.SliceOf(slicesx.MapKeys(candidatesByRegion)))
		}
		regionCandidates, ok := candidatesByRegion[minRegion]
		if !ok {
			return res, errors.New("no candidates in expected region: this is a bug")
		}
		chosen := selectNode(views.SliceOf(regionCandidates), prevSuggestion)
		res.ID = chosen.StableID()
		res.Name = chosen.Name()
		if hi := chosen.Hostinfo(); hi.Valid() {
			if loc := hi.Location(); loc.Valid() {
				res.Location = loc
			}
		}
		return res, nil
	}
	// None of the candidates have a DERP home, so proceed to select based on geographical distance from our preferred DERP region.

	// allowanceMeters is the extra distance that will be permitted when considering peers. By this point, there
	// are multiple approximations taking place (DERP location standing in for this device's location, the peer's
	// location may only be city granularity, the distance algorithm assumes a spherical planet, etc.) so it is
	// reasonable to consider peers that are similar distances. Those peers are good enough to be within
	// measurement error. 100km corresponds to approximately 1ms of additional round trip light
	// propagation delay in a fiber optic cable and seems like a reasonable heuristic. It may be adjusted in
	// future.
	const allowanceMeters = 100000
	pickFrom := make([]tailcfg.NodeView, 0, len(distances))
	for _, candidate := range distances {
		if candidate.nv.Valid() && candidate.distance <= minDistance+allowanceMeters {
			pickFrom = append(pickFrom, candidate.nv)
		}
	}
	bestCandidates := pickWeighted(pickFrom)
	chosen := selectNode(views.SliceOf(bestCandidates), prevSuggestion)
	if !chosen.Valid() {
		return res, errors.New("chosen candidate invalid: this is a bug")
	}
	res.ID = chosen.StableID()
	res.Name = chosen.Name()
	if hi := chosen.Hostinfo(); hi.Valid() {
		if loc := hi.Location(); loc.Valid() {
			res.Location = loc
		}
	}
	return res, nil
}

var ErrNoNetMap = errors.New("no network map, try again later")

// suggestExitNodeUsingTrafficSteering uses traffic steering priority scores to
// pick one of the best exit nodes. These priorities are provided by Control in
// the node’s [tailcfg.Location]. To be eligible for consideration, the node
// must have NodeAttrSuggestExitNode in its CapMap.
func suggestExitNodeUsingTrafficSteering(nb *nodeBackend, allowed set.Set[tailcfg.StableNodeID]) (apitype.ExitNodeSuggestionResponse, error) {
	// TODO(sfllaw): Context needs to be plumbed down here to support
	// reachability testing.
	ctx := context.TODO()

	nm := nb.NetMap()
	if nm == nil {
		return apitype.ExitNodeSuggestionResponse{}, ErrNoNetMap
	}

	self := nb.Self()
	if !self.Valid() {
		return apitype.ExitNodeSuggestionResponse{}, ErrNoNetMap
	}

	if !nb.SelfHasCap(tailcfg.NodeAttrTrafficSteering) {
		panic("missing traffic-steering capability")
	}

	nodes := nb.AppendMatchingPeers(nil, func(p tailcfg.NodeView) bool {
		if !p.Valid() {
			return false
		}
		if !nb.PeerIsReachable(ctx, p) {
			return false
		}
		if allowed != nil && !allowed.Contains(p.StableID()) {
			return false
		}
		if !p.CapMap().Contains(tailcfg.NodeAttrSuggestExitNode) {
			return false
		}
		if !tsaddr.ContainsExitRoutes(p.AllowedIPs()) {
			return false
		}
		return true
	})

	scores := make(map[tailcfg.NodeID]int, len(nodes))
	score := func(n tailcfg.NodeView) int {
		id := n.ID()
		s, ok := scores[id]
		if !ok {
			s = 0 // score of zero means incomparable
			if hi := n.Hostinfo(); hi.Valid() {
				if loc := hi.Location(); loc.Valid() {
					s = loc.Priority()
				}
			}
			scores[id] = s
		}
		return s
	}
	rdvHash := makeRendezvousHasher(self.ID())

	var pick tailcfg.NodeView
	if len(nodes) == 1 {
		pick = nodes[0]
	}
	if len(nodes) > 1 {
		// Find the highest scoring exit nodes.
		slices.SortFunc(nodes, func(a, b tailcfg.NodeView) int {
			c := cmp.Compare(score(b), score(a)) // Highest score first.
			if c == 0 {
				// Rendezvous hashing for reliably picking the
				// same node from a list: tailscale/tailscale#16551.
				return cmp.Compare(rdvHash(b.ID()), rdvHash(a.ID()))
			}
			return c
		})

		// TODO(sfllaw): add a temperature knob so that this client has
		// a chance of picking the next best option.
		pick = nodes[0]
	}

	if !pick.Valid() {
		return apitype.ExitNodeSuggestionResponse{}, nil
	}
	res := apitype.ExitNodeSuggestionResponse{
		ID:   pick.StableID(),
		Name: pick.Name(),
	}
	if hi := pick.Hostinfo(); hi.Valid() {
		if loc := hi.Location(); loc.Valid() {
			res.Location = loc
		}
	}
	return res, nil
}

// pickWeighted chooses the node with highest priority given a list of mullvad nodes.
func pickWeighted(candidates []tailcfg.NodeView) []tailcfg.NodeView {
	maxWeight := 0
	best := make([]tailcfg.NodeView, 0, 1)
	for _, c := range candidates {
		hi := c.Hostinfo()
		if !hi.Valid() {
			continue
		}
		loc := hi.Location()
		if !loc.Valid() || loc.Priority() < maxWeight {
			continue
		}
		if maxWeight != loc.Priority() {
			best = best[:0]
		}
		maxWeight = loc.Priority()
		best = append(best, c)
	}
	return best
}

// randomRegion is a selectRegionFunc that selects a uniformly random region.
func randomRegion(regions views.Slice[int]) int {
	return regions.At(rand.IntN(regions.Len()))
}

// randomNode is a selectNodeFunc that will return the node matching prefer if
// present, otherwise a uniformly random node will be selected.
func randomNode(nodes views.Slice[tailcfg.NodeView], prefer tailcfg.StableNodeID) tailcfg.NodeView {
	if !prefer.IsZero() {
		for i := range nodes.Len() {
			nv := nodes.At(i)
			if nv.StableID() == prefer {
				return nv
			}
		}
	}

	return nodes.At(rand.IntN(nodes.Len()))
}

// minLatencyDERPRegion returns the region with the lowest latency value given the last netcheck report.
// If there are no latency values, it returns 0.
func minLatencyDERPRegion(regions []int, report *netcheck.Report) int {
	min := slices.MinFunc(regions, func(i, j int) int {
		const largeDuration time.Duration = math.MaxInt64
		iLatency, ok := report.RegionLatency[i]
		if !ok {
			iLatency = largeDuration
		}
		jLatency, ok := report.RegionLatency[j]
		if !ok {
			jLatency = largeDuration
		}
		if c := cmp.Compare(iLatency, jLatency); c != 0 {
			return c
		}
		return cmp.Compare(i, j)
	})
	latency, ok := report.RegionLatency[min]
	if !ok || latency == 0 {
		return 0
	} else {
		return min
	}
}

// longLatDistance returns an estimated distance given the geographic coordinates of two locations, in degrees.
// The coordinates are separated into four separate float64 values.
// Value is returned in meters.
func longLatDistance(fromLat, fromLong, toLat, toLong float64) float64 {
	const toRadians = math.Pi / 180
	diffLat := (fromLat - toLat) * toRadians
	diffLong := (fromLong - toLong) * toRadians
	lat1 := fromLat * toRadians
	lat2 := toLat * toRadians
	a := math.Pow(math.Sin(diffLat/2), 2) + math.Cos(lat1)*math.Cos(lat2)*math.Pow(math.Sin(diffLong/2), 2)
	const earthRadiusMeters = 6371000
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusMeters * c
}

// makeRendezvousHasher returns a function that hashes a node ID to a uint64.
// https://en.wikipedia.org/wiki/Rendezvous_hashing
func makeRendezvousHasher(seed tailcfg.NodeID) func(tailcfg.NodeID) uint64 {
	en := binary.BigEndian
	return func(n tailcfg.NodeID) uint64 {
		var b [16]byte
		en.PutUint64(b[:], uint64(seed))
		en.PutUint64(b[8:], uint64(n))
		v := sha256.Sum256(b[:])
		return en.Uint64(v[:])
	}
}

const (
	// unresolvedExitNodeID is a special [tailcfg.StableNodeID] value
	// used as an exit node ID to install a blackhole route, preventing
	// accidental non-exit-node usage until the [ipn.ExitNodeExpression]
	// is evaluated and an actual exit node is selected.
	//
	// We use "auto:any" for compatibility with older, pre-[ipn.ExitNodeExpression]
	// clients that have been using "auto:any" for this purpose for a long time.
	unresolvedExitNodeID tailcfg.StableNodeID = "auto:any"
)

func isAllowedAutoExitNodeID(polc policyclient.Client, exitNodeID tailcfg.StableNodeID) bool {
	if exitNodeID == "" {
		return false // an exit node is required
	}
	if nodes, _ := polc.GetStringArray(pkey.AllowedSuggestedExitNodes, nil); nodes != nil {
		return slices.Contains(nodes, string(exitNodeID))
	}
	return true // no policy configured; allow all exit nodes
}

// srcIPHasCapForFilter is called by the packet filter when evaluating firewall
// rules that require a source IP to have a certain node capability.
//
// TODO(bradfitz): optimize this later if/when it matters.
// TODO(nickkhyl): move this into [nodeBackend] along with [LocalBackend.updateFilterLocked].
func (b *LocalBackend) srcIPHasCapForFilter(srcIP netip.Addr, cap tailcfg.NodeCapability) bool {
	if cap == "" {
		// Shouldn't happen, but just in case.
		// But the empty cap also shouldn't be found in Node.CapMap.
		return false
	}
	cn := b.currentNode()
	nodeID, ok := cn.NodeByAddr(srcIP)
	if !ok {
		return false
	}
	n, ok := cn.NodeByID(nodeID)
	if !ok {
		return false
	}
	return n.HasCap(cap)
}

// maybeUsernameOf returns the actor's username if the actor
// is non-nil and its username can be resolved.
func maybeUsernameOf(actor ipnauth.Actor) string {
	var username string
	if actor != nil {
		username, _ = actor.Username()
	}
	return username
}

func (b *LocalBackend) vipServiceHash(services []*tailcfg.VIPService) string {
	if len(services) == 0 {
		return ""
	}
	buf, err := json.Marshal(services)
	if err != nil {
		b.logf("vipServiceHashLocked: %v", err)
		return ""
	}
	hash := sha256.Sum256(buf)
	return hex.EncodeToString(hash[:])
}

var (
	metricCurrentWatchIPNBus = clientmetric.NewGauge("localbackend_current_watch_ipn_bus")
)

func (b *LocalBackend) stateEncrypted() opt.Bool {
	switch runtime.GOOS {
	case "android", "ios":
		return opt.NewBool(true)
	case "darwin":
		switch {
		case version.IsMacAppStore():
			return opt.NewBool(true)
		case version.IsMacSysExt():
			sp, _ := b.polc.GetBoolean(pkey.EncryptState, true)
			return opt.NewBool(sp)
		default:
			// Probably self-compiled tailscaled, we don't use the Keychain
			// there.
			return opt.NewBool(false)
		}
	default:
		_, ok := b.store.(ipn.EncryptedStateStore)
		return opt.NewBool(ok)
	}
}
