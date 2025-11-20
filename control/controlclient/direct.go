// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"go4.org/mem"
	"tailscale.com/control/controlknobs"
	"tailscale.com/control/ts2021"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/logtail"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netutil"
	"tailscale.com/net/netx"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tsdial"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
	"tailscale.com/types/ptr"
	"tailscale.com/types/tkatype"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/singleflight"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/testenv"
	"tailscale.com/util/zstdframe"
)

// Direct is the client that connects to a tailcontrol server for a node.
type Direct struct {
	httpc                 *http.Client // HTTP client used to do TLS requests to control (just https://controlplane.tailscale.com/key?v=123)
	interceptedDial       *atomic.Bool // if non-nil, pointer to bool whether ScreenTime intercepted our dial
	dialer                *tsdial.Dialer
	dnsCache              *dnscache.Resolver
	controlKnobs          *controlknobs.Knobs // always non-nil
	serverURL             string              // URL of the tailcontrol server
	clock                 tstime.Clock
	logf                  logger.Logf
	netMon                *netmon.Monitor // non-nil
	health                *health.Tracker
	busClient             *eventbus.Client
	clientVersionPub      *eventbus.Publisher[tailcfg.ClientVersion]
	autoUpdatePub         *eventbus.Publisher[AutoUpdate]
	controlTimePub        *eventbus.Publisher[ControlTime]
	getMachinePrivKey     func() (key.MachinePrivate, error)
	debugFlags            []string
	skipIPForwardingCheck bool
	pinger                Pinger
	popBrowser            func(url string)    // or nil
	polc                  policyclient.Client // always non-nil
	c2nHandler            http.Handler        // or nil
	panicOnUse            bool                // if true, panic if client is used (for testing)
	closedCtx             context.Context     // alive until Direct.Close is called
	closeCtx              context.CancelFunc  // cancels closedCtx

	dialPlan ControlDialPlanner // can be nil

	mu              syncs.Mutex       // mutex guards the following fields
	serverLegacyKey key.MachinePublic // original ("legacy") nacl crypto_box-based public key; only used for signRegisterRequest on Windows now
	serverNoiseKey  key.MachinePublic
	discoPubKey     key.DiscoPublic // protected by mu; can be updated via [SetDiscoPublicKey]

	sfGroup     singleflight.Group[struct{}, *ts2021.Client] // protects noiseClient creation.
	noiseClient *ts2021.Client                               // also protected by mu

	persist                 persist.PersistView
	authKey                 string
	tryingNewKey            key.NodePrivate
	expiry                  time.Time         // or zero value if none/unknown
	hostinfo                *tailcfg.Hostinfo // always non-nil
	netinfo                 *tailcfg.NetInfo
	endpoints               []tailcfg.Endpoint
	tkaHead                 string
	lastPingURL             string // last PingRequest.URL received, for dup suppression
	connectionHandleForTest string // sent in MapRequest.ConnectionHandleForTest

	controlClientID int64 // Random ID used to differentiate clients for consumers of messages.
}

// Observer is implemented by users of the control client (such as LocalBackend)
// to get notified of changes in the control client's status.
//
// If an implementation of Observer also implements [NetmapDeltaUpdater], they get
// delta updates as well as full netmap updates.
type Observer interface {
	// SetControlClientStatus is called when the client has a new status to
	// report. The Client is provided to allow the Observer to track which
	// Client is reporting the status, allowing it to ignore stale status
	// reports from previous Clients.
	SetControlClientStatus(Client, Status)
}

type Options struct {
	Persist              persist.Persist                    // initial persistent data
	GetMachinePrivateKey func() (key.MachinePrivate, error) // returns the machine key to use
	ServerURL            string                             // URL of the tailcontrol server
	AuthKey              string                             // optional node auth key for auto registration
	Clock                tstime.Clock
	Hostinfo             *tailcfg.Hostinfo // non-nil passes ownership, nil means to use default using os.Hostname, etc
	DiscoPublicKey       key.DiscoPublic
	PolicyClient         policyclient.Client // or nil for none
	Logf                 logger.Logf
	HTTPTestClient       *http.Client // optional HTTP client to use (for tests only)
	NoiseTestClient      *http.Client // optional HTTP client to use for noise RPCs (tests only)
	DebugFlags           []string     // debug settings to send to control
	HealthTracker        *health.Tracker
	PopBrowserURL        func(url string)    // optional func to open browser
	Dialer               *tsdial.Dialer      // non-nil
	C2NHandler           http.Handler        // or nil
	ControlKnobs         *controlknobs.Knobs // or nil to ignore
	Bus                  *eventbus.Bus       // non-nil, for setting up publishers

	SkipStartForTests bool // if true, don't call [Auto.Start] to avoid any background goroutines (for tests only)

	// StartPaused indicates whether the client should start in a paused state
	// where it doesn't do network requests. This primarily exists for testing
	// but not necessarily "go test" tests, so it isn't restricted to only
	// being used in tests.
	StartPaused bool

	// Observer is called when there's a change in status to report
	// from the control client.
	// If nil, no status updates are reported.
	Observer Observer

	// SkipIPForwardingCheck declares that the host's IP
	// forwarding works and should not be double-checked by the
	// controlclient package.
	SkipIPForwardingCheck bool

	// Pinger optionally specifies the Pinger to use to satisfy
	// MapResponse.PingRequest queries from the control plane.
	// If nil, PingRequest queries are not answered.
	Pinger Pinger

	// DialPlan contains and stores a previous dial plan that we received
	// from the control server; if nil, we fall back to using DNS.
	//
	// If we receive a new DialPlan from the server, this value will be
	// updated.
	DialPlan ControlDialPlanner

	// Shutdown is an optional function that will be called before client shutdown is
	// attempted. It is used to allow the client to clean up any resources or complete any
	// tasks that are dependent on a live client.
	Shutdown func()
}

// ControlDialPlanner is the interface optionally supplied when creating a
// control client to control exactly how TCP connections to the control plane
// are dialed.
//
// It is usually implemented by an atomic.Pointer.
type ControlDialPlanner interface {
	// Load returns the current plan for how to connect to control.
	//
	// The returned plan can be nil. If so, connections should be made by
	// resolving the control URL using DNS.
	Load() *tailcfg.ControlDialPlan

	// Store updates the dial plan with new directions from the control
	// server.
	//
	// The dial plan can span multiple connections to the control server.
	// That is, a dial plan received when connected over Wi-Fi is still
	// valid for a subsequent connection over LTE after a network switch.
	Store(*tailcfg.ControlDialPlan)
}

// Pinger is the LocalBackend.Ping method.
type Pinger interface {
	// Ping is a request to do a ping with the peer handling the given IP.
	Ping(ctx context.Context, ip netip.Addr, pingType tailcfg.PingType, size int) (*ipnstate.PingResult, error)
}

// NetmapUpdater is the interface needed by the controlclient to enact change in
// the world as a function of updates received from the network.
type NetmapUpdater interface {
	UpdateFullNetmap(*netmap.NetworkMap)

	// TODO(bradfitz): add methods to do fine-grained updates, mutating just
	// parts of peers, without implementations of NetmapUpdater needing to do
	// the diff themselves between the previous full & next full network maps.
}

// NetmapDeltaUpdater is an optional interface that can be implemented by
// NetmapUpdater implementations to receive delta updates from the controlclient
// rather than just full updates.
type NetmapDeltaUpdater interface {
	// UpdateNetmapDelta is called with discrete changes to the network map.
	//
	// The ok result is whether the implementation was able to apply the
	// mutations. It might return false if its internal state doesn't
	// support applying them or a NetmapUpdater it's wrapping doesn't
	// implement the NetmapDeltaUpdater optional method.
	UpdateNetmapDelta([]netmap.NodeMutation) (ok bool)
}

var nextControlClientID atomic.Int64

// NewDirect returns a new Direct client.
func NewDirect(opts Options) (*Direct, error) {
	if opts.ServerURL == "" {
		return nil, errors.New("controlclient.New: no server URL specified")
	}
	if opts.GetMachinePrivateKey == nil {
		return nil, errors.New("controlclient.New: no GetMachinePrivateKey specified")
	}
	if opts.Dialer == nil {
		if testenv.InTest() {
			panic("no Dialer")
		}
		return nil, errors.New("controlclient.New: no Dialer specified")
	}
	netMon := opts.Dialer.NetMon()
	if netMon == nil {
		if testenv.InTest() {
			panic("no NetMon in Dialer")
		}
		return nil, errors.New("controlclient.New: Dialer has nil NetMon")
	}
	if opts.ControlKnobs == nil {
		opts.ControlKnobs = &controlknobs.Knobs{}
	}
	opts.ServerURL = strings.TrimRight(opts.ServerURL, "/")
	if opts.Clock == nil {
		opts.Clock = tstime.StdClock{}
	}
	if opts.Logf == nil {
		// TODO(apenwarr): remove this default and fail instead.
		// TODO(bradfitz): ... but then it shouldn't be in Options.
		opts.Logf = log.Printf
	}

	dnsCache := &dnscache.Resolver{
		Forward:          dnscache.Get().Forward, // use default cache's forwarder
		UseLastGood:      true,
		LookupIPFallback: dnsfallback.MakeLookupFunc(opts.Logf, netMon),
		Logf:             opts.Logf,
	}

	httpc := opts.HTTPTestClient
	if httpc == nil && runtime.GOOS == "js" {
		// In js/wasm, net/http.Transport (as of Go 1.18) will
		// only use the browser's Fetch API if you're using
		// the DefaultClient (or a client without dial hooks
		// etc set).
		httpc = http.DefaultClient
	}
	var interceptedDial *atomic.Bool
	if httpc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if buildfeatures.HasUseProxy {
			tr.Proxy = feature.HookProxyFromEnvironment.GetOrNil()
			if f, ok := feature.HookProxySetTransportGetProxyConnectHeader.GetOk(); ok {
				f(tr)
			}
		}
		tr.TLSClientConfig = tlsdial.Config(opts.HealthTracker, tr.TLSClientConfig)
		var dialFunc netx.DialFunc
		dialFunc, interceptedDial = makeScreenTimeDetectingDialFunc(opts.Dialer.SystemDial)
		tr.DialContext = dnscache.Dialer(dialFunc, dnsCache)
		tr.DialTLSContext = dnscache.TLSDialer(dialFunc, dnsCache, tr.TLSClientConfig)
		tr.ForceAttemptHTTP2 = true
		// Disable implicit gzip compression; the various
		// handlers (register, map, set-dns, etc) do their own
		// zstd compression per naclbox.
		tr.DisableCompression = true

		httpc = &http.Client{Transport: tr}
	}

	c := &Direct{
		httpc:                 httpc,
		interceptedDial:       interceptedDial,
		controlKnobs:          opts.ControlKnobs,
		getMachinePrivKey:     opts.GetMachinePrivateKey,
		serverURL:             opts.ServerURL,
		clock:                 opts.Clock,
		logf:                  opts.Logf,
		persist:               opts.Persist.View(),
		authKey:               opts.AuthKey,
		debugFlags:            opts.DebugFlags,
		netMon:                netMon,
		health:                opts.HealthTracker,
		skipIPForwardingCheck: opts.SkipIPForwardingCheck,
		pinger:                opts.Pinger,
		polc:                  cmp.Or(opts.PolicyClient, policyclient.Client(policyclient.NoPolicyClient{})),
		popBrowser:            opts.PopBrowserURL,
		c2nHandler:            opts.C2NHandler,
		dialer:                opts.Dialer,
		dnsCache:              dnsCache,
		dialPlan:              opts.DialPlan,
	}
	c.discoPubKey = opts.DiscoPublicKey
	c.closedCtx, c.closeCtx = context.WithCancel(context.Background())

	c.controlClientID = nextControlClientID.Add(1)

	if opts.Hostinfo == nil {
		c.SetHostinfo(hostinfo.New())
	} else {
		c.SetHostinfo(opts.Hostinfo)
		if ni := opts.Hostinfo.NetInfo; ni != nil {
			c.SetNetInfo(ni)
		}
	}
	if opts.NoiseTestClient != nil {
		c.noiseClient = &ts2021.Client{
			Client: opts.NoiseTestClient,
		}
		c.serverNoiseKey = key.NewMachine().Public() // prevent early error before hitting test client
	}
	if strings.Contains(opts.ServerURL, "controlplane.tailscale.com") && envknob.Bool("TS_PANIC_IF_HIT_MAIN_CONTROL") {
		c.panicOnUse = true
	}

	c.busClient = opts.Bus.Client("controlClient.direct")
	c.clientVersionPub = eventbus.Publish[tailcfg.ClientVersion](c.busClient)
	c.autoUpdatePub = eventbus.Publish[AutoUpdate](c.busClient)
	c.controlTimePub = eventbus.Publish[ControlTime](c.busClient)

	return c, nil
}

// Close closes the underlying Noise connection(s).
func (c *Direct) Close() error {
	c.closeCtx()

	c.mu.Lock()
	defer c.mu.Unlock()
	c.busClient.Close()
	if c.noiseClient != nil {
		if err := c.noiseClient.Close(); err != nil {
			return err
		}
	}
	c.noiseClient = nil
	c.httpc.CloseIdleConnections()
	return nil
}

// SetHostinfo clones the provided Hostinfo and remembers it for the
// next update. It reports whether the Hostinfo has changed.
func (c *Direct) SetHostinfo(hi *tailcfg.Hostinfo) bool {
	if hi == nil {
		panic("nil Hostinfo")
	}
	hi = ptr.To(*hi)
	hi.NetInfo = nil
	c.mu.Lock()
	defer c.mu.Unlock()

	if hi.Equal(c.hostinfo) {
		return false
	}
	c.hostinfo = hi.Clone()
	j, _ := json.Marshal(c.hostinfo)
	c.logf("[v1] HostInfo: %s", j)
	return true
}

// SetNetInfo clones the provided NetInfo and remembers it for the
// next update. It reports whether the NetInfo has changed.
func (c *Direct) SetNetInfo(ni *tailcfg.NetInfo) bool {
	if ni == nil {
		panic("nil NetInfo")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if reflect.DeepEqual(ni, c.netinfo) {
		return false
	}
	c.netinfo = ni.Clone()
	c.logf("NetInfo: %v", ni)
	return true
}

// SetTKAHead stores a new TKA head value for next update.
// It reports whether the TKA head changed.
func (c *Direct) SetTKAHead(tkaHead string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if tkaHead == c.tkaHead {
		return false
	}

	c.tkaHead = tkaHead
	c.logf("tkaHead: %v", tkaHead)
	return true
}

// SetConnectionHandleForTest stores a new MapRequest.ConnectionHandleForTest
// value for the next update.
func (c *Direct) SetConnectionHandleForTest(handle string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connectionHandleForTest = handle
}

func (c *Direct) GetPersist() persist.PersistView {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.persist
}

func (c *Direct) TryLogout(ctx context.Context) error {
	c.logf("[v1] direct.TryLogout()")

	mustRegen, newURL, _, err := c.doLogin(ctx, loginOpt{Logout: true})
	c.logf("[v1] TryLogout control response: mustRegen=%v, newURL=%v, err=%v", mustRegen, newURL, err)

	c.mu.Lock()
	c.persist = new(persist.Persist).View()
	c.mu.Unlock()

	return err
}

func (c *Direct) TryLogin(ctx context.Context, flags LoginFlags) (url string, err error) {
	if strings.Contains(c.serverURL, "controlplane.tailscale.com") && envknob.Bool("TS_PANIC_IF_HIT_MAIN_CONTROL") {
		panic(fmt.Sprintf("[unexpected] controlclient: TryLogin called on %s; tainted=%v", c.serverURL, c.panicOnUse))
	}
	c.logf("[v1] direct.TryLogin(flags=%v)", flags)
	return c.doLoginOrRegen(ctx, loginOpt{Flags: flags})
}

// WaitLoginURL sits in a long poll waiting for the user to authenticate at url.
//
// On success, newURL and err will both be nil.
func (c *Direct) WaitLoginURL(ctx context.Context, url string) (newURL string, err error) {
	c.logf("[v1] direct.WaitLoginURL")
	return c.doLoginOrRegen(ctx, loginOpt{URL: url})
}

func (c *Direct) doLoginOrRegen(ctx context.Context, opt loginOpt) (newURL string, err error) {
	mustRegen, url, oldNodeKeySignature, err := c.doLogin(ctx, opt)
	if err != nil {
		return url, err
	}
	if mustRegen {
		opt.Regen = true
		opt.OldNodeKeySignature = oldNodeKeySignature
		_, url, _, err = c.doLogin(ctx, opt)
	}
	return url, err
}

// SetExpirySooner attempts to shorten the expiry to the specified time.
func (c *Direct) SetExpirySooner(ctx context.Context, expiry time.Time) error {
	c.logf("[v1] direct.SetExpirySooner()")

	newURL, err := c.doLoginOrRegen(ctx, loginOpt{Expiry: &expiry})
	c.logf("[v1] SetExpirySooner control response: newURL=%v, err=%v", newURL, err)

	return err
}

type loginOpt struct {
	Flags  LoginFlags
	Regen  bool // generate a new nodekey, can be overridden in doLogin
	URL    string
	Logout bool // set the expiry to the far past, expiring the node
	// Expiry, if non-nil, attempts to set the node expiry to the
	// specified time and cannot be used to extend the expiry.
	// It is ignored if Logout is set since Logout works by setting a
	// expiry time in the far past.
	Expiry *time.Time

	// OldNodeKeySignature indicates the former NodeKeySignature
	// that must be resigned for the new node-key.
	OldNodeKeySignature tkatype.MarshaledSignature
}

// hostInfoLocked returns a Clone of c.hostinfo and c.netinfo.
// It must only be called with c.mu held.
func (c *Direct) hostInfoLocked() *tailcfg.Hostinfo {
	hi := c.hostinfo.Clone()
	hi.NetInfo = c.netinfo.Clone()
	return hi
}

var macOSScreenTime = health.Register(&health.Warnable{
	Code:     "macos-screen-time-controlclient",
	Severity: health.SeverityHigh,
	Title:    "Tailscale blocked by Screen Time",
	Text: func(args health.Args) string {
		return "macOS Screen Time seems to be blocking Tailscale. Try disabling Screen Time in System Settings > Screen Time > Content & Privacy > Access to Web Content."
	},
	ImpactsConnectivity: true,
})

func (c *Direct) doLogin(ctx context.Context, opt loginOpt) (mustRegen bool, newURL string, nks tkatype.MarshaledSignature, err error) {
	if c.panicOnUse {
		panic("tainted client")
	}
	c.mu.Lock()
	persist := c.persist.AsStruct()
	tryingNewKey := c.tryingNewKey
	serverKey := c.serverLegacyKey
	serverNoiseKey := c.serverNoiseKey
	authKey, isWrapped, wrappedSig, wrappedKey := tka.DecodeWrappedAuthkey(c.authKey, c.logf)
	hi := c.hostInfoLocked()
	backendLogID := hi.BackendLogID
	expired := !c.expiry.IsZero() && c.expiry.Before(c.clock.Now())
	c.mu.Unlock()

	machinePrivKey, err := c.getMachinePrivKey()
	if err != nil {
		return false, "", nil, fmt.Errorf("getMachinePrivKey: %w", err)
	}
	if machinePrivKey.IsZero() {
		return false, "", nil, errors.New("getMachinePrivKey returned zero key")
	}

	regen := opt.Regen
	if opt.Logout {
		c.logf("logging out...")
	} else {
		if expired {
			c.logf("Old key expired -> regen=true")
			if f, ok := feature.HookSystemdStatus.GetOk(); ok {
				f("key expired; run 'tailscale up' to authenticate")
			}
			regen = true
		}
		if (opt.Flags & LoginInteractive) != 0 {
			c.logf("LoginInteractive -> regen=true")
			regen = true
		}
	}

	c.logf("doLogin(regen=%v, hasUrl=%v)", regen, opt.URL != "")
	if serverKey.IsZero() {
		keys, err := loadServerPubKeys(ctx, c.httpc, c.serverURL)
		if err != nil && c.interceptedDial != nil && c.interceptedDial.Load() {
			c.health.SetUnhealthy(macOSScreenTime, nil)
		} else {
			c.health.SetHealthy(macOSScreenTime)
		}
		if err != nil {
			return regen, opt.URL, nil, err
		}
		c.logf("control server key from %s: ts2021=%s, legacy=%v", c.serverURL, keys.PublicKey.ShortString(), keys.LegacyPublicKey.ShortString())

		c.mu.Lock()
		c.serverLegacyKey = keys.LegacyPublicKey
		c.serverNoiseKey = keys.PublicKey
		c.mu.Unlock()
		serverKey = keys.LegacyPublicKey
		serverNoiseKey = keys.PublicKey

		// Proactively shut down our TLS TCP connection.
		// We're not going to need it and it's nicer to the
		// server.
		c.httpc.CloseIdleConnections()
	}

	if serverNoiseKey.IsZero() {
		return false, "", nil, errors.New("control server is too old; no noise key")
	}

	var oldNodeKey key.NodePublic
	switch {
	case opt.Logout:
		tryingNewKey = persist.PrivateNodeKey
	case opt.URL != "":
		// Nothing.
	case regen || persist.PrivateNodeKey.IsZero():
		c.logf("Generating a new nodekey.")
		persist.OldPrivateNodeKey = persist.PrivateNodeKey
		tryingNewKey = key.NewNode()
	default:
		// Try refreshing the current key first
		tryingNewKey = persist.PrivateNodeKey
	}
	if !persist.OldPrivateNodeKey.IsZero() {
		oldNodeKey = persist.OldPrivateNodeKey.Public()
	}
	if persist.NetworkLockKey.IsZero() {
		persist.NetworkLockKey = key.NewNLPrivate()
	}

	nlPub := persist.NetworkLockKey.Public()

	if tryingNewKey.IsZero() {
		if opt.Logout {
			return false, "", nil, errors.New("no nodekey to log out")
		}
		log.Fatalf("tryingNewKey is empty, give up")
	}

	var nodeKeySignature tkatype.MarshaledSignature
	if !oldNodeKey.IsZero() && opt.OldNodeKeySignature != nil {
		if nodeKeySignature, err = tka.ResignNKS(persist.NetworkLockKey, tryingNewKey.Public(), opt.OldNodeKeySignature); err != nil {
			c.logf("Failed re-signing node-key signature: %v", err)
		}
	} else if isWrapped {
		// We were given a wrapped pre-auth key, which means that in addition
		// to being a regular pre-auth key there was a suffix with information to
		// generate a tailnet-lock signature.
		nodeKeySignature, err = tka.SignByCredential(wrappedKey, wrappedSig, tryingNewKey.Public())
		if err != nil {
			return false, "", nil, err
		}
	}

	if backendLogID == "" {
		err = errors.New("hostinfo: BackendLogID missing")
		return regen, opt.URL, nil, err
	}

	tailnet, err := c.polc.GetString(pkey.Tailnet, "")
	if err != nil {
		c.logf("unable to provide Tailnet field in register request. err: %v", err)
	}
	now := c.clock.Now().Round(time.Second)
	request := tailcfg.RegisterRequest{
		Version:          1,
		OldNodeKey:       oldNodeKey,
		NodeKey:          tryingNewKey.Public(),
		NLKey:            nlPub,
		Hostinfo:         hi,
		Followup:         opt.URL,
		Timestamp:        &now,
		Ephemeral:        (opt.Flags & LoginEphemeral) != 0,
		NodeKeySignature: nodeKeySignature,
		Tailnet:          tailnet,
	}
	if opt.Logout {
		request.Expiry = time.Unix(123, 0) // far in the past
	} else if opt.Expiry != nil {
		request.Expiry = *opt.Expiry
	}
	c.logf("RegisterReq: onode=%v node=%v fup=%v nks=%v",
		request.OldNodeKey.ShortString(),
		request.NodeKey.ShortString(), opt.URL != "", len(nodeKeySignature) > 0)
	if authKey != "" {
		request.Auth = &tailcfg.RegisterResponseAuth{
			AuthKey: authKey,
		}
	}
	err = signRegisterRequest(c.polc, &request, c.serverURL, c.serverLegacyKey, machinePrivKey.Public())
	if err != nil {
		// If signing failed, clear all related fields
		request.SignatureType = tailcfg.SignatureNone
		request.Timestamp = nil
		request.DeviceCert = nil
		request.Signature = nil

		// Don't log the common error types. Signatures are not usually enabled,
		// so these are expected.
		if !errors.Is(err, errCertificateNotConfigured) && !errors.Is(err, errNoCertStore) {
			c.logf("RegisterReq sign error: %v", err)
		}
	}
	if DevKnob.DumpRegister() {
		j, _ := json.MarshalIndent(request, "", "\t")
		c.logf("RegisterRequest: %s", j)
	}

	// URL and httpc are protocol specific.

	request.Version = tailcfg.CurrentCapabilityVersion
	httpc, err := c.getNoiseClient()
	if err != nil {
		return regen, opt.URL, nil, fmt.Errorf("getNoiseClient: %w", err)
	}
	url := fmt.Sprintf("%s/machine/register", c.serverURL)
	url = strings.Replace(url, "http:", "https:", 1)

	bodyData, err := encode(request)
	if err != nil {
		return regen, opt.URL, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyData))
	if err != nil {
		return regen, opt.URL, nil, err
	}
	ts2021.AddLBHeader(req, request.OldNodeKey)
	ts2021.AddLBHeader(req, request.NodeKey)

	res, err := httpc.Do(req)
	if err != nil {
		return regen, opt.URL, nil, fmt.Errorf("register request: %w", err)
	}
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return regen, opt.URL, nil, fmt.Errorf("register request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	resp := tailcfg.RegisterResponse{}
	if err := decode(res, &resp); err != nil {
		c.logf("error decoding RegisterResponse with server key %s and machine key %s: %v", serverKey, machinePrivKey.Public(), err)
		return regen, opt.URL, nil, fmt.Errorf("register request: %v", err)
	}
	if DevKnob.DumpRegister() {
		j, _ := json.MarshalIndent(resp, "", "\t")
		c.logf("RegisterResponse: %s", j)
	}

	// Log without PII:
	c.logf("RegisterReq: got response; nodeKeyExpired=%v, machineAuthorized=%v; authURL=%v",
		resp.NodeKeyExpired, resp.MachineAuthorized, resp.AuthURL != "")

	if resp.Error != "" {
		return false, "", nil, UserVisibleError(resp.Error)
	}
	if len(resp.NodeKeySignature) > 0 {
		return true, "", resp.NodeKeySignature, nil
	}

	if resp.NodeKeyExpired {
		if regen {
			return true, "", nil, fmt.Errorf("weird: regen=true but server says NodeKeyExpired: %v", request.NodeKey)
		}
		c.logf("server reports new node key %v has expired",
			request.NodeKey.ShortString())
		return true, "", nil, nil
	}
	persist.UserProfile = tailcfg.UserProfile{
		ID:            resp.User.ID,
		DisplayName:   resp.Login.DisplayName,
		ProfilePicURL: resp.Login.ProfilePicURL,
		LoginName:     resp.Login.LoginName,
	}

	// TODO(crawshaw): RegisterResponse should be able to mechanically
	// communicate some extra instructions from the server:
	//	- new node key required
	//	- machine key no longer supported
	//	- user is disabled

	if resp.AuthURL != "" {
		c.logf("AuthURL is %v", resp.AuthURL)
	} else {
		c.logf("[v1] No AuthURL")
	}

	c.mu.Lock()
	if resp.AuthURL == "" {
		// key rotation is complete
		persist.PrivateNodeKey = tryingNewKey
	} else {
		// save it for the retry-with-URL
		c.tryingNewKey = tryingNewKey
	}
	c.persist = persist.View()
	c.mu.Unlock()

	if ctx.Err() != nil {
		return regen, "", nil, ctx.Err()
	}
	return false, resp.AuthURL, nil, nil
}

// newEndpoints acquires c.mu and sets the local port and endpoints and reports
// whether they've changed.
//
// It does not retain the provided slice.
func (c *Direct) newEndpoints(endpoints []tailcfg.Endpoint) (changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Nothing new?
	if slices.Equal(c.endpoints, endpoints) {
		return false // unchanged
	}
	c.logf("[v2] client.newEndpoints(%v)", endpoints)
	c.endpoints = slices.Clone(endpoints)
	return true // changed
}

// SetEndpoints updates the list of locally advertised endpoints.
// It won't be replicated to the server until a *fresh* call to PollNetMap().
// You don't need to restart PollNetMap if we return changed==false.
func (c *Direct) SetEndpoints(endpoints []tailcfg.Endpoint) (changed bool) {
	// (no log message on function entry, because it clutters the logs
	//  if endpoints haven't changed. newEndpoints() will log it.)
	return c.newEndpoints(endpoints)
}

// PollNetMap makes a /map request to download the network map, calling
// NetmapUpdater on each update from the control plane.
//
// It always returns a non-nil error describing the reason for the failure or
// why the request ended.
func (c *Direct) PollNetMap(ctx context.Context, nu NetmapUpdater) error {
	return c.sendMapRequest(ctx, true, nu)
}

type rememberLastNetmapUpdater struct {
	last *netmap.NetworkMap
}

func (nu *rememberLastNetmapUpdater) UpdateFullNetmap(nm *netmap.NetworkMap) {
	nu.last = nm
}

// FetchNetMapForTest fetches the netmap once.
func (c *Direct) FetchNetMapForTest(ctx context.Context) (*netmap.NetworkMap, error) {
	var nu rememberLastNetmapUpdater
	err := c.sendMapRequest(ctx, false, &nu)
	if err == nil && nu.last == nil {
		return nil, errors.New("[unexpected] sendMapRequest success without callback")
	}
	return nu.last, err
}

// SendUpdate makes a /map request to update the server of our latest state, but
// does not fetch anything. It returns an error if the server did not return a
// successful 200 OK response.
func (c *Direct) SendUpdate(ctx context.Context) error {
	return c.sendMapRequest(ctx, false, nil)
}

// SetDiscoPublicKey updates the disco public key in local state.
// It does not implicitly trigger [SendUpdate]; callers should arrange for that.
func (c *Direct) SetDiscoPublicKey(key key.DiscoPublic) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.discoPubKey = key
}

// ClientID returns the controlClientID of the controlClient.
func (c *Direct) ClientID() int64 {
	return c.controlClientID
}

// AutoUpdate is an eventbus value, reporting the value of tailcfg.MapResponse.DefaultAutoUpdate.
type AutoUpdate struct {
	ClientID int64 // The ID field is used for consumers to differentiate instances of Direct.
	Value    bool  // The Value represents DefaultAutoUpdate from [tailcfg.MapResponse].
}

// ControlTime is an eventbus value, reporting the value of tailcfg.MapResponse.ControlTime.
type ControlTime struct {
	ClientID int64     // The ID field is used for consumers to differentiate instances of Direct.
	Value    time.Time // The Value represents ControlTime from [tailcfg.MapResponse].
}

// If we go more than watchdogTimeout without hearing from the server,
// end the long poll. We should be receiving a keep alive ping
// every minute.
const watchdogTimeout = 120 * time.Second

// sendMapRequest makes a /map request to download the network map, calling cb
// with each new netmap. If isStreaming, it will poll forever and only returns
// if the context expires or the server returns an error/closes the connection
// and as such always returns a non-nil error.
//
// If nu is nil, OmitPeers will be set to true.
func (c *Direct) sendMapRequest(ctx context.Context, isStreaming bool, nu NetmapUpdater) error {
	if c.panicOnUse {
		panic("tainted client")
	}
	if isStreaming && nu == nil {
		panic("cb must be non-nil if isStreaming is true")
	}

	metricMapRequests.Add(1)
	metricMapRequestsActive.Add(1)
	defer metricMapRequestsActive.Add(-1)
	if isStreaming {
		metricMapRequestsPoll.Add(1)
	} else {
		metricMapRequestsLite.Add(1)
	}

	c.mu.Lock()
	persist := c.persist
	serverURL := c.serverURL
	serverNoiseKey := c.serverNoiseKey
	discoKey := c.discoPubKey
	hi := c.hostInfoLocked()
	backendLogID := hi.BackendLogID
	connectionHandleForTest := c.connectionHandleForTest
	tkaHead := c.tkaHead
	var epStrs []string
	var eps []netip.AddrPort
	var epTypes []tailcfg.EndpointType
	for _, ep := range c.endpoints {
		eps = append(eps, ep.Addr)
		epStrs = append(epStrs, ep.Addr.String())
		epTypes = append(epTypes, ep.Type)
	}
	c.mu.Unlock()

	if serverNoiseKey.IsZero() {
		return errors.New("control server is too old; no noise key")
	}

	machinePrivKey, err := c.getMachinePrivKey()
	if err != nil {
		return fmt.Errorf("getMachinePrivKey: %w", err)
	}
	if machinePrivKey.IsZero() {
		return errors.New("getMachinePrivKey returned zero key")
	}

	if persist.PrivateNodeKey().IsZero() {
		return errors.New("privateNodeKey is zero")
	}
	if backendLogID == "" {
		return errors.New("hostinfo: BackendLogID missing")
	}

	c.logf("[v1] PollNetMap: stream=%v ep=%v", isStreaming, epStrs)

	vlogf := logger.Discard
	if DevKnob.DumpNetMapsVerbose() {
		// TODO(bradfitz): update this to use "[v2]" prefix perhaps? but we don't
		// want to upload it always.
		vlogf = c.logf
	}

	nodeKey := persist.PublicNodeKey()

	request := &tailcfg.MapRequest{
		Version:                 tailcfg.CurrentCapabilityVersion,
		KeepAlive:               true,
		NodeKey:                 nodeKey,
		DiscoKey:                discoKey,
		Endpoints:               eps,
		EndpointTypes:           epTypes,
		Stream:                  isStreaming,
		Hostinfo:                hi,
		DebugFlags:              c.debugFlags,
		OmitPeers:               nu == nil,
		TKAHead:                 tkaHead,
		ConnectionHandleForTest: connectionHandleForTest,
	}

	// If we have a hardware attestation key, sign the node key with it and send
	// the key & signature in the map request.
	if buildfeatures.HasTPM {
		if k := persist.AsStruct().AttestationKey; k != nil && !k.IsZero() {
			hwPub := key.HardwareAttestationPublicFromPlatformKey(k)
			request.HardwareAttestationKey = hwPub

			t := c.clock.Now()
			msg := fmt.Sprintf("%d|%s", t.Unix(), nodeKey.String())
			digest := sha256.Sum256([]byte(msg))
			sig, err := k.Sign(nil, digest[:], crypto.SHA256)
			if err != nil {
				c.logf("failed to sign node key with hardware attestation key: %v", err)
			} else {
				request.HardwareAttestationKeySignature = sig
				request.HardwareAttestationKeySignatureTimestamp = t
			}
		}
	}

	var extraDebugFlags []string
	if buildfeatures.HasAdvertiseRoutes && hi != nil && c.netMon != nil && !c.skipIPForwardingCheck &&
		ipForwardingBroken(hi.RoutableIPs, c.netMon.InterfaceState()) {
		extraDebugFlags = append(extraDebugFlags, "warn-ip-forwarding-off")
	}
	if c.health.RouterHealth() != nil {
		extraDebugFlags = append(extraDebugFlags, "warn-router-unhealthy")
	}
	extraDebugFlags = c.health.AppendWarnableDebugFlags(extraDebugFlags)
	if hostinfo.DisabledEtcAptSource() {
		extraDebugFlags = append(extraDebugFlags, "warn-etc-apt-source-disabled")
	}
	if len(extraDebugFlags) > 0 {
		old := request.DebugFlags
		request.DebugFlags = append(old[:len(old):len(old)], extraDebugFlags...)
	}
	request.Compress = "zstd"

	bodyData, err := encode(request)
	if err != nil {
		vlogf("netmap: encode: %v", err)
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	machinePubKey := machinePrivKey.Public()
	t0 := c.clock.Now()

	httpc, err := c.getNoiseClient()
	if err != nil {
		return fmt.Errorf("getNoiseClient: %w", err)
	}
	url := fmt.Sprintf("%s/machine/map", serverURL)
	url = strings.Replace(url, "http:", "https:", 1)

	// Create a watchdog timer that breaks the connection if we don't receive a
	// MapResponse from the network at least once every two minutes. The
	// watchdog timer is stopped every time we receive a MapResponse (so it
	// doesn't run when we're processing a MapResponse message, including any
	// long-running requested operations like Debug.Sleep) and is reset whenever
	// we go back to blocking on network reads.
	// The watchdog timer also covers the initial request (effectively the
	// pre-body and initial-body read timeouts) as we do not have any other
	// keep-alive mechanism for the initial request.
	watchdogTimer, watchdogTimedOut := c.clock.NewTimer(watchdogTimeout)
	defer watchdogTimer.Stop()

	go func() {
		select {
		case <-ctx.Done():
			vlogf("netmap: ending timeout goroutine")
			return
		case <-watchdogTimedOut:
			c.logf("map response long-poll timed out!")
			cancel()
			return
		}
	}()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}
	ts2021.AddLBHeader(req, nodeKey)

	res, err := httpc.Do(req)
	if err != nil {
		vlogf("netmap: Do: %v", err)
		return err
	}
	vlogf("netmap: Do = %v after %v", res.StatusCode, time.Since(t0).Round(time.Millisecond))
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("initial fetch failed %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	defer res.Body.Close()

	c.health.NoteMapRequestHeard(request)
	watchdogTimer.Reset(watchdogTimeout)

	if nu == nil {
		io.Copy(io.Discard, res.Body)
		return nil
	}

	sess := newMapSession(persist.PrivateNodeKey(), nu, c.controlKnobs)
	defer sess.Close()
	sess.cancel = cancel
	sess.logf = c.logf
	sess.vlogf = vlogf
	sess.altClock = c.clock
	sess.machinePubKey = machinePubKey
	sess.onDebug = c.handleDebugMessage
	sess.onSelfNodeChanged = func(nm *netmap.NetworkMap) {
		c.mu.Lock()
		defer c.mu.Unlock()
		// If we are the ones who last updated persist, then we can update it
		// again. Otherwise, we should not touch it. Also, it's only worth
		// change it if the Node info changed.
		if persist == c.persist {
			newPersist := persist.AsStruct()
			newPersist.NodeID = nm.SelfNode.StableID()
			if up, ok := nm.UserProfiles[nm.User()]; ok {
				newPersist.UserProfile = *up.AsStruct()
			}

			c.persist = newPersist.View()
			persist = c.persist
		}
		c.expiry = nm.SelfKeyExpiry()
	}

	// gotNonKeepAliveMessage is whether we've yet received a MapResponse message without
	// KeepAlive set.
	var gotNonKeepAliveMessage bool

	// If allowStream, then the server will use an HTTP long poll to
	// return incremental results. There is always one response right
	// away, followed by a delay, and eventually others.
	// If !allowStream, it'll still send the first result in exactly
	// the same format before just closing the connection.
	// We can use this same read loop either way.
	var msg []byte
	for mapResIdx := 0; mapResIdx == 0 || isStreaming; mapResIdx++ {
		watchdogTimer.Reset(watchdogTimeout)
		vlogf("netmap: starting size read after %v (poll %v)", time.Since(t0).Round(time.Millisecond), mapResIdx)
		var siz [4]byte
		if _, err := io.ReadFull(res.Body, siz[:]); err != nil {
			vlogf("netmap: size read error after %v: %v", time.Since(t0).Round(time.Millisecond), err)
			return err
		}
		size := binary.LittleEndian.Uint32(siz[:])
		vlogf("netmap: read size %v after %v", size, time.Since(t0).Round(time.Millisecond))
		msg = append(msg[:0], make([]byte, size)...)
		if _, err := io.ReadFull(res.Body, msg); err != nil {
			vlogf("netmap: body read error: %v", err)
			return err
		}
		vlogf("netmap: read body after %v", time.Since(t0).Round(time.Millisecond))

		var resp tailcfg.MapResponse
		if err := sess.decodeMsg(msg, &resp); err != nil {
			vlogf("netmap: decode error: %v", err)
			return err
		}
		watchdogTimer.Stop()

		metricMapResponseMessages.Add(1)

		if isStreaming {
			c.health.GotStreamedMapResponse()
		}

		if pr := resp.PingRequest; pr != nil && c.isUniquePingRequest(pr) {
			metricMapResponsePings.Add(1)
			go c.answerPing(pr)
		}
		if u := resp.PopBrowserURL; u != "" && u != sess.lastPopBrowserURL {
			sess.lastPopBrowserURL = u
			if c.popBrowser != nil {
				c.logf("netmap: control says to open URL %v; opening...", u)
				c.popBrowser(u)
			} else {
				c.logf("netmap: control says to open URL %v; no popBrowser func", u)
			}
		}
		if resp.ClientVersion != nil {
			c.clientVersionPub.Publish(*resp.ClientVersion)
		}
		if resp.ControlTime != nil && !resp.ControlTime.IsZero() {
			c.logf.JSON(1, "controltime", resp.ControlTime.UTC())
			c.controlTimePub.Publish(ControlTime{c.controlClientID, *resp.ControlTime})
		}
		if resp.KeepAlive {
			vlogf("netmap: got keep-alive")
		} else {
			vlogf("netmap: got new map")
		}
		if resp.ControlDialPlan != nil && !ignoreDialPlan() {
			if c.dialPlan != nil {
				c.logf("netmap: got new dial plan from control")
				c.dialPlan.Store(resp.ControlDialPlan)
			} else {
				c.logf("netmap: [unexpected] new dial plan; nowhere to store it")
			}
		}
		if resp.KeepAlive {
			metricMapResponseKeepAlives.Add(1)
			continue
		}
		if au, ok := resp.DefaultAutoUpdate.Get(); ok {
			c.autoUpdatePub.Publish(AutoUpdate{c.controlClientID, au})
		}

		metricMapResponseMap.Add(1)
		if gotNonKeepAliveMessage {
			// If we've already seen a non-keep-alive message, this is a delta update.
			metricMapResponseMapDelta.Add(1)
		} else if resp.Node == nil {
			// The very first non-keep-alive message should have Node populated.
			c.logf("initial MapResponse lacked Node")
			return errors.New("initial MapResponse lacked node")
		}
		gotNonKeepAliveMessage = true

		if err := sess.HandleNonKeepAliveMapResponse(ctx, &resp); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// NetmapFromMapResponseForDebug returns a NetworkMap from the given MapResponse.
// It is intended for debugging only.
func NetmapFromMapResponseForDebug(ctx context.Context, pr persist.PersistView, resp *tailcfg.MapResponse) (*netmap.NetworkMap, error) {
	if resp == nil {
		return nil, errors.New("nil MapResponse")
	}
	if resp.Node == nil {
		return nil, errors.New("MapResponse lacks Node")
	}

	nu := &rememberLastNetmapUpdater{}
	sess := newMapSession(pr.PrivateNodeKey(), nu, nil)
	defer sess.Close()

	if err := sess.HandleNonKeepAliveMapResponse(ctx, resp); err != nil {
		return nil, fmt.Errorf("HandleNonKeepAliveMapResponse: %w", err)
	}

	return sess.netmap(), nil
}

func (c *Direct) handleDebugMessage(ctx context.Context, debug *tailcfg.Debug) error {
	if code := debug.Exit; code != nil {
		c.logf("exiting process with status %v per controlplane", *code)
		os.Exit(*code)
	}
	if buildfeatures.HasLogTail && debug.DisableLogTail {
		logtail.Disable()
		envknob.SetNoLogsNoSupport()
	}
	if sleep := time.Duration(debug.SleepSeconds * float64(time.Second)); sleep > 0 {
		if err := sleepAsRequested(ctx, c.logf, sleep, c.clock); err != nil {
			return err
		}
	}
	return nil
}

// initDisplayNames mutates any tailcfg.Nodes in resp to populate their display names,
// calling InitDisplayNames on each.
//
// The magicDNSSuffix used is based on selfNode.
func initDisplayNames(selfNode tailcfg.NodeView, resp *tailcfg.MapResponse) {
	if resp.Node == nil && len(resp.Peers) == 0 && len(resp.PeersChanged) == 0 {
		// Fast path for a common case (delta updates). No need to compute
		// magicDNSSuffix.
		return
	}
	magicDNSSuffix := netmap.MagicDNSSuffixOfNodeName(selfNode.Name())
	if resp.Node != nil {
		resp.Node.InitDisplayNames(magicDNSSuffix)
	}
	for _, n := range resp.Peers {
		n.InitDisplayNames(magicDNSSuffix)
	}
	for _, n := range resp.PeersChanged {
		n.InitDisplayNames(magicDNSSuffix)
	}
}

// decode JSON decodes the res.Body into v.
func decode(res *http.Response, v any) error {
	defer res.Body.Close()
	msg, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("%d: %v", res.StatusCode, string(msg))
	}
	return json.Unmarshal(msg, v)
}

var jsonEscapedZero = []byte(`\u0000`)

const justKeepAliveStr = `{"KeepAlive":true}`

// decodeMsg is responsible for uncompressing msg and unmarshaling into v.
func (sess *mapSession) decodeMsg(compressedMsg []byte, v *tailcfg.MapResponse) error {
	// Fast path for common case of keep-alive message.
	// See tailscale/tailscale#17343.
	if sess.keepAliveZ != nil && bytes.Equal(compressedMsg, sess.keepAliveZ) {
		v.KeepAlive = true
		return nil
	}

	b, err := zstdframe.AppendDecode(nil, compressedMsg)
	if err != nil {
		return err
	}
	sess.ztdDecodesForTest++

	if DevKnob.DumpNetMaps() {
		var buf bytes.Buffer
		json.Indent(&buf, b, "", "    ")
		log.Printf("MapResponse: %s", buf.Bytes())
	}

	if bytes.Contains(b, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in controlclient.Direct.decodeMsg into %T: %q", v, b)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	if v.KeepAlive && string(b) == justKeepAliveStr {
		sess.keepAliveZ = compressedMsg
	}
	return nil
}

// encode JSON encodes v as JSON, logging tailcfg.MapRequest values if
// debugMap is set.
func encode(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if DevKnob.DumpNetMaps() {
		if _, ok := v.(*tailcfg.MapRequest); ok {
			log.Printf("MapRequest: %s", b)
		}
	}
	return b, nil
}

func loadServerPubKeys(ctx context.Context, httpc *http.Client, serverURL string) (*tailcfg.OverTLSPublicKeyResponse, error) {
	keyURL := fmt.Sprintf("%v/key?v=%d", serverURL, tailcfg.CurrentCapabilityVersion)
	req, err := http.NewRequestWithContext(ctx, "GET", keyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create control key request: %v", err)
	}
	res, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch control key: %v", err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("fetch control key response: %v", err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetch control key: %v", res.Status)
	}
	var out tailcfg.OverTLSPublicKeyResponse
	jsonErr := json.Unmarshal(b, &out)
	if jsonErr == nil {
		return &out, nil
	}

	// Some old control servers might not be updated to send the new format.
	// Accept the old pre-JSON format too.
	out = tailcfg.OverTLSPublicKeyResponse{}
	k, err := key.ParseMachinePublicUntyped(mem.B(b))
	if err != nil {
		return nil, errors.Join(jsonErr, err)
	}
	out.LegacyPublicKey = k
	return &out, nil
}

// DevKnob contains temporary internal-only debug knobs.
// They're unexported to not draw attention to them.
var DevKnob = initDevKnob()

type devKnobs struct {
	DumpRegister       func() bool
	DumpNetMaps        func() bool
	DumpNetMapsVerbose func() bool
	ForceProxyDNS      func() bool
	StripEndpoints     func() bool // strip endpoints from control (only use disco messages)
	StripHomeDERP      func() bool // strip Home DERP from control
	StripCaps          func() bool // strip all local node's control-provided capabilities
}

func initDevKnob() devKnobs {
	nm := envknob.RegisterInt("TS_DEBUG_MAP")
	return devKnobs{
		DumpNetMaps:        func() bool { return nm() > 0 },
		DumpNetMapsVerbose: func() bool { return nm() > 1 },
		DumpRegister:       envknob.RegisterBool("TS_DEBUG_REGISTER"),
		ForceProxyDNS:      envknob.RegisterBool("TS_DEBUG_PROXY_DNS"),
		StripEndpoints:     envknob.RegisterBool("TS_DEBUG_STRIP_ENDPOINTS"),
		StripHomeDERP:      envknob.RegisterBool("TS_DEBUG_STRIP_HOME_DERP"),
		StripCaps:          envknob.RegisterBool("TS_DEBUG_STRIP_CAPS"),
	}
}

var clock tstime.Clock = tstime.StdClock{}

// ipForwardingBroken reports whether the system's IP forwarding is disabled
// and will definitely not work for the routes provided.
//
// It should not return false positives.
//
// TODO(bradfitz): Change controlclient.Options.SkipIPForwardingCheck into a
// func([]netip.Prefix) error signature instead.
func ipForwardingBroken(routes []netip.Prefix, state *netmon.State) bool {
	warn, err := netutil.CheckIPForwarding(routes, state)
	if err != nil {
		// Oh well, we tried. This is just for debugging.
		// We don't want false positives.
		// TODO: maybe we want a different warning for inability to check?
		return false
	}
	return warn != nil
}

// isUniquePingRequest reports whether pr contains a new PingRequest.URL
// not already handled, noting its value when returning true.
func (c *Direct) isUniquePingRequest(pr *tailcfg.PingRequest) bool {
	if pr == nil || pr.URL == "" {
		// Bogus.
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if pr.URL == c.lastPingURL {
		return false
	}
	c.lastPingURL = pr.URL
	return true
}

// HookAnswerC2NPing is where feature/c2n conditionally registers support
// for handling C2N (control-to-node) HTTP requests.
var HookAnswerC2NPing feature.Hook[func(logger.Logf, http.Handler, *http.Client, *tailcfg.PingRequest)]

func (c *Direct) answerPing(pr *tailcfg.PingRequest) {
	httpc := c.httpc
	useNoise := pr.URLIsNoise || pr.Types == "c2n"
	if useNoise {
		nc, err := c.getNoiseClient()
		if err != nil {
			c.logf("failed to get noise client for ping request: %v", err)
			return
		}
		httpc = nc.Client
	}
	if pr.URL == "" {
		c.logf("invalid PingRequest with no URL")
		return
	}
	switch pr.Types {
	case "":
		answerHeadPing(c.logf, httpc, pr)
		return
	case "c2n":
		if !buildfeatures.HasC2N {
			return
		}
		if !useNoise && !envknob.Bool("TS_DEBUG_PERMIT_HTTP_C2N") {
			c.logf("refusing to answer c2n ping without noise")
			return
		}
		if f, ok := HookAnswerC2NPing.GetOk(); ok {
			f(c.logf, c.c2nHandler, httpc, pr)
		}
		return
	}
	for _, t := range strings.Split(pr.Types, ",") {
		switch pt := tailcfg.PingType(t); pt {
		case tailcfg.PingTSMP, tailcfg.PingDisco, tailcfg.PingICMP, tailcfg.PingPeerAPI:
			go doPingerPing(c.logf, httpc, pr, c.pinger, pt)
		default:
			c.logf("unsupported ping request type: %q", t)
		}
	}
}

func answerHeadPing(logf logger.Logf, c *http.Client, pr *tailcfg.PingRequest) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", pr.URL, nil)
	if err != nil {
		logf("answerHeadPing: NewRequestWithContext: %v", err)
		return
	}
	if pr.Log {
		logf("answerHeadPing: sending HEAD ping to %v ...", pr.URL)
	}
	t0 := clock.Now()
	_, err = c.Do(req)
	d := clock.Since(t0).Round(time.Millisecond)
	if err != nil {
		logf("answerHeadPing error: %v to %v (after %v)", err, pr.URL, d)
	} else if pr.Log {
		logf("answerHeadPing complete to %v (after %v)", pr.URL, d)
	}
}

// sleepAsRequest implements the sleep for a tailcfg.Debug message requesting
// that the client sleep. The complication is that while we're sleeping (if for
// a long time), we need to periodically reset the watchdog timer before it
// expires.
func sleepAsRequested(ctx context.Context, logf logger.Logf, d time.Duration, clock tstime.Clock) error {
	const maxSleep = 5 * time.Minute
	if d > maxSleep {
		logf("sleeping for %v, capped from server-requested %v ...", maxSleep, d)
		d = maxSleep
	} else {
		logf("sleeping for server-requested %v ...", d)
	}

	timer, timerChannel := clock.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timerChannel:
		return nil
	}
}

// getNoiseClient returns the noise client, creating one if one doesn't exist.
func (c *Direct) getNoiseClient() (*ts2021.Client, error) {
	c.mu.Lock()
	serverNoiseKey := c.serverNoiseKey
	nc := c.noiseClient
	c.mu.Unlock()
	if serverNoiseKey.IsZero() {
		return nil, errors.New("zero serverNoiseKey")
	}
	if nc != nil {
		return nc, nil
	}
	var dp func() *tailcfg.ControlDialPlan
	if c.dialPlan != nil {
		dp = c.dialPlan.Load
	}
	nc, err, _ := c.sfGroup.Do(struct{}{}, func() (*ts2021.Client, error) {
		k, err := c.getMachinePrivKey()
		if err != nil {
			return nil, err
		}
		c.logf("[v1] creating new noise client")
		nc, err := ts2021.NewClient(ts2021.ClientOpts{
			PrivKey:       k,
			ServerPubKey:  serverNoiseKey,
			ServerURL:     c.serverURL,
			Dialer:        c.dialer,
			DNSCache:      c.dnsCache,
			Logf:          c.logf,
			NetMon:        c.netMon,
			HealthTracker: c.health,
			DialPlan:      dp,
		})
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.noiseClient = nc
		return nc, nil
	})
	if err != nil {
		return nil, err
	}
	return nc, nil
}

// setDNSNoise sends the SetDNSRequest request to the control plane server over Noise,
// requesting a DNS record be created or updated.
func (c *Direct) setDNSNoise(ctx context.Context, req *tailcfg.SetDNSRequest) error {
	newReq := *req
	newReq.Version = tailcfg.CurrentCapabilityVersion
	nc, err := c.getNoiseClient()
	if err != nil {
		return err
	}
	res, err := nc.Post(ctx, "/machine/set-dns", newReq.NodeKey, &newReq)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		msg, _ := io.ReadAll(res.Body)
		return fmt.Errorf("set-dns response: %v, %.200s", res.Status, strings.TrimSpace(string(msg)))
	}
	var setDNSRes tailcfg.SetDNSResponse
	if err := json.NewDecoder(res.Body).Decode(&setDNSRes); err != nil {
		c.logf("error decoding SetDNSResponse: %v", err)
		return fmt.Errorf("set-dns-response: %w", err)
	}

	return nil
}

// SetDNS sends the SetDNSRequest request to the control plane server,
// requesting a DNS record be created or updated.
func (c *Direct) SetDNS(ctx context.Context, req *tailcfg.SetDNSRequest) (err error) {
	if !buildfeatures.HasACME {
		return feature.ErrUnavailable
	}
	metricSetDNS.Add(1)
	defer func() {
		if err != nil {
			metricSetDNSError.Add(1)
		}
	}()
	return c.setDNSNoise(ctx, req)
}

func (c *Direct) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	if c.panicOnUse {
		panic("tainted client")
	}
	nc, err := c.getNoiseClient()
	if err != nil {
		return nil, err
	}
	return nc.Do(req)
}

// doPingerPing sends a Ping to pr.IP using pinger, and sends an http request back to
// pr.URL with ping response data.
func doPingerPing(logf logger.Logf, c *http.Client, pr *tailcfg.PingRequest, pinger Pinger, pingType tailcfg.PingType) {
	if pr.URL == "" || !pr.IP.IsValid() || pinger == nil {
		logf("invalid ping request: missing url, ip or pinger")
		return
	}
	start := clock.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := pinger.Ping(ctx, pr.IP, pingType, 0)
	if err != nil {
		d := time.Since(start).Round(time.Millisecond)
		logf("doPingerPing: ping error of type %q to %v after %v: %v", pingType, pr.IP, d, err)
		return
	}
	postPingResult(start, logf, c, pr, res.ToPingResponse(pingType))
}

func postPingResult(start time.Time, logf logger.Logf, c *http.Client, pr *tailcfg.PingRequest, res *tailcfg.PingResponse) error {
	duration := time.Since(start)
	if pr.Log {
		if res.Err == "" {
			logf("ping to %v completed in %v. pinger.Ping took %v seconds", pr.IP, res.LatencySeconds, duration)
		} else {
			logf("ping to %v failed after %v: %v", pr.IP, duration, res.Err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	jsonPingRes, err := json.Marshal(res)
	if err != nil {
		return err
	}
	// Send the results of the Ping, back to control URL.
	req, err := http.NewRequestWithContext(ctx, "POST", pr.URL, bytes.NewReader(jsonPingRes))
	if err != nil {
		return fmt.Errorf("http.NewRequestWithContext(%q): %w", pr.URL, err)
	}
	if pr.Log {
		logf("postPingResult: sending ping results to %v ...", pr.URL)
	}
	t0 := clock.Now()
	_, err = c.Do(req)
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		return fmt.Errorf("postPingResult error: %w to %v (after %v)", err, pr.URL, d)
	} else if pr.Log {
		logf("postPingResult complete to %v (after %v)", pr.URL, d)
	}
	return nil
}

// SetDeviceAttrs does a synchronous call to the control plane to update
// the node's attributes.
//
// See docs on [tailcfg.SetDeviceAttributesRequest] for background.
func (c *Auto) SetDeviceAttrs(ctx context.Context, attrs tailcfg.AttrUpdate) error {
	return c.direct.SetDeviceAttrs(ctx, attrs)
}

// SetDeviceAttrs does a synchronous call to the control plane to update
// the node's attributes.
//
// See docs on [tailcfg.SetDeviceAttributesRequest] for background.
func (c *Direct) SetDeviceAttrs(ctx context.Context, attrs tailcfg.AttrUpdate) error {
	nc, err := c.getNoiseClient()
	if err != nil {
		return fmt.Errorf("%w: %w", errNoNoiseClient, err)
	}
	nodeKey, ok := c.GetPersist().PublicNodeKeyOK()
	if !ok {
		return errNoNodeKey
	}
	if c.panicOnUse {
		panic("tainted client")
	}
	req := &tailcfg.SetDeviceAttributesRequest{
		NodeKey: nodeKey,
		Version: tailcfg.CurrentCapabilityVersion,
		Update:  attrs,
	}

	// TODO(bradfitz): unify the callers using doWithBody vs those using
	// DoNoiseRequest. There seems to be a ~50/50 split and they're very close,
	// but doWithBody sets the load balancing header and auto-JSON-encodes the
	// body, but DoNoiseRequest is exported. Clean it up so they're consistent
	// one way or another.

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := nc.DoWithBody(ctx, "PATCH", "/machine/set-device-attr", nodeKey, req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	all, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return fmt.Errorf("HTTP error from control plane: %v: %s", res.Status, all)
	}
	return nil
}

// SendAuditLog implements [auditlog.Transport] by sending an audit log synchronously to the control plane.
//
// See docs on [tailcfg.AuditLogRequest] and [auditlog.Logger] for background.
func (c *Auto) SendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) (err error) {
	return c.direct.sendAuditLog(ctx, auditLog)
}

func (c *Direct) sendAuditLog(ctx context.Context, auditLog tailcfg.AuditLogRequest) (err error) {
	nc, err := c.getNoiseClient()
	if err != nil {
		return fmt.Errorf("%w: %w", errNoNoiseClient, err)
	}

	nodeKey, ok := c.GetPersist().PublicNodeKeyOK()
	if !ok {
		return errNoNodeKey
	}

	req := &tailcfg.AuditLogRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey,
		Action:  auditLog.Action,
		Details: auditLog.Details,
	}

	if c.panicOnUse {
		panic("tainted client")
	}

	res, err := nc.Post(ctx, "/machine/audit-log", nodeKey, req)
	if err != nil {
		return fmt.Errorf("%w: %w", errHTTPPostFailure, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		all, _ := io.ReadAll(res.Body)
		return errBadHTTPResponse(res.StatusCode, string(all))
	}
	return nil
}

// makeScreenTimeDetectingDialFunc returns dialFunc, optionally wrapped (on
// Apple systems) with a func that sets the returned atomic.Bool for whether
// Screen Time seemed to intercept the connection.
//
// The returned *atomic.Bool is nil on non-Apple systems.
func makeScreenTimeDetectingDialFunc(dial netx.DialFunc) (netx.DialFunc, *atomic.Bool) {
	switch runtime.GOOS {
	case "darwin", "ios":
		// Continue below.
	default:
		return dial, nil
	}
	ab := new(atomic.Bool)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		ab.Store(isTCPLoopback(c.LocalAddr()) && isTCPLoopback(c.RemoteAddr()))
		return c, nil
	}, ab
}

func ignoreDialPlan() bool {
	// If we're running in v86 (a JavaScript-based emulation of a 32-bit x86)
	// our networking is very limited. Let's ignore the dial plan since it's too
	// complicated to race that many IPs anyway.
	return hostinfo.IsInVM86()
}

func isTCPLoopback(a net.Addr) bool {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP.IsLoopback()
	}
	return false
}

var (
	metricMapRequestsActive = clientmetric.NewGauge("controlclient_map_requests_active")

	metricMapRequests     = clientmetric.NewCounter("controlclient_map_requests")
	metricMapRequestsLite = clientmetric.NewCounter("controlclient_map_requests_lite")
	metricMapRequestsPoll = clientmetric.NewCounter("controlclient_map_requests_poll")

	metricMapResponseMessages   = clientmetric.NewCounter("controlclient_map_response_message") // any message type
	metricMapResponsePings      = clientmetric.NewCounter("controlclient_map_response_ping")
	metricMapResponseKeepAlives = clientmetric.NewCounter("controlclient_map_response_keepalive")
	metricMapResponseMap        = clientmetric.NewCounter("controlclient_map_response_map")       // any non-keepalive map response
	metricMapResponseMapDelta   = clientmetric.NewCounter("controlclient_map_response_map_delta") // 2nd+ non-keepalive map response

	metricSetDNS      = clientmetric.NewCounter("controlclient_setdns")
	metricSetDNSError = clientmetric.NewCounter("controlclient_setdns_error")
)
