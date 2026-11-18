// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/feature"
	"tailscale.com/feature/loginbeacon/api"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/localapi"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	tsversion "tailscale.com/version"
	"tailscale.com/version/distro"
)

func init() {
	if !feature.Register("loginbeacon") {
		return
	}
	ipnext.RegisterExtension("loginbeacon", newExtension)
	localapi.Register("loginbeacon/", serveResources)
}

// extension runs both roles of the beacon protocol from within the daemon:
//
//   - Sender: explicitly started via LocalAPI on any platform, or automatically
//     on gokrazy appliances when /perm/loginbeacon.json enables it. Advertises
//     only while there is a pending browseToURL.
//   - Receiver: on any node running the daemon, listen for beacons on the LAN
//     and publish them onto the Notify bus as LoginBeaconRequest. Approve /
//     Delete come back via LocalAPI. Approval returns a correlated URL result;
//     the client opens the browser and deletes the request only on handoff success.
type extension struct {
	logf logger.Logf
	host ipnext.Host

	ctx    context.Context
	cancel context.CancelFunc

	broadcastMu      sync.Mutex // serializes sender creation and stop
	automaticSender  bool
	senderConfig     *senderCfg
	broadcastEnabled bool
	newSender        func(context.Context, Config) (*Sender, error)
	deviceID         string // random per extension run; stable across broadcast retries

	netMon             *netmon.Monitor
	unregisterNetMon   func()
	polc               policyclient.Client
	unregisterPolicy   func()
	receiverDone       chan struct{} // lifecycle worker completion
	receiverWake       chan struct{} // coalesced network/backend readiness events
	receiverControl    chan struct{} // preference, policy and foreground lease changes
	newReceiver        func(context.Context, ReceiverConfig) (*Receiver, error)
	resumeReceiver     func(*Receiver) error
	receiverNeedsLease bool // iOS defaults to no reception without an active GUI

	mu                 sync.Mutex
	backendReadySeen   bool // the first ready state needs no membership refresh
	url                string
	sender             *Sender
	receiver           *Receiver
	receiverLeaseUntil time.Time
	receiverEpoch      uint64 // invalidates socket setup across revocation/profile changes
	acceptRequests     bool
	policyDenied       bool
	receiving          bool
	broadcastID        string
	broadcastOwner     ipn.WindowsUserID
	broadcastConfig    api.Broadcast
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &extension{
		logf:               logger.WithPrefix(logf, "loginbeacon: "),
		ctx:                ctx,
		cancel:             cancel,
		newSender:          Start,
		deviceID:           rand.Text(),
		netMon:             sb.Sys().NetMon.Get(),
		polc:               sb.Sys().PolicyClientOrDefault(),
		newReceiver:        StartReceiver,
		resumeReceiver:     (*Receiver).listen,
		receiverNeedsLease: tsversion.OS() == "iOS",
	}, nil
}

func (e *extension) Name() string { return "loginbeacon" }

func (e *extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().MutateNotifyLocked.Add(e.onNotify)
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)
	h.Hooks().ProfileStateChange.Add(e.onProfileStateChange)
	e.acceptRequests = h.Profiles().CurrentPrefs().AcceptLoginRequests()
	e.senderConfig = senderConfig()
	e.automaticSender = e.senderConfig != nil && e.senderConfig.kind != "tvos"
	e.receiverWake = make(chan struct{}, 1)
	e.receiverControl = make(chan struct{}, 1)
	unregister, err := e.polc.RegisterChangeCallback("", func(policyclient.PolicyChange) { e.updatePolicy() })
	if err != nil {
		return err
	}
	e.unregisterPolicy = unregister
	e.updatePolicy()

	e.logf("Init on os=%q gokrazy=%v", tsversion.OS(), distro.Get() == distro.Gokrazy)
	if cfg := e.senderConfig; cfg != nil {
		// Sender-role devices don't also approve other devices' logins.
		// This avoids a tvOS/appliance echoing its own beacon back through
		// the receiver path.
		e.logf("starting sender kind=%q hostname=%q (receiver disabled on sender)", cfg.kind, cfg.hostname)
		if cfg.kind == "tvos" {
			e.logf("tvOS sender waiting for explicit LAN sign-in")
		}
	}

	e.logf("starting receiver lifecycle (foreground lease required=%v)", e.receiverNeedsLease)
	e.unregisterNetMon = e.netMon.RegisterChangeCallback(func(delta *netmon.ChangeDelta) {
		if !delta.RebindLikelyRequired && !delta.TimeJumped() {
			return
		}
		e.wakeReceiver()
	})
	e.receiverDone = make(chan struct{})
	go e.runReceiver(e.receiverWake)
	return nil
}

// senderConfig selects dedicated sender-role devices and their display
// metadata. Other nodes can still explicitly start a sender via LocalAPI:
//   - a gokrazy appliance flashed with --enable-login-beacon
//   - a tvOS device (broadcasting starts when the LAN sign-in button is pressed)
//
// nil permits reception by default, with explicit sender control available.
func senderConfig() *senderCfg {
	if distro.Get() == distro.Gokrazy {
		if c, err := LoadApplianceConfig(); err == nil && c != nil && c.Enabled {
			return &senderCfg{hostname: c.Hostname, kind: "appliance"}
		}
	}
	if tsversion.OS() == "tvOS" {
		return &senderCfg{kind: "tvos"}
	}
	return nil
}

type senderCfg struct {
	hostname string
	kind     string
}

func (e *extension) Shutdown() error {
	e.cancel()
	if e.unregisterPolicy != nil {
		e.unregisterPolicy()
	}
	if e.unregisterNetMon != nil {
		e.unregisterNetMon()
	}
	if e.receiverDone != nil {
		<-e.receiverDone
	}
	e.broadcastMu.Lock()
	defer e.broadcastMu.Unlock()
	e.mu.Lock()
	s, r := e.sender, e.receiver
	e.sender, e.receiver = nil, nil
	e.mu.Unlock()
	if s != nil {
		s.Stop()
	}
	if r != nil {
		r.Stop()
	}
	return nil
}

// onNotify runs under LocalBackend.mu; keep it non-blocking.
func (e *extension) onNotify(n *ipn.Notify) {
	if n == nil || (n.LoginBeaconRequest == nil && n.BrowseToURL == nil) {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.acceptRequests || e.policyDenied {
		n.LoginBeaconRequest = nil
	}
	if e.receiverNeedsLease && !time.Now().Before(e.receiverLeaseUntil) {
		n.LoginBeaconRequest = nil
	}
	if n.BrowseToURL != nil {
		e.url = *n.BrowseToURL
	}
}

func (e *extension) onBackendStateChange(st ipn.State) {
	e.mu.Lock()
	ready := st == ipn.Running || st == ipn.NeedsLogin
	rejoin := ready && e.backendReadySeen
	if ready {
		e.backendReadySeen = true
	}
	if st != ipn.NeedsLogin {
		e.url = ""
		e.broadcastEnabled = false
	}
	e.mu.Unlock()
	if rejoin {
		// A packet-tunnel restart need not change the physical LAN interface.
		e.wakeReceiver()
	} else {
		// Initial readiness retries a failed listener without rejoining a
		// healthy one that already started during extension initialization.
		e.wakeReceiverControl()
	}
}

func (e *extension) currentAuthURL() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.policyDenied || (!e.automaticSender && !e.broadcastEnabled) {
		return ""
	}
	if !e.broadcastConfig.Expires.IsZero() && !time.Now().Before(e.broadcastConfig.Expires) {
		return ""
	}
	return e.url
}

func (e *extension) startSender(cfg *senderCfg) error {
	hostname := cfg.hostname
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}
	s, err := e.newSender(e.ctx, Config{
		Hostname:   hostname,
		DeviceKind: cfg.kind,
		DeviceID:   e.deviceID,
		AuthURL:    e.currentAuthURL,
		OnApproved: e.onSenderApproved,
		Logf:       e.logf,
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	if e.policyDenied || (!e.automaticSender && !e.broadcastEnabled) || e.ctx.Err() != nil {
		e.mu.Unlock()
		s.Stop()
		return errors.New("loginbeacon: broadcast canceled during startup")
	}
	e.sender = s
	if e.broadcastID == "" {
		var id [16]byte
		rand.Read(id[:])
		e.broadcastID = hex.EncodeToString(id[:])
	}
	e.mu.Unlock()
	return nil
}

// setBroadcastLocked gives each explicit LAN login attempt a fresh request ID/keypair,
// even when the login URL was prefetched or a prior request expired on a receiver.
// hostname optionally overrides the native name. For example, the TV app
// supplies its user-assigned name because its extension reports "localhost".
func (e *extension) setBroadcastLocked(enabled bool, hostname string) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	if enabled && e.policyDenied {
		e.mu.Unlock()
		return errPolicyDenied
	}
	if enabled && e.url == "" {
		e.mu.Unlock()
		return errors.New("loginbeacon: no pending login URL")
	}
	e.broadcastID = ""
	e.broadcastOwner = ""
	e.broadcastConfig = api.Broadcast{}
	old := e.sender
	e.sender = nil
	e.broadcastEnabled = enabled
	e.mu.Unlock()
	if old != nil {
		old.Stop()
	}
	if !enabled {
		return nil
	}
	cfg := senderCfg{kind: strings.ToLower(tsversion.OS())}
	if e.senderConfig != nil {
		cfg = *e.senderConfig
	}
	if hostname != "" {
		cfg.hostname = hostname
	}
	if err := e.startSender(&cfg); err != nil {
		e.mu.Lock()
		e.broadcastEnabled = false
		e.mu.Unlock()
		return err
	}
	e.logf("explicit LAN sign-in broadcast started")
	return nil
}

// Receiver activity is a short-lived GUI lease on iOS. Explicit revocation
// stops reception promptly; expiry also handles app death or a lost stop call.
// Desktop receivers remain independent of GUI activity.
const receiverActivityLease = 45 * time.Second

func (e *extension) setReceiverActivity(active bool) error {
	if err := e.ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	e.receiverLeaseUntil = time.Time{}
	if active {
		e.receiverLeaseUntil = time.Now().Add(receiverActivityLease)
	}
	e.mu.Unlock()
	e.wakeReceiverControl()
	return nil
}

func (e *extension) onSenderApproved(approverName string) {
	e.host.SendNotifyAsync(ipn.Notify{
		LoginBeaconApproved: &api.Approved{
			ApproverName: approverName,
		},
	})
}

const receiverRetryInterval = 5 * time.Second

// This is safe in backend hooks: it never blocks or touches sockets.
func (e *extension) wakeReceiver() {
	select {
	case e.receiverWake <- struct{}{}:
	default:
	}
}

func (e *extension) wakeReceiverControl() {
	select {
	case e.receiverControl <- struct{}{}:
	default:
	}
}

// runReceiver owns sender cleanup, receiver startup and membership refresh for
// the daemon's lifetime. Policy, preference and network changes wake it;
// enabled reception also retries without another network event.
func (e *extension) runReceiver(wake <-chan struct{}) {
	defer close(e.receiverDone)
	timer := time.NewTimer(receiverRetryInterval)
	defer timer.Stop()
	rejoin := true
	for {
		if e.ctx.Err() != nil {
			return
		}
		e.cleanupSender()
		err := e.refreshReceiver(rejoin)
		e.mu.Lock()
		needsLease, until, expires := e.receiverNeedsLease, e.receiverLeaseUntil, e.broadcastConfig.Expires
		e.mu.Unlock()
		var delay time.Duration
		if err != nil && (!needsLease || time.Now().Before(until)) {
			e.logf("receiver unavailable: %v; retrying in %s", err, receiverRetryInterval)
			delay = receiverRetryInterval
		}
		if needsLease && !until.IsZero() {
			// A lease expiring during socket setup still needs an immediate
			// pass to pause reception. The next pass clears expired leases.
			remaining := max(time.Until(until), time.Nanosecond)
			if delay == 0 || remaining < delay {
				delay = remaining
			}
		}
		if !expires.IsZero() {
			if remaining := max(time.Until(expires), time.Nanosecond); delay == 0 || remaining < delay {
				delay = remaining
			}
		}
		var tick <-chan time.Time
		if delay > 0 {
			timer.Reset(delay)
			tick = timer.C
		} else {
			timer.Stop()
		}
		rejoin = false
		select {
		case <-e.ctx.Done():
			return
		case <-wake:
			rejoin = true
		case <-e.receiverControl:
		case <-tick:
		}
	}
}

// Only runReceiver calls refreshReceiver. Shutdown waits for it to finish
// before stopping the receiver, so no socket can be published after shutdown.
func (e *extension) refreshReceiver(rejoin bool) error {
	e.mu.Lock()
	r := e.receiver
	epoch := e.receiverEpoch
	permitted := e.acceptRequests && !e.policyDenied && e.senderConfig == nil
	if !permitted {
		e.receiver = nil
		e.receiving = false
		e.mu.Unlock()
		if r != nil {
			r.Stop()
		}
		return nil
	}
	if e.receiverNeedsLease && !time.Now().Before(e.receiverLeaseUntil) {
		e.receiverLeaseUntil = time.Time{}
	}
	enabled := !e.receiverNeedsLease || !e.receiverLeaseUntil.IsZero()
	e.receiving = false
	e.mu.Unlock()
	if !enabled {
		if r != nil {
			r.pause()
		}
		return nil
	}
	if r != nil {
		if r.conn == nil {
			if err := e.resumeReceiver(r); err != nil {
				return err
			}
			rejoin = false
		}
		e.mu.Lock()
		if epoch != e.receiverEpoch || !e.acceptRequests || e.policyDenied {
			e.mu.Unlock()
			return nil
		}
		r.enableRequests()
		e.receiving = true
		e.mu.Unlock()
		if !rejoin {
			return nil
		}
		ifs, err := net.Interfaces()
		if err != nil {
			return err
		}
		return r.rejoinMulticast(ifs)
	}
	r, err := e.newReceiver(e.ctx, ReceiverConfig{
		OnBeacon: func(b Beacon) {
			request := b.apiRequest()
			e.host.SendNotifyAsync(ipn.Notify{LoginBeaconRequest: &request})
		},
		OnRemoved: func(id [16]byte) {
			rid := hex.EncodeToString(id[:])
			e.host.SendNotifyAsync(ipn.Notify{LoginBeaconRemoved: &rid})
		},
		IgnoreDeviceIDHash: hashDeviceID(e.deviceID),
		URLAllowed:         api.DefaultURLAllowed,
		Logf:               e.logf,
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	if epoch != e.receiverEpoch || !e.acceptRequests || e.policyDenied {
		e.mu.Unlock()
		r.Stop()
		return nil
	}
	e.receiver = r
	e.receiving = true
	e.mu.Unlock()
	return nil
}

func (e *extension) approve(ctx context.Context, rid [16]byte) (string, error) {
	e.mu.Lock()
	r := e.receiver
	epoch := e.receiverEpoch
	if !e.acceptRequests || e.policyDenied {
		e.mu.Unlock()
		return "", errReceptionDisabled
	}
	e.mu.Unlock()
	if r == nil {
		return "", errors.New("loginbeacon: receiver not running")
	}
	url, err := r.Approve(ctx, rid)
	e.mu.Lock()
	valid := e.receiver == r && e.receiverEpoch == epoch && e.acceptRequests && !e.policyDenied
	e.mu.Unlock()
	if !valid {
		return "", context.Canceled
	}
	return url, err
}

func (e *extension) deleteRequest(rid [16]byte) {
	e.mu.Lock()
	r := e.receiver
	e.mu.Unlock()
	if r != nil {
		r.Delete(rid)
	}
}

var errPolicyDenied = errors.New("loginbeacon: prohibited by administrative policy")
var errReceptionDisabled = errors.New("loginbeacon: reception is disabled")

func (e *extension) updatePolicy() {
	allowed, err := e.polc.GetBoolean(pkey.AllowLoginBeacon, true)
	// A policy read error must not bypass a configured restriction.
	denied := err != nil || !allowed
	e.mu.Lock()
	if denied && !e.policyDenied {
		e.receiverEpoch++
	}
	e.policyDenied = denied
	if denied {
		e.broadcastEnabled = false
		if e.receiver != nil {
			e.receiver.clearRequests()
		}
	}
	e.mu.Unlock()
	e.wakeReceiverControl()
}

// This hook runs under LocalBackend.mu. Socket cleanup belongs to the worker;
// request cancellation is immediate so an in-flight retrieval cannot succeed.
func (e *extension) onProfileStateChange(_ ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	e.acceptRequests = prefs.AcceptLoginRequests()
	if !sameNode {
		e.url = ""
		e.broadcastEnabled = false
	}
	if !sameNode || !e.acceptRequests {
		e.receiverEpoch++
		if e.receiver != nil {
			e.receiver.clearRequests()
		}
	}
	e.mu.Unlock()
	e.wakeReceiverControl()
}

func (e *extension) cleanupSender() {
	e.broadcastMu.Lock()
	defer e.broadcastMu.Unlock()
	e.mu.Lock()
	expires := e.broadcastConfig.Expires
	stop := e.policyDenied || (!e.automaticSender && !e.broadcastEnabled) || (!expires.IsZero() && !time.Now().Before(expires))
	restart := !e.policyDenied && e.automaticSender && e.sender == nil
	e.mu.Unlock()
	if stop {
		_ = e.setBroadcastLocked(false, "")
	} else if restart && e.ctx.Err() == nil {
		if err := e.startSender(e.senderConfig); err != nil {
			e.logf("automatic sender: %v", err)
		}
	}
}
