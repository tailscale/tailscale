// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package health is a registry for other packages to report & check
// overall health status of the node.
package health

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"maps"
	"net/http"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/metrics"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/opt"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
	"tailscale.com/util/usermetric"
	"tailscale.com/version"
)

var (
	mu           sync.Mutex
	debugHandler map[string]http.Handler
)

// ReceiveFunc is one of the three magicsock Receive funcs (IPv4, IPv6, or
// DERP).
type ReceiveFunc int

// ReceiveFunc indices for Tracker.MagicSockReceiveFuncs.
const (
	ReceiveIPv4 ReceiveFunc = 0
	ReceiveIPv6 ReceiveFunc = 1
	ReceiveDERP ReceiveFunc = 2
)

func (f ReceiveFunc) String() string {
	if f < 0 || int(f) >= len(receiveNames) {
		return fmt.Sprintf("ReceiveFunc(%d)", f)
	}
	return receiveNames[f]
}

var receiveNames = []string{
	ReceiveIPv4: "ReceiveIPv4",
	ReceiveIPv6: "ReceiveIPv6",
	ReceiveDERP: "ReceiveDERP",
}

// Tracker tracks the health of various Tailscale subsystems,
// comparing each subsystems' state with each other to make sure
// they're consistent based on the user's intended state.
//
// If a client [Warnable] becomes unhealthy or its unhealthy state is updated,
// an event will be emitted with WarnableChanged set to true and the Warnable
// and its UnhealthyState:
//
//	Change{WarnableChanged: true, Warnable: w, UnhealthyState: us}
//
// If a Warnable becomes healthy, an event will be emitted with
// WarnableChanged set to true, the Warnable set, and UnhealthyState set to nil:
//
//	Change{WarnableChanged: true, Warnable: w, UnhealthyState: nil}
//
// If the health messages from the control-plane change, an event will be
// emitted with ControlHealthChanged set to true. Recipients can fetch the set of
// control-plane health messages by calling [Tracker.CurrentState]:
type Tracker struct {
	// MagicSockReceiveFuncs tracks the state of the three
	// magicsock receive functions: IPv4, IPv6, and DERP.
	MagicSockReceiveFuncs [3]ReceiveFuncStats // indexed by ReceiveFunc values

	// initOnce guards the initialization of the Tracker.
	// Notably, it initializes the MagicSockReceiveFuncs names.
	// mu should not be held during init.
	initOnce sync.Once

	testClock tstime.Clock // nil means use time.Now / tstime.StdClock{}

	eventClient *eventbus.Client
	changePub   *eventbus.Publisher[Change]

	// mu guards everything that follows.
	mu sync.Mutex

	warnables   []*Warnable // keys ever set
	warnableVal map[*Warnable]*warningState
	// pendingVisibleTimers contains timers for Warnables that are unhealthy, but are
	// not visible to the user yet, because they haven't been unhealthy for TimeToVisible
	pendingVisibleTimers map[*Warnable]tstime.TimerController

	// sysErr maps subsystems to their current error (or nil if the subsystem is healthy)
	// Deprecated: using Warnables should be preferred
	sysErr map[Subsystem]error
	timer  tstime.TimerController

	latestVersion   *tailcfg.ClientVersion // or nil
	checkForUpdates bool
	applyUpdates    opt.Bool

	inMapPoll                   bool
	inMapPollSince              time.Time
	lastMapPollEndedAt          time.Time
	lastStreamedMapResponse     time.Time
	lastNoiseDial               time.Time
	derpHomeRegion              int
	derpHomeless                bool
	derpRegionConnected         map[int]bool
	derpRegionHealthProblem     map[int]string
	derpRegionLastFrame         map[int]time.Time
	derpMap                     *tailcfg.DERPMap // last DERP map from control, could be nil if never received one
	lastMapRequestHeard         time.Time        // time we got a 200 from control for a MapRequest
	ipnState                    string
	ipnWantRunning              bool
	ipnWantRunningLastTrue      time.Time                                           // when ipnWantRunning last changed false -> true
	anyInterfaceUp              opt.Bool                                            // empty means unknown (assume true)
	lastNotifiedControlMessages map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage // latest control messages processed, kept for change detection
	controlMessages             map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage // latest control messages received
	lastLoginErr                error
	localLogConfigErr           error
	tlsConnectionErrors         map[string]error // map[ServerName]error
	metricHealthMessage         *metrics.MultiLabelMap[metricHealthMessageLabel]
}

// NewTracker contructs a new [Tracker] and attaches the given eventbus.
// NewTracker will panic is no eventbus is given.
func NewTracker(bus *eventbus.Bus) *Tracker {
	if bus == nil {
		panic("no eventbus set")
	}

	ec := bus.Client("health.Tracker")
	t := &Tracker{
		eventClient: ec,
		changePub:   eventbus.Publish[Change](ec),
	}
	t.timer = t.clock().AfterFunc(time.Minute, t.timerSelfCheck)

	ec.Monitor(t.awaitEventClientDone)

	return t
}

func (t *Tracker) awaitEventClientDone(ec *eventbus.Client) {
	<-ec.Done()
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, timer := range t.pendingVisibleTimers {
		timer.Stop()
	}
	t.timer.Stop()
	clear(t.pendingVisibleTimers)
}

func (t *Tracker) now() time.Time {
	if t.testClock != nil {
		return t.testClock.Now()
	}
	return time.Now()
}

func (t *Tracker) clock() tstime.Clock {
	if t.testClock != nil {
		return t.testClock
	}
	return tstime.StdClock{}
}

// Subsystem is the name of a subsystem whose health can be monitored.
//
// Deprecated: Registering a Warnable using Register() and updating its health state
// with  SetUnhealthy() and SetHealthy() should be preferred.
type Subsystem string

const (
	// SysRouter is the name of the wgengine/router subsystem.
	SysRouter = Subsystem("router")

	// SysDNS is the name of the net/dns subsystem.
	SysDNS = Subsystem("dns")

	// SysDNSManager is the name of the net/dns manager subsystem.
	SysDNSManager = Subsystem("dns-manager")

	// SysTKA is the name of the tailnet key authority subsystem.
	SysTKA = Subsystem("tailnet-lock")
)

var subsystemsWarnables = map[Subsystem]*Warnable{}

func init() {
	for _, s := range []Subsystem{SysRouter, SysDNS, SysDNSManager, SysTKA} {
		w := Register(&Warnable{
			Code:     WarnableCode(s),
			Severity: SeverityMedium,
			Text: func(args Args) string {
				return args[legacyErrorArgKey]
			},
		})
		subsystemsWarnables[s] = w
	}
}

const legacyErrorArgKey = "LegacyError"

// Warnable returns a Warnable representing a legacy Subsystem. This is used
// temporarily (2024-06-14) while we migrate the old health infrastructure based
// on Subsystems to the new Warnables architecture.
func (s Subsystem) Warnable() *Warnable {
	w, ok := subsystemsWarnables[s]
	if !ok {
		panic(fmt.Sprintf("health: no Warnable for Subsystem %q", s))
	}
	return w
}

var registeredWarnables = map[WarnableCode]*Warnable{}

// Register registers a new Warnable with the health package and returns it.
// Register panics if the Warnable was already registered, because Warnables
// should be unique across the program.
func Register(w *Warnable) *Warnable {
	if registeredWarnables[w.Code] != nil {
		panic(fmt.Sprintf("health: a Warnable with code %q was already registered", w.Code))
	}

	mak.Set(&registeredWarnables, w.Code, w)
	return w
}

// unregister removes a Warnable from the health package. It should only be used
// for testing purposes.
func unregister(w *Warnable) {
	if registeredWarnables[w.Code] == nil {
		panic(fmt.Sprintf("health: attempting to unregister Warnable %q that was not registered", w.Code))
	}
	delete(registeredWarnables, w.Code)
}

// WarnableCode is a string that distinguishes each Warnable from others. It is globally unique within
// the program.
type WarnableCode string

// A Warnable is something that we might want to warn the user about, or not. A
// Warnable is either in a healthy or unhealthy state. A Warnable is unhealthy if
// the Tracker knows about a WarningState affecting the Warnable.
//
// In most cases, Warnables are components of the backend (for instance, "DNS"
// or "Magicsock"). Warnables are similar to the Subsystem type previously used
// in this package, but they provide a unique identifying code for each
// Warnable, along with more metadata that makes it easier for a GUI to display
// the Warnable in a user-friendly way.
type Warnable struct {
	// Code is a string that uniquely identifies this Warnable across the entire Tailscale backend,
	// and can be mapped to a user-displayable localized string.
	Code WarnableCode
	// Title is a string that the GUI uses as title for any message involving this Warnable. The title
	// should be short and fit in a single line.
	Title string
	// Text is a function that generates an extended string that the GUI will display to the user when
	// this Warnable is in an unhealthy state. The function can use the Args map to provide dynamic
	// information to the user.
	Text func(args Args) string
	// Severity is the severity of the Warnable, which the GUI can use to determine how to display it.
	// For instance, a Warnable with SeverityHigh could trigger a modal view, while a Warnable with
	// SeverityLow could be displayed in a less intrusive way.
	// TODO(angott): turn this into a SeverityFunc, which allows the Warnable to change its severity based on
	// the Args of the unhappy state, just like we do in the Text function.
	Severity Severity
	// DependsOn is a set of Warnables that this Warnable depends on and need to be healthy
	// before this Warnable is relevant. The GUI can use this information to ignore
	// this Warnable if one of its dependencies is unhealthy.
	// That is, if any of these Warnables are unhealthy, then this Warnable is not relevant
	// and should be considered healthy to bother the user about.
	DependsOn []*Warnable

	// MapDebugFlag is a MapRequest.DebugFlag that is sent to control when this Warnable is unhealthy
	//
	// Deprecated: this is only used in one case, and will be removed in a future PR
	MapDebugFlag string

	// ImpactsConnectivity is whether this Warnable in an unhealthy state will impact the user's
	// ability to connect to the Internet or other nodes on the tailnet. On platforms where
	// the client GUI supports a tray icon, the client will display an exclamation mark
	// on the tray icon when ImpactsConnectivity is set to true and the Warnable is unhealthy.
	ImpactsConnectivity bool

	// TimeToVisible is the Duration that the Warnable has to be in an unhealthy state before it
	// should be surfaced as unhealthy to the user. This is used to prevent transient errors from being
	// displayed to the user.
	TimeToVisible time.Duration
}

// StaticMessage returns a function that always returns the input string, to be used in
// simple Warnables that do not use the Args map to generate their Text.
func StaticMessage(s string) func(Args) string {
	return func(Args) string { return s }
}

// nil reports whether t is nil.
// It exists to accept nil *Tracker receivers on all methods
// to at least not crash. But because a nil receiver indicates
// some lost Tracker plumbing, we want to capture stack trace
// samples when it occurs.
func (t *Tracker) nil() bool {
	if t != nil {
		return false
	}

	if cibuild.On() {
		stack := make([]byte, 1<<10)
		stack = stack[:runtime.Stack(stack, false)]
		fmt.Fprintf(os.Stderr, "## WARNING: (non-fatal) nil health.Tracker (being strict in CI):\n%s\n", stack)
	}
	// TODO(bradfitz): open source our "unexpected" package
	// and use it here to capture samples of stacks where
	// t is nil.
	return true
}

// Severity represents how serious an error is. Each GUI interprets this severity value in different ways,
// to surface the error in a more or less visible way. For instance, the macOS GUI could change its menubar
// icon to display an exclamation mark and present a modal notification for SeverityHigh warnings, but not
// for SeverityLow messages, which would only appear in the Settings window.
type Severity string

const (
	// SeverityHigh is the highest severity level, used for critical errors that need immediate attention.
	// On platforms where the client GUI can deliver notifications, a SeverityHigh Warnable will trigger
	// a modal notification.
	SeverityHigh Severity = "high"
	// SeverityMedium is used for errors that are important but not critical. This won't trigger a modal
	// notification, however it will be displayed in a more visible way than a SeverityLow Warnable.
	SeverityMedium Severity = "medium"
	// SeverityLow is used for less important notices that don't need immediate attention. The user will
	// have to go to a Settings window, or another "hidden" GUI location to see these messages.
	SeverityLow Severity = "low"
)

// Args is a map of Args to string values that can be used to provide parameters regarding
// the unhealthy state of a Warnable.
// For instance, if you have a Warnable to track the health of DNS lookups, here you can include
// the hostname that failed to resolve, or the IP address of the DNS server that has been failing
// to respond. You can then use these parameters in the Text function of the Warnable to provide a detailed
// error message to the user.
type Args map[Arg]string

// A warningState is a condition affecting a Warnable. For each Warnable known to the Tracker, a Warnable
// is in an unhappy state if there is a warningState associated with the Warnable.
type warningState struct {
	BrokenSince time.Time // when the Warnable became unhealthy
	Args        Args      // args can be used to provide parameters to the function that generates the Text in the Warnable
}

func (ws *warningState) Equal(other *warningState) bool {
	if ws == nil && other == nil {
		return true
	}
	if ws == nil || other == nil {
		return false
	}
	return ws.BrokenSince.Equal(other.BrokenSince) && maps.Equal(ws.Args, other.Args)
}

// IsVisible returns whether the Warnable should be visible to the user, based on the TimeToVisible
// field of the Warnable and the BrokenSince time when the Warnable became unhealthy.
func (w *Warnable) IsVisible(ws *warningState, clockNow func() time.Time) bool {
	if ws == nil || w.TimeToVisible == 0 {
		return true
	}
	return clockNow().Sub(ws.BrokenSince) >= w.TimeToVisible
}

// SetMetricsRegistry sets up the metrics for the Tracker. It takes
// a usermetric.Registry and registers the metrics there.
func (t *Tracker) SetMetricsRegistry(reg *usermetric.Registry) {
	if reg == nil || t.metricHealthMessage != nil {
		return
	}

	t.metricHealthMessage = usermetric.NewMultiLabelMapWithRegistry[metricHealthMessageLabel](
		reg,
		"tailscaled_health_messages",
		"gauge",
		"Number of health messages broken down by type.",
	)

	t.metricHealthMessage.Set(metricHealthMessageLabel{
		Type: MetricLabelWarning,
	}, expvar.Func(func() any {
		if t.nil() {
			return 0
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		t.updateBuiltinWarnablesLocked()
		return int64(len(t.stringsLocked()))
	}))
}

// IsUnhealthy reports whether the current state is unhealthy because the given
// warnable is set.
func (t *Tracker) IsUnhealthy(w *Warnable) bool {
	if t.nil() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	_, exists := t.warnableVal[w]
	return exists
}

// SetUnhealthy sets a warningState for the given Warnable with the provided Args, and should be
// called when a Warnable becomes unhealthy, or its unhealthy status needs to be updated.
// SetUnhealthy takes ownership of args. The args can be nil if no additional information is
// needed for the unhealthy state.
func (t *Tracker) SetUnhealthy(w *Warnable, args Args) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setUnhealthyLocked(w, args)
}

func (t *Tracker) setUnhealthyLocked(w *Warnable, args Args) {
	if w == nil {
		return
	}

	// If we already have a warningState for this Warnable with an earlier BrokenSince time, keep that
	// BrokenSince time.
	brokenSince := t.now()
	if existingWS := t.warnableVal[w]; existingWS != nil {
		brokenSince = existingWS.BrokenSince
	}

	if t.warnableVal[w] == nil {
		t.warnables = append(t.warnables, w)
	}
	ws := &warningState{
		BrokenSince: brokenSince,
		Args:        args,
	}
	prevWs := t.warnableVal[w]
	mak.Set(&t.warnableVal, w, ws)
	if !ws.Equal(prevWs) {

		change := Change{
			WarnableChanged: true,
			Warnable:        w,
			UnhealthyState:  w.unhealthyState(ws),
		}
		// Publish the change to the event bus. If the change is already visible
		// now, publish it immediately; otherwise queue a timer to publish it at
		// a future time when it becomes visible.
		if w.IsVisible(ws, t.now) {
			t.changePub.Publish(change)
		} else {
			visibleIn := w.TimeToVisible - t.now().Sub(brokenSince)
			tc := t.clock().AfterFunc(visibleIn, func() {
				t.mu.Lock()
				defer t.mu.Unlock()
				// Check if the Warnable is still unhealthy, as it could have become healthy between the time
				// the timer was set for and the time it was executed.
				if t.warnableVal[w] != nil {
					t.changePub.Publish(change)
					delete(t.pendingVisibleTimers, w)
				}
			})
			mak.Set(&t.pendingVisibleTimers, w, tc)
		}
	}
}

// SetHealthy removes any warningState for the given Warnable.
func (t *Tracker) SetHealthy(w *Warnable) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setHealthyLocked(w)
}

func (t *Tracker) setHealthyLocked(w *Warnable) {
	if t.warnableVal[w] == nil {
		// Nothing to remove
		return
	}

	delete(t.warnableVal, w)

	// Stop any pending visiblity timers for this Warnable
	if canc, ok := t.pendingVisibleTimers[w]; ok {
		canc.Stop()
		delete(t.pendingVisibleTimers, w)
	}

	change := Change{
		WarnableChanged: true,
		Warnable:        w,
	}
	t.changePub.Publish(change)
}

// notifyWatchersControlChangedLocked calls each watcher to signal that control
// health messages have changed (and should be fetched via CurrentState).
func (t *Tracker) notifyWatchersControlChangedLocked() {
	change := Change{
		ControlHealthChanged: true,
	}
	t.changePub.Publish(change)
}

// AppendWarnableDebugFlags appends to base any health items that are currently in failed
// state and were created with MapDebugFlag.
func (t *Tracker) AppendWarnableDebugFlags(base []string) []string {
	if t.nil() {
		return base
	}

	ret := base

	t.mu.Lock()
	defer t.mu.Unlock()
	for w, err := range t.warnableVal {
		if w.MapDebugFlag == "" {
			continue
		}
		if err != nil {
			ret = append(ret, w.MapDebugFlag)
		}
	}
	sort.Strings(ret[len(base):]) // sort the new ones
	return ret
}

// Change is used to communicate a change to health. This could either be due to
// a Warnable changing from health to unhealthy (or vice-versa), or because the
// health messages received from the control-plane have changed.
//
// Exactly one *Changed field will be true.
type Change struct {
	// ControlHealthChanged indicates it was health messages from the
	// control-plane server that changed.
	ControlHealthChanged bool

	// WarnableChanged indicates it was a client Warnable which changed state.
	WarnableChanged bool
	// Warnable is whose health changed, as indicated in UnhealthyState.
	Warnable *Warnable
	// UnhealthyState is set if the changed Warnable is now unhealthy, or nil
	// if Warnable is now healthy.
	UnhealthyState *UnhealthyState
}

// SetRouterHealth sets the state of the wgengine/router.Router.
//
// Deprecated: Warnables should be preferred over Subsystem errors.
func (t *Tracker) SetRouterHealth(err error) { t.setErr(SysRouter, err) }

// RouterHealth returns the wgengine/router.Router error state.
//
// Deprecated: Warnables should be preferred over Subsystem errors.
func (t *Tracker) RouterHealth() error { return t.get(SysRouter) }

// SetDNSHealth sets the state of the net/dns.Manager
//
// Deprecated: Warnables should be preferred over Subsystem errors.
func (t *Tracker) SetDNSHealth(err error) { t.setErr(SysDNS, err) }

// DNSHealth returns the net/dns.Manager error state.
//
// Deprecated: Warnables should be preferred over Subsystem errors.
func (t *Tracker) DNSHealth() error { return t.get(SysDNS) }

// SetDNSManagerHealth sets the state of the Linux net/dns manager's
// discovery of the /etc/resolv.conf situation.
//
// Deprecated: Warnables should be preferred over Subsystem errors.
func (t *Tracker) SetDNSManagerHealth(err error) { t.setErr(SysDNSManager, err) }

// SetTKAHealth sets the health of the tailnet key authority.
//
// Deprecated: Warnables should be preferred over Subsystem errors.
func (t *Tracker) SetTKAHealth(err error) { t.setErr(SysTKA, err) }

// TKAHealth returns the tailnet key authority error state.
//
// Deprecated: Warnables should be preferred over Subsystem errors.
func (t *Tracker) TKAHealth() error { return t.get(SysTKA) }

// SetLocalLogConfigHealth sets the error state of this client's local log configuration.
func (t *Tracker) SetLocalLogConfigHealth(err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.localLogConfigErr = err
}

// SetTLSConnectionError sets the error state for connections to a specific
// host. Setting the error to nil will clear any previously-set error.
func (t *Tracker) SetTLSConnectionError(host string, err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err == nil {
		delete(t.tlsConnectionErrors, host)
	} else {
		mak.Set(&t.tlsConnectionErrors, host, err)
	}
}

func RegisterDebugHandler(typ string, h http.Handler) {
	mu.Lock()
	defer mu.Unlock()
	mak.Set(&debugHandler, typ, h)
}

func DebugHandler(typ string) http.Handler {
	mu.Lock()
	defer mu.Unlock()
	return debugHandler[typ]
}

func (t *Tracker) get(key Subsystem) error {
	if t.nil() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sysErr[key]
}

func (t *Tracker) setErr(key Subsystem, err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.setLocked(key, err)
}

func (t *Tracker) setLocked(key Subsystem, err error) {
	if t.sysErr == nil {
		t.sysErr = map[Subsystem]error{}
	}
	old, ok := t.sysErr[key]
	if !ok && err == nil {
		// Initial happy path.
		t.sysErr[key] = nil
		t.selfCheckLocked()
		return
	}
	if ok && (old == nil) == (err == nil) {
		// No change in overall error status (nil-vs-not), so
		// don't run callbacks, but exact error might've
		// changed, so note it.
		if err != nil {
			t.sysErr[key] = err
		}
		return
	}
	t.sysErr[key] = err
	t.selfCheckLocked()
}

// updateLegacyErrorWarnableLocked takes a legacy Subsystem and an optional error, and
// updates the WarningState for that legacy Subsystem, setting it to healthy or unhealthy.
// It is used temporarily while we migrate from Subsystems to Warnables.
//
// Deprecated: this function will be removed after migrating all subsystem errors to use
// Warnables instead.
func (t *Tracker) updateLegacyErrorWarnableLocked(key Subsystem, err error) {
	w := key.Warnable()
	if err != nil {
		t.setUnhealthyLocked(key.Warnable(), Args{legacyErrorArgKey: err.Error()})
	} else {
		t.setHealthyLocked(w)
	}
}

func (t *Tracker) SetControlHealth(problems map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.controlMessages = problems

	t.selfCheckLocked()
}

// GotStreamedMapResponse notes that we got a tailcfg.MapResponse
// message in streaming mode, even if it's just a keep-alive message.
//
// This also notes that a map poll is in progress. To unset that, call
// SetOutOfPollNetMap().
func (t *Tracker) GotStreamedMapResponse() {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastStreamedMapResponse = t.now()
	if !t.inMapPoll {
		t.inMapPoll = true
		t.inMapPollSince = t.now()
	}
	t.selfCheckLocked()
}

// SetOutOfPollNetMap records that the client is no longer in
// an HTTP map request long poll to the control plane.
func (t *Tracker) SetOutOfPollNetMap() {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.inMapPoll {
		return
	}
	t.inMapPoll = false
	t.lastMapPollEndedAt = t.now()
	t.selfCheckLocked()
}

// GetInPollNetMap reports whether the client has an open
// HTTP long poll open to the control plane.
func (t *Tracker) GetInPollNetMap() bool {
	if t.nil() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.inMapPoll
}

// SetMagicSockDERPHome notes what magicsock's view of its home DERP is.
//
// The homeless parameter is whether magicsock is running in DERP-disconnected
// mode, without discovering and maintaining a connection to its home DERP.
func (t *Tracker) SetMagicSockDERPHome(region int, homeless bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.derpHomeRegion = region
	t.derpHomeless = homeless
	t.selfCheckLocked()
}

// NoteMapRequestHeard notes whenever we successfully sent a map request
// to control for which we received a 200 response.
func (t *Tracker) NoteMapRequestHeard(mr *tailcfg.MapRequest) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// TODO: extract mr.HostInfo.NetInfo.PreferredDERP, compare
	// against SetMagicSockDERPHome and
	// SetDERPRegionConnectedState

	t.lastMapRequestHeard = t.now()
	t.selfCheckLocked()
}

func (t *Tracker) SetDERPRegionConnectedState(region int, connected bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	mak.Set(&t.derpRegionConnected, region, connected)
	t.selfCheckLocked()
}

// SetDERPRegionHealth sets or clears any problem associated with the
// provided DERP region.
func (t *Tracker) SetDERPRegionHealth(region int, problem string) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if problem == "" {
		delete(t.derpRegionHealthProblem, region)
	} else {
		mak.Set(&t.derpRegionHealthProblem, region, problem)
	}
	t.selfCheckLocked()
}

// NoteDERPRegionReceivedFrame is called to note that a frame was received from
// the given DERP region at the current time.
func (t *Tracker) NoteDERPRegionReceivedFrame(region int) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	mak.Set(&t.derpRegionLastFrame, region, t.now())
	t.selfCheckLocked()
}

// GetDERPRegionReceivedTime returns the last time that a frame was received
// from the given DERP region, or the zero time if no communication with that
// region has occurred.
func (t *Tracker) GetDERPRegionReceivedTime(region int) time.Time {
	if t.nil() {
		return time.Time{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.derpRegionLastFrame[region]
}

// SetDERPMap sets the last fetched DERP map in the Tracker. The DERP map is used
// to provide a region name in user-facing DERP-related warnings.
func (t *Tracker) SetDERPMap(dm *tailcfg.DERPMap) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.derpMap = dm
	t.selfCheckLocked()
}

// derpRegionNameLocked returns the name of the DERP region with the given ID
// or the empty string if unknown.
func (t *Tracker) derpRegionNameLocked(regID int) string {
	if t.derpMap == nil {
		return ""
	}
	if r, ok := t.derpMap.Regions[regID]; ok {
		return r.RegionName
	}
	return ""
}

// state is an ipn.State.String() value: "Running", "Stopped", "NeedsLogin", etc.
func (t *Tracker) SetIPNState(state string, wantRunning bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ipnState = state
	prevWantRunning := t.ipnWantRunning
	t.ipnWantRunning = wantRunning

	if state == "Running" {
		// Any time we are told the backend is Running (control+DERP are connected), the Warnable
		// should be set to healthy, no matter if 5 seconds have passed or not.
		t.setHealthyLocked(warmingUpWarnable)
	} else if wantRunning && !prevWantRunning && t.ipnWantRunningLastTrue.IsZero() {
		// The first time we see wantRunning=true and it used to be false, it means the user requested
		// the backend to start. We store this timestamp and use it to silence some warnings that are
		// expected during startup.
		t.ipnWantRunningLastTrue = t.now()
		t.setUnhealthyLocked(warmingUpWarnable, nil)
		t.clock().AfterFunc(warmingUpWarnableDuration, func() {
			t.mu.Lock()
			t.updateWarmingUpWarnableLocked()
			t.mu.Unlock()
		})
	} else if !wantRunning {
		// Reset the timer when the user decides to stop the backend.
		t.ipnWantRunningLastTrue = time.Time{}
	}

	t.selfCheckLocked()
}

// SetAnyInterfaceUp sets whether any network interface is up.
func (t *Tracker) SetAnyInterfaceUp(up bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.anyInterfaceUp.Set(up)
	t.selfCheckLocked()
}

// SetUDP4Unbound sets whether the udp4 bind failed completely.
func (t *Tracker) SetUDP4Unbound(unbound bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	if unbound {
		t.setUnhealthyLocked(noUDP4BindWarnable, nil)
	} else {
		t.setHealthyLocked(noUDP4BindWarnable)
	}
}

// SetAuthRoutineInError records the latest error encountered as a result of a
// login attempt. Providing a nil error indicates successful login, or that
// being logged in w/coordination is not currently desired.
func (t *Tracker) SetAuthRoutineInError(err error) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err == nil && t.lastLoginErr == nil {
		return
	}
	t.lastLoginErr = err
	t.selfCheckLocked()
}

// SetLatestVersion records the latest version of the Tailscale client.
// v can be nil if unknown.
func (t *Tracker) SetLatestVersion(v *tailcfg.ClientVersion) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.latestVersion = v
	t.selfCheckLocked()
}

// SetAutoUpdatePrefs sets the client auto-update preferences. The arguments
// match the fields of ipn.AutoUpdatePrefs, but we cannot pass that struct
// directly due to a circular import.
func (t *Tracker) SetAutoUpdatePrefs(check bool, apply opt.Bool) {
	if t.nil() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.checkForUpdates == check && t.applyUpdates == apply {
		return
	}
	t.checkForUpdates = check
	t.applyUpdates = apply
	t.selfCheckLocked()
}

func (t *Tracker) timerSelfCheck() {
	if t.nil() {
		return
	}
	t.initOnce.Do(t.doOnceInit)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.checkReceiveFuncsLocked()
	t.selfCheckLocked()
	if t.timer != nil {
		t.timer.Reset(time.Minute)
	}
}

func (t *Tracker) selfCheckLocked() {
	if t.ipnState == "" {
		// Don't check yet.
		return
	}
	t.updateBuiltinWarnablesLocked()
}

// OverallError returns a summary of the health state.
//
// If there are multiple problems, the error will be of type
// multierr.Error.
func (t *Tracker) OverallError() error {
	if t.nil() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.updateBuiltinWarnablesLocked()
	return t.multiErrLocked()
}

// Strings() returns a string array containing the Text of all Warnings and
// ControlHealth messages currently known to the Tracker. These strings can be
// presented to the user, although ideally you would use the Code property on
// each Warning to show a localized version of them instead. This function is
// here for legacy compatibility purposes and is deprecated.
func (t *Tracker) Strings() []string {
	if t.nil() {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.stringsLocked()
}

func (t *Tracker) stringsLocked() []string {
	result := []string{}
	for w, ws := range t.warnableVal {
		if !w.IsVisible(ws, t.now) {
			// Do not append invisible warnings.
			continue
		}
		if t.isEffectivelyHealthyLocked(w) {
			continue
		}
		if ws.Args == nil {
			result = append(result, w.Text(Args{}))
		} else {
			result = append(result, w.Text(ws.Args))
		}
	}

	warnLen := len(result)
	for _, c := range t.controlMessages {
		var msg string
		if c.Title != "" && c.Text != "" {
			msg = c.Title + ": " + c.Text
		} else if c.Title != "" {
			msg = c.Title + "."
		} else if c.Text != "" {
			msg = c.Text
		}
		if c.PrimaryAction != nil {
			msg = msg + " " + c.PrimaryAction.Label + ": " + c.PrimaryAction.URL
		}
		result = append(result, msg)
	}
	sort.Strings(result[warnLen:])

	return result
}

// errorsLocked returns an array of errors where each error is the Text
// of a Warning known to the Tracker.
// This function is here for legacy compatibility purposes and is deprecated.
func (t *Tracker) errorsLocked() []error {
	strs := t.stringsLocked()
	errs := []error{}
	for _, str := range strs {
		errs = append(errs, errors.New(str))
	}
	return errs
}

// multiErrLocked returns an error listing all errors known to the Tracker.
// This function is here for legacy compatibility purposes and is deprecated.
func (t *Tracker) multiErrLocked() error {
	errs := t.errorsLocked()
	return multierr.New(errs...)
}

var fakeErrForTesting = envknob.RegisterString("TS_DEBUG_FAKE_HEALTH_ERROR")

// updateBuiltinWarnablesLocked performs a number of checks on the state of the backend,
// and adds/removes Warnings from the Tracker as needed.
func (t *Tracker) updateBuiltinWarnablesLocked() {
	t.updateWarmingUpWarnableLocked()

	if w, show := t.showUpdateWarnable(); show {
		t.setUnhealthyLocked(w, Args{
			ArgCurrentVersion:   version.Short(),
			ArgAvailableVersion: t.latestVersion.LatestVersion,
		})
	} else {
		t.setHealthyLocked(updateAvailableWarnable)
		t.setHealthyLocked(securityUpdateAvailableWarnable)
	}

	if version.IsUnstableBuild() {
		t.setUnhealthyLocked(unstableWarnable, Args{
			ArgCurrentVersion: version.Short(),
		})
	}

	if v, ok := t.anyInterfaceUp.Get(); ok && !v {
		t.setUnhealthyLocked(NetworkStatusWarnable, nil)
	} else {
		t.setHealthyLocked(NetworkStatusWarnable)
	}

	if t.localLogConfigErr != nil {
		t.setUnhealthyLocked(localLogWarnable, Args{
			ArgError: t.localLogConfigErr.Error(),
		})
	} else {
		t.setHealthyLocked(localLogWarnable)
	}

	now := t.now()

	// How long we assume we'll have heard a DERP frame or a MapResponse
	// KeepAlive by.
	const tooIdle = 2*time.Minute + 5*time.Second

	// Whether user recently turned on Tailscale.
	recentlyOn := now.Sub(t.ipnWantRunningLastTrue) < 5*time.Second

	homeDERP := t.derpHomeRegion
	if recentlyOn || !t.inMapPoll {
		// If user just turned Tailscale on, don't warn for a bit.
		// Also, if we're not in a map poll, that means we don't yet
		// have a DERPMap or aren't in a state where we even want
		t.setHealthyLocked(noDERPHomeWarnable)
		t.setHealthyLocked(noDERPConnectionWarnable)
		t.setHealthyLocked(derpTimeoutWarnable)
	} else if !t.ipnWantRunning || t.derpHomeless || homeDERP != 0 {
		t.setHealthyLocked(noDERPHomeWarnable)
	} else {
		t.setUnhealthyLocked(noDERPHomeWarnable, nil)
	}

	if homeDERP != 0 && t.derpRegionConnected[homeDERP] {
		t.setHealthyLocked(noDERPConnectionWarnable)

		if d := now.Sub(t.derpRegionLastFrame[homeDERP]); d < tooIdle {
			t.setHealthyLocked(derpTimeoutWarnable)
		} else {
			t.setUnhealthyLocked(derpTimeoutWarnable, Args{
				ArgDERPRegionID:   fmt.Sprint(homeDERP),
				ArgDERPRegionName: t.derpRegionNameLocked(homeDERP),
				ArgDuration:       d.Round(time.Second).String(),
			})
		}
	} else if homeDERP != 0 {
		t.setUnhealthyLocked(noDERPConnectionWarnable, Args{
			ArgDERPRegionID:   fmt.Sprint(homeDERP),
			ArgDERPRegionName: t.derpRegionNameLocked(homeDERP),
		})
	} else {
		// No DERP home yet determined yet. There's probably some
		// other problem or things are just starting up.
		t.setHealthyLocked(noDERPConnectionWarnable)
	}

	if !t.ipnWantRunning {
		t.setUnhealthyLocked(IPNStateWarnable, Args{
			"State": t.ipnState,
		})
		return
	} else {
		t.setHealthyLocked(IPNStateWarnable)
	}

	if t.lastLoginErr != nil {
		var errMsg string
		if !errors.Is(t.lastLoginErr, context.Canceled) {
			errMsg = t.lastLoginErr.Error()
		}
		t.setUnhealthyLocked(LoginStateWarnable, Args{
			ArgError: errMsg,
		})
		return
	} else {
		t.setHealthyLocked(LoginStateWarnable)
	}

	if !t.inMapPoll && (t.lastMapPollEndedAt.IsZero() || now.Sub(t.lastMapPollEndedAt) > 10*time.Second) {
		t.setUnhealthyLocked(notInMapPollWarnable, nil)
		return
	} else {
		t.setHealthyLocked(notInMapPollWarnable)
	}

	if d := now.Sub(t.lastStreamedMapResponse).Round(time.Second); d > tooIdle {
		t.setUnhealthyLocked(mapResponseTimeoutWarnable, Args{
			ArgDuration: d.String(),
		})
		return
	} else {
		t.setHealthyLocked(mapResponseTimeoutWarnable)
	}

	// TODO: use
	_ = t.inMapPollSince
	_ = t.lastMapPollEndedAt
	_ = t.lastStreamedMapResponse
	_ = t.lastMapRequestHeard

	shouldClearMagicsockWarnings := true
	for i := range t.MagicSockReceiveFuncs {
		f := &t.MagicSockReceiveFuncs[i]
		if f.missing {
			t.setUnhealthyLocked(magicsockReceiveFuncWarnable, Args{
				ArgMagicsockFunctionName: f.name,
			})
			shouldClearMagicsockWarnings = false
			break
		}
	}
	if shouldClearMagicsockWarnings {
		t.setHealthyLocked(magicsockReceiveFuncWarnable)
	}

	// Iterates over the legacy subsystems and their error, and turns them into structured errors
	for sys, err := range t.sysErr {
		t.updateLegacyErrorWarnableLocked(sys, err)
	}

	if len(t.derpRegionHealthProblem) > 0 {
		for regionID, problem := range t.derpRegionHealthProblem {
			t.setUnhealthyLocked(derpRegionErrorWarnable, Args{
				ArgDERPRegionID: fmt.Sprint(regionID),
				ArgError:        problem,
			})
		}
	} else {
		t.setHealthyLocked(derpRegionErrorWarnable)
	}

	// Check if control health messages have changed
	if !maps.EqualFunc(t.lastNotifiedControlMessages, t.controlMessages, tailcfg.DisplayMessage.Equal) {
		t.lastNotifiedControlMessages = t.controlMessages
		t.notifyWatchersControlChangedLocked()
	}

	if err := envknob.ApplyDiskConfigError(); err != nil {
		t.setUnhealthyLocked(applyDiskConfigWarnable, Args{
			ArgError: err.Error(),
		})
	} else {
		t.setHealthyLocked(applyDiskConfigWarnable)
	}

	if len(t.tlsConnectionErrors) > 0 {
		for serverName, err := range t.tlsConnectionErrors {
			t.setUnhealthyLocked(tlsConnectionFailedWarnable, Args{
				ArgServerName: serverName,
				ArgError:      err.Error(),
			})
		}
	} else {
		t.setHealthyLocked(tlsConnectionFailedWarnable)
	}

	if e := fakeErrForTesting(); len(t.warnables) == 0 && e != "" {
		t.setUnhealthyLocked(testWarnable, Args{
			ArgError: e,
		})
	} else {
		t.setHealthyLocked(testWarnable)
	}
}

// updateWarmingUpWarnableLocked ensures the warmingUpWarnable is healthy if wantRunning has been set to true
// for more than warmingUpWarnableDuration.
func (t *Tracker) updateWarmingUpWarnableLocked() {
	if !t.ipnWantRunningLastTrue.IsZero() && t.now().After(t.ipnWantRunningLastTrue.Add(warmingUpWarnableDuration)) {
		t.setHealthyLocked(warmingUpWarnable)
	}
}

func (t *Tracker) showUpdateWarnable() (*Warnable, bool) {
	if !t.checkForUpdates {
		return nil, false
	}
	cv := t.latestVersion
	if cv == nil || cv.RunningLatest || cv.LatestVersion == "" {
		return nil, false
	}
	if cv.UrgentSecurityUpdate {
		return securityUpdateAvailableWarnable, true
	}
	// Only show update warning when auto-updates are off
	if !t.applyUpdates.EqualBool(true) {
		return updateAvailableWarnable, true
	}
	return nil, false
}

// ReceiveFuncStats tracks the calls made to a wireguard-go receive func.
type ReceiveFuncStats struct {
	// name is the name of the receive func.
	// It's lazily populated.
	name string
	// numCalls is the number of times the receive func has ever been called.
	// It is required because it is possible for a receive func's wireguard-go goroutine
	// to be active even though the receive func isn't.
	// The wireguard-go goroutine alternates between calling the receive func and
	// processing what the func returned.
	numCalls atomic.Uint64
	// prevNumCalls is the value of numCalls last time the health check examined it.
	prevNumCalls uint64
	// inCall indicates whether the receive func is currently running.
	inCall atomic.Bool
	// missing indicates whether the receive func is not running.
	missing bool
}

// Name returns the name of the receive func ("ReceiveIPv4", "ReceiveIPv6", etc).
func (s *ReceiveFuncStats) Name() string {
	return s.name
}

func (s *ReceiveFuncStats) Enter() {
	s.numCalls.Add(1)
	s.inCall.Store(true)
}

func (s *ReceiveFuncStats) Exit() {
	s.inCall.Store(false)
}

// ReceiveFuncStats returns the ReceiveFuncStats tracker for the given func
// type.
//
// If t is nil, it returns nil.
func (t *Tracker) ReceiveFuncStats(which ReceiveFunc) *ReceiveFuncStats {
	if t == nil {
		return nil
	}
	t.initOnce.Do(t.doOnceInit)
	return &t.MagicSockReceiveFuncs[which]
}

func (t *Tracker) doOnceInit() {
	for i := range t.MagicSockReceiveFuncs {
		f := &t.MagicSockReceiveFuncs[i]
		f.name = (ReceiveFunc(i)).String()
	}
}

func (t *Tracker) checkReceiveFuncsLocked() {
	for i := range t.MagicSockReceiveFuncs {
		f := &t.MagicSockReceiveFuncs[i]
		if runtime.GOOS == "js" && i < 2 {
			// Skip IPv4 and IPv6 on js.
			continue
		}
		f.missing = false
		prev := f.prevNumCalls
		numCalls := f.numCalls.Load()
		f.prevNumCalls = numCalls
		if numCalls > prev {
			// OK: the function has gotten called since last we checked
			continue
		}
		if f.inCall.Load() {
			// OK: the function is active, probably blocked due to inactivity
			continue
		}
		// Not OK: The function is not active, and not accumulating new calls.
		// It is probably MIA.
		f.missing = true
	}
}

// LastNoiseDialWasRecent notes that we're attempting to dial control via the
// ts2021 noise protocol and reports whether the prior dial was "recent"
// (currently defined as 2 minutes but subject to change).
//
// If t is nil, it reports false.
func (t *Tracker) LastNoiseDialWasRecent() bool {
	if t.nil() {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	dur := now.Sub(t.lastNoiseDial)
	t.lastNoiseDial = now
	return dur < 2*time.Minute
}

const MetricLabelWarning = "warning"

type metricHealthMessageLabel struct {
	// TODO: break down by warnable.severity as well?
	Type string
}
