// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package health is a registry for other packages to report & check
// overall health status of the node.
package health

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/util/multierr"
	"tailscale.com/util/set"
)

var (
	// mu guards everything in this var block.
	mu sync.Mutex

	sysErr    = map[Subsystem]error{}                   // error key => err (or nil for no error)
	watchers  = set.HandleSet[func(Subsystem, error)]{} // opt func to run if error state changes
	warnables = set.Set[*Warnable]{}
	timer     *time.Timer

	debugHandler = map[string]http.Handler{}

	inMapPoll               bool
	inMapPollSince          time.Time
	lastMapPollEndedAt      time.Time
	lastStreamedMapResponse time.Time
	derpHomeRegion          int
	derpHomeless            bool
	derpRegionConnected     = map[int]bool{}
	derpRegionHealthProblem = map[int]string{}
	derpRegionLastFrame     = map[int]time.Time{}
	lastMapRequestHeard     time.Time // time we got a 200 from control for a MapRequest
	ipnState                string
	ipnWantRunning          bool
	anyInterfaceUp          = true // until told otherwise
	udp4Unbound             bool
	controlHealth           []string
	lastLoginErr            error
	localLogConfigErr       error
	tlsConnectionErrors     = map[string]error{} // map[ServerName]error
)

// Subsystem is the name of a subsystem whose health can be monitored.
type Subsystem string

const (
	// SysOverall is the name representing the overall health of
	// the system, rather than one particular subsystem.
	SysOverall = Subsystem("overall")

	// SysRouter is the name of the wgengine/router subsystem.
	SysRouter = Subsystem("router")

	// SysDNS is the name of the net/dns subsystem.
	SysDNS = Subsystem("dns")

	// SysDNSOS is the name of the net/dns OSConfigurator subsystem.
	SysDNSOS = Subsystem("dns-os")

	// SysDNSManager is the name of the net/dns manager subsystem.
	SysDNSManager = Subsystem("dns-manager")

	// SysTKA is the name of the tailnet key authority subsystem.
	SysTKA = Subsystem("tailnet-lock")
)

// NewWarnable returns a new warnable item that the caller can mark
// as health or in warning state.
func NewWarnable(opts ...WarnableOpt) *Warnable {
	w := new(Warnable)
	for _, o := range opts {
		o.mod(w)
	}
	mu.Lock()
	defer mu.Unlock()
	warnables.Add(w)
	return w
}

// WarnableOpt is an option passed to NewWarnable.
type WarnableOpt interface {
	mod(*Warnable)
}

// WithMapDebugFlag returns a WarnableOpt for NewWarnable that makes the returned
// Warnable report itself to the coordination server as broken with this
// string in MapRequest.DebugFlag when Set to a non-nil value.
func WithMapDebugFlag(name string) WarnableOpt {
	return warnOptFunc(func(w *Warnable) {
		w.debugFlag = name
	})
}

// WithConnectivityImpact returns an option which makes a Warnable annotated as
// something that could be breaking external network connectivity on the
// machine. This will make the warnable returned by OverallError alongside
// network connectivity errors.
func WithConnectivityImpact() WarnableOpt {
	return warnOptFunc(func(w *Warnable) {
		w.hasConnectivityImpact = true
	})
}

type warnOptFunc func(*Warnable)

func (f warnOptFunc) mod(w *Warnable) { f(w) }

// Warnable is a health check item that may or may not be in a bad warning state.
// The caller of NewWarnable is responsible for calling Set to update the state.
type Warnable struct {
	debugFlag string // optional MapRequest.DebugFlag to send when unhealthy

	// If true, this warning is related to configuration of networking stack
	// on the machine that impacts connectivity.
	hasConnectivityImpact bool

	isSet atomic.Bool
	mu    sync.Mutex
	err   error
}

// Set updates the Warnable's state.
// If non-nil, it's considered unhealthy.
func (w *Warnable) Set(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.err = err
	w.isSet.Store(err != nil)
}

func (w *Warnable) get() error {
	if !w.isSet.Load() {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// AppendWarnableDebugFlags appends to base any health items that are currently in failed
// state and were created with MapDebugFlag.
func AppendWarnableDebugFlags(base []string) []string {
	ret := base

	mu.Lock()
	defer mu.Unlock()
	for w := range warnables {
		if w.debugFlag == "" {
			continue
		}
		if err := w.get(); err != nil {
			ret = append(ret, w.debugFlag)
		}
	}
	sort.Strings(ret[len(base):]) // sort the new ones
	return ret
}

// RegisterWatcher adds a function that will be called if an
// error changes state either to unhealthy or from unhealthy. It is
// not called on transition from unknown to healthy. It must be non-nil
// and is run in its own goroutine. The returned func unregisters it.
func RegisterWatcher(cb func(key Subsystem, err error)) (unregister func()) {
	mu.Lock()
	defer mu.Unlock()
	handle := watchers.Add(cb)
	if timer == nil {
		timer = time.AfterFunc(time.Minute, timerSelfCheck)
	}
	return func() {
		mu.Lock()
		defer mu.Unlock()
		delete(watchers, handle)
		if len(watchers) == 0 && timer != nil {
			timer.Stop()
			timer = nil
		}
	}
}

// SetRouterHealth sets the state of the wgengine/router.Router.
func SetRouterHealth(err error) { setErr(SysRouter, err) }

// RouterHealth returns the wgengine/router.Router error state.
func RouterHealth() error { return get(SysRouter) }

// SetDNSHealth sets the state of the net/dns.Manager
func SetDNSHealth(err error) { setErr(SysDNS, err) }

// DNSHealth returns the net/dns.Manager error state.
func DNSHealth() error { return get(SysDNS) }

// SetDNSOSHealth sets the state of the net/dns.OSConfigurator
func SetDNSOSHealth(err error) { setErr(SysDNSOS, err) }

// SetDNSManagerHealth sets the state of the Linux net/dns manager's
// discovery of the /etc/resolv.conf situation.
func SetDNSManagerHealth(err error) { setErr(SysDNSManager, err) }

// DNSOSHealth returns the net/dns.OSConfigurator error state.
func DNSOSHealth() error { return get(SysDNSOS) }

// SetTKAHealth sets the health of the tailnet key authority.
func SetTKAHealth(err error) { setErr(SysTKA, err) }

// TKAHealth returns the tailnet key authority error state.
func TKAHealth() error { return get(SysTKA) }

// SetLocalLogConfigHealth sets the error state of this client's local log configuration.
func SetLocalLogConfigHealth(err error) {
	mu.Lock()
	defer mu.Unlock()
	localLogConfigErr = err
}

// SetTLSConnectionError sets the error state for connections to a specific
// host. Setting the error to nil will clear any previously-set error.
func SetTLSConnectionError(host string, err error) {
	mu.Lock()
	defer mu.Unlock()
	if err == nil {
		delete(tlsConnectionErrors, host)
	} else {
		tlsConnectionErrors[host] = err
	}
}

func RegisterDebugHandler(typ string, h http.Handler) {
	mu.Lock()
	defer mu.Unlock()
	debugHandler[typ] = h
}

func DebugHandler(typ string) http.Handler {
	mu.Lock()
	defer mu.Unlock()
	return debugHandler[typ]
}

func get(key Subsystem) error {
	mu.Lock()
	defer mu.Unlock()
	return sysErr[key]
}

func setErr(key Subsystem, err error) {
	mu.Lock()
	defer mu.Unlock()
	setLocked(key, err)
}

func setLocked(key Subsystem, err error) {
	old, ok := sysErr[key]
	if !ok && err == nil {
		// Initial happy path.
		sysErr[key] = nil
		selfCheckLocked()
		return
	}
	if ok && (old == nil) == (err == nil) {
		// No change in overall error status (nil-vs-not), so
		// don't run callbacks, but exact error might've
		// changed, so note it.
		if err != nil {
			sysErr[key] = err
		}
		return
	}
	sysErr[key] = err
	selfCheckLocked()
	for _, cb := range watchers {
		go cb(key, err)
	}
}

func SetControlHealth(problems []string) {
	mu.Lock()
	defer mu.Unlock()
	controlHealth = problems
	selfCheckLocked()
}

// GotStreamedMapResponse notes that we got a tailcfg.MapResponse
// message in streaming mode, even if it's just a keep-alive message.
//
// This also notes that a map poll is in progress. To unset that, call
// SetOutOfPollNetMap().
func GotStreamedMapResponse() {
	mu.Lock()
	defer mu.Unlock()
	lastStreamedMapResponse = time.Now()
	if !inMapPoll {
		inMapPoll = true
		inMapPollSince = time.Now()
	}
	selfCheckLocked()
}

// SetOutOfPollNetMap records that the client is no longer in
// an HTTP map request long poll to the control plane.
func SetOutOfPollNetMap() {
	mu.Lock()
	defer mu.Unlock()
	if !inMapPoll {
		return
	}
	inMapPoll = false
	lastMapPollEndedAt = time.Now()
	selfCheckLocked()
}

// GetInPollNetMap reports whether the client has an open
// HTTP long poll open to the control plane.
func GetInPollNetMap() bool {
	mu.Lock()
	defer mu.Unlock()
	return inMapPoll
}

// SetMagicSockDERPHome notes what magicsock's view of its home DERP is.
//
// The homeless parameter is whether magicsock is running in DERP-disconnected
// mode, without discovering and maintaining a connection to its home DERP.
func SetMagicSockDERPHome(region int, homeless bool) {
	mu.Lock()
	defer mu.Unlock()
	derpHomeRegion = region
	derpHomeless = homeless
	selfCheckLocked()
}

// NoteMapRequestHeard notes whenever we successfully sent a map request
// to control for which we received a 200 response.
func NoteMapRequestHeard(mr *tailcfg.MapRequest) {
	mu.Lock()
	defer mu.Unlock()
	// TODO: extract mr.HostInfo.NetInfo.PreferredDERP, compare
	// against SetMagicSockDERPHome and
	// SetDERPRegionConnectedState

	lastMapRequestHeard = time.Now()
	selfCheckLocked()
}

func SetDERPRegionConnectedState(region int, connected bool) {
	mu.Lock()
	defer mu.Unlock()
	derpRegionConnected[region] = connected
	selfCheckLocked()
}

// SetDERPRegionHealth sets or clears any problem associated with the
// provided DERP region.
func SetDERPRegionHealth(region int, problem string) {
	mu.Lock()
	defer mu.Unlock()
	if problem == "" {
		delete(derpRegionHealthProblem, region)
	} else {
		derpRegionHealthProblem[region] = problem
	}
	selfCheckLocked()
}

// NoteDERPRegionReceivedFrame is called to note that a frame was received from
// the given DERP region at the current time.
func NoteDERPRegionReceivedFrame(region int) {
	mu.Lock()
	defer mu.Unlock()
	derpRegionLastFrame[region] = time.Now()
	selfCheckLocked()
}

// GetDERPRegionReceivedTime returns the last time that a frame was received
// from the given DERP region, or the zero time if no communication with that
// region has occurred.
func GetDERPRegionReceivedTime(region int) time.Time {
	mu.Lock()
	defer mu.Unlock()
	return derpRegionLastFrame[region]
}

// state is an ipn.State.String() value: "Running", "Stopped", "NeedsLogin", etc.
func SetIPNState(state string, wantRunning bool) {
	mu.Lock()
	defer mu.Unlock()
	ipnState = state
	ipnWantRunning = wantRunning
	selfCheckLocked()
}

// SetAnyInterfaceUp sets whether any network interface is up.
func SetAnyInterfaceUp(up bool) {
	mu.Lock()
	defer mu.Unlock()
	anyInterfaceUp = up
	selfCheckLocked()
}

// SetUDP4Unbound sets whether the udp4 bind failed completely.
func SetUDP4Unbound(unbound bool) {
	mu.Lock()
	defer mu.Unlock()
	udp4Unbound = unbound
	selfCheckLocked()
}

// SetAuthRoutineInError records the latest error encountered as a result of a
// login attempt. Providing a nil error indicates successful login, or that
// being logged in w/coordination is not currently desired.
func SetAuthRoutineInError(err error) {
	mu.Lock()
	defer mu.Unlock()
	lastLoginErr = err
}

func timerSelfCheck() {
	mu.Lock()
	defer mu.Unlock()
	checkReceiveFuncs()
	selfCheckLocked()
	if timer != nil {
		timer.Reset(time.Minute)
	}
}

func selfCheckLocked() {
	if ipnState == "" {
		// Don't check yet.
		return
	}
	setLocked(SysOverall, overallErrorLocked())
}

// OverallError returns a summary of the health state.
//
// If there are multiple problems, the error will be of type
// multierr.Error.
func OverallError() error {
	mu.Lock()
	defer mu.Unlock()
	return overallErrorLocked()
}

var fakeErrForTesting = envknob.RegisterString("TS_DEBUG_FAKE_HEALTH_ERROR")

// networkErrorf creates an error that indicates issues with outgoing network
// connectivity. Any active warnings related to network connectivity will
// automatically be appended to it.
func networkErrorf(format string, a ...any) error {
	errs := []error{
		fmt.Errorf(format, a...),
	}
	for w := range warnables {
		if !w.hasConnectivityImpact {
			continue
		}
		if err := w.get(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 1 {
		return errs[0]
	}
	return multierr.New(errs...)
}

var errNetworkDown = networkErrorf("network down")
var errNotInMapPoll = networkErrorf("not in map poll")
var errNoDERPHome = errors.New("no DERP home")
var errNoUDP4Bind = networkErrorf("no udp4 bind")

func overallErrorLocked() error {
	if !anyInterfaceUp {
		return errNetworkDown
	}
	if localLogConfigErr != nil {
		return localLogConfigErr
	}
	if !ipnWantRunning {
		return fmt.Errorf("state=%v, wantRunning=%v", ipnState, ipnWantRunning)
	}
	if lastLoginErr != nil {
		return fmt.Errorf("not logged in, last login error=%v", lastLoginErr)
	}
	now := time.Now()
	if !inMapPoll && (lastMapPollEndedAt.IsZero() || now.Sub(lastMapPollEndedAt) > 10*time.Second) {
		return errNotInMapPoll
	}
	const tooIdle = 2*time.Minute + 5*time.Second
	if d := now.Sub(lastStreamedMapResponse).Round(time.Second); d > tooIdle {
		return networkErrorf("no map response in %v", d)
	}
	if !derpHomeless {
		rid := derpHomeRegion
		if rid == 0 {
			return errNoDERPHome
		}
		if !derpRegionConnected[rid] {
			return networkErrorf("not connected to home DERP region %v", rid)
		}
		if d := now.Sub(derpRegionLastFrame[rid]).Round(time.Second); d > tooIdle {
			return networkErrorf("haven't heard from home DERP region %v in %v", rid, d)
		}
	}
	if udp4Unbound {
		return errNoUDP4Bind
	}

	// TODO: use
	_ = inMapPollSince
	_ = lastMapPollEndedAt
	_ = lastStreamedMapResponse
	_ = lastMapRequestHeard

	var errs []error
	for _, recv := range receiveFuncs {
		if recv.missing {
			errs = append(errs, fmt.Errorf("%s is not running", recv.name))
		}
	}
	for sys, err := range sysErr {
		if err == nil || sys == SysOverall {
			continue
		}
		errs = append(errs, fmt.Errorf("%v: %w", sys, err))
	}
	for w := range warnables {
		if err := w.get(); err != nil {
			errs = append(errs, err)
		}
	}
	for regionID, problem := range derpRegionHealthProblem {
		errs = append(errs, fmt.Errorf("derp%d: %v", regionID, problem))
	}
	for _, s := range controlHealth {
		errs = append(errs, errors.New(s))
	}
	if err := envknob.ApplyDiskConfigError(); err != nil {
		errs = append(errs, err)
	}
	for serverName, err := range tlsConnectionErrors {
		errs = append(errs, fmt.Errorf("TLS connection error for %q: %w", serverName, err))
	}
	if e := fakeErrForTesting(); len(errs) == 0 && e != "" {
		return errors.New(e)
	}
	sort.Slice(errs, func(i, j int) bool {
		// Not super efficient (stringifying these in a sort), but probably max 2 or 3 items.
		return errs[i].Error() < errs[j].Error()
	})
	return multierr.New(errs...)
}

var (
	ReceiveIPv4 = ReceiveFuncStats{name: "ReceiveIPv4"}
	ReceiveIPv6 = ReceiveFuncStats{name: "ReceiveIPv6"}
	ReceiveDERP = ReceiveFuncStats{name: "ReceiveDERP"}

	receiveFuncs = []*ReceiveFuncStats{&ReceiveIPv4, &ReceiveIPv6, &ReceiveDERP}
)

func init() {
	if runtime.GOOS == "js" {
		receiveFuncs = receiveFuncs[2:] // ignore IPv4 and IPv6
	}
}

// ReceiveFuncStats tracks the calls made to a wireguard-go receive func.
type ReceiveFuncStats struct {
	// name is the name of the receive func.
	name string
	// numCalls is the number of times the receive func has ever been called.
	// It is required because it is possible for a receive func's wireguard-go goroutine
	// to be active even though the receive func isn't.
	// The wireguard-go goroutine alternates between calling the receive func and
	// processing what the func returned.
	numCalls uint64 // accessed atomically
	// prevNumCalls is the value of numCalls last time the health check examined it.
	prevNumCalls uint64
	// inCall indicates whether the receive func is currently running.
	inCall uint32 // bool, accessed atomically
	// missing indicates whether the receive func is not running.
	missing bool
}

func (s *ReceiveFuncStats) Enter() {
	atomic.AddUint64(&s.numCalls, 1)
	atomic.StoreUint32(&s.inCall, 1)
}

func (s *ReceiveFuncStats) Exit() {
	atomic.StoreUint32(&s.inCall, 0)
}

func checkReceiveFuncs() {
	for _, recv := range receiveFuncs {
		recv.missing = false
		prev := recv.prevNumCalls
		numCalls := atomic.LoadUint64(&recv.numCalls)
		recv.prevNumCalls = numCalls
		if numCalls > prev {
			// OK: the function has gotten called since last we checked
			continue
		}
		if atomic.LoadUint32(&recv.inCall) == 1 {
			// OK: the function is active, probably blocked due to inactivity
			continue
		}
		// Not OK: The function is not active, and not accumulating new calls.
		// It is probably MIA.
		recv.missing = true
	}
}
