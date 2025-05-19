// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/execqueue"
	"tailscale.com/util/mak"
	"tailscale.com/util/testenv"
)

// ExtensionHost is a bridge between the [LocalBackend] and the registered [ipnext.Extension]s.
// It implements [ipnext.Host] and is safe for concurrent use.
//
// A nil pointer to [ExtensionHost] is a valid, no-op extension host which is primarily used in tests
// that instantiate [LocalBackend] directly without using [NewExtensionHost].
//
// The [LocalBackend] is not required to hold its mutex when calling the host's methods,
// but it typically does so either to prevent changes to its state (for example, the current profile)
// while callbacks are executing, or because it calls the host's methods as part of a larger operation
// that requires the mutex to be held.
//
// Extensions might invoke the host's methods either from callbacks triggered by the [LocalBackend],
// or in a response to external events. Some methods can be called by both the extensions and the backend.
//
// As a general rule, the host cannot assume anything about the current state of the [LocalBackend]'s
// internal mutex on entry to its methods, and therefore cannot safely call [LocalBackend] methods directly.
//
// The following are typical and supported patterns:
//   - LocalBackend notifies the host about an event, such as a change in the current profile.
//     The host invokes callbacks registered by Extensions, forwarding the event arguments to them.
//     If necessary, the host can also update its own state for future use.
//   - LocalBackend requests information from the host, such as the effective [ipnauth.AuditLogFunc]
//     or the [ipn.LoginProfile] to use when no GUI/CLI client is connected. Typically, [LocalBackend]
//     provides the required context to the host, and the host returns the result to [LocalBackend]
//     after forwarding the request to the extensions.
//   - Extension invokes the host's method to perform an action, such as switching to the "best" profile
//     in response to a change in the device's state. Since the host does not know whether the [LocalBackend]'s
//     internal mutex is held, it cannot invoke any methods on the [LocalBackend] directly and must instead
//     do so asynchronously, such as by using [ExtensionHost.enqueueBackendOperation].
//   - Extension requests information from the host, such as the effective [ipnauth.AuditLogFunc]
//     or the current [ipn.LoginProfile]. Since the host cannot invoke any methods on the [LocalBackend] directly,
//     it should maintain its own view of the current state, updating it when the [LocalBackend] notifies it
//     about a change or event.
//
// To safeguard against adopting incorrect or risky patterns, the host does not store [LocalBackend] in its fields
// and instead provides [ExtensionHost.enqueueBackendOperation]. Additionally, to make it easier to test extensions
// and to further reduce the risk of accessing unexported methods or fields of [LocalBackend], the host interacts
// with it via the [Backend] interface.
type ExtensionHost struct {
	b     Backend
	hooks ipnext.Hooks
	logf  logger.Logf // prefixed with "ipnext:"

	// allExtensions holds the extensions in the order they were registered,
	// including those that have not yet attempted initialization or have failed to initialize.
	allExtensions []ipnext.Extension

	// initOnce is used to ensure that the extensions are initialized only once,
	// even if [extensionHost.Init] is called multiple times.
	initOnce sync.Once
	initDone atomic.Bool
	// shutdownOnce is like initOnce, but for [ExtensionHost.Shutdown].
	shutdownOnce sync.Once

	// workQueue maintains execution order for asynchronous operations requested by extensions.
	// It is always an [execqueue.ExecQueue] except in some tests.
	workQueue execQueue
	// doEnqueueBackendOperation adds an asynchronous [LocalBackend] operation to the workQueue.
	doEnqueueBackendOperation func(func(Backend))

	shuttingDown atomic.Bool

	extByType sync.Map // reflect.Type -> ipnext.Extension

	// mu protects the following fields.
	// It must not be held when calling [LocalBackend] methods
	// or when invoking callbacks registered by extensions.
	mu sync.Mutex
	// initialized is whether the host and extensions have been fully initialized.
	initialized atomic.Bool
	// activeExtensions is a subset of allExtensions that have been initialized and are ready to use.
	activeExtensions []ipnext.Extension
	// extensionsByName are the extensions indexed by their names.
	// They are not necessarily initialized (in activeExtensions) yet.
	extensionsByName map[string]ipnext.Extension
	// postInitWorkQueue is a queue of functions to be executed
	// by the workQueue after all extensions have been initialized.
	postInitWorkQueue []func(Backend)

	// currentProfile is a read-only view of the currently used profile.
	// The view is always Valid, but might be of an empty, non-persisted profile.
	currentProfile ipn.LoginProfileView
	// currentPrefs is a read-only view of the current profile's [ipn.Prefs]
	// with any private keys stripped. It is always Valid.
	currentPrefs ipn.PrefsView
}

// Backend is a subset of [LocalBackend] methods that are used by [ExtensionHost].
// It is primarily used for testing.
type Backend interface {
	// SwitchToBestProfile switches to the best profile for the current state of the system.
	// The reason indicates why the profile is being switched.
	SwitchToBestProfile(reason string)

	SendNotify(ipn.Notify)

	NodeBackend() ipnext.NodeBackend

	ipnext.SafeBackend
}

// NewExtensionHost returns a new [ExtensionHost] which manages registered extensions for the given backend.
// The extensions are instantiated, but are not initialized until [ExtensionHost.Init] is called.
// It returns an error if instantiating any extension fails.
func NewExtensionHost(logf logger.Logf, b Backend) (*ExtensionHost, error) {
	return newExtensionHost(logf, b)
}

func NewExtensionHostForTest(logf logger.Logf, b Backend, overrideExts ...*ipnext.Definition) (*ExtensionHost, error) {
	if !testenv.InTest() {
		panic("use outside of test")
	}
	return newExtensionHost(logf, b, overrideExts...)
}

// newExtensionHost is the shared implementation of [NewExtensionHost] and
// [NewExtensionHostForTest].
//
// If overrideExts is non-nil, the registered extensions are ignored and the
// provided extensions are used instead. Overriding extensions is primarily used
// for testing.
func newExtensionHost(logf logger.Logf, b Backend, overrideExts ...*ipnext.Definition) (_ *ExtensionHost, err error) {
	host := &ExtensionHost{
		b:         b,
		logf:      logger.WithPrefix(logf, "ipnext: "),
		workQueue: &execqueue.ExecQueue{},
		// The host starts with an empty profile and default prefs.
		// We'll update them once [profileManager] notifies us of the initial profile.
		currentProfile: zeroProfile,
		currentPrefs:   defaultPrefs,
	}

	// All operations on the backend must be executed asynchronously by the work queue.
	// DO NOT retain a direct reference to the backend in the host.
	// See the docstring for [ExtensionHost] for more details.
	host.doEnqueueBackendOperation = func(f func(Backend)) {
		if f == nil {
			panic("nil backend operation")
		}
		host.workQueue.Add(func() { f(b) })
	}

	// Use registered extensions.
	extDef := ipnext.Extensions()
	if overrideExts != nil {
		// Use the provided, potentially empty, overrideExts
		// instead of the registered ones.
		extDef = slices.Values(overrideExts)
	}

	for d := range extDef {
		ext, err := d.MakeExtension(logf, b)
		if errors.Is(err, ipnext.SkipExtension) {
			// The extension wants to be skipped.
			host.logf("%q: %v", d.Name(), err)
			continue
		} else if err != nil {
			return nil, fmt.Errorf("failed to create %q extension: %v", d.Name(), err)
		}
		host.allExtensions = append(host.allExtensions, ext)

		if d.Name() != ext.Name() {
			return nil, fmt.Errorf("extension name %q does not match the registered name %q", ext.Name(), d.Name())
		}

		if _, ok := host.extensionsByName[ext.Name()]; ok {
			return nil, fmt.Errorf("duplicate extension name %q", ext.Name())
		} else {
			mak.Set(&host.extensionsByName, ext.Name(), ext)
		}

		typ := reflect.TypeOf(ext)
		if _, ok := host.extByType.Load(typ); ok {
			if _, ok := ext.(interface{ PermitDoubleRegister() }); !ok {
				return nil, fmt.Errorf("duplicate extension type %T", ext)
			}
		}
		host.extByType.Store(typ, ext)
	}
	return host, nil
}

func (h *ExtensionHost) NodeBackend() ipnext.NodeBackend {
	if h == nil {
		return nil
	}
	return h.b.NodeBackend()
}

// Init initializes the host and the extensions it manages.
func (h *ExtensionHost) Init() {
	if h != nil {
		h.initOnce.Do(h.init)
	}
}

var zeroHooks ipnext.Hooks

func (h *ExtensionHost) Hooks() *ipnext.Hooks {
	if h == nil {
		return &zeroHooks
	}
	return &h.hooks
}

func (h *ExtensionHost) init() {
	defer h.initDone.Store(true)

	// Initialize the extensions in the order they were registered.
	for _, ext := range h.allExtensions {
		// Do not hold the lock while calling [ipnext.Extension.Init].
		// Extensions call back into the host to register their callbacks,
		// and that would cause a deadlock if the h.mu is already held.
		if err := ext.Init(h); err != nil {
			// As per the [ipnext.Extension] interface, failures to initialize
			// an extension are never fatal. The extension is simply skipped.
			//
			// But we handle [ipnext.SkipExtension] differently for nicer logging
			// if the extension wants to be skipped and not actually failing.
			if errors.Is(err, ipnext.SkipExtension) {
				h.logf("%q: %v", ext.Name(), err)
			} else {
				h.logf("%q init failed: %v", ext.Name(), err)
			}
			continue
		}
		// Update the initialized extensions lists as soon as the extension is initialized.
		// We'd like to make them visible to other extensions that are initialized later.
		h.mu.Lock()
		h.activeExtensions = append(h.activeExtensions, ext)
		h.mu.Unlock()
	}

	// Report active extensions to the log.
	// TODO(nickkhyl): update client metrics to include the active/failed/skipped extensions.
	h.mu.Lock()
	extensionNames := slices.Collect(maps.Keys(h.extensionsByName))
	h.mu.Unlock()
	h.logf("active extensions: %v", strings.Join(extensionNames, ", "))

	// Additional init steps that need to be performed after all extensions have been initialized.
	h.mu.Lock()
	wq := h.postInitWorkQueue
	h.postInitWorkQueue = nil
	h.initialized.Store(true)
	h.mu.Unlock()

	// Enqueue work that was requested and deferred during initialization.
	h.doEnqueueBackendOperation(func(b Backend) {
		for _, f := range wq {
			f(b)
		}
	})
}

// Extensions implements [ipnext.Host].
func (h *ExtensionHost) Extensions() ipnext.ExtensionServices {
	// Currently, [ExtensionHost] implements [ExtensionServices] directly.
	// We might want to extract it to a separate type in the future.
	return h
}

// FindExtensionByName implements [ipnext.ExtensionServices]
// and is also used by the [LocalBackend].
// It returns nil if the extension is not found.
func (h *ExtensionHost) FindExtensionByName(name string) any {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.extensionsByName[name]
}

// extensionIfaceType is the runtime type of the [ipnext.Extension] interface.
var extensionIfaceType = reflect.TypeFor[ipnext.Extension]()

// GetExt returns the extension of type T registered with lb.
// If lb is nil or the extension is not found, it returns zero, false.
func GetExt[T ipnext.Extension](lb *LocalBackend) (_ T, ok bool) {
	var zero T
	if lb == nil {
		return zero, false
	}
	if ext, ok := lb.extHost.extensionOfType(reflect.TypeFor[T]()); ok {
		return ext.(T), true
	}
	return zero, false
}

func (h *ExtensionHost) extensionOfType(t reflect.Type) (_ ipnext.Extension, ok bool) {
	if h == nil {
		return nil, false
	}
	if v, ok := h.extByType.Load(t); ok {
		return v.(ipnext.Extension), true
	}
	return nil, false
}

// FindMatchingExtension implements [ipnext.ExtensionServices]
// and is also used by the [LocalBackend].
func (h *ExtensionHost) FindMatchingExtension(target any) bool {
	if h == nil {
		return false
	}

	if target == nil {
		panic("ipnext: target cannot be nil")
	}

	val := reflect.ValueOf(target)
	typ := val.Type()
	if typ.Kind() != reflect.Ptr || val.IsNil() {
		panic("ipnext: target must be a non-nil pointer")
	}
	targetType := typ.Elem()
	if targetType.Kind() != reflect.Interface && !targetType.Implements(extensionIfaceType) {
		panic("ipnext: *target must be interface or implement ipnext.Extension")
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	for _, ext := range h.activeExtensions {
		if reflect.TypeOf(ext).AssignableTo(targetType) {
			val.Elem().Set(reflect.ValueOf(ext))
			return true
		}
	}
	return false
}

// Profiles implements [ipnext.Host].
func (h *ExtensionHost) Profiles() ipnext.ProfileServices {
	// Currently, [ExtensionHost] implements [ipnext.ProfileServices] directly.
	// We might want to extract it to a separate type in the future.
	return h
}

// CurrentProfileState implements [ipnext.ProfileServices].
func (h *ExtensionHost) CurrentProfileState() (ipn.LoginProfileView, ipn.PrefsView) {
	if h == nil {
		return zeroProfile, defaultPrefs
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.currentProfile, h.currentPrefs
}

// CurrentPrefs implements [ipnext.ProfileServices].
func (h *ExtensionHost) CurrentPrefs() ipn.PrefsView {
	_, prefs := h.CurrentProfileState()
	return prefs
}

// SwitchToBestProfileAsync implements [ipnext.ProfileServices].
func (h *ExtensionHost) SwitchToBestProfileAsync(reason string) {
	if h == nil {
		return
	}
	h.enqueueBackendOperation(func(b Backend) {
		b.SwitchToBestProfile(reason)
	})
}

// SendNotifyAsync implements [ipnext.Host].
func (h *ExtensionHost) SendNotifyAsync(n ipn.Notify) {
	if h == nil {
		return
	}
	h.enqueueBackendOperation(func(b Backend) {
		b.SendNotify(n)
	})
}

// NotifyProfileChange invokes registered profile state change callbacks
// and updates the current profile and prefs in the host.
// It strips private keys from the [ipn.Prefs] before preserving
// or passing them to the callbacks.
func (h *ExtensionHost) NotifyProfileChange(profile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	if !h.active() {
		return
	}
	h.mu.Lock()
	// Strip private keys from the prefs before preserving or passing them to the callbacks.
	// Extensions should not need them (unless proven otherwise in the future),
	// and this is a good way to ensure that they won't accidentally leak them.
	prefs = stripKeysFromPrefs(prefs)
	// Update the current profile and prefs in the host,
	// so we can provide them to the extensions later if they ask.
	h.currentPrefs = prefs
	h.currentProfile = profile
	h.mu.Unlock()

	for _, cb := range h.hooks.ProfileStateChange {
		cb(profile, prefs, sameNode)
	}
}

// NotifyProfilePrefsChanged invokes registered profile state change callbacks,
// and updates the current profile and prefs in the host.
// It strips private keys from the [ipn.Prefs] before preserving or using them.
func (h *ExtensionHost) NotifyProfilePrefsChanged(profile ipn.LoginProfileView, oldPrefs, newPrefs ipn.PrefsView) {
	if !h.active() {
		return
	}
	h.mu.Lock()
	// Strip private keys from the prefs before preserving or passing them to the callbacks.
	// Extensions should not need them (unless proven otherwise in the future),
	// and this is a good way to ensure that they won't accidentally leak them.
	newPrefs = stripKeysFromPrefs(newPrefs)
	// Update the current profile and prefs in the host,
	// so we can provide them to the extensions later if they ask.
	h.currentPrefs = newPrefs
	h.currentProfile = profile
	// Get the callbacks to be invoked.
	h.mu.Unlock()

	for _, cb := range h.hooks.ProfileStateChange {
		cb(profile, newPrefs, true)
	}
}

func (h *ExtensionHost) active() bool {
	return h != nil && !h.shuttingDown.Load()
}

// DetermineBackgroundProfile returns a read-only view of the profile
// used when no GUI/CLI client is connected, using background profile
// resolvers registered by extensions.
//
// It returns an invalid view if Tailscale should not run in the background
// and instead disconnect until a GUI/CLI client connects.
//
// As of 2025-02-07, this is only used on Windows.
func (h *ExtensionHost) DetermineBackgroundProfile(profiles ipnext.ProfileStore) ipn.LoginProfileView {
	if !h.active() {
		return ipn.LoginProfileView{}
	}
	// TODO(nickkhyl): check if the returned profile is allowed on the device,
	// such as when [syspolicy.Tailnet] policy setting requires a specific Tailnet.
	// See tailscale/corp#26249.

	// Attempt to resolve the background profile using the registered
	// background profile resolvers (e.g., [ipn/desktop.desktopSessionsExt] on Windows).
	for _, resolver := range h.hooks.BackgroundProfileResolvers {
		if profile := resolver(profiles); profile.Valid() {
			return profile
		}
	}

	// Otherwise, switch to an empty profile and disconnect Tailscale
	// until a GUI or CLI client connects.
	return ipn.LoginProfileView{}
}

// NotifyNewControlClient invokes all registered control client callbacks.
// It returns callbacks to be executed when the control client shuts down.
func (h *ExtensionHost) NotifyNewControlClient(cc controlclient.Client, profile ipn.LoginProfileView) (ccShutdownCbs []func()) {
	if !h.active() {
		return nil
	}
	for _, cb := range h.hooks.NewControlClient {
		if shutdown := cb(cc, profile); shutdown != nil {
			ccShutdownCbs = append(ccShutdownCbs, shutdown)
		}
	}
	return ccShutdownCbs
}

// AuditLogger returns a function that reports an auditable action
// to all registered audit loggers. It fails if any of them returns an error,
// indicating that the action cannot be logged and must not be performed.
//
// It implements [ipnext.Host], but is also used by the [LocalBackend].
//
// The returned function closes over the current state of the host and extensions,
// which typically includes the current profile and the audit loggers registered by extensions.
// It must not be persisted outside of the auditable action context.
func (h *ExtensionHost) AuditLogger() ipnauth.AuditLogFunc {
	if !h.active() {
		return func(tailcfg.ClientAuditAction, string) error { return nil }
	}
	loggers := make([]ipnauth.AuditLogFunc, 0, len(h.hooks.AuditLoggers))
	for _, provider := range h.hooks.AuditLoggers {
		loggers = append(loggers, provider())
	}
	return func(action tailcfg.ClientAuditAction, details string) error {
		// Log auditable actions to the host's log regardless of whether
		// the audit loggers are available or not.
		h.logf("auditlog: %v: %v", action, details)

		// Invoke all registered audit loggers and collect errors.
		// If any of them returns an error, the action is denied.
		var errs []error
		for _, logger := range loggers {
			if err := logger(action, details); err != nil {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
}

// Shutdown shuts down the extension host and all initialized extensions.
func (h *ExtensionHost) Shutdown() {
	if h == nil {
		return
	}
	// Ensure that the init function has completed before shutting down,
	// or prevent any further init calls from happening.
	h.initOnce.Do(func() {})
	h.shutdownOnce.Do(h.shutdown)
}

func (h *ExtensionHost) shutdown() {
	h.shuttingDown.Store(true)
	// Prevent any queued but not yet started operations from running,
	// block new operations from being enqueued, and wait for the
	// currently executing operation (if any) to finish.
	h.shutdownWorkQueue()
	// Invoke shutdown callbacks registered by extensions.
	h.shutdownExtensions()
}

func (h *ExtensionHost) shutdownWorkQueue() {
	h.workQueue.Shutdown()
	var ctx context.Context
	if testenv.InTest() {
		// In tests, we'd like to wait indefinitely for the current operation to finish,
		// mostly to help avoid flaky tests. Test runners can be pretty slow.
		ctx = context.Background()
	} else {
		// In prod, however, we want to avoid blocking indefinitely.
		// The 5s timeout is somewhat arbitrary; LocalBackend operations
		// should not take that long.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}
	// Since callbacks are invoked synchronously, this will also wait
	// for in-flight callbacks associated with those operations to finish.
	if err := h.workQueue.Wait(ctx); err != nil {
		h.logf("work queue shutdown failed: %v", err)
	}
}

func (h *ExtensionHost) shutdownExtensions() {
	h.mu.Lock()
	extensions := h.activeExtensions
	h.mu.Unlock()

	// h.mu must not be held while shutting down extensions.
	// Extensions might call back into the host and that would cause
	// a deadlock if the h.mu is already held.
	//
	// Shutdown is called in the reverse order of Init.
	for _, ext := range slices.Backward(extensions) {
		if err := ext.Shutdown(); err != nil {
			// Extension shutdown errors are never fatal, but we log them for debugging purposes.
			h.logf("%q: shutdown callback failed: %v", ext.Name(), err)
		}
	}
}

// enqueueBackendOperation enqueues a function to perform an operation on the [Backend].
// If the host has not yet been initialized (e.g., when called from an extension's Init method),
// the operation is deferred until after the host and all extensions have completed initialization.
// It panics if the f is nil.
func (h *ExtensionHost) enqueueBackendOperation(f func(Backend)) {
	if h == nil {
		return
	}
	if f == nil {
		panic("nil backend operation")
	}
	h.mu.Lock() // protects h.initialized and h.postInitWorkQueue
	defer h.mu.Unlock()
	if h.initialized.Load() {
		h.doEnqueueBackendOperation(f)
	} else {
		h.postInitWorkQueue = append(h.postInitWorkQueue, f)
	}
}

// execQueue is an ordered asynchronous queue for executing functions.
// It is implemented by [execqueue.ExecQueue]. The interface is used
// to allow testing with a mock implementation.
type execQueue interface {
	Add(func())
	Shutdown()
	Wait(context.Context) error
}
