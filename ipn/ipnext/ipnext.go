// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnext defines types and interfaces used for extending the core LocalBackend
// functionality with additional features and services.
package ipnext

import (
	"errors"
	"fmt"
	"iter"
	"net/netip"

	"tailscale.com/control/controlclient"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/tstime"
	"tailscale.com/types/logger"
	"tailscale.com/types/mapx"
	"tailscale.com/wgengine/filter"
)

// Extension augments LocalBackend with additional functionality.
//
// An extension uses the provided [Host] to register callbacks
// and interact with the backend in a controlled, well-defined
// and thread-safe manner.
//
// Extensions are registered using [RegisterExtension].
//
// They must be safe for concurrent use.
type Extension interface {
	// Name is a unique name of the extension.
	// It must be the same as the name used to register the extension.
	Name() string

	// Init is called to initialize the extension when LocalBackend's
	// Start method is called. Extensions are created but not initialized
	// unless LocalBackend is started.
	//
	// If the extension cannot be initialized, it must return an error,
	// and its Shutdown method will not be called on the host's shutdown.
	// Returned errors are not fatal; they are used for logging.
	// A [SkipExtension] error indicates an intentional decision rather than a failure.
	Init(Host) error

	// Shutdown is called when LocalBackend is shutting down,
	// provided the extension was initialized. For multiple extensions,
	// Shutdown is called in the reverse order of Init.
	// Returned errors are not fatal; they are used for logging.
	// After a call to Shutdown, the extension will not be called again.
	Shutdown() error
}

// NewExtensionFn is a function that instantiates an [Extension].
// If a registered extension cannot be instantiated, the function must return an error.
// If the extension should be skipped at runtime, it must return either [SkipExtension]
// or a wrapped [SkipExtension]. Any other error returned is fatal and will prevent
// the LocalBackend from starting.
type NewExtensionFn func(logger.Logf, SafeBackend) (Extension, error)

// SkipExtension is an error returned by [NewExtensionFn] to indicate that the extension
// should be skipped rather than prevent the LocalBackend from starting.
//
// Skipping an extension should be reserved for cases where the extension is not supported
// on the current platform or configuration, or depends on a feature that is not available,
// or otherwise should be disabled permanently rather than temporarily.
//
// Specifically, it must not be returned if the extension is not required right now
// based on user preferences, policy settings, the current tailnet, or other factors
// that may change throughout the LocalBackend's lifetime.
var SkipExtension = errors.New("skipping extension")

// Definition describes a registered [Extension].
type Definition struct {
	name  string         // name under which the extension is registered
	newFn NewExtensionFn // function that creates a new instance of the extension
}

// Name returns the name of the extension.
func (d *Definition) Name() string {
	return d.name
}

// MakeExtension instantiates the extension.
func (d *Definition) MakeExtension(logf logger.Logf, sb SafeBackend) (Extension, error) {
	ext, err := d.newFn(logf, sb)
	if err != nil {
		return nil, err
	}
	if ext.Name() != d.name {
		return nil, fmt.Errorf("extension name mismatch: registered %q; actual %q", d.name, ext.Name())
	}
	return ext, nil
}

// extensions is a map of registered extensions,
// where the key is the name of the extension.
var extensions mapx.OrderedMap[string, *Definition]

// RegisterExtension registers a function that instantiates an [Extension].
// The name must be the same as returned by the extension's [Extension.Name].
//
// It must be called on the main goroutine before LocalBackend is created,
// such as from an init function of the package implementing the extension.
//
// It panics if newExt is nil or if an extension with the same name
// has already been registered.
func RegisterExtension(name string, newExt NewExtensionFn) {
	if newExt == nil {
		panic(fmt.Sprintf("ipnext: newExt is nil: %q", name))
	}
	if extensions.Contains(name) {
		panic(fmt.Sprintf("ipnext: duplicate extension name %q", name))
	}
	extensions.Set(name, &Definition{name, newExt})
}

// Extensions iterates over the extensions in the order they were registered
// via [RegisterExtension].
func Extensions() iter.Seq[*Definition] {
	return extensions.Values()
}

// DefinitionForTest returns a [Definition] for the specified [Extension].
// It is primarily used for testing where the test code needs to instantiate
// and use an extension without registering it.
func DefinitionForTest(ext Extension) *Definition {
	return &Definition{
		name:  ext.Name(),
		newFn: func(logger.Logf, SafeBackend) (Extension, error) { return ext, nil },
	}
}

// DefinitionWithErrForTest returns a [Definition] with the specified extension name
// whose [Definition.MakeExtension] method returns the specified error.
// It is used for testing.
func DefinitionWithErrForTest(name string, err error) *Definition {
	return &Definition{
		name:  name,
		newFn: func(logger.Logf, SafeBackend) (Extension, error) { return nil, err },
	}
}

// Host is the API surface used by [Extension]s to interact with LocalBackend
// in a controlled manner.
//
// Extensions can register callbacks, request information, or perform actions
// via the [Host] interface.
//
// Typically, the host invokes registered callbacks when one of the following occurs:
//   - LocalBackend notifies it of an event or state change that may be
//     of interest to extensions, such as when switching [ipn.LoginProfile].
//   - LocalBackend needs to consult extensions for information, for example,
//     determining the most appropriate profile for the current state of the system.
//   - LocalBackend performs an extensible action, such as logging an auditable event,
//     and delegates its execution to the extension.
//
// The callbacks are invoked synchronously, and the LocalBackend's state
// remains unchanged while callbacks execute.
//
// In contrast, actions initiated by extensions are generally asynchronous,
// as indicated by the "Async" suffix in their names.
// Performing actions may result in callbacks being invoked as described above.
//
// To prevent conflicts between extensions competing for shared state,
// such as the current profile or prefs, the host must not expose methods
// that directly modify that state. For example, instead of allowing extensions
// to switch profiles at-will, the host's [ProfileServices] provides a method
// to switch to the "best" profile. The host can then consult extensions
// to determine the appropriate profile to use and resolve any conflicts
// in a controlled manner.
//
// A host must be safe for concurrent use.
type Host interface {
	// Extensions returns the host's [ExtensionServices].
	Extensions() ExtensionServices

	// Profiles returns the host's [ProfileServices].
	Profiles() ProfileServices

	// AuditLogger returns a function that calls all currently registered audit loggers.
	// The function fails if any logger returns an error, indicating that the action
	// cannot be logged and must not be performed.
	//
	// The returned function captures the current state (e.g., the current profile) at
	// the time of the call and must not be persisted.
	AuditLogger() ipnauth.AuditLogFunc

	// Hooks returns a non-nil pointer to a [Hooks] struct.
	// Hooks must not be modified concurrently or after Tailscale has started.
	Hooks() *Hooks

	// SendNotifyAsync sends a notification to the IPN bus,
	// typically to the GUI client.
	SendNotifyAsync(ipn.Notify)

	// NodeBackend returns the [NodeBackend] for the currently active node
	// (which is approximately the same as the current profile).
	NodeBackend() NodeBackend
}

// SafeBackend is a subset of the [ipnlocal.LocalBackend] type's methods that
// are safe to call from extension hooks at any time (even hooks called while
// LocalBackend's internal mutex is held).
type SafeBackend interface {
	Sys() *tsd.System
	Clock() tstime.Clock
	TailscaleVarRoot() string
}

// ExtensionServices provides access to the [Host]'s extension management services,
// such as fetching active extensions.
type ExtensionServices interface {
	// FindExtensionByName returns an active extension with the given name,
	// or nil if no such extension exists.
	FindExtensionByName(name string) any

	// FindMatchingExtension finds the first active extension that matches target,
	// and if one is found, sets target to that extension and returns true.
	// Otherwise, it returns false.
	//
	// It panics if target is not a non-nil pointer to either a type
	// that implements [ipnext.Extension], or to any interface type.
	FindMatchingExtension(target any) bool
}

// ProfileServices provides access to the [Host]'s profile management services,
// such as switching profiles and registering profile change callbacks.
type ProfileServices interface {
	// CurrentProfileState returns read-only views of the current profile
	// and its preferences. The returned views are always valid,
	// but the profile's [ipn.LoginProfileView.ID] returns ""
	// if the profile is new and has not been persisted yet.
	//
	// The returned views are immutable snapshots of the current profile
	// and prefs at the time of the call. The actual state is only guaranteed
	// to remain unchanged and match these views for the duration
	// of a callback invoked by the host, if used within that callback.
	//
	// Extensions that need the current profile or prefs at other times
	// should typically subscribe to [ProfileStateChangeCallback]
	// to be notified if the profile or prefs change after retrieval.
	// CurrentProfileState returns both the profile and prefs
	// to guarantee that they are consistent with each other.
	CurrentProfileState() (ipn.LoginProfileView, ipn.PrefsView)

	// CurrentPrefs is like [CurrentProfileState] but only returns prefs.
	CurrentPrefs() ipn.PrefsView

	// SwitchToBestProfileAsync asynchronously selects the best profile to use
	// and switches to it, unless it is already the current profile.
	//
	// If an extension needs to know when a profile switch occurs,
	// it must use [ProfileServices.RegisterProfileStateChangeCallback]
	// to register a [ProfileStateChangeCallback].
	//
	// The reason indicates why the profile is being switched, such as due
	// to a client connecting or disconnecting or a change in the desktop
	// session state. It is used for logging.
	SwitchToBestProfileAsync(reason string)
}

// ProfileStore provides read-only access to available login profiles and their preferences.
// It is not safe for concurrent use and can only be used from the callback it is passed to.
type ProfileStore interface {
	// CurrentUserID returns the current user ID. It is only non-empty on
	// Windows where we have a multi-user system.
	//
	// Deprecated: this method exists for compatibility with the current (as of 2024-08-27)
	// permission model and will be removed as we progress on tailscale/corp#18342.
	CurrentUserID() ipn.WindowsUserID

	// CurrentProfile returns a read-only [ipn.LoginProfileView] of the current profile.
	// The returned view is always valid, but the profile's [ipn.LoginProfileView.ID]
	// returns "" if the profile is new and has not been persisted yet.
	CurrentProfile() ipn.LoginProfileView

	// CurrentPrefs returns a read-only view of the current prefs.
	// The returned view is always valid.
	CurrentPrefs() ipn.PrefsView

	// DefaultUserProfile returns a read-only view of the default (last used) profile for the specified user.
	// It returns a read-only view of a new, non-persisted profile if the specified user does not have a default profile.
	DefaultUserProfile(uid ipn.WindowsUserID) ipn.LoginProfileView
}

// AuditLogProvider is a function that returns an [ipnauth.AuditLogFunc] for
// logging auditable actions.
type AuditLogProvider func() ipnauth.AuditLogFunc

// ProfileResolver is a function that returns a read-only view of a login profile.
// An invalid view indicates no profile. A valid profile view with an empty [ipn.ProfileID]
// indicates that the profile is new and has not been persisted yet.
// The provided [ProfileStore] can only be used for the duration of the callback.
type ProfileResolver func(ProfileStore) ipn.LoginProfileView

// ProfileStateChangeCallback is a function to be called when the current login profile
// or its preferences change.
//
// The sameNode parameter indicates whether the profile represents the same node as before,
// which is true when:
//   - Only the profile's [ipn.Prefs] or metadata (e.g., [tailcfg.UserProfile]) have changed,
//     but the node ID and [ipn.ProfileID] remain the same.
//   - The profile has been persisted and assigned an [ipn.ProfileID] for the first time,
//     so while its node ID and [ipn.ProfileID] have changed, it is still the same profile.
//
// It can be used to decide whether to reset state bound to the current profile or node identity.
//
// The profile and prefs are always valid, but the profile's [ipn.LoginProfileView.ID]
// returns "" if the profile is new and has not been persisted yet.
type ProfileStateChangeCallback func(_ ipn.LoginProfileView, _ ipn.PrefsView, sameNode bool)

// NewControlClientCallback is a function to be called when a new [controlclient.Client]
// is created and before it is first used. The specified profile represents the node
// for which the cc is created and is always valid. Its [ipn.LoginProfileView.ID]
// returns "" if it is a new node whose profile has never been persisted.
//
// If the [controlclient.Client] is created due to a profile switch, any registered
// [ProfileStateChangeCallback]s are called first.
//
// It returns a function to be called when the cc is being shut down,
// or nil if no cleanup is needed. That cleanup function should not call
// back into LocalBackend, which may be locked during shutdown.
type NewControlClientCallback func(controlclient.Client, ipn.LoginProfileView) (cleanup func())

// Hooks is a collection of hooks that extensions can add to (non-concurrently)
// during program initialization and can be called by LocalBackend and others at
// runtime.
//
// Each hook has its own rules about when it's called and what environment it
// has access to and what it's allowed to do.
type Hooks struct {
	// BackendStateChange is called when the backend state changes.
	BackendStateChange feature.Hooks[func(ipn.State)]

	// ProfileStateChange contains callbacks that are invoked when the current login profile
	// or its [ipn.Prefs] change, after those changes have been made. The current login profile
	// may be changed either because of a profile switch, or because the profile information
	// was updated by [LocalBackend.SetControlClientStatus], including when the profile
	// is first populated and persisted.
	ProfileStateChange feature.Hooks[ProfileStateChangeCallback]

	// BackgroundProfileResolvers are registered background profile resolvers.
	// They're used to determine the profile to use when no GUI/CLI client is connected.
	//
	// TODO(nickkhyl): allow specifying some kind of priority/altitude for the resolver.
	// TODO(nickkhyl): make it a "profile resolver" instead of a "background profile resolver".
	// The concepts of the "current user", "foreground profile" and "background profile"
	// only exist on Windows, and we're moving away from them anyway.
	BackgroundProfileResolvers feature.Hooks[ProfileResolver]

	// AuditLoggers are registered [AuditLogProvider]s.
	// Each provider is called to get an [ipnauth.AuditLogFunc] when an auditable action
	// is about to be performed. If an audit logger returns an error, the action is denied.
	AuditLoggers feature.Hooks[AuditLogProvider]

	// NewControlClient are the functions to be called when a new control client
	// is created. It is called with the LocalBackend locked.
	NewControlClient feature.Hooks[NewControlClientCallback]

	// OnSelfChange is called (with LocalBackend.mu held) when the self node
	// changes, including changing to nothing (an invalid view).
	OnSelfChange feature.Hooks[func(tailcfg.NodeView)]

	// MutateNotifyLocked is called to optionally mutate the provided Notify
	// before sending it to the IPN bus. It is called with LocalBackend.mu held.
	MutateNotifyLocked feature.Hooks[func(*ipn.Notify)]

	// SetPeerStatus is called to mutate PeerStatus.
	// Callers must only use NodeBackend to read data.
	SetPeerStatus feature.Hooks[func(*ipnstate.PeerStatus, tailcfg.NodeView, NodeBackend)]

	// ShouldUploadServices reports whether this node should include services
	// in Hostinfo from the portlist extension.
	ShouldUploadServices feature.Hook[func() bool]

	// Filter contains hooks for the packet filter.
	// See [filter.Filter] for details on how these hooks are invoked.
	Filter FilterHooks
}

// FilterHooks contains hooks that extensions can use to customize the packet
// filter. Field names match the corresponding fields in filter.Filter.
type FilterHooks struct {
	// IngressAllowHooks are hooks that allow extensions to accept inbound
	// packets beyond the standard filter rules. Packets that are not dropped
	// by the direction-agnostic pre-check, but would be not accepted by the
	// main filter rules, including the check for destinations in the node's
	// local IP set, will be accepted if they match one of these hooks.
	// As of 2026-02-24, the ingress filter does not implement explicit drop
	// rules, but if it does, an explicitly dropped packet will be dropped,
	// and these hooks will not be evaluated.
	//
	// Processing of hooks stop after the first one that returns true.
	// The returned why string of the first match is used in logging.
	// Returning false does not drop the packet.
	// See also [filter.Filter.IngressAllowHooks].
	IngressAllowHooks feature.Hooks[filter.PacketMatch]

	// LinkLocalAllowHooks are hooks that provide exceptions to the default
	// policy of dropping link-local unicast packets. They run inside the
	// direction-agnostic pre-checks for both ingress and egress.
	//
	// A hook can allow a link-local packet to pass the link-local check,
	// but the packet is still subject to all other filter rules, and could be
	// dropped elsewhere. Matching link-local packets are not logged.
	// See also [filter.Filter.LinkLocalAllowHooks].
	LinkLocalAllowHooks feature.Hooks[filter.PacketMatch]
}

// NodeBackend is an interface to query the current node and its peers.
//
// It is not a snapshot in time but is locked to a particular node.
type NodeBackend interface {
	// AppendMatchingPeers appends all peers that match the predicate
	// to the base slice and returns it.
	AppendMatchingPeers(base []tailcfg.NodeView, pred func(tailcfg.NodeView) bool) []tailcfg.NodeView

	// PeerCaps returns the capabilities that src has to this node.
	PeerCaps(src netip.Addr) tailcfg.PeerCapMap

	// PeerHasCap reports whether the peer has the specified peer capability.
	PeerHasCap(peer tailcfg.NodeView, cap tailcfg.PeerCapability) bool

	// PeerAPIBase returns the "http://ip:port" URL base to reach peer's
	// PeerAPI, or the empty string if the peer is invalid or doesn't support
	// PeerAPI.
	PeerAPIBase(tailcfg.NodeView) string

	// PeerHasPeerAPI whether the provided peer supports PeerAPI.
	//
	// It effectively just reports whether PeerAPIBase(node) is non-empty, but
	// potentially more efficiently.
	PeerHasPeerAPI(tailcfg.NodeView) bool

	// CollectServices reports whether the control plane is telling this
	// node that the portlist service collection is desirable, should it
	// choose to report them.
	CollectServices() bool
}
