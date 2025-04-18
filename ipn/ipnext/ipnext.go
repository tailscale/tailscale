// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ipnext defines types and interfaces used for extending the core LocalBackend
// functionality with additional features and services.
package ipnext

import (
	"errors"
	"fmt"
	"reflect"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/tsd"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
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

	// Init is called to initialize the extension when LocalBackend is initialized.
	// If the extension cannot be initialized, it must return an error,
	// and its Shutdown method will not be called on the host's shutdown.
	// Returned errors are not fatal; they are used for logging.
	// A [SkipExtension] error indicates an intentional decision rather than a failure.
	Init(Host) error

	// Shutdown is called when LocalBackend is shutting down,
	// provided the extension was initialized. For multiple extensions,
	// Shutdown is called in the reverse order of Init.
	// Returned errors are not fatal; they are used for logging.
	Shutdown() error
}

// NewExtensionFn is a function that instantiates an [Extension].
// If a registered extension cannot be instantiated, the function must return an error.
// If the extension should be skipped at runtime, it must return either [SkipExtension]
// or a wrapped [SkipExtension]. Any other error returned is fatal and will prevent
// the LocalBackend from starting.
type NewExtensionFn func(logger.Logf, *tsd.System) (Extension, error)

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
func (d *Definition) MakeExtension(logf logger.Logf, sys *tsd.System) (Extension, error) {
	ext, err := d.newFn(logf, sys)
	if err != nil {
		return nil, err
	}
	if ext.Name() != d.name {
		return nil, fmt.Errorf("extension name mismatch: registered %q; actual %q", d.name, ext.Name())
	}
	return ext, nil
}

// extensionsByName is a map of registered extensions,
// where the key is the name of the extension.
var extensionsByName map[string]*Definition

// extensionsByOrder is a slice of registered extensions,
// in the order they were registered.
var extensionsByOrder []*Definition

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
	if _, ok := extensionsByName[name]; ok {
		panic(fmt.Sprintf("ipnext: duplicate extensions: %q", name))
	}
	ext := &Definition{name, newExt}
	mak.Set(&extensionsByName, name, ext)
	extensionsByOrder = append(extensionsByOrder, ext)
}

// Extensions returns a read-only view of the extensions
// registered via [RegisterExtension]. It preserves the order
// in which the extensions were registered.
func Extensions() views.Slice[*Definition] {
	return views.SliceOf(extensionsByOrder)
}

// DefinitionForTest returns a [Definition] for the specified [Extension].
// It is primarily used for testing where the test code needs to instantiate
// and use an extension without registering it.
func DefinitionForTest(ext Extension) *Definition {
	return &Definition{
		name:  ext.Name(),
		newFn: func(logger.Logf, *tsd.System) (Extension, error) { return ext, nil },
	}
}

// DefinitionWithErrForTest returns a [Definition] with the specified extension name
// whose [Definition.MakeExtension] method returns the specified error.
// It is used for testing.
func DefinitionWithErrForTest(name string, err error) *Definition {
	return &Definition{
		name:  name,
		newFn: func(logger.Logf, *tsd.System) (Extension, error) { return nil, err },
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

	// RegisterAuditLogProvider registers an audit log provider,
	// which returns a function to be called when an auditable action
	// is about to be performed. The returned function unregisters the provider.
	// It is a runtime error to register a nil provider.
	RegisterAuditLogProvider(AuditLogProvider) (unregister func())

	// AuditLogger returns a function that calls all currently registered audit loggers.
	// The function fails if any logger returns an error, indicating that the action
	// cannot be logged and must not be performed.
	//
	// The returned function captures the current state (e.g., the current profile) at
	// the time of the call and must not be persisted.
	AuditLogger() ipnauth.AuditLogFunc

	// RegisterControlClientCallback registers a function to be called every time a new
	// control client is created. The returned function unregisters the callback.
	// It is a runtime error to register a nil callback.
	//
	// The callback is called with the LocalBackend's mutex locked so it's not
	// possible to call back into it.
	RegisterControlClientCallback(NewControlClientCallback) (unregister func())

	// RegisterNetmapChangeCallback registers a function to be called when the
	// network map changes, including changing to nil. The returned function
	// unregisters the callback.
	//
	// The callback is called with the LocalBackend's mutex locked so it's not
	// possible to call back into it.
	RegisterNetmapChangeCallback(NetmapChangeCallback) (unregister func())

	// RegisterOptionSetter registers a function to handle SetExtensionOption
	// calls of a given type.
	RegisterOptionSetter(reflect.Type, func(any) error)
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

	// RegisterBackgroundProfileResolver registers a function to be used when
	// resolving the background profile. The returned function unregisters the resolver.
	// It is a runtime error to register a nil resolver.
	//
	// TODO(nickkhyl): allow specifying some kind of priority/altitude for the resolver.
	// TODO(nickkhyl): make it a "profile resolver" instead of a "background profile resolver".
	// The concepts of the "current user", "foreground profile" and "background profile"
	// only exist on Windows, and we're moving away from them anyway.
	RegisterBackgroundProfileResolver(ProfileResolver) (unregister func())

	// RegisterProfileStateChangeCallback registers a function to be called when the current
	// [ipn.LoginProfile] or its [ipn.Prefs] change. The returned function unregisters the callback.
	//
	// To get the initial profile or prefs, use [ProfileServices.CurrentProfileState]
	// or [ProfileServices.CurrentPrefs] from the extension's [Extension.Init].
	//
	// It is a runtime error to register a nil callback.
	RegisterProfileStateChangeCallback(ProfileStateChangeCallback) (unregister func())
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
// or nil if no cleanup is needed.
type NewControlClientCallback func(controlclient.Client, ipn.LoginProfileView) (cleanup func())

// NetmapChangeCallback is called when the network map changes,
// including changing to nil.
type NetmapChangeCallback func(*netmap.NetworkMap)
