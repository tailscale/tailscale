// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"fmt"
	"reflect"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
)

// errNotAllowed is an error returned when access is neither explicitly allowed,
// nor denied with a more specific error.
var errNotAllowed error = ipn.NewAccessDeniedError("the requested operation is not allowed")

// AccessCheckResult represents the result of an access check.
// Its zero value is valid and indicates that the access request
// has neither been explicitly allowed nor denied for a specific reason.
//
// Higher-level access control code should forward the AccessCheckResult
// from lower-level access control mechanisms to the caller
// immediately upon receiving a definitive result, as indicated
// by the AccessCheckResult.HasResult() method returning true.
//
// Requested access that has not been explicitly allowed
// or explicitly denied is implicitly denied. This is reflected
// in the values returned by AccessCheckResult's Allowed, Denied, and Error methods.
type AccessCheckResult struct {
	err       error
	hasResult bool
}

// AllowAccess returns a new AccessCheckResult indicating that
// the requested access has been allowed.
//
// Access control implementations should return AllowAccess()
// only when they are certain that further access checks
// are unnecessary and the requested access is definitively allowed.
//
// This includes cases where a certain access right, that might
// otherwise be denied based on the environment and normal user rights,
// is explicitly allowed by a corporate admin through syspolicy (GP or MDM).
// It also covers situations where access is not denied by
// higher-level access control mechanisms, such as syspolicy,
// and is granted based on the user's identity, following
// platform and environment-specific rules.
// (e.g., because they are root on Unix or a profile owner on a personal Windows device).
func AllowAccess() AccessCheckResult {
	return AccessCheckResult{hasResult: true}
}

// DenyAccess returns a new AccessCheckResult indicating that
// the requested access has been denied with the specified err.
//
// Access control implementations should return DenyAccess()
// as soon as the requested access has been denied, without calling
// any subsequent lower-level access checking mechanisms, if any.
//
// Higher-level access control code should forward the AccessCheckResult
// from any lower-level access check to the caller as soon as it receives
// a definitive result as indicated by the HasResult() method returning true.
// Therefore, if access is denied due to tailscaled config or syspolicy settings,
// it will be immediately denied, regardless of the caller's identity.
func DenyAccess(err error) AccessCheckResult {
	if err == nil {
		err = ipn.NewInternalServerError("access denied with a nil error")
	} else {
		err = &ipn.AccessDeniedError{Err: err}
	}
	return AccessCheckResult{err: err, hasResult: true}
}

// ContinueCheck returns a new AccessCheckResult indicating that
// the requested access has neither been allowed, nor denied,
// and any further access checks should be performed to determine the result.
//
// An an example, a higher level access control code that denies
// certain access rights based on syspolicy may return ContinueCheck()
// to indicate that access is not denied by any applicable policies,
// and lower-level access checks should be performed.
//
// Similarly, if a tailscaled config file is present and restricts certain ipn.Prefs fields
// from being modified, its access checking mechanism should return ContinueCheck()
// when a user tries to change only preferences that are not locked down.
//
// As a general rule, any higher-level access checking code should
// continue calling lower-level access checking code, until it either receives
// and forwards a definitive result from one of the lower-level mechanisms,
// or until there are no additional checks to be performed.
// In the latter case, it can also return ContinueCheck(),
// resulting in the requested access being implicitly denied.
func ContinueCheck() AccessCheckResult {
	return AccessCheckResult{}
}

// HasResult reports whether a definitive access decision (either allowed or denied) has been made.
func (r AccessCheckResult) HasResult() bool {
	return r.hasResult
}

// Allowed reports whether the requested access has been allowed.
func (r AccessCheckResult) Allowed() bool {
	return r.hasResult && r.err == nil
}

// Denied reports whether the requested access should be denied.
func (r AccessCheckResult) Denied() bool {
	return !r.hasResult || r.err != nil
}

// Error returns an ipn.AccessDeniedError detailing why access was denied,
// or nil if access has been allowed.
func (r AccessCheckResult) Error() error {
	if !r.hasResult && r.err == nil {
		return errNotAllowed
	}
	return r.err
}

// String returns a string representation of r.
func (r AccessCheckResult) String() string {
	switch {
	case !r.hasResult:
		return "Implicit Deny"
	case r.err != nil:
		return "Deny: " + r.err.Error()
	default:
		return "Allow"
	}
}

// accessChecker is a helper type that allows step-by-step granting or denying of access rights.
type accessChecker[T ~uint32] struct {
	remain T // access rights that were requested but have not been granted yet.
	res    AccessCheckResult
}

// newAccessChecker returns a new accessChecker with the specified requested access.
func newAccessChecker[T ~uint32](requested T) accessChecker[T] {
	return accessChecker[T]{remain: requested}
}

// remaining returns the access rights that have been requested but not yet granted.
func (ac *accessChecker[T]) remaining() T {
	return ac.remain
}

// result determines if access is Allowed, Denied, or requires further evaluation.
func (ac *accessChecker[T]) result() AccessCheckResult {
	if !ac.res.HasResult() && ac.remaining() == 0 {
		ac.res = AllowAccess()
	}
	return ac.res
}

// grant unconditionally grants the specified rights, updating and returning an AccessCheckResult.
func (ac *accessChecker[T]) grant(rights T) AccessCheckResult {
	ac.remain &= ^rights
	return ac.result()
}

// deny unconditionally denies the specified rights, updating and returning an AccessCheckResult.
// If the specified rights were not requested, it is a no-op.
func (ac *accessChecker[T]) deny(rights T, err error) AccessCheckResult {
	if ac.remain&rights != 0 {
		ac.res = DenyAccess(err)
	}
	return ac.result()
}

// tryGrant grants the specified rights and updates the result if those rights have been requested
// and the check does not return an error.
// Otherwise, it is a no-op.
func (ac *accessChecker[T]) tryGrant(rights T, check func() error) AccessCheckResult {
	if ac.remain&rights != 0 && check() == nil {
		return ac.grant(rights)
	}
	return ac.result()
}

// mustGrant attempts to grant specified rights if they have been requested.
// If the check fails with an error, that error is used as the reason for access denial.
// If the specified rights were not requested, it is a no-op.
func (ac *accessChecker[T]) mustGrant(rights T, check func() error) AccessCheckResult {
	if ac.remain&rights != 0 {
		if err := check(); err != nil {
			return ac.deny(rights, err)
		}
		return ac.grant(rights)
	}
	return ac.result()
}

// CheckAccess reports whether the caller is allowed or denied the desired access.
func CheckAccess(caller Identity, desired DeviceAccess) AccessCheckResult {
	// Allow non-user originating changes, such as any changes requested by the control plane.
	// We don't want these to be affected by GP/MDM policies or any other restrictions.
	if IsUnrestricted(caller) {
		return AllowAccess()
	}

	// TODO(nickkhyl): check syspolicy.

	return caller.CheckAccess(desired)
}

// CheckProfileAccess reports whether the caller is allowed or denied the desired access
// to a specific profile and its prefs.
func CheckProfileAccess(caller Identity, profile ipn.LoginProfileView, prefs ipn.PrefsGetter, requested ProfileAccess) AccessCheckResult {
	// TODO(nickkhyl): consider moving or copying OperatorUser from ipn.Prefs to ipn.LoginProfile,
	// as this is the main reason why we need to read prefs here.

	// Allow non-user originating changes, such as any changes requested by the control plane.
	// We don't want these to be affected by GP/MDM policies or any other restrictions.
	if IsUnrestricted(caller) {
		return AllowAccess()
	}

	// TODO(nickkhyl): check syspolicy.

	return caller.CheckProfileAccess(profile, prefs, requested)
}

// CheckEditProfile reports whether the caller has access to apply the specified changes to
// the profile and prefs.
func CheckEditProfile(caller Identity, profile ipn.LoginProfileView, prefs ipn.PrefsGetter, changes *ipn.MaskedPrefs) AccessCheckResult {
	if IsUnrestricted(caller) {
		return AllowAccess()
	}

	requiredAccess := PrefsChangeRequiredAccess(changes)
	return CheckProfileAccess(caller, profile, prefs, requiredAccess)
}

// FilterProfile returns the specified profile, filtering or masking out fields
// inaccessible to the caller. The provided profile value is considered immutable,
// and a new instance of ipn.LoginProfile will be returned if any filtering is necessary.
func FilterProfile(caller Identity, profile ipn.LoginProfileView, prefs ipn.PrefsGetter) ipn.LoginProfileView {
	switch {
	case CheckProfileAccess(caller, profile, prefs, ReadProfileInfo).Allowed():
		return profile
	default:
		res := &ipn.LoginProfile{
			ID:             profile.ID(),
			Key:            profile.Key(),
			LocalUserID:    profile.LocalUserID(),
			UserProfile:    maskedUserProfile(profile),
			NetworkProfile: maskedNetworkProfile(profile),
		}
		res.Name = res.UserProfile.LoginName
		return res.View()
	}
}

// maskedNetworkProfile returns a masked tailcfg.UserProfile for the specified profile.
// The returned value is used by ipnauth.FilterProfile in place of the actual ipn.LoginProfile.UserProfile
// when the caller does not have ipnauth.ReadProfileInfo access to the profile.
//
// Although CLI or GUI clients can render this value as is, it's not localizable, may lead to a suboptimal UX,
// and is provided mainly for compatibility with existing clients.
//
// For an improved UX, CLI and GUI clients should use UserProfile.ID.IsZero() to check
// whether profile information is inaccessible and then render such profiles
// in a platform-specific and localizable way.
func maskedUserProfile(ipn.LoginProfileView) tailcfg.UserProfile {
	return tailcfg.UserProfile{
		LoginName:     maskedLoginName,
		DisplayName:   maskedDisplayName,
		ProfilePicURL: maskedProfilePicURL,
	}
}

// maskedNetworkProfile returns a masked ipn.NetworkProfile for the specified profile.
// It is like maskedUserProfile, but for NetworkProfile.
func maskedNetworkProfile(ipn.LoginProfileView) ipn.NetworkProfile {
	return ipn.NetworkProfile{
		DomainName: maskedDomainName,
	}
}

// PrefsChangeRequiredAccess returns the access required to change prefs as requested by mp.
func PrefsChangeRequiredAccess(mp *ipn.MaskedPrefs) ProfileAccess {
	masked := reflect.ValueOf(mp).Elem()
	return maskedPrefsFieldsAccess(&mp.Prefs, "", masked)
}

// maskedPrefsFieldsAccess returns the access required to change preferences, whose
// corresponding {FieldName}Set flags are set in masked, to the values specified in p.
// The `path` represents a dot-separated path to masked from the ipn.MaskedPrefs root.
func maskedPrefsFieldsAccess(p *ipn.Prefs, path string, masked reflect.Value) ProfileAccess {
	var access ProfileAccess
	for i := 0; i < masked.NumField(); i++ {
		fName := masked.Type().Field(i).Name
		if !strings.HasSuffix(fName, "Set") {
			continue
		}
		fName = strings.TrimSuffix(fName, "Set")
		fPath := path + fName
		fValue := masked.Field(i)

		switch fKind := fValue.Kind(); fKind {
		case reflect.Bool:
			if fValue.Bool() {
				access |= prefsFieldRequiredAccess(p, fPath)
			}
		case reflect.Struct:
			access |= maskedPrefsFieldsAccess(p, fPath+".", fValue)
		default:
			panic(fmt.Sprintf("unsupported mask field kind %v", fKind))
		}
	}
	return access
}

// prefsDefaultFieldAccess is the default ProfileAccess required to modify ipn.Prefs fields
// that do not have access rights overrides.
const prefsDefaultFieldAccess = ChangePrefs

var (
	// prefsStaticFieldAccessOverride allows to override ProfileAccess needed to modify ipn.Prefs fields.
	// The map uses dot-separated field paths as keys.
	prefsStaticFieldAccessOverride = map[string]ProfileAccess{
		"ExitNodeID":             ChangeExitNode,
		"ExitNodeIP":             ChangeExitNode,
		"ExitNodeAllowLANAccess": ChangeExitNode,
	}
	// prefsDynamicFieldAccessOverride is like prefsStaticFieldAccessOverride, but it maps field paths
	// to functions that dynamically determine ProfileAccess based on the target value to be set.
	prefsDynamicFieldAccessOverride = map[string]func(p *ipn.Prefs) ProfileAccess{
		"WantRunning": prefsWantRunningRequiredAccess,
	}
)

// prefsFieldRequiredAccess returns the access required to change a prefs field
// represented by its field path in ipn.MaskedPrefs to the corresponding value in p.
func prefsFieldRequiredAccess(p *ipn.Prefs, path string) ProfileAccess {
	if access, ok := prefsStaticFieldAccessOverride[path]; ok {
		return access
	}
	if accessFn, ok := prefsDynamicFieldAccessOverride[path]; ok {
		return accessFn(p)
	}
	return prefsDefaultFieldAccess
}

// prefsWantRunningRequiredAccess returns the access required to change WantRunning to the value in p.
func prefsWantRunningRequiredAccess(p *ipn.Prefs) ProfileAccess {
	if p.WantRunning {
		return Connect
	}
	return Disconnect
}
