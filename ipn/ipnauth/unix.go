// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"time"

	"github.com/tailscale/peercred"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/util/groupmember"
	"tailscale.com/util/osuser"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

var (
	errMustBeRootOrOperator       = ipn.NewAccessDeniedError("must be root or an operator")
	errMustBeRootOrSudoerOperator = ipn.NewAccessDeniedError("must be root, or be an operator and able to run 'sudo tailscale' to serve a path")
)

var _ Identity = (*unixIdentity)(nil)

// unixIdentity is a non-Windows user identity.
type unixIdentity struct {
	goos  string
	creds *peercred.Creds // or nil

	// forceForTest are fields used exclusively for testing purposes.
	// Only non-nil values within this struct are used.
	forceForTest struct {
		uid, username *string
		isAdmin       *bool
	}
}

// UserID returns the empty string; it exists only to implement ipnauth.Identity.
func (id *unixIdentity) UserID() ipn.WindowsUserID {
	return ""
}

// Username returns the user name associated with the identity.
func (id *unixIdentity) Username() (string, error) {
	if id.forceForTest.username != nil {
		return *id.forceForTest.username, nil
	}
	switch id.goos {
	case "darwin", "linux":
		uid, ok := id.creds.UserID()
		if !ok {
			return "", errors.New("missing user ID")
		}
		u, err := osuser.LookupByUID(uid)
		if err != nil {
			return "", fmt.Errorf("lookup user: %w", err)
		}
		return u.Username, nil
	default:
		return "", errors.New("unsupported OS")
	}
}

// CheckAccess reports whether user is allowed or denied the requested access.
func (id *unixIdentity) CheckAccess(requested DeviceAccess) AccessCheckResult {
	if id.isPrivileged(nil, logger.Discard) {
		return AllowAccess()
	}
	allowed := GenerateBugReport | ReadDeviceStatus | InstallUpdates
	if requested&^allowed == 0 {
		return AllowAccess()
	}
	return DenyAccess(errMustBeRootOrOperator)
}

// CheckProfileAccess reports whether user is allowed or denied the requested access to the profile.
func (id *unixIdentity) CheckProfileAccess(profile ipn.LoginProfileView, prefs ipn.PrefsGetter, requested ProfileAccess) AccessCheckResult {
	operatorUID := operatorUIDFromPrefs(prefs)
	checker := newAccessChecker(requested)
	// Deny access immediately if ServePath was requested, unless the user is root,
	// or both a sudoer and an operator.
	if checker.remaining()&ServePath != 0 {
		if !id.canServePath(operatorUID) {
			return checker.deny(ServePath, errMustBeRootOrSudoerOperator)
		}
		if res := checker.grant(ServePath); res.HasResult() {
			return res
		}
	}
	// Grant non-privileges access to everyone.
	if res := checker.grant(ReadProfileInfo | ListPeers | ReadPrefs | ReadServe); res.HasResult() {
		return res
	}
	// Grant all access to root, admins and the operator.
	if id.isPrivileged(operatorUID, logger.Discard) {
		if res := checker.grant(UnrestrictedProfileAccess); res.HasResult() {
			return res
		}
	}
	// Grant cert fetching access to the TS_PERMIT_CERT_UID user.
	if id.canFetchCerts() {
		if res := checker.grant(FetchCerts); res.HasResult() {
			return res
		}
	}
	// Deny any other access.
	return DenyAccess(errMustBeRootOrOperator)
}

func operatorUIDFromPrefs(prefs ipn.PrefsGetter) func() string {
	return func() string {
		prefs, err := prefs()
		if err != nil {
			return ""
		}
		opUserName := prefs.OperatorUser()
		if opUserName == "" {
			return ""
		}
		u, err := user.Lookup(opUserName)
		if err != nil {
			return ""
		}
		return u.Uid
	}
}

// isPrivileged reports whether the identity should be considered privileged,
// meaning it's allowed to change the state of the node and access sensitive information.
func (id *unixIdentity) isPrivileged(operatorUID func() string, logf logger.Logf) bool {
	if logf == nil {
		logf = func(format string, args ...any) {
			fmt.Printf("%s", fmt.Sprintf(format, args...))
		}
	}
	const ro, rw = false, true
	if !safesocket.GOOSUsesPeerCreds(id.goos) {
		return rw
	}
	if id.forceForTest.isAdmin != nil {
		return *id.forceForTest.isAdmin
	}
	creds := id.creds
	if creds == nil {
		logf("connection from unknown peer; read-only")
		return ro
	}
	uid, ok := creds.UserID()
	if !ok {
		logf("connection from peer with unknown userid; read-only")
		return ro
	}
	if uid == "0" {
		logf("connection from userid %v; root has access", uid)
		return rw
	}
	if selfUID := os.Getuid(); selfUID != 0 && uid == strconv.Itoa(selfUID) {
		logf("connection from userid %v; connection from non-root user matching daemon has access", uid)
		return rw
	}
	if operatorUID != nil {
		if operatorUID := operatorUID(); operatorUID != "" && uid == operatorUID {
			logf("connection from userid %v; is configured operator", uid)
			return rw
		}
	}
	if yes, err := isLocalAdmin(uid); err != nil {
		logf("connection from userid %v; read-only; %v", uid, err)
		return ro
	} else if yes {
		logf("connection from userid %v; is local admin, has access", uid)
		return rw
	}
	logf("connection from userid %v; read-only", uid)
	return ro
}

// canFetchCerts reports whether id is allowed to fetch HTTPS
// certs from this server when it wouldn't otherwise be able to.
//
// That is, this reports whether id should grant additional
// capabilities over what the conn would otherwise be able to do.
//
// For now this only returns true on Unix machines when
// TS_PERMIT_CERT_UID is set the to the userid of the peer
// connection. It's intended to give your non-root webserver access
// (www-data, caddy, nginx, etc) to certs.
func (id *unixIdentity) canFetchCerts() bool {
	var uid string
	var hasUID bool
	if id.forceForTest.uid != nil {
		uid, hasUID = *id.forceForTest.uid, true
	} else if id.creds != nil {
		uid, hasUID = id.creds.UserID()
	}
	if hasUID && uid == userIDFromString(envknob.String("TS_PERMIT_CERT_UID")) {
		return true
	}
	return false
}

func (id *unixIdentity) canServePath(operatorUID func() string) bool {
	switch id.goos {
	case "linux", "darwin":
		// continue
	case "windows":
		panic("unreachable")
	default:
		return id.isPrivileged(operatorUID, logger.Discard)
	}
	// Only check for local admin on tailscaled-on-mac (based on "sudo"
	// permissions). On sandboxed variants (MacSys and AppStore), tailscaled
	// cannot serve files outside of the sandbox and this check is not
	// relevant.
	if id.goos == "darwin" && version.IsSandboxedMacOS() {
		return true
	}

	return id.isLocalAdminForServe(operatorUID)
}

// isLocalAdminForServe reports whether the identity representing a connected client
// has administrative access to the local machine, for whatever that means with respect to the
// current OS.
//
// This is useful because tailscaled itself always runs with elevated rights:
// we want to avoid privilege escalation for certain mutative operations.
func (id *unixIdentity) isLocalAdminForServe(operatorUID func() string) bool {
	if id.forceForTest.isAdmin != nil {
		return *id.forceForTest.isAdmin
	}
	switch id.goos {
	case "darwin":
		// Unknown, or at least unchecked on sandboxed macOS variants. Err on
		// the side of less permissions.
		//
		// canSetServePath should not call connIsLocalAdmin on sandboxed variants anyway.
		if version.IsSandboxedMacOS() {
			return false
		}
		// This is a standalone tailscaled setup, use the same logic as on
		// Linux.
		fallthrough
	case "linux":
		uid, ok := id.creds.UserID()
		if !ok {
			return false
		}
		// root is always admin.
		if uid == "0" {
			return true
		}
		// if non-root, must be operator AND able to execute "sudo tailscale".
		if operatorUID := operatorUID(); operatorUID != "" && uid != operatorUID {
			return false
		}
		u, err := osuser.LookupByUID(uid)
		if err != nil {
			return false
		}
		// Short timeout just in case sudo hangs for some reason.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := exec.CommandContext(ctx, "sudo", "--other-user="+u.Name, "--list", "tailscale").Run(); err != nil {
			return false
		}
		return true

	default:
		return false
	}
}

func isLocalAdmin(uid string) (bool, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return false, err
	}
	var adminGroup string
	switch {
	case runtime.GOOS == "darwin":
		adminGroup = "admin"
	case distro.Get() == distro.QNAP:
		adminGroup = "administrators"
	default:
		return false, errors.New("no system admin group found")
	}
	return groupmember.IsMemberOfGroup(adminGroup, u.Username)
}

// userIDFromString maps from either a numeric user id in string form
// ("998") or username ("caddy") to its string userid ("998").
// It returns the empty string on error.
func userIDFromString(v string) string {
	if v == "" || isAllDigit(v) {
		return v
	}
	u, err := user.Lookup(v)
	if err != nil {
		return ""
	}
	return u.Uid
}

func isAllDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b < '0' || b > '9' {
			return false
		}
	}
	return true
}
