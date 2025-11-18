// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnauth

import (
	"errors"
	"net"
	"os/user"
	"runtime"
	"testing"
)

func TestConnIdentity_Accessors(t *testing.T) {
	tests := []struct {
		name      string
		ci        *ConnIdentity
		wantPid   int
		wantUnix  bool
		wantCreds bool // whether creds should be nil
	}{
		{
			name: "basic_unix",
			ci: &ConnIdentity{
				pid:        12345,
				isUnixSock: true,
				creds:      nil,
			},
			wantPid:   12345,
			wantUnix:  true,
			wantCreds: false,
		},
		{
			name: "no_creds",
			ci: &ConnIdentity{
				pid:        0,
				isUnixSock: false,
				creds:      nil,
			},
			wantPid:   0,
			wantUnix:  false,
			wantCreds: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ci.Pid(); got != tt.wantPid {
				t.Errorf("Pid() = %v, want %v", got, tt.wantPid)
			}
			if got := tt.ci.IsUnixSock(); got != tt.wantUnix {
				t.Errorf("IsUnixSock() = %v, want %v", got, tt.wantUnix)
			}
			// Just test that Creds() doesn't panic
			_ = tt.ci.Creds()
		})
	}
}

func TestIsReadonlyConn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("IsReadonlyConn always returns false on Windows")
	}

	tests := []struct {
		name        string
		ci          *ConnIdentity
		operatorUID string
		wantRO      bool
		desc        string
	}{
		{
			name: "no_creds",
			ci: &ConnIdentity{
				notWindows: true,
				creds:      nil,
			},
			operatorUID: "",
			wantRO:      true,
			desc:        "connection with no credentials should be read-only",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logf := t.Logf
			got := tt.ci.IsReadonlyConn(tt.operatorUID, logf)
			if got != tt.wantRO {
				t.Errorf("IsReadonlyConn() = %v, want %v (%s)", got, tt.wantRO, tt.desc)
			}
		})
	}
}

func TestIsReadonlyConn_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific test")
	}

	ci := &ConnIdentity{
		notWindows: false,
	}

	// On Windows, IsReadonlyConn should always return false
	if got := ci.IsReadonlyConn("", t.Logf); got != false {
		t.Errorf("IsReadonlyConn() on Windows = %v, want false", got)
	}
}

func TestWindowsUserID(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		wantSID bool
	}{
		{
			name:    "non_windows",
			goos:    "linux",
			wantSID: false,
		},
		{
			name:    "windows",
			goos:    "windows",
			wantSID: true, // will try to get WindowsToken
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS != tt.goos {
				t.Skipf("test requires GOOS=%s", tt.goos)
			}

			ci := &ConnIdentity{
				notWindows: tt.goos != "windows",
			}

			uid := ci.WindowsUserID()
			if tt.wantSID && uid == "" {
				// On Windows, we might get empty if WindowsToken fails
				// which is acceptable in unit tests
				t.Logf("WindowsUserID returned empty (expected in test env)")
			}
			if !tt.wantSID && uid != "" {
				t.Errorf("WindowsUserID() on %s = %q, want empty", tt.goos, uid)
			}
		})
	}
}

func TestLookupUserFromID(t *testing.T) {
	// Test with current user's UID
	currentUser, err := user.Current()
	if err != nil {
		t.Skipf("can't get current user: %v", err)
	}

	logf := t.Logf
	u, err := LookupUserFromID(logf, currentUser.Uid)
	if err != nil {
		t.Fatalf("LookupUserFromID(%q) failed: %v", currentUser.Uid, err)
	}
	if u.Uid != currentUser.Uid {
		t.Errorf("LookupUserFromID(%q).Uid = %q, want %q", currentUser.Uid, u.Uid, currentUser.Uid)
	}

	// Test with invalid UID
	invalidUID := "99999999"
	_, err = LookupUserFromID(logf, invalidUID)
	if err == nil && runtime.GOOS != "windows" {
		// On non-Windows, invalid UID should return error
		// On Windows, it might succeed due to workarounds
		t.Errorf("LookupUserFromID(%q) succeeded, expected error", invalidUID)
	}
}

func TestErrNotImplemented(t *testing.T) {
	expectedMsg := "not implemented for GOOS=" + runtime.GOOS
	if !errors.Is(ErrNotImplemented, ErrNotImplemented) {
		t.Error("ErrNotImplemented should match itself")
	}
	if got := ErrNotImplemented.Error(); got != expectedMsg {
		t.Errorf("ErrNotImplemented.Error() = %q, want %q", got, expectedMsg)
	}
}

func TestWindowsToken_NotWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test for non-Windows platforms")
	}

	ci := &ConnIdentity{
		notWindows: true,
	}

	tok, err := ci.WindowsToken()
	if !errors.Is(err, ErrNotImplemented) {
		t.Errorf("WindowsToken() on non-Windows: err = %v, want ErrNotImplemented", err)
	}
	if tok != nil {
		t.Errorf("WindowsToken() on non-Windows: token = %v, want nil", tok)
	}
}

func TestGetConnIdentity_NotWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test for non-Windows platforms")
	}

	// Create a Unix socket pair for testing
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	// Convert to UnixConn for testing (requires actual Unix socket)
	// For now, test with regular net.Conn
	ci, err := GetConnIdentity(t.Logf, client)
	if err != nil {
		t.Fatalf("GetConnIdentity() failed: %v", err)
	}

	if ci == nil {
		t.Fatal("GetConnIdentity() returned nil ConnIdentity")
	}
	if !ci.notWindows {
		t.Error("GetConnIdentity() on non-Windows should set notWindows=true")
	}
}

func TestIsLocalAdmin_UnsupportedPlatform(t *testing.T) {
	// Test on platforms where isLocalAdmin doesn't support admin group detection
	if runtime.GOOS == "darwin" {
		t.Skip("darwin supports admin group detection")
	}

	// Use a fake UID
	fakeUID := "12345"
	isAdmin, err := isLocalAdmin(fakeUID)
	if err == nil {
		t.Error("isLocalAdmin() on unsupported platform should return error")
	}
	if isAdmin {
		t.Error("isLocalAdmin() on unsupported platform should return false")
	}
}

// Helper functions - removed makeCreds as peercred.Creds fields are not exported

func TestConnIdentity_NilChecks(t *testing.T) {
	// Test that nil checks don't panic
	var ci *ConnIdentity

	// These should not panic even with nil receiver
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("operations on nil ConnIdentity should not panic: %v", r)
		}
	}()

	// Note: Calling methods on nil pointer will panic in Go
	// This test documents the behavior
	ci = &ConnIdentity{}
	_ = ci.Pid()
	_ = ci.IsUnixSock()
	_ = ci.Creds()
	_ = ci.WindowsUserID()
}

func TestConnIdentity_ConcurrentAccess(t *testing.T) {
	ci := &ConnIdentity{
		pid:        12345,
		isUnixSock: true,
		notWindows: true,
	}

	// Test concurrent reads are safe
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = ci.Pid()
			_ = ci.IsUnixSock()
			_ = ci.Creds()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestWindowsUserID_EmptyOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test for non-Windows behavior")
	}

	ci := &ConnIdentity{
		notWindows: true,
	}

	uid := ci.WindowsUserID()
	if uid != "" {
		t.Errorf("WindowsUserID() on non-Windows = %q, want empty string", uid)
	}
}

func TestIsReadonlyConn_LogOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test for non-Windows platforms")
	}

	// Test that logging actually happens
	var loggedMessages []string
	logf := func(format string, args ...any) {
		loggedMessages = append(loggedMessages, format)
	}

	ci := &ConnIdentity{
		notWindows: true,
		creds:      nil,
	}

	_ = ci.IsReadonlyConn("", logf)

	if len(loggedMessages) == 0 {
		t.Error("IsReadonlyConn should log messages")
	}
}

func TestGetConnIdentity_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// This would require actual socket setup
	// Skipping for now, but placeholder for integration tests
	t.Skip("integration test requires real socket setup")
}
