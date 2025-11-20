// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import (
	"os"
	"strings"
	"testing"

	"tailscale.com/tstest"
)

// TestSetCredentials verifies that calling SetCredentials
// sets the port and token correctly and that LocalTCPPortAndToken
// returns the given values.
func TestSetCredentials(t *testing.T) {
	const (
		wantToken = "token"
		wantPort  = 123
	)

	tstest.Replace(t, &ssd.isMacGUIApp, func() bool { return false })
	SetCredentials(wantToken, wantPort)

	gotPort, gotToken, err := LocalTCPPortAndToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotPort != wantPort {
		t.Errorf("port: got %d, want %d", gotPort, wantPort)
	}

	if gotToken != wantToken {
		t.Errorf("token: got %s, want %s", gotToken, wantToken)
	}
}

// TestFallbackToSameuserproof verifies that we fallback to the
// sameuserproof file via LocalTCPPortAndToken when we're running
//
//	s cmd/tailscale
func TestFallbackToSameuserproof(t *testing.T) {
	dir := t.TempDir()
	const (
		wantToken = "token"
		wantPort  = 123
	)

	// Mimics cmd/tailscale falling back to sameuserproof
	tstest.Replace(t, &ssd.isMacGUIApp, func() bool { return false })
	tstest.Replace(t, &ssd.sharedDir, dir)
	tstest.Replace(t, &ssd.checkConn, false)

	// Behave as macSysExt when initializing sameuserproof
	tstest.Replace(t, &ssd.isMacSysExt, func() bool { return true })
	if err := initSameUserProofToken(dir, wantPort, wantToken); err != nil {
		t.Fatalf("initSameUserProofToken: %v", err)
	}

	gotPort, gotToken, err := LocalTCPPortAndToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotPort != wantPort {
		t.Errorf("port: got %d, want %d", gotPort, wantPort)
	}

	if gotToken != wantToken {
		t.Errorf("token: got %s, want %s", gotToken, wantToken)
	}
}

// TestInitListenerDarwin verifies that InitListenerDarwin
// returns a listener and a non-zero port and non-empty token.
func TestInitListenerDarwin(t *testing.T) {
	temp := t.TempDir()
	tstest.Replace(t, &ssd.isMacGUIApp, func() bool { return false })

	ln, err := InitListenerDarwin(temp)
	if err != nil || ln == nil {
		t.Fatalf("InitListenerDarwin failed: %v", err)
	}
	defer (*ln).Close()

	port, token, err := LocalTCPPortAndToken()
	if err != nil {
		t.Fatalf("LocalTCPPortAndToken failed: %v", err)
	}

	if port == 0 {
		t.Errorf("port: got %d, want non-zero", port)
	}

	if token == "" {
		t.Errorf("token: got %s, want non-empty", token)
	}
}

func TestTokenGeneration(t *testing.T) {
	token, err := getToken()
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}

	// Verify token length (hex string is 2x byte length)
	wantLen := sameUserProofTokenLength * 2
	if got := len(token); got != wantLen {
		t.Errorf("token length: got %d, want %d", got, wantLen)
	}

	// Verify token persistence
	subsequentToken, err := getToken()
	if err != nil {
		t.Fatalf("subsequent getToken: %v", err)
	}
	if subsequentToken != token {
		t.Errorf("subsequent token: got %q, want %q", subsequentToken, token)
	}
}

// TestSameUserProofToken verifies that the sameuserproof file
// is created and read correctly for the macsys variant
func TestMacsysSameuserproof(t *testing.T) {
	dir := t.TempDir()

	tstest.Replace(t, &ssd.isMacSysExt, func() bool { return true })
	tstest.Replace(t, &ssd.checkConn, false)
	tstest.Replace(t, &ssd.sharedDir, dir)

	const (
		wantToken = "token"
		wantPort  = 123
	)

	if err := initSameUserProofToken(dir, wantPort, wantToken); err != nil {
		t.Fatalf("initSameUserProofToken: %v", err)
	}

	gotPort, gotToken, err := readMacsysSameUserProof()
	if err != nil {
		t.Fatalf("readMacOSSameUserProof: %v", err)
	}

	if gotPort != wantPort {
		t.Errorf("port: got %d, want %d", gotPort, wantPort)
	}
	if wantToken != gotToken {
		t.Errorf("token: got %s, want %s", wantToken, gotToken)
	}
	assertFileCount(t, dir, 1, "sameuserproof-")
}

// TestMacosSameuserproof verifies that the sameuserproof file
// is created correctly for the macos variant
func TestMacosSameuserproof(t *testing.T) {
	dir := t.TempDir()
	wantToken := "token"
	wantPort := 123

	initSameUserProofToken(dir, wantPort, wantToken)

	// initSameUserProofToken should never leave duplicates
	initSameUserProofToken(dir, wantPort, wantToken)

	// we can't just call readMacosSameUserProof because it relies on lsof
	// and makes some assumptions about the user.  But we can make sure
	// the file exists
	assertFileCount(t, dir, 1, "sameuserproof-")
}

func assertFileCount(t *testing.T, dir string, want int, prefix string) {
	t.Helper()

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("[unexpected] error: %v", err)
	}
	count := 0
	for _, file := range files {
		if strings.HasPrefix(file.Name(), prefix) {
			count += 1
		}
	}
	if count != want {
		t.Errorf("files: got %d, want 1", count)
	}
}
