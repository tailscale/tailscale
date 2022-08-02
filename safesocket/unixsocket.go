// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows && !js
// +build !windows,!js

package safesocket

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
)

// TODO(apenwarr): handle magic cookie auth
func connect(s *ConnectionStrategy) (net.Conn, error) {
	if runtime.GOOS == "js" {
		return nil, errors.New("safesocket.Connect not yet implemented on js/wasm")
	}
	if runtime.GOOS == "darwin" && s.fallback && s.path == "" && s.port == 0 {
		return connectMacOSAppSandbox()
	}
	pipe, err := net.Dial("unix", s.path)
	if err != nil {
		if runtime.GOOS == "darwin" && s.fallback {
			extConn, extErr := connectMacOSAppSandbox()
			if extErr != nil {
				return nil, fmt.Errorf("safesocket: failed to connect to %v: %v; failed to connect to Tailscale IPNExtension: %v", s.path, err, extErr)
			}
			return extConn, nil
		}
		return nil, err
	}
	return pipe, nil
}

// TODO(apenwarr): handle magic cookie auth
func listen(path string, port uint16) (ln net.Listener, _ uint16, err error) {
	// Unix sockets hang around in the filesystem even after nobody
	// is listening on them. (Which is really unfortunate but long-
	// entrenched semantics.) Try connecting first; if it works, then
	// the socket is still live, so let's not replace it. If it doesn't
	// work, then replace it.
	//
	// Note that there's a race condition between these two steps. A
	// "proper" daemon usually uses a dance involving pidfiles to first
	// ensure that no other instances of itself are running, but that's
	// beyond the scope of our simple socket library.
	c, err := net.Dial("unix", path)
	if err == nil {
		c.Close()
		if tailscaledRunningUnderLaunchd() {
			return nil, 0, fmt.Errorf("%v: address already in use; tailscaled already running under launchd (to stop, run: $ sudo launchctl stop com.tailscale.tailscaled)", path)
		}
		return nil, 0, fmt.Errorf("%v: address already in use", path)
	}
	_ = os.Remove(path)

	perm := socketPermissionsForOS()

	sockDir := filepath.Dir(path)
	if _, err := os.Stat(sockDir); os.IsNotExist(err) {
		os.MkdirAll(sockDir, 0755) // best effort

		// If we're on a platform where we want the socket
		// world-readable, open up the permissions on the
		// just-created directory too, in case a umask ate
		// it. This primarily affects running tailscaled by
		// hand as root in a shell, as there is no umask when
		// running under systemd.
		if perm == 0666 {
			if fi, err := os.Stat(sockDir); err == nil && fi.Mode()&0077 == 0 {
				if err := os.Chmod(sockDir, 0755); err != nil {
					log.Print(err)
				}
			}
		}
	}
	pipe, err := net.Listen("unix", path)
	if err != nil {
		return nil, 0, err
	}
	os.Chmod(path, perm)
	return pipe, 0, err
}

func tailscaledRunningUnderLaunchd() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	plist, err := exec.Command("launchctl", "list", "com.tailscale.tailscaled").Output()
	_ = plist // parse it? https://github.com/DHowett/go-plist if we need something.
	running := err == nil
	return running
}

// socketPermissionsForOS returns the permissions to use for the
// tailscaled.sock.
func socketPermissionsForOS() os.FileMode {
	if PlatformUsesPeerCreds() {
		return 0666
	}
	// Otherwise, root only.
	return 0600
}

// connectMacOSAppSandbox connects to the Tailscale Network Extension (macOS App
// Store build) or App Extension (macsys standalone build), where the CLI itself
// is either running within the macOS App Sandbox or built separately (e.g.
// homebrew or go install). This little dance to connect a regular user binary
// to the sandboxed network extension is:
//
//   - the sandboxed IPNExtension picks a random localhost:0 TCP port
//     to listen on
//   - it also picks a random hex string that acts as an auth token
//   - the CLI looks on disk for that TCP port + auth token (see localTCPPortAndTokenDarwin)
//   - we send it upon TCP connect to prove to the Tailscale daemon that
//     we're a suitably privileged user to have access the files on disk
//     which the Network/App Extension wrote.
func connectMacOSAppSandbox() (net.Conn, error) {
	port, token, err := LocalTCPPortAndToken()
	if err != nil {
		return nil, fmt.Errorf("failed to find local Tailscale daemon: %w", err)
	}
	return connectMacTCP(port, token)
}

// connectMacTCP creates an authenticated net.Conn to the local macOS Tailscale
// daemon for used by the "IPN" JSON message bus protocol (Tailscale's original
// local non-HTTP IPC protocol).
func connectMacTCP(port int, token string) (net.Conn, error) {
	c, err := net.Dial("tcp", "localhost:"+strconv.Itoa(port))
	if err != nil {
		return nil, fmt.Errorf("error dialing IPNExtension: %w", err)
	}
	if _, err := io.WriteString(c, token+"\n"); err != nil {
		return nil, fmt.Errorf("error writing auth token: %w", err)
	}
	buf := make([]byte, 5)
	const authOK = "#IPN\n"
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, fmt.Errorf("error reading from IPNExtension post-auth: %w", err)
	}
	if string(buf) != authOK {
		return nil, fmt.Errorf("invalid response reading from IPNExtension post-auth")
	}
	return c, nil
}
