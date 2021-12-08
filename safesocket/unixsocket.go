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
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
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

// connectMacOSAppSandbox connects to the Tailscale Network Extension,
// which is necessarily running within the macOS App Sandbox.  Our
// little dance to connect a regular user binary to the sandboxed
// network extension is:
//
//   * the sandboxed IPNExtension picks a random localhost:0 TCP port
//     to listen on
//   * it also picks a random hex string that acts as an auth token
//   * it then creates a file named "sameuserproof-$PORT-$TOKEN" and leaves
//     that file descriptor open forever.
//
// Then, we do different things depending on whether the user is
// running cmd/tailscale that they built themselves (running as
// themselves, outside the App Sandbox), or whether the user is
// running the CLI via the GUI binary
// (e.g. /Applications/Tailscale.app/Contents/MacOS/Tailscale <args>),
// in which case we're running within the App Sandbox.
//
// If we're outside the App Sandbox:
//
//   * then we come along here, running as the same UID, but outside
//     of the sandbox, and look for it. We can run lsof on our own processes,
//     but other users on the system can't.
//   * we parse out the localhost port number and the auth token
//   * we connect to TCP localhost:$PORT
//   * we send $TOKEN + "\n"
//   * server verifies $TOKEN, sends "#IPN\n" if okay.
//   * server is now protocol switched
//   * we return the net.Conn and the caller speaks the normal protocol
//
// If we're inside the App Sandbox, then TS_MACOS_CLI_SHARED_DIR has
// been set to our shared directory. We now have to find the most
// recent "sameuserproof" file (there should only be 1, but previous
// versions of the macOS app didn't clean them up).
func connectMacOSAppSandbox() (net.Conn, error) {
	// Are we running the Tailscale.app GUI binary as a CLI, running within the App Sandbox?
	if d := os.Getenv("TS_MACOS_CLI_SHARED_DIR"); d != "" {
		fis, err := ioutil.ReadDir(d)
		if err != nil {
			return nil, fmt.Errorf("reading TS_MACOS_CLI_SHARED_DIR: %w", err)
		}
		var best os.FileInfo
		for _, fi := range fis {
			if !strings.HasPrefix(fi.Name(), "sameuserproof-") || strings.Count(fi.Name(), "-") != 2 {
				continue
			}
			if best == nil || fi.ModTime().After(best.ModTime()) {
				best = fi
			}
		}
		if best == nil {
			return nil, fmt.Errorf("no sameuserproof token found in TS_MACOS_CLI_SHARED_DIR %q", d)
		}
		f := strings.SplitN(best.Name(), "-", 3)
		portStr, token := f[1], f[2]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q", portStr)
		}
		return connectMacTCP(port, token)
	}

	// Otherwise, assume we're running the cmd/tailscale binary from outside the
	// App Sandbox.
	port, token, err := LocalTCPPortAndToken()
	if err != nil {
		return nil, err
	}
	return connectMacTCP(port, token)
}

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
