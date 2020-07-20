// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package safesocket

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// TODO(apenwarr): handle magic cookie auth
func connect(path string, port uint16) (net.Conn, error) {
	if runtime.GOOS == "darwin" && path == "" && port == 0 {
		return connectMacOSAppSandbox()
	}
	pipe, err := net.Dial("unix", path)
	if err != nil {
		if runtime.GOOS == "darwin" {
			extConn, err := connectMacOSAppSandbox()
			if err != nil {
				log.Printf("safesocket: failed to connect to Tailscale IPNExtension: %v", err)
			} else {
				return extConn, nil
			}
		}
		return nil, err
	}
	return pipe, err
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
		return nil, 0, fmt.Errorf("%v: address already in use", path)
	}
	_ = os.Remove(path)
	os.MkdirAll(filepath.Dir(path), 0755) // best effort
	pipe, err := net.Listen("unix", path)
	if err != nil {
		return nil, 0, err
	}
	os.Chmod(path, 0666)
	return pipe, 0, err
}

// connectMacOSAppSandbox connects to the Tailscale Network Extension,
// which is necessarily running within the macOS App Sandbox.  Our
// little dance to connect a regular user binary to the sandboxed
// nework extension is:
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
		return connectMacTCP(portStr, token)
	}

	// Otherwise, assume we're running the cmd/tailscale binary from outside the
	// App Sandbox.

	out, err := exec.Command("lsof",
		"-n",                             // numeric sockets; don't do DNS lookups, etc
		"-a",                             // logical AND remaining options
		fmt.Sprintf("-u%d", os.Getuid()), // process of same user only
		"-c", "IPNExtension",             // starting with IPNExtension
		"-F", // machine-readable output
	).Output()
	if err != nil {
		return nil, err
	}
	bs := bufio.NewScanner(bytes.NewReader(out))
	subStr := []byte(".tailscale.ipn.macos/sameuserproof-")
	for bs.Scan() {
		line := bs.Bytes()
		i := bytes.Index(line, subStr)
		if i == -1 {
			continue
		}
		f := strings.SplitN(string(line[i+len(subStr):]), "-", 2)
		if len(f) != 2 {
			continue
		}
		portStr, token := f[0], f[1]
		return connectMacTCP(portStr, token)
	}
	return nil, fmt.Errorf("failed to find Tailscale's IPNExtension process")
}

func connectMacTCP(portStr, token string) (net.Conn, error) {
	c, err := net.Dial("tcp", "localhost:"+portStr)
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
