// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package safesocket

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/version"
)

func init() {
	localTCPPortAndToken = localTCPPortAndTokenDarwin
}

// localTCPPortAndTokenMacsys returns the localhost TCP port number and auth token
// from /Library/Tailscale.
//
// In that case the files are:
//
//	/Library/Tailscale/ipnport => $port (symlink with localhost port number target)
//	/Library/Tailscale/sameuserproof-$port is a file with auth
func localTCPPortAndTokenMacsys() (port int, token string, err error) {

	const dir = "/Library/Tailscale"
	portStr, err := os.Readlink(filepath.Join(dir, "ipnport"))
	if err != nil {
		return 0, "", err
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return 0, "", err
	}
	authb, err := os.ReadFile(filepath.Join(dir, "sameuserproof-"+portStr))
	if err != nil {
		return 0, "", err
	}
	auth := strings.TrimSpace(string(authb))
	if auth == "" {
		return 0, "", errors.New("empty auth token in sameuserproof file")
	}

	// The above files exist forever after the first run of
	// /Applications/Tailscale.app, so check we can connect to avoid returning a
	// port nothing is listening on. Connect to "127.0.0.1" rather than
	// "localhost" due to #7851.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+portStr, time.Second)
	if err != nil {
		return 0, "", err
	}
	conn.Close()

	return port, auth, nil
}

var warnAboutRootOnce sync.Once

func localTCPPortAndTokenDarwin() (port int, token string, err error) {
	// There are two ways this binary can be run: as the Mac App Store sandboxed binary,
	// or a normal binary that somebody built or download and are being run from outside
	// the sandbox. Detect which way we're running and then figure out how to connect
	// to the local daemon.

	if dir := os.Getenv("TS_MACOS_CLI_SHARED_DIR"); dir != "" {
		// First see if we're running as the non-AppStore "macsys" variant.
		if version.IsMacSys() {
			if port, token, err := localTCPPortAndTokenMacsys(); err == nil {
				return port, token, nil
			}
		}

		// The current binary (this process) is sandboxed. The user is
		// running the CLI via /Applications/Tailscale.app/Contents/MacOS/Tailscale
		// which sets the TS_MACOS_CLI_SHARED_DIR environment variable.
		fis, err := os.ReadDir(dir)
		if err != nil {
			return 0, "", err
		}
		for _, fi := range fis {
			name := filepath.Base(fi.Name())
			// Look for name like "sameuserproof-61577-2ae2ec9e0aa2005784f1"
			// to extract out the port number and token.
			if strings.HasPrefix(name, "sameuserproof-") {
				f := strings.SplitN(name, "-", 3)
				if len(f) == 3 {
					if port, err := strconv.Atoi(f[1]); err == nil {
						return port, f[2], nil
					}
				}
			}
		}
		if os.Geteuid() == 0 {
			// Log a warning as the clue to the user, in case the error
			// message is swallowed. Only do this once since we may retry
			// multiple times to connect, and don't want to spam.
			warnAboutRootOnce.Do(func() {
				fmt.Fprintf(os.Stderr, "Warning: The CLI is running as root from within a sandboxed binary. It cannot reach the local tailscaled, please try again as a regular user.\n")
			})
		}
		return 0, "", fmt.Errorf("failed to find sandboxed sameuserproof-* file in TS_MACOS_CLI_SHARED_DIR %q", dir)
	}

	// The current process is running outside the sandbox, so use
	// lsof to find the IPNExtension (the Mac App Store variant).

	cmd := exec.Command("lsof",
		"-n",                             // numeric sockets; don't do DNS lookups, etc
		"-a",                             // logical AND remaining options
		fmt.Sprintf("-u%d", os.Getuid()), // process of same user only
		"-c", "IPNExtension",             // starting with IPNExtension
		"-F", // machine-readable output
	)
	out, err := cmd.Output()
	if err != nil {
		// Before returning an error, see if we're running the
		// macsys variant at the normal location.
		if port, token, err := localTCPPortAndTokenMacsys(); err == nil {
			return port, token, nil
		}

		return 0, "", fmt.Errorf("failed to run '%s' looking for IPNExtension: %w", cmd, err)
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
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return 0, "", fmt.Errorf("invalid port %q found in lsof", portStr)
		}
		return port, token, nil
	}

	// Before returning an error, see if we're running the
	// macsys variant at the normal location.
	if port, token, err := localTCPPortAndTokenMacsys(); err == nil {
		return port, token, nil
	}
	return 0, "", ErrTokenNotFound
}
