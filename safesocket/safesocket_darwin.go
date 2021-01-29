// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package safesocket

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func init() {
	localTCPPortAndToken = localTCPPortAndTokenDarwin
}

func localTCPPortAndTokenDarwin() (port int, token string, err error) {
	out, err := exec.Command("lsof",
		"-n",                             // numeric sockets; don't do DNS lookups, etc
		"-a",                             // logical AND remaining options
		fmt.Sprintf("-u%d", os.Getuid()), // process of same user only
		"-c", "IPNExtension",             // starting with IPNExtension
		"-F", // machine-readable output
	).Output()
	if err != nil {
		return 0, "", fmt.Errorf("failed to run lsof looking for IPNExtension: %w", err)
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
	return 0, "", ErrTokenNotFound
}
