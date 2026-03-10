// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"runtime"
	"slices"

	"go4.org/mem"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/tailcfg"
	"tailscale.com/util/lineiter"
)

func handleC2NSSHUsernames(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	var req tailcfg.C2NSSHUsernamesRequest
	if r.Method == "POST" {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	res, err := getSSHUsernames(b, &req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// getSSHUsernames discovers and returns the list of usernames that are
// potential Tailscale SSH user targets.
func getSSHUsernames(b *ipnlocal.LocalBackend, req *tailcfg.C2NSSHUsernamesRequest) (*tailcfg.C2NSSHUsernamesResponse, error) {
	res := new(tailcfg.C2NSSHUsernamesResponse)
	if b == nil || !b.ShouldRunSSH() {
		return res, nil
	}

	max := 10
	if req != nil && req.Max != 0 {
		max = req.Max
	}

	add := func(u string) {
		if req != nil && req.Exclude[u] {
			return
		}
		switch u {
		case "nobody", "daemon", "sync":
			return
		}
		if slices.Contains(res.Usernames, u) {
			return
		}
		if len(res.Usernames) > max {
			// Enough for a hint.
			return
		}
		res.Usernames = append(res.Usernames, u)
	}

	if opUser := b.OperatorUserName(); opUser != "" {
		add(opUser)
	}

	// Check popular usernames and see if they exist with a real shell.
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("dscl", ".", "list", "/Users").Output()
		if err != nil {
			return nil, err
		}
		for line := range lineiter.Bytes(out) {
			line = bytes.TrimSpace(line)
			if len(line) == 0 || line[0] == '_' {
				continue
			}
			add(string(line))
		}
	default:
		for lr := range lineiter.File("/etc/passwd") {
			line, err := lr.Value()
			if err != nil {
				break
			}
			line = bytes.TrimSpace(line)
			if len(line) == 0 || line[0] == '#' || line[0] == '_' {
				continue
			}
			if mem.HasSuffix(mem.B(line), mem.S("/nologin")) ||
				mem.HasSuffix(mem.B(line), mem.S("/false")) {
				continue
			}
			before, _, ok := bytes.Cut(line, []byte{':'})
			if ok {
				add(string(before))
			}
		}
	}
	return res, nil
}
