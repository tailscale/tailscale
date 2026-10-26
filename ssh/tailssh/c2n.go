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
	"tailscale.com/util/set"
)

// hookLocalUsernames, if non-nil, lists the local user accounts on
// platforms without /etc/passwd. It is set by platform-specific code.
var hookLocalUsernames func() ([]string, error)

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

// maxSSHUsernameHints caps the number of usernames returned to a client;
// the list is only a login hint.
const maxSSHUsernameHints = 100

// appendSSHUsernameHint appends u to names unless it is excluded or a
// service account, is already present, or the list already has max entries
// (so the result never exceeds max entries).
func appendSSHUsernameHint(names []string, u string, exclude set.Set[string], max int) []string {
	if exclude.Contains(u) {
		return names
	}
	switch u {
	case "nobody", "daemon", "sync":
		return names
	}
	if slices.Contains(names, u) {
		return names
	}
	if len(names) >= max {
		// Enough for a hint.
		return names
	}
	return append(names, u)
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
		// The client-supplied cap is just a hint; clamp it to a sane ceiling.
		max = min(req.Max, maxSSHUsernameHints)
	}

	exclude := make(set.Set[string])
	for u, e := range req.Exclude {
		if e {
			exclude.Add(u)
		}
	}
	add := func(u string) {
		res.Usernames = appendSSHUsernameHint(res.Usernames, u, exclude, max)
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
		if hookLocalUsernames != nil {
			names, err := hookLocalUsernames()
			if err != nil {
				return nil, err
			}
			for _, name := range names {
				add(name)
			}
			break
		}
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
