// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/goroutines"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

func (b *LocalBackend) handleC2N(w http.ResponseWriter, r *http.Request) {
	writeJSON := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	switch r.URL.Path {
	case "/echo":
		// Test handler.
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	case "/update":
		b.handleC2NUpdate(w, r)
	case "/logtail/flush":
		if r.Method != "POST" {
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		if b.TryFlushLogs() {
			w.WriteHeader(http.StatusNoContent)
		} else {
			http.Error(w, "no log flusher wired up", http.StatusInternalServerError)
		}
	case "/debug/goroutines":
		w.Header().Set("Content-Type", "text/plain")
		w.Write(goroutines.ScrubbedGoroutineDump())
	case "/debug/prefs":
		writeJSON(b.Prefs())
	case "/debug/metrics":
		w.Header().Set("Content-Type", "text/plain")
		clientmetric.WritePrometheusExpositionFormat(w)
	case "/debug/component-logging":
		component := r.FormValue("component")
		secs, _ := strconv.Atoi(r.FormValue("secs"))
		if secs == 0 {
			secs -= 1
		}
		until := time.Now().Add(time.Duration(secs) * time.Second)
		err := b.SetComponentDebugLogging(component, until)
		var res struct {
			Error string `json:",omitempty"`
		}
		if err != nil {
			res.Error = err.Error()
		}
		writeJSON(res)
	case "/ssh/usernames":
		var req tailcfg.C2NSSHUsernamesRequest
		if r.Method == "POST" {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		res, err := b.getSSHUsernames(&req)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(res)
	case "/sockstats":
		w.Header().Set("Content-Type", "text/plain")
		b.sockstatLogger.WriteLogs(w)
	default:
		http.Error(w, "unknown c2n path", http.StatusBadRequest)
	}
}

func (b *LocalBackend) handleC2NUpdate(w http.ResponseWriter, r *http.Request) {
	// TODO(bradfitz): add some sort of semaphore that prevents two concurrent
	// updates, or if one happened in the past 5 minutes, or something.

	// TODO(bradfitz): move this type to some leaf package
	type updateResponse struct {
		Err       string // error message, if any
		Enabled   bool   // user has opted-in to remote updates
		Supported bool   // Tailscale supports updating this OS/platform
		Started   bool
	}
	var res updateResponse
	res.Enabled = envknob.AllowsRemoteUpdate()
	res.Supported = runtime.GOOS == "windows" || (runtime.GOOS == "linux" && distro.Get() == distro.Debian)

	switch r.Method {
	case "GET", "POST":
	default:
		http.Error(w, "bad method", http.StatusMethodNotAllowed)
		return
	}

	defer func() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	}()

	if r.Method == "GET" {
		return
	}

	if !res.Enabled {
		res.Err = "not enabled"
		return
	}

	if !res.Supported {
		res.Err = "not supported"
		return
	}
	cmdTS, err := findCmdTailscale()
	if err != nil {
		res.Err = fmt.Sprintf("failed to find cmd/tailscale binary: %v", err)
		return
	}
	var ver struct {
		Long string `json:"long"`
	}
	out, err := exec.Command(cmdTS, "version", "--json").Output()
	if err != nil {
		res.Err = fmt.Sprintf("failed to find cmd/tailscale binary: %v", err)
		return
	}
	if err := json.Unmarshal(out, &ver); err != nil {
		res.Err = "invalid JSON from cmd/tailscale version --json"
		return
	}
	if ver.Long != version.Long() {
		res.Err = "cmd/tailscale version mismatch"
		return
	}
	cmd := exec.Command(cmdTS, "update", "--yes")
	if err := cmd.Start(); err != nil {
		res.Err = fmt.Sprintf("failed to start cmd/tailscale update: %v", err)
		return
	}
	res.Started = true

	// TODO(bradfitz,andrew): There might be a race condition here on Windows:
	// * We start the update process.
	// * tailscale.exe copies itself and kicks off the update process
	// * msiexec stops this process during the update before the selfCopy exits(?)
	// * This doesn't return because the process is dead.
	//
	// This seems fairly unlikely, but worth checking.
	defer cmd.Wait()
	return
}

// findCmdTailscale looks for the cmd/tailscale that corresponds to the
// currently running cmd/tailscaled. It's up to the caller to verify that the
// two match, but this function does its best to find the right one. Notably, it
// doesn't use $PATH for security reasons.
func findCmdTailscale() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "linux":
		if self == "/usr/sbin/tailscaled" {
			return "/usr/bin/tailscale", nil
		}
		return "", errors.New("tailscale not found in expected place")
	case "windows":
		dir := filepath.Dir(self)
		ts := filepath.Join(dir, "tailscale.exe")
		if fi, err := os.Stat(ts); err == nil && fi.Mode().IsRegular() {
			return ts, nil
		}
		return "", errors.New("tailscale.exe not found in expected place")
	}
	return "", fmt.Errorf("unsupported OS %v", runtime.GOOS)
}
