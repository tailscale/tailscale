// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package clientupdate enables the client update feature.
package clientupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/clientupdate"
	"tailscale.com/envknob"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/localapi"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
	"tailscale.com/version"
	"tailscale.com/version/distro"
)

func init() {
	ipnext.RegisterExtension("clientupdate", newExt)

	// C2N
	ipnlocal.RegisterC2N("GET /update", handleC2NUpdateGet)
	ipnlocal.RegisterC2N("POST /update", handleC2NUpdatePost)

	//	LocalAPI:
	localapi.Register("update/install", serveUpdateInstall)
	localapi.Register("update/progress", serveUpdateProgress)
}

func newExt(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf: logf,
		sb:   sb,

		lastSelfUpdateState: ipnstate.UpdateFinished,
	}, nil
}

type extension struct {
	logf logger.Logf
	sb   ipnext.SafeBackend

	mu sync.Mutex

	// c2nUpdateStatus is the status of c2n-triggered client update.
	c2nUpdateStatus updateStatus
	prefs           ipn.PrefsView
	state           ipn.State

	lastSelfUpdateState ipnstate.SelfUpdateStatus
	selfUpdateProgress  []ipnstate.UpdateProgress

	// offlineAutoUpdateCancel stops offline auto-updates when called. It
	// should be used via stopOfflineAutoUpdate and
	// maybeStartOfflineAutoUpdate. It is nil when offline auto-updates are
	// not running.
	//
	//lint:ignore U1000 only used in Linux and Windows builds in autoupdate.go
	offlineAutoUpdateCancel func()
}

func (e *extension) Name() string { return "clientupdate" }

func (e *extension) Init(h ipnext.Host) error {

	h.Hooks().ProfileStateChange.Add(e.onChangeProfile)
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)

	// TODO(nickkhyl): remove this after the profileManager refactoring.
	// See tailscale/tailscale#15974.
	// This same workaround appears in feature/portlist/portlist.go.
	profile, prefs := h.Profiles().CurrentProfileState()
	e.onChangeProfile(profile, prefs, false)

	return nil
}

func (e *extension) Shutdown() error {
	e.stopOfflineAutoUpdate()
	return nil
}

func (e *extension) onBackendStateChange(newState ipn.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state = newState
	e.updateOfflineAutoUpdateLocked()
}

func (e *extension) onChangeProfile(profile ipn.LoginProfileView, prefs ipn.PrefsView, sameNode bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.prefs = prefs
	e.updateOfflineAutoUpdateLocked()
}

func (e *extension) updateOfflineAutoUpdateLocked() {
	want := e.prefs.Valid() && e.prefs.AutoUpdate().Apply.EqualBool(true) &&
		e.state != ipn.Running && e.state != ipn.Starting

	cur := e.offlineAutoUpdateCancel != nil

	if want && !cur {
		e.maybeStartOfflineAutoUpdateLocked(e.prefs)
	} else if !want && cur {
		e.stopOfflineAutoUpdateLocked()
	}
}

type updateStatus struct {
	started bool
}

func (e *extension) clearSelfUpdateProgress() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.selfUpdateProgress = make([]ipnstate.UpdateProgress, 0)
	e.lastSelfUpdateState = ipnstate.UpdateFinished
}

func (e *extension) GetSelfUpdateProgress() []ipnstate.UpdateProgress {
	e.mu.Lock()
	defer e.mu.Unlock()
	res := make([]ipnstate.UpdateProgress, len(e.selfUpdateProgress))
	copy(res, e.selfUpdateProgress)
	return res
}

func (e *extension) DoSelfUpdate() {
	e.mu.Lock()
	updateState := e.lastSelfUpdateState
	e.mu.Unlock()
	// don't start an update if one is already in progress
	if updateState == ipnstate.UpdateInProgress {
		return
	}
	e.clearSelfUpdateProgress()
	e.pushSelfUpdateProgress(ipnstate.NewUpdateProgress(ipnstate.UpdateInProgress, ""))
	up, err := clientupdate.NewUpdater(clientupdate.Arguments{
		Logf: func(format string, args ...any) {
			e.pushSelfUpdateProgress(ipnstate.NewUpdateProgress(ipnstate.UpdateInProgress, fmt.Sprintf(format, args...)))
		},
	})
	if err != nil {
		e.pushSelfUpdateProgress(ipnstate.NewUpdateProgress(ipnstate.UpdateFailed, err.Error()))
	}
	err = up.Update()
	if err != nil {
		e.pushSelfUpdateProgress(ipnstate.NewUpdateProgress(ipnstate.UpdateFailed, err.Error()))
	} else {
		e.pushSelfUpdateProgress(ipnstate.NewUpdateProgress(ipnstate.UpdateFinished, "tailscaled did not restart; please restart Tailscale manually."))
	}
}

// serveUpdateInstall sends a request to the LocalBackend to start a Tailscale
// self-update. A successful response does not indicate whether the update
// succeeded, only that the request was accepted. Clients should use
// serveUpdateProgress after pinging this endpoint to check how the update is
// going.
func serveUpdateInstall(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	b := h.LocalBackend()
	ext, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		http.Error(w, "clientupdate extension not found", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)

	go ext.DoSelfUpdate()
}

// serveUpdateProgress returns the status of an in-progress Tailscale self-update.
// This is provided as a slice of ipnstate.UpdateProgress structs with various
// log messages in order from oldest to newest. If an update is not in progress,
// the returned slice will be empty.
func serveUpdateProgress(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "only GET allowed", http.StatusMethodNotAllowed)
		return
	}

	b := h.LocalBackend()
	ext, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		http.Error(w, "clientupdate extension not found", http.StatusInternalServerError)
		return
	}

	ups := ext.GetSelfUpdateProgress()

	json.NewEncoder(w).Encode(ups)
}

func (e *extension) pushSelfUpdateProgress(up ipnstate.UpdateProgress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.selfUpdateProgress = append(e.selfUpdateProgress, up)
	e.lastSelfUpdateState = up.Status
}

func handleC2NUpdateGet(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		http.Error(w, "clientupdate extension not found", http.StatusInternalServerError)
		return
	}

	e.logf("c2n: GET /update received")

	res := e.newC2NUpdateResponse()
	res.Started = e.c2nUpdateStarted()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleC2NUpdatePost(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		http.Error(w, "clientupdate extension not found", http.StatusInternalServerError)
		return
	}
	e.logf("c2n: POST /update received")
	res := e.newC2NUpdateResponse()
	defer func() {
		if res.Err != "" {
			e.logf("c2n: POST /update failed: %s", res.Err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	}()

	if !res.Enabled {
		res.Err = "not enabled"
		return
	}
	if !res.Supported {
		res.Err = "not supported"
		return
	}

	// Do not update if we have active inbound SSH connections. Control can set
	// force=true query parameter to override this.
	if r.FormValue("force") != "true" && b.ActiveSSHConns() > 0 {
		res.Err = "not updating due to active SSH connections"
		return
	}

	if err := e.startAutoUpdate("c2n"); err != nil {
		res.Err = err.Error()
		return
	}
	res.Started = true
}

func (e *extension) newC2NUpdateResponse() tailcfg.C2NUpdateResponse {
	e.mu.Lock()
	defer e.mu.Unlock()

	// If NewUpdater does not return an error, we can update the installation.
	//
	// Note that we create the Updater solely to check for errors; we do not
	// invoke it here. For this purpose, it is ok to pass it a zero Arguments.
	var upPref ipn.AutoUpdatePrefs
	if e.prefs.Valid() {
		upPref = e.prefs.AutoUpdate()
	}
	return tailcfg.C2NUpdateResponse{
		Enabled:   envknob.AllowsRemoteUpdate() || upPref.Apply.EqualBool(true),
		Supported: feature.CanAutoUpdate() && !version.IsMacSysExt(),
	}
}

func (e *extension) c2nUpdateStarted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.c2nUpdateStatus.started
}

func (e *extension) setC2NUpdateStarted(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.c2nUpdateStatus.started = v
}

func (e *extension) trySetC2NUpdateStarted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.c2nUpdateStatus.started {
		return false
	}
	e.c2nUpdateStatus.started = true
	return true
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
	var ts string
	switch runtime.GOOS {
	case "linux":
		if self == "/usr/sbin/tailscaled" || self == "/usr/bin/tailscaled" {
			ts = "/usr/bin/tailscale"
		}
		if self == "/usr/local/sbin/tailscaled" || self == "/usr/local/bin/tailscaled" {
			ts = "/usr/local/bin/tailscale"
		}
		switch distro.Get() {
		case distro.QNAP:
			// The volume under /share/ where qpkg are installed is not
			// predictable. But the rest of the path is.
			ok, err := filepath.Match("/share/*/.qpkg/Tailscale/tailscaled", self)
			if err == nil && ok {
				ts = filepath.Join(filepath.Dir(self), "tailscale")
			}
		case distro.Unraid:
			if self == "/usr/local/emhttp/plugins/tailscale/bin/tailscaled" {
				ts = "/usr/local/emhttp/plugins/tailscale/bin/tailscale"
			}
		}
	case "windows":
		ts = filepath.Join(filepath.Dir(self), "tailscale.exe")
	case "freebsd", "openbsd":
		if self == "/usr/local/bin/tailscaled" {
			ts = "/usr/local/bin/tailscale"
		}
	default:
		return "", fmt.Errorf("unsupported OS %v", runtime.GOOS)
	}
	if ts != "" && regularFileExists(ts) {
		return ts, nil
	}
	return "", errors.New("tailscale executable not found in expected place")
}

func tailscaleUpdateCmd(cmdTS string) *exec.Cmd {
	defaultCmd := exec.Command(cmdTS, "update", "--yes")
	if runtime.GOOS != "linux" {
		return defaultCmd
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return defaultCmd
	}

	// When systemd-run is available, use it to run the update command. This
	// creates a new temporary unit separate from the tailscaled unit. When
	// tailscaled is restarted during the update, systemd won't kill this
	// temporary update unit, which could cause unexpected breakage.
	//
	// We want to use a few optional flags:
	//  * --wait, to block the update command until completion (added in systemd 232)
	//  * --pipe, to collect stdout/stderr (added in systemd 235)
	//  * --collect, to clean up failed runs from memory (added in systemd 236)
	//
	// We need to check the version of systemd to figure out if those flags are
	// available.
	//
	// The output will look like:
	//
	//   systemd 255 (255.7-1-arch)
	//   +PAM +AUDIT ... other feature flags ...
	systemdVerOut, err := exec.Command("systemd-run", "--version").Output()
	if err != nil {
		return defaultCmd
	}
	parts := strings.Fields(string(systemdVerOut))
	if len(parts) < 2 || parts[0] != "systemd" {
		return defaultCmd
	}
	systemdVer, err := strconv.Atoi(parts[1])
	if err != nil {
		return defaultCmd
	}
	if systemdVer >= 236 {
		return exec.Command("systemd-run", "--wait", "--pipe", "--collect", cmdTS, "update", "--yes")
	} else if systemdVer >= 235 {
		return exec.Command("systemd-run", "--wait", "--pipe", cmdTS, "update", "--yes")
	} else if systemdVer >= 232 {
		return exec.Command("systemd-run", "--wait", cmdTS, "update", "--yes")
	} else {
		return exec.Command("systemd-run", cmdTS, "update", "--yes")
	}
}

func regularFileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// startAutoUpdate triggers an auto-update attempt. The actual update happens
// asynchronously. If another update is in progress, an error is returned.
func (e *extension) startAutoUpdate(logPrefix string) (retErr error) {
	// Check if update was already started, and mark as started.
	if !e.trySetC2NUpdateStarted() {
		return errors.New("update already started")
	}
	defer func() {
		// Clear the started flag if something failed.
		if retErr != nil {
			e.setC2NUpdateStarted(false)
		}
	}()

	cmdTS, err := findCmdTailscale()
	if err != nil {
		return fmt.Errorf("failed to find cmd/tailscale binary: %w", err)
	}
	var ver struct {
		Long string `json:"long"`
	}
	out, err := exec.Command(cmdTS, "version", "--json").Output()
	if err != nil {
		return fmt.Errorf("failed to find cmd/tailscale binary: %w", err)
	}
	if err := json.Unmarshal(out, &ver); err != nil {
		return fmt.Errorf("invalid JSON from cmd/tailscale version --json: %w", err)
	}
	if ver.Long != version.Long() {
		return fmt.Errorf("cmd/tailscale version %q does not match tailscaled version %q", ver.Long, version.Long())
	}

	cmd := tailscaleUpdateCmd(cmdTS)
	buf := new(bytes.Buffer)
	cmd.Stdout = buf
	cmd.Stderr = buf
	e.logf("%s: running %q", logPrefix, strings.Join(cmd.Args, " "))
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start cmd/tailscale update: %w", err)
	}

	go func() {
		if err := cmd.Wait(); err != nil {
			e.logf("%s: update command failed: %v, output: %s", logPrefix, err, buf)
		} else {
			e.logf("%s: update attempt complete", logPrefix)
		}
		e.setC2NUpdateStarted(false)
	}()
	return nil
}

func (e *extension) stopOfflineAutoUpdate() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopOfflineAutoUpdateLocked()
}

func (e *extension) stopOfflineAutoUpdateLocked() {
	if e.offlineAutoUpdateCancel == nil {
		return
	}
	e.logf("offline auto-update: stopping update checks")
	e.offlineAutoUpdateCancel()
	e.offlineAutoUpdateCancel = nil
}

// e.mu must be held
func (e *extension) maybeStartOfflineAutoUpdateLocked(prefs ipn.PrefsView) {
	if !prefs.Valid() || !prefs.AutoUpdate().Apply.EqualBool(true) {
		return
	}
	// AutoUpdate.Apply field in prefs can only be true for platforms that
	// support auto-updates. But check it here again, just in case.
	if !feature.CanAutoUpdate() {
		return
	}
	// On macsys, auto-updates are managed by Sparkle.
	if version.IsMacSysExt() {
		return
	}

	if e.offlineAutoUpdateCancel != nil {
		// Already running.
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.offlineAutoUpdateCancel = cancel

	e.logf("offline auto-update: starting update checks")
	go e.offlineAutoUpdate(ctx)
}

const offlineAutoUpdateCheckPeriod = time.Hour

func (e *extension) offlineAutoUpdate(ctx context.Context) {
	t := time.NewTicker(offlineAutoUpdateCheckPeriod)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := e.startAutoUpdate("offline auto-update"); err != nil {
			e.logf("offline auto-update: failed: %v", err)
		}
	}
}
