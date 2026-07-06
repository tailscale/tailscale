// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"sync"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/localapi"
	"tailscale.com/types/logger"
	tsversion "tailscale.com/version"
	"tailscale.com/version/distro"
)

func init() {
	ipnext.RegisterExtension("loginbeacon", newExtension)
	localapi.Register("loginbeacon-approve", serveApprove)
	localapi.Register("loginbeacon-ignore", serveIgnore)
}

// extension runs both roles of the beacon protocol from within the daemon:
//
//   - Sender: on gokrazy appliances when /perm/loginbeacon.json enables it,
//     multicast a beacon whenever there is a pending browseToURL.
//   - Receiver: on any node running the daemon, listen for beacons on the LAN
//     and publish them onto the Notify bus as LoginBeaconRequest. Approve /
//     Ignore come back via LocalAPI. On approve success the decrypted URL is
//     republished as a regular BrowseToURL so existing UI observers pick it
//     up without knowing anything about beacons.
type extension struct {
	logf logger.Logf
	host ipnext.Host

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	url      string
	sender   *Sender
	receiver *Receiver
}

func newExtension(logf logger.Logf, _ ipnext.SafeBackend) (ipnext.Extension, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &extension{
		logf:   logger.WithPrefix(logf, "loginbeacon: "),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (e *extension) Name() string { return "loginbeacon" }

func (e *extension) Init(h ipnext.Host) error {
	e.host = h
	h.Hooks().MutateNotifyLocked.Add(e.onNotify)
	h.Hooks().BackendStateChange.Add(e.onBackendStateChange)

	e.logf("Init on os=%q gokrazy=%v", tsversion.OS(), distro.Get() == distro.Gokrazy)
	if cfg := senderConfig(); cfg != nil {
		// Sender-role devices don't also approve other devices' logins.
		// This avoids a tvOS/appliance echoing its own beacon back through
		// the receiver path.
		e.logf("starting sender kind=%q hostname=%q (receiver disabled on sender)", cfg.kind, cfg.hostname)
		e.startSender(cfg)
	} else {
		e.logf("starting receiver")
		e.startReceiver()
	}
	return nil
}

// senderConfig decides whether this node should originate beacons, and if so,
// returns the display metadata. Two supported cases today:
//   - a gokrazy appliance flashed with --enable-login-beacon
//   - a tvOS device (auto-enabled; there's no keyboard for the QR alternative)
//
// nil means "don't be a sender."
func senderConfig() *senderCfg {
	if distro.Get() == distro.Gokrazy {
		if c, err := LoadApplianceConfig(); err == nil && c != nil && c.Enabled {
			return &senderCfg{hostname: c.Hostname, kind: "appliance"}
		}
	}
	if tsversion.OS() == "tvOS" {
		return &senderCfg{kind: "tvos"}
	}
	return nil
}

type senderCfg struct {
	hostname string
	kind     string
}

func (e *extension) Shutdown() error {
	e.cancel()
	e.mu.Lock()
	s, r := e.sender, e.receiver
	e.sender, e.receiver = nil, nil
	e.mu.Unlock()
	if s != nil {
		s.Stop()
	}
	if r != nil {
		r.Stop()
	}
	return nil
}

// onNotify runs under LocalBackend.mu; keep it non-blocking.
func (e *extension) onNotify(n *ipn.Notify) {
	if n == nil || n.BrowseToURL == nil {
		return
	}
	e.mu.Lock()
	e.url = *n.BrowseToURL
	e.mu.Unlock()
}

func (e *extension) onBackendStateChange(st ipn.State) {
	if st == ipn.NeedsLogin {
		return
	}
	e.mu.Lock()
	e.url = ""
	e.mu.Unlock()
}

func (e *extension) currentAuthURL() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.url
}

func (e *extension) startSender(cfg *senderCfg) {
	hostname := cfg.hostname
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}
	s, err := Start(e.ctx, Config{
		Hostname:   hostname,
		DeviceKind: cfg.kind,
		DeviceID:   hostname,
		AuthURL:    e.currentAuthURL,
		OnApproved: e.onSenderApproved,
		Logf:       e.logf,
	})
	if err != nil {
		e.logf("sender start: %v", err)
		return
	}
	e.mu.Lock()
	e.sender = s
	e.mu.Unlock()
}

func (e *extension) onSenderApproved(approverName string) {
	e.host.SendNotifyAsync(ipn.Notify{
		LoginBeaconApproved: &ipn.LoginBeaconApproved{
			ApproverName: approverName,
		},
	})
}

func (e *extension) startReceiver() {
	r, err := StartReceiver(e.ctx, ReceiverConfig{
		OnBeacon:   e.onIncomingBeacon,
		OnAuthURL:  e.onDecryptedAuthURL,
		URLAllowed: DefaultURLAllowed,
		Logf:       e.logf,
	})
	if err != nil {
		e.logf("receiver start: %v", err)
		return
	}
	e.mu.Lock()
	e.receiver = r
	e.mu.Unlock()
}

func (e *extension) onIncomingBeacon(b Beacon) {
	e.host.SendNotifyAsync(ipn.Notify{
		LoginBeaconRequest: &ipn.LoginBeaconRequest{
			RequestID:    hex.EncodeToString(b.RequestID[:]),
			Hostname:     b.Hostname,
			DeviceKind:   b.DeviceKind,
			DeviceIDHash: hex.EncodeToString(b.DeviceIDHash[:]),
		},
	})
}

func (e *extension) onDecryptedAuthURL(url string) {
	e.host.SendNotifyAsync(ipn.Notify{BrowseToURL: &url})
}

func (e *extension) approve(rid [16]byte) error {
	e.mu.Lock()
	r := e.receiver
	e.mu.Unlock()
	if r == nil {
		return errors.New("loginbeacon: receiver not running")
	}
	go func() {
		if err := r.Approve(rid); err != nil {
			e.logf("approve rid=%x: %v", rid[:4], err)
		}
	}()
	return nil
}

func (e *extension) ignore(rid [16]byte) {
	e.mu.Lock()
	r := e.receiver
	e.mu.Unlock()
	if r != nil {
		r.Ignore(rid)
	}
}

// serveApprove / serveIgnore are LocalAPI endpoints the client hits after the
// user taps Approve or Ignore on the sheet. The request ID is passed as a
// hex-encoded query parameter to keep the payload trivial.
func serveApprove(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	e, ok := findExtension(h)
	if !ok {
		http.Error(w, "loginbeacon extension not available", http.StatusServiceUnavailable)
		return
	}
	rid, err := parseRequestIDParam(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := e.approve(rid); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func serveIgnore(h *localapi.Handler, w http.ResponseWriter, r *http.Request) {
	e, ok := findExtension(h)
	if !ok {
		http.Error(w, "loginbeacon extension not available", http.StatusServiceUnavailable)
		return
	}
	rid, err := parseRequestIDParam(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	e.ignore(rid)
	w.WriteHeader(http.StatusNoContent)
}

func findExtension(h *localapi.Handler) (*extension, bool) {
	var e *extension
	ok := h.LocalBackend().FindMatchingExtension(&e)
	return e, ok
}

func parseRequestIDParam(r *http.Request) ([16]byte, error) {
	var rid [16]byte
	raw := r.URL.Query().Get("rid")
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 16 {
		return rid, errors.New("loginbeacon: rid must be a 32-char hex string")
	}
	copy(rid[:], b)
	return rid, nil
}
