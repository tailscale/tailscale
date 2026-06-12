// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"cmp"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/crypto/curve25519"
	"tailscale.com/wgengine/wgcfg"
)

func init() {
	wgServerUp = wgServerUpLinux
}

var (
	wgServerMu  sync.Mutex
	wgServerDev *device.Device // retained so the goroutines stay alive
)

// wgServerUpLinux brings up a userspace WireGuard interface on the local VM
// configured as a single-peer "Mullvad-style" exit node, then sets up the
// kernel-side IP/forwarding/MASQUERADE so that decrypted traffic from the
// peer egresses to the test internet.
//
// Required URL query parameters:
//   - addr: CIDR for the WG interface (e.g. "10.64.0.1/24")
//   - listen-port: WG listen port
//   - peer-pub-b64: base64-encoded 32-byte WG public key of the only peer
//   - peer-allowed-ip: prefix the peer is allowed to source from
//     (e.g. "10.64.0.2/32")
//   - masq-src: prefix to MASQUERADE on egress (e.g. "10.64.0.0/24")
//
// Optional:
//   - name: TUN device name (default "wg0")
//
// On success, it writes "PUBKEY=<base64>\n" — the freshly generated public
// key the caller must pin as the peer's WG public key.
func wgServerUpLinux(w http.ResponseWriter, r *http.Request) {
	wgServerMu.Lock()
	defer wgServerMu.Unlock()
	if wgServerDev != nil {
		http.Error(w, "wg server already up", http.StatusConflict)
		return
	}

	q := r.URL.Query()
	name := cmp.Or(q.Get("name"), "wg0")
	addr := q.Get("addr")
	listenPort := q.Get("listen-port")
	peerPubB64 := q.Get("peer-pub-b64")
	peerAllowedIP := q.Get("peer-allowed-ip")
	masqSrc := q.Get("masq-src")
	for _, kv := range []struct{ k, v string }{
		{"addr", addr},
		{"listen-port", listenPort},
		{"peer-pub-b64", peerPubB64},
		{"peer-allowed-ip", peerAllowedIP},
		{"masq-src", masqSrc},
	} {
		if kv.v == "" {
			http.Error(w, "missing "+kv.k, http.StatusBadRequest)
			return
		}
	}

	peerPub, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil || len(peerPub) != 32 {
		http.Error(w, fmt.Sprintf("bad peer-pub-b64: %v (len=%d)", err, len(peerPub)), http.StatusBadRequest)
		return
	}

	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		http.Error(w, "rand: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// X25519 key clamping.
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		http.Error(w, "deriving pubkey: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tdev, err := tun.CreateTUN(name, device.DefaultMTU)
	if err != nil {
		http.Error(w, "tun.CreateTUN: "+err.Error(), http.StatusInternalServerError)
		return
	}
	wglog := &device.Logger{
		Verbosef: func(string, ...any) {},
		Errorf:   func(f string, a ...any) { log.Printf("wg-server: "+f, a...) },
	}
	dev := wgcfg.NewDevice(tdev, conn.NewDefaultBind(), wglog)

	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%s\npublic_key=%s\nallowed_ip=%s\n",
		hex.EncodeToString(priv[:]), listenPort,
		hex.EncodeToString(peerPub), peerAllowedIP)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		http.Error(w, "IpcSet: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		http.Error(w, "dev.Up: "+err.Error(), http.StatusInternalServerError)
		return
	}

	steps := []struct {
		why  string
		exec []string
		file struct{ path, data string }
	}{
		{why: "ip addr add", exec: []string{"ip", "addr", "add", addr, "dev", name}},
		{why: "ip link up", exec: []string{"ip", "link", "set", name, "up"}},
		{why: "enable forwarding", file: struct{ path, data string }{"/proc/sys/net/ipv4/ip_forward", "1\n"}},
		{why: "FORWARD policy", exec: []string{"iptables", "-P", "FORWARD", "ACCEPT"}},
		{why: "MASQUERADE", exec: []string{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", masqSrc, "-j", "MASQUERADE"}},
	}
	for _, s := range steps {
		if s.file.path != "" {
			if err := os.WriteFile(s.file.path, []byte(s.file.data), 0644); err != nil {
				dev.Close()
				http.Error(w, fmt.Sprintf("%s: %v", s.why, err), http.StatusInternalServerError)
				return
			}
			continue
		}
		if out, err := exec.Command(s.exec[0], s.exec[1:]...).CombinedOutput(); err != nil {
			dev.Close()
			http.Error(w, fmt.Sprintf("%s: %v: %s", s.why, err, out), http.StatusInternalServerError)
			return
		}
	}

	wgServerDev = dev
	fmt.Fprintf(w, "PUBKEY=%s\n", base64.StdEncoding.EncodeToString(pub))
}
