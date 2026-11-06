// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg"
)

func init() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tswg/load", tswgLoad)
	mux.HandleFunc("POST /tswg/up", tswgUp)
	mux.HandleFunc("GET /tswg/show", tswgShow)
	mux.HandleFunc("GET /tswg/dmesg", tswgDmesg)
	tswgHandler = mux
}

// tswgLoad loads the tswg kernel module from the tswg.ko image in the
// request body.
func tswgLoad(w http.ResponseWriter, r *http.Request) {
	image, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := tswg.LoadModule(image); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

// tswgUp creates (if needed), configures and brings up a tswg device with
// a single peer.
//
// Query parameters:
//   - dev: device name
//   - addr: interface address prefix, such as 10.99.0.1/24
//   - private-key: device private key (privkey:...)
//   - listen-port: UDP listen port
//   - peer: peer public key (nodekey:...)
//   - endpoint: peer endpoint IP:port
//   - allowed-ips: comma-separated peer allowed IP prefixes
func tswgUp(w http.ResponseWriter, r *http.Request) {
	if err := tswgUpErr(r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

func tswgUpErr(r *http.Request) error {
	q := r.URL.Query()
	dev := q.Get("dev")
	if dev == "" {
		return errors.New("missing dev")
	}
	addr, err := netip.ParsePrefix(q.Get("addr"))
	if err != nil {
		return fmt.Errorf("addr: %w", err)
	}
	var priv key.NodePrivate
	if err := priv.UnmarshalText([]byte(q.Get("private-key"))); err != nil {
		return fmt.Errorf("private-key: %w", err)
	}
	port, err := strconv.ParseUint(q.Get("listen-port"), 10, 16)
	if err != nil {
		return fmt.Errorf("listen-port: %w", err)
	}
	var pc tswg.PeerConfig
	if err := pc.PublicKey.UnmarshalText([]byte(q.Get("peer"))); err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	if pc.Endpoint, err = netip.ParseAddrPort(q.Get("endpoint")); err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	for s := range strings.SplitSeq(q.Get("allowed-ips"), ",") {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("allowed-ips: %w", err)
		}
		pc.AllowedIPs = append(pc.AllowedIPs, pfx)
	}

	if err := tswg.AddLink(dev); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	link, err := netlink.LinkByName(dev)
	if err != nil {
		return err
	}
	nlAddr, err := netlink.ParseAddr(addr.String())
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, nlAddr); err != nil {
		return fmt.Errorf("adding address: %w", err)
	}

	c, err := tswg.Open()
	if err != nil {
		return err
	}
	defer c.Close()
	port16 := uint16(port)
	if err := c.ConfigureDevice(dev, tswg.Config{
		PrivateKey: &priv,
		ListenPort: &port16,
		Peers:      []tswg.PeerConfig{pc},
	}); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

// tswgShow writes the JSON state of the tswg device named by the dev query
// parameter, without its private key.
func tswgShow(w http.ResponseWriter, r *http.Request) {
	c, err := tswg.Open()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	d, err := c.Device(r.URL.Query().Get("dev"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	d.PrivateKey = key.NodePrivate{}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(d)
}

// tswgDmesg writes the kernel log messages that mention tswg. gokrazy has
// no dmesg binary, so it reads /dev/kmsg directly.
//
// It uses raw syscalls rather than an *os.File, which would hand the
// non-blocking fd to the Go netpoller and turn the EAGAIN that marks the
// end of the log into an indefinite wait.
func tswgDmesg(w http.ResponseWriter, r *http.Request) {
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer unix.Close(fd)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	buf := make([]byte, 8192)
	for {
		// Each read returns one record: "prio,seq,usec,flags;message\n".
		n, err := unix.Read(fd, buf)
		if err == unix.EINTR || err == unix.EPIPE {
			continue // EPIPE: record overwritten while reading; skip it
		}
		if err != nil || n <= 0 {
			return // EAGAIN: no more records
		}
		rec := string(buf[:n])
		if _, msg, ok := strings.Cut(rec, ";"); ok && strings.Contains(msg, "tswg") {
			io.WriteString(w, msg)
		}
	}
}
