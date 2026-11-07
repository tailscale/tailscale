// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/tswg"
)

func init() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tswg/load", tswgLoad)
	mux.HandleFunc("POST /tswg/up", tswgUp)
	mux.HandleFunc("POST /tswg/peer", tswgPeer)
	mux.HandleFunc("GET /tswg/show", tswgShow)
	mux.HandleFunc("GET /tswg/dmesg", tswgDmesg)
	mux.HandleFunc("POST /tswg/sock-send", tswgSockSend)
	mux.HandleFunc("GET /tswg/sock-recv", tswgSockRecv)
	mux.HandleFunc("POST /tswg/sock-close", tswgSockClose)
	mux.HandleFunc("POST /tswg/drop-udp-from", tswgDropUDPFrom)
	mux.HandleFunc("POST /tswg/bench/serve", benchServe)
	mux.HandleFunc("GET /tswg/bench/stats", benchStats)
	mux.HandleFunc("GET /tswg/bench/cpu", benchCPU)
	mux.HandleFunc("GET /tswg/bench/tcp", benchTCP)
	mux.HandleFunc("GET /tswg/bench/udp", benchUDP)
	mux.HandleFunc("GET /tswg/bench/rtt", benchRTT)
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
//   - user-socket: if "1", open a UDP socket on listen-port and share it
//     with the device (see /tswg/sock-send, /tswg/sock-recv and
//     /tswg/sock-close), rather than having the device open its own
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
	cfg := tswg.Config{
		PrivateKey: &priv,
		Peers:      []tswg.PeerConfig{pc},
	}
	if q.Get("user-socket") == "1" {
		// Share a UDP socket of our own with the device, as tailscaled will.
		us, err := newTSWGUserSock(dev, uint16(port))
		if err != nil {
			return err
		}
		if err := us.withFD(func(fd int) error {
			cfg.SocketFD4 = &fd
			return c.ConfigureDevice(dev, cfg)
		}); err != nil {
			us.close()
			return err
		}
	} else {
		port16 := uint16(port)
		cfg.ListenPort = &port16
		if err := c.ConfigureDevice(dev, cfg); err != nil {
			return err
		}
	}
	return netlink.LinkSetUp(link)
}

// tswgPeer updates an existing peer of a tswg device, as tailscaled's disco
// path selection will.
//
// Query parameters:
//   - dev: device name
//   - peer: peer public key (nodekey:...)
//   - endpoint: if set, the new endpoint IP:port
//   - no-roam: if set, "1" or "0" to set or clear the no-roam flag
func tswgPeer(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	pc := tswg.PeerConfig{UpdateOnly: true}
	if err := pc.PublicKey.UnmarshalText([]byte(q.Get("peer"))); err != nil {
		http.Error(w, "peer: "+err.Error(), http.StatusBadRequest)
		return
	}
	if s := q.Get("endpoint"); s != "" {
		ep, err := netip.ParseAddrPort(s)
		if err != nil {
			http.Error(w, "endpoint: "+err.Error(), http.StatusBadRequest)
			return
		}
		pc.Endpoint = ep
	}
	if s := q.Get("no-roam"); s != "" {
		v := s == "1"
		pc.NoRoam = &v
	}
	c, err := tswg.Open()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer c.Close()
	if err := c.ConfigureDevice(q.Get("dev"), tswg.Config{Peers: []tswg.PeerConfig{pc}}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

// tswgUserSock is a UDP socket that tta shares with a tswg device, standing
// in for tailscaled's magicsock socket. It records every datagram that the
// device leaves for userspace.
type tswgUserSock struct {
	conn *net.UDPConn

	mu   sync.Mutex
	recv []tswgDatagram
}

// tswgDatagram is a datagram received on a tswgUserSock.
type tswgDatagram struct {
	From netip.AddrPort
	Data []byte
}

var (
	tswgUserSocksMu sync.Mutex
	tswgUserSocks   = map[string]*tswgUserSock{} // by device name
)

// newTSWGUserSock opens a UDP socket on port for device dev, replacing (and
// closing) any previous one.
func newTSWGUserSock(dev string, port uint16) (*tswgUserSock, error) {
	tswgUserSocksMu.Lock()
	defer tswgUserSocksMu.Unlock()
	if old := tswgUserSocks[dev]; old != nil {
		old.conn.Close()
		delete(tswgUserSocks, dev)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, err
	}
	us := &tswgUserSock{conn: conn}
	tswgUserSocks[dev] = us
	go us.readLoop()
	return us, nil
}

func (us *tswgUserSock) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, from, err := us.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		us.mu.Lock()
		us.recv = append(us.recv, tswgDatagram{From: from, Data: bytes.Clone(buf[:n])})
		us.mu.Unlock()
	}
}

// withFD calls f with the socket's file descriptor.
func (us *tswgUserSock) withFD(f func(fd int) error) error {
	rc, err := us.conn.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

func (us *tswgUserSock) close() error {
	return us.conn.Close()
}

// tswgUserSockFor returns the user socket for the device named by r's dev
// query parameter, writing an HTTP error and returning nil if there isn't
// one.
func tswgUserSockFor(w http.ResponseWriter, r *http.Request) *tswgUserSock {
	dev := r.URL.Query().Get("dev")
	tswgUserSocksMu.Lock()
	us := tswgUserSocks[dev]
	tswgUserSocksMu.Unlock()
	if us == nil {
		http.Error(w, "no user socket for "+dev, http.StatusNotFound)
	}
	return us
}

// tswgSockSend sends the request body as a datagram from the user socket of
// device dev to the to query parameter (IP:port).
func tswgSockSend(w http.ResponseWriter, r *http.Request) {
	us := tswgUserSockFor(w, r)
	if us == nil {
		return
	}
	to, err := netip.ParseAddrPort(r.URL.Query().Get("to"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := us.conn.WriteToUDPAddrPort(data, to); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.WriteString(w, "OK\n")
}

// tswgSockRecv writes, as JSON, the datagrams received so far on the user
// socket of device dev, and forgets them.
func tswgSockRecv(w http.ResponseWriter, r *http.Request) {
	us := tswgUserSockFor(w, r)
	if us == nil {
		return
	}
	us.mu.Lock()
	recv := us.recv
	us.recv = nil
	us.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recv)
}

// tswgSockClose closes the user socket of device dev.
func tswgSockClose(w http.ResponseWriter, r *http.Request) {
	dev := r.URL.Query().Get("dev")
	tswgUserSocksMu.Lock()
	us := tswgUserSocks[dev]
	delete(tswgUserSocks, dev)
	tswgUserSocksMu.Unlock()
	if us == nil {
		http.Error(w, "no user socket for "+dev, http.StatusNotFound)
		return
	}
	us.close()
	io.WriteString(w, "OK\n")
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
