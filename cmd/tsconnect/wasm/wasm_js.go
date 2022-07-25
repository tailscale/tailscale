// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The wasm package builds a WebAssembly module that provides a subset of
// Tailscale APIs to JavaScript.
//
// When run in the browser, a newIPN(config) function is added to the global JS
// namespace. When called it returns an ipn object with the methods
// run(callbacks), login(), logout(), and ssh(...).
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/words"
)

func main() {
	js.Global().Set("newIPN", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			log.Fatal("Usage: newIPN(config)")
			return nil
		}
		return newIPN(args[0])
	}))
	// Keep Go runtime alive, otherwise it will be shut down before newIPN gets
	// called.
	<-make(chan bool)
}

func newIPN(jsConfig js.Value) map[string]any {
	netns.SetEnabled(false)
	var logf logger.Logf = log.Printf

	dialer := new(tsdial.Dialer)
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Dialer: dialer,
	})
	if err != nil {
		log.Fatal(err)
	}

	tunDev, magicConn, dnsManager, ok := eng.(wgengine.InternalsGetter).GetInternals()
	if !ok {
		log.Fatalf("%T is not a wgengine.InternalsGetter", eng)
	}
	ns, err := netstack.Create(logf, tunDev, eng, magicConn, dialer, dnsManager)
	if err != nil {
		log.Fatalf("netstack.Create: %v", err)
	}
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	if err := ns.Start(); err != nil {
		log.Fatalf("failed to start netstack: %v", err)
	}
	dialer.UseNetstackForIP = func(ip netaddr.IP) bool {
		return true
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netaddr.IPPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}

	jsStateStorage := jsConfig.Get("stateStorage")
	var store ipn.StateStore
	if jsStateStorage.IsUndefined() {
		store = new(mem.Store)
	} else {
		store = &jsStateStore{jsStateStorage}
	}
	srv, err := ipnserver.New(log.Printf, "some-logid", store, eng, dialer, nil, ipnserver.Options{
		SurviveDisconnects: true,
		LoginFlags:         controlclient.LoginEphemeral,
	})
	if err != nil {
		log.Fatalf("ipnserver.New: %v", err)
	}
	lb := srv.LocalBackend()

	jsIPN := &jsIPN{
		dialer: dialer,
		srv:    srv,
		lb:     lb,
	}

	return map[string]any{
		"run": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 1 {
				log.Fatal(`Usage: run({
					notifyState(state: int): void,
					notifyNetMap(netMap: object): void,
					notifyBrowseToURL(url: string): void,
				})`)
				return nil
			}
			jsIPN.run(args[0])
			return nil
		}),
		"login": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 0 {
				log.Printf("Usage: login()")
				return nil
			}
			jsIPN.login()
			return nil
		}),
		"logout": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 0 {
				log.Printf("Usage: logout()")
				return nil
			}
			jsIPN.logout()
			return nil
		}),
		"ssh": js.FuncOf(func(this js.Value, args []js.Value) interface{} {
			if len(args) != 6 {
				log.Printf("Usage: ssh(hostname, writeFn, readFn, rows, cols, onDone)")
				return nil
			}
			go jsIPN.ssh(
				args[0].String(),
				args[1],
				args[2],
				args[3].Int(),
				args[4].Int(),
				args[5])
			return nil
		}),
	}
}

type jsIPN struct {
	dialer *tsdial.Dialer
	srv    *ipnserver.Server
	lb     *ipnlocal.LocalBackend
}

func (i *jsIPN) run(jsCallbacks js.Value) {
	notifyState := func(state ipn.State) {
		jsCallbacks.Call("notifyState", int(state))
	}
	notifyState(ipn.NoState)

	i.lb.SetNotifyCallback(func(n ipn.Notify) {
		log.Printf("NOTIFY: %+v", n)
		if n.State != nil {
			notifyState(*n.State)
		}
		if nm := n.NetMap; nm != nil {
			jsNetMap := jsNetMap{
				Self: jsNetMapSelfNode{
					jsNetMapNode: jsNetMapNode{
						Name:       nm.Name,
						Addresses:  mapSlice(nm.Addresses, func(a netaddr.IPPrefix) string { return a.Addr().String() }),
						NodeKey:    nm.NodeKey.String(),
						MachineKey: nm.MachineKey.String(),
					},
					MachineStatus: int(nm.MachineStatus),
				},
				Peers: mapSlice(nm.Peers, func(p *tailcfg.Node) jsNetMapPeerNode {
					return jsNetMapPeerNode{
						jsNetMapNode: jsNetMapNode{
							Name:       p.Name,
							Addresses:  mapSlice(p.Addresses, func(a netaddr.IPPrefix) string { return a.Addr().String() }),
							MachineKey: p.Machine.String(),
							NodeKey:    p.Key.String(),
						},
						Online:              *p.Online,
						TailscaleSSHEnabled: p.Hostinfo.TailscaleSSHEnabled(),
					}
				}),
			}
			if jsonNetMap, err := json.Marshal(jsNetMap); err == nil {
				jsCallbacks.Call("notifyNetMap", string(jsonNetMap))
			} else {
				log.Printf("Could not generate JSON netmap: %v", err)
			}
		}
		if n.BrowseToURL != nil {
			jsCallbacks.Call("notifyBrowseToURL", *n.BrowseToURL)
		}
	})

	go func() {
		err := i.lb.Start(ipn.Options{
			StateKey: "wasm",
			UpdatePrefs: &ipn.Prefs{
				ControlURL:       ipn.DefaultControlURL,
				RouteAll:         false,
				AllowSingleHosts: true,
				WantRunning:      true,
				Hostname:         generateHostname(),
			},
		})
		if err != nil {
			log.Printf("Start error: %v", err)
		}
	}()

	go func() {
		ln, _, err := safesocket.Listen("", 0)
		if err != nil {
			log.Fatalf("safesocket.Listen: %v", err)
		}

		err = i.srv.Run(context.Background(), ln)
		log.Fatalf("ipnserver.Run exited: %v", err)
	}()
}

func (i *jsIPN) login() {
	go i.lb.StartLoginInteractive()
}

func (i *jsIPN) logout() {
	if i.lb.State() == ipn.NoState {
		log.Printf("Backend not running")
	}
	go i.lb.Logout()
}

func (i *jsIPN) ssh(host string, writeFn js.Value, setReadFn js.Value, rows, cols int, onDone js.Value) {
	defer onDone.Invoke()

	write := func(s string) {
		writeFn.Invoke(s)
	}
	writeError := func(label string, err error) {
		write(fmt.Sprintf("%s Error: %v\r\n", label, err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := i.dialer.UserDial(ctx, "tcp", net.JoinHostPort(host, "22"))
	if err != nil {
		writeError("Dial", err)
		return
	}
	defer c.Close()

	config := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshConn, _, _, err := ssh.NewClientConn(c, host, config)
	if err != nil {
		writeError("SSH Connection", err)
		return
	}
	defer sshConn.Close()
	write("SSH Connected\r\n")

	sshClient := ssh.NewClient(sshConn, nil, nil)
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		writeError("SSH Session", err)
		return
	}
	write("Session Established\r\n")
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		writeError("SSH Stdin", err)
		return
	}

	session.Stdout = termWriter{writeFn}
	session.Stderr = termWriter{writeFn}

	setReadFn.Invoke(js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		input := args[0].String()
		_, err := stdin.Write([]byte(input))
		if err != nil {
			writeError("Write Input", err)
		}
		return nil
	}))

	err = session.RequestPty("xterm", rows, cols, ssh.TerminalModes{})

	if err != nil {
		writeError("Pseudo Terminal", err)
		return
	}

	err = session.Shell()
	if err != nil {
		writeError("Shell", err)
		return
	}

	err = session.Wait()
	if err != nil {
		writeError("Exit", err)
		return
	}
}

type termWriter struct {
	f js.Value
}

func (w termWriter) Write(p []byte) (n int, err error) {
	r := bytes.Replace(p, []byte("\n"), []byte("\n\r"), -1)
	w.f.Invoke(string(r))
	return len(p), nil
}

type jsNetMap struct {
	Self  jsNetMapSelfNode   `json:"self"`
	Peers []jsNetMapPeerNode `json:"peers"`
}

type jsNetMapNode struct {
	Name          string   `json:"name"`
	Addresses     []string `json:"addresses"`
	MachineStatus int      `json:"machineStatus"`
	MachineKey    string   `json:"machineKey"`
	NodeKey       string   `json:"nodeKey"`
}

type jsNetMapSelfNode struct {
	jsNetMapNode
	MachineStatus int `json:"machineStatus"`
}

type jsNetMapPeerNode struct {
	jsNetMapNode
	Online              bool `json:"online"`
	TailscaleSSHEnabled bool `json:"tailscaleSSHEnabled"`
}

type jsStateStore struct {
	jsStateStorage js.Value
}

func (s *jsStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	jsValue := s.jsStateStorage.Call("getState", string(id))
	if jsValue.String() == "" {
		return nil, ipn.ErrStateNotExist
	}
	return hex.DecodeString(jsValue.String())
}

func (s *jsStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	s.jsStateStorage.Call("setState", string(id), hex.EncodeToString(bs))
	return nil
}

func mapSlice[T any, M any](a []T, f func(T) M) []M {
	n := make([]M, len(a))
	for i, e := range a {
		n[i] = f(e)
	}
	return n
}

func filterSlice[T any](a []T, f func(T) bool) []T {
	n := make([]T, 0, len(a))
	for _, e := range a {
		if f(e) {
			n = append(n, e)
		}
	}
	return n
}

func generateHostname() string {
	tails := words.Tails()
	scales := words.Scales()
	if rand.Int()%2 == 0 {
		// JavaScript
		tails = filterSlice(tails, func(s string) bool { return strings.HasPrefix(s, "j") })
		scales = filterSlice(scales, func(s string) bool { return strings.HasPrefix(s, "s") })
	} else {
		// WebAssembly
		tails = filterSlice(tails, func(s string) bool { return strings.HasPrefix(s, "w") })
		scales = filterSlice(scales, func(s string) bool { return strings.HasPrefix(s, "a") })
	}

	tail := tails[rand.Intn(len(tails))]
	scale := scales[rand.Intn(len(scales))]
	return fmt.Sprintf("%s-%s", tail, scale)
}
