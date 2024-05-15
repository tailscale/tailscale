// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

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
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"syscall/js"
	"time"

	"golang.org/x/crypto/ssh"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/safesocket"
	"tailscale.com/tailcfg"
	"tailscale.com/tsd"
	"tailscale.com/types/views"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/words"
)

// ControlURL defines the URL to be used for connection to Control.
var ControlURL = ipn.DefaultControlURL

func main() {
	js.Global().Set("newIPN", js.FuncOf(func(this js.Value, args []js.Value) any {
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

	var store ipn.StateStore
	if jsStateStorage := jsConfig.Get("stateStorage"); !jsStateStorage.IsUndefined() {
		store = &jsStateStore{jsStateStorage}
	} else {
		store = new(mem.Store)
	}

	controlURL := ControlURL
	if jsControlURL := jsConfig.Get("controlURL"); jsControlURL.Type() == js.TypeString {
		controlURL = jsControlURL.String()
	}

	var authKey string
	if jsAuthKey := jsConfig.Get("authKey"); jsAuthKey.Type() == js.TypeString {
		authKey = jsAuthKey.String()
	}

	var hostname string
	if jsHostname := jsConfig.Get("hostname"); jsHostname.Type() == js.TypeString {
		hostname = jsHostname.String()
	} else {
		hostname = generateHostname()
	}

	routeAll := false
	if jsRouteAll := jsConfig.Get("routeAll"); jsRouteAll.Type() == js.TypeBoolean {
		routeAll = jsRouteAll.Bool()
	}

	lpc := getOrCreateLogPolicyConfig(store)
	c := logtail.Config{
		Collection: lpc.Collection,
		PrivateID:  lpc.PrivateID,

		// Compressed requests set HTTP headers that are not supported by the
		// no-cors fetching mode:
		CompressLogs: false,

		HTTPC: &http.Client{Transport: &noCORSTransport{http.DefaultTransport}},
	}
	logtail := logtail.NewLogger(c, log.Printf)
	logf := logtail.Logf

	sys := new(tsd.System)
	sys.Set(store)
	dialer := &tsdial.Dialer{Logf: logf}
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Dialer:        dialer,
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		HealthTracker: sys.HealthTracker(),
	})
	if err != nil {
		log.Fatal(err)
	}
	sys.Set(eng)

	ns, err := netstack.Create(logf, sys.Tun.Get(), eng, sys.MagicSock.Get(), dialer, sys.DNSManager.Get(), sys.ProxyMapper(), nil)
	if err != nil {
		log.Fatalf("netstack.Create: %v", err)
	}
	sys.Set(ns)
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true

	dialer.UseNetstackForIP = func(ip netip.Addr) bool {
		return true
	}
	dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return ns.DialContextTCP(ctx, dst)
	}
	sys.NetstackRouter.Set(true)
	sys.Tun.Get().Start()

	logid := lpc.PublicID
	srv := ipnserver.New(logf, logid, sys.NetMon.Get())
	lb, err := ipnlocal.NewLocalBackend(logf, logid, sys, controlclient.LoginEphemeral)
	if err != nil {
		log.Fatalf("ipnlocal.NewLocalBackend: %v", err)
	}
	if err := ns.Start(lb); err != nil {
		log.Fatalf("failed to start netstack: %v", err)
	}
	srv.SetLocalBackend(lb)

	jsIPN := &jsIPN{
		dialer:     dialer,
		srv:        srv,
		lb:         lb,
		controlURL: controlURL,
		authKey:    authKey,
		hostname:   hostname,
		routeAll:   routeAll,
	}

	return map[string]any{
		"run": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 || args[0].Type() != js.TypeObject {
				log.Fatal(`Usage: run({
					notifyState(state: int): void,
					notifyNetMap(netMap: object): void,
					notifyBrowseToURL(url: string): void,
					notifyPanicRecover(err: string): void,
				})`)
				return nil
			}
			jsIPN.run(args[0])
			return nil
		}),
		"login": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 0 {
				log.Printf("Usage: login()")
				return nil
			}
			jsIPN.login()
			return nil
		}),
		"logout": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 0 {
				log.Printf("Usage: logout()")
				return nil
			}
			jsIPN.logout()
			return nil
		}),
		"ssh": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 3 {
				log.Printf("Usage: ssh(hostname, userName, termConfig)")
				return nil
			}
			return jsIPN.ssh(
				args[0].String(),
				args[1].String(),
				args[2])
		}),
		"fetch": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 {
				log.Printf("Usage: fetch(url)")
				return nil
			}

			url := args[0].String()
			return jsIPN.fetch(url)
		}),
		"tcp": js.FuncOf(func(this js.Value, args []js.Value) any {
			if len(args) != 1 || args[0].Type() != js.TypeObject {
				log.Fatal(`Usage: tcp({
 					hostname: string
      				port: number
      				readCallback: (data: Uint8Array) => void,
      				connectTimeoutSeconds?: number
					writeBufferSizeInBytes?: number
      				readBufferSizeInBytes?: number
				})`)
				return nil
			}

			return jsIPN.tcp(args[0])
		}),
	}
}

type jsIPN struct {
	dialer     *tsdial.Dialer
	srv        *ipnserver.Server
	lb         *ipnlocal.LocalBackend
	controlURL string
	authKey    string
	hostname   string
	routeAll   bool
}

var jsIPNState = map[ipn.State]string{
	ipn.NoState:          "NoState",
	ipn.InUseOtherUser:   "InUseOtherUser",
	ipn.NeedsLogin:       "NeedsLogin",
	ipn.NeedsMachineAuth: "NeedsMachineAuth",
	ipn.Stopped:          "Stopped",
	ipn.Starting:         "Starting",
	ipn.Running:          "Running",
}

var jsMachineStatus = map[tailcfg.MachineStatus]string{
	tailcfg.MachineUnknown:      "MachineUnknown",
	tailcfg.MachineUnauthorized: "MachineUnauthorized",
	tailcfg.MachineAuthorized:   "MachineAuthorized",
	tailcfg.MachineInvalid:      "MachineInvalid",
}

func (i *jsIPN) run(jsCallbacks js.Value) {
	notifyState := func(state ipn.State) {
		jsCallbacks.Call("notifyState", jsIPNState[state])
	}
	notifyState(ipn.NoState)

	i.lb.SetNotifyCallback(func(n ipn.Notify) {
		// Panics in the notify callback are likely due to be due to bugs in
		// this bridging module (as opposed to actual bugs in Tailscale) and
		// thus may be recoverable. Let the UI know, and allow the user to
		// choose if they want to reload the page.
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("Panic recovered:", r)
				jsCallbacks.Call("notifyPanicRecover", fmt.Sprint(r))
			}
		}()
		log.Printf("NOTIFY: %+v", n)
		if n.State != nil {
			notifyState(*n.State)
		}
		if nm := n.NetMap; nm != nil {
			jsNetMap := jsNetMap{
				Self: jsNetMapSelfNode{
					jsNetMapNode: jsNetMapNode{
						Name:       nm.Name,
						Addresses:  mapSliceView(nm.GetAddresses(), func(a netip.Prefix) string { return a.Addr().String() }),
						NodeKey:    nm.NodeKey.String(),
						MachineKey: nm.MachineKey.String(),
					},
					MachineStatus: jsMachineStatus[nm.GetMachineStatus()],
				},
				Peers: mapSlice(nm.Peers, func(p tailcfg.NodeView) jsNetMapPeerNode {
					name := p.Name()
					if name == "" {
						// In practice this should only happen for Hello.
						name = p.Hostinfo().Hostname()
					}
					addrs := make([]string, p.Addresses().Len())
					for i := range p.Addresses().Len() {
						addrs[i] = p.Addresses().At(i).Addr().String()
					}
					return jsNetMapPeerNode{
						jsNetMapNode: jsNetMapNode{
							Name:       name,
							Addresses:  addrs,
							MachineKey: p.Machine().String(),
							NodeKey:    p.Key().String(),
						},
						Online:              p.Online(),
						TailscaleSSHEnabled: p.Hostinfo().TailscaleSSHEnabled(),
					}
				}),
				LockedOut: nm.TKAEnabled && nm.SelfNode.KeySignature().Len() == 0,
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
			UpdatePrefs: &ipn.Prefs{
				ControlURL:       i.controlURL,
				RouteAll:         i.routeAll,
				AllowSingleHosts: true,
				WantRunning:      true,
				Hostname:         i.hostname,
			},
			AuthKey: i.authKey,
		})
		if err != nil {
			log.Printf("Start error: %v", err)
		}
	}()

	go func() {
		ln, err := safesocket.Listen("")
		if err != nil {
			log.Fatalf("safesocket.Listen: %v", err)
		}

		err = i.srv.Run(context.Background(), ln)
		log.Fatalf("ipnserver.Run exited: %v", err)
	}()
}

func (i *jsIPN) login() {
	go i.lb.StartLoginInteractive(context.Background())
}

func (i *jsIPN) logout() {
	if i.lb.State() == ipn.NoState {
		log.Printf("Backend not running")
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		i.lb.Logout(ctx)
	}()
}

func (i *jsIPN) tcp(config js.Value) any {
	return makePromise(func() (any, error) {
		jsTCPSession, err := i.newJSTCPSession(config)
		if err != nil {
			return nil, err
		}

		jsObjectWrapper := jsTCPSession.jsWrapper()
		return jsObjectWrapper, nil
	})
}

const defaultTCPConnectTimeoutSeconds = 5 * time.Second
const defaultTCPWriteBufferSizeBytes = 1 << 20
const defaultTCPReadBufferSizeBytes = 1 << 20

type jsTCPSessionBuilder struct {
	jsIPN *jsIPN
	addr string
	readCallback func(js.Value)
	writeBufferSize int
	readBufferSize int
	connectTimeout time.Duration
}

func (i *jsIPN) newJSTCPSession(config js.Value) (*jsTCPSession, error) {
	builder := jsTCPSessionBuilder{
		jsIPN: i,
		writeBufferSize: defaultTCPWriteBufferSizeBytes,
		readBufferSize: defaultTCPReadBufferSizeBytes,
		connectTimeout: defaultTCPConnectTimeoutSeconds,
	}

	if err := builder.setAddr(config); err != nil {
		return nil, err
	}
	if err := builder.setReadCallback(config); err != nil {
		return nil, err
	}
	builder.setBufferSizes(config)
	builder.setConnectTimeout(config)

	return builder.connect()
}

func (b *jsTCPSessionBuilder) setAddr(config js.Value) error {
	jsHostname := config.Get("hostname")
	if  jsHostname.Type() != js.TypeString {
		return errors.New("Hostname must be a string")
	}

	jsPort := config.Get("port")
	if jsPort.Type() != js.TypeNumber {
		return errors.New("Port must be a number")
	}
	port := strconv.Itoa(jsPort.Int())
	b.addr = net.JoinHostPort(jsHostname.String(), port)

	return nil
}

func (b *jsTCPSessionBuilder) setReadCallback(config js.Value) error {
	jsReadCallback := config.Get("readCallback");
	if jsReadCallback.Type() != js.TypeFunction {
		return errors.New("Invalid readCallback received")
	}
	b.readCallback = func(subarray js.Value) {
		jsReadCallback.Invoke(subarray)
	}

	return nil
}

func (b *jsTCPSessionBuilder) setBufferSizes(config js.Value) {
	if jsWriteBufferSize := config.Get("writeBufferSizeInBytes"); jsWriteBufferSize.Type() == js.TypeNumber {
		b.writeBufferSize = jsWriteBufferSize.Int()
	}

	if jsReadBufferSize := config.Get("ReadBufferSizeInBytes"); jsReadBufferSize.Type() == js.TypeNumber {
		b.readBufferSize = jsReadBufferSize.Int()
	}
}

func (b *jsTCPSessionBuilder) setConnectTimeout(config js.Value) {
	if jsConnectTimeout := config.Get("connectTimeout"); jsConnectTimeout.Type() == js.TypeNumber {
		b.connectTimeout = time.Duration(jsConnectTimeout.Float() * float64(time.Second))
	}
}

func (b *jsTCPSessionBuilder) connect() (*jsTCPSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.connectTimeout)
	defer cancel()

	conn, err := b.jsIPN.dialer.UserDial(ctx, "tcp", b.addr)
	if err != nil {
		return nil, err
	}

	s := &jsTCPSession{
		jsIPN:       b.jsIPN,
		conn:        conn,
		writeBuffer: make([]byte, b.writeBufferSize),
		readBuffer:  make([]byte, b.readBufferSize),
		readCallback: b.readCallback,
	}

	go s.readLoop()

	return s, nil
}

type jsTCPSession struct {
	jsIPN       *jsIPN
	conn        net.Conn
	writeBuffer []byte
	readBuffer  []byte
	readCallback func(js.Value)
}

func (s *jsTCPSession) readLoop() {
	defer s.conn.Close()
	dst := js.Global().Get("Uint8Array").New(len(s.readBuffer))

	// we always reuse the same dst but make use of subarrays
	subarray := dst.Call("subarray", 0, len(s.readBuffer))
	subarrayLength := len(s.readBuffer)
	for {
		n, err := s.conn.Read(s.readBuffer[:])
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("read error: %v", err)
			return
		}
		// if subarray is not already the correct length,
		// create a new one from dst with correct len
		if subarrayLength != n {
			subarrayLength = n
			subarray = dst.Call("subarray", 0, n)
		}

		js.CopyBytesToJS(subarray, s.readBuffer[:n])

		s.readCallback(subarray)
	}
}

func (s *jsTCPSession) jsWrapper() any {
	return map[string]any{
		/**
		 * Closes the TCP connetion
		 *
		 * @returns Promise<void>
		 */
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				err := s.conn.Close()
				return nil, err
			})
		}),
		/**
		 * Write to the TCP connection
		 *
		 * @param src ArrayBuffer
		 * @returns Promise<number> of bytes written
		 */
		"write": js.FuncOf(func(this js.Value, args []js.Value) any {
			return makePromise(func() (any, error) {
				if len(args) != 1 {
					return nil, errors.New("Did not receive src argument")
				}
				src := args[0]
				if byteLength := src.Get("byteLength"); byteLength.Type() == js.TypeNumber {
					return s.write(src, byteLength.Int())
				}
				return nil, errors.New("Invalid type has no byteLength")
			})
		}),
	}
}

func (s *jsTCPSession) write(src js.Value, length int) (int, error) {
	if len(s.writeBuffer) < length {
		s.writeBuffer = make([]byte, length)
	}
	js.CopyBytesToGo(s.writeBuffer, src)
	return s.conn.Write(s.writeBuffer[:length])
}

func (i *jsIPN) ssh(host, username string, termConfig js.Value) map[string]any {
	jsSSHSession := &jsSSHSession{
		jsIPN:      i,
		host:       host,
		username:   username,
		termConfig: termConfig,
	}

	go jsSSHSession.Run()

	return map[string]any{
		"close": js.FuncOf(func(this js.Value, args []js.Value) any {
			return jsSSHSession.Close() != nil
		}),
		"resize": js.FuncOf(func(this js.Value, args []js.Value) any {
			rows := args[0].Int()
			cols := args[1].Int()
			return jsSSHSession.Resize(rows, cols) != nil
		}),
	}
}

type jsSSHSession struct {
	jsIPN      *jsIPN
	host       string
	username   string
	termConfig js.Value
	session    *ssh.Session

	pendingResizeRows int
	pendingResizeCols int
}

func (s *jsSSHSession) Run() {
	writeFn := s.termConfig.Get("writeFn")
	writeErrorFn := s.termConfig.Get("writeErrorFn")
	setReadFn := s.termConfig.Get("setReadFn")
	rows := s.termConfig.Get("rows").Int()
	cols := s.termConfig.Get("cols").Int()
	timeoutSeconds := 5.0
	if jsTimeoutSeconds := s.termConfig.Get("timeoutSeconds"); jsTimeoutSeconds.Type() == js.TypeNumber {
		timeoutSeconds = jsTimeoutSeconds.Float()
	}
	onConnectionProgress := s.termConfig.Get("onConnectionProgress")
	onConnected := s.termConfig.Get("onConnected")
	onDone := s.termConfig.Get("onDone")
	defer onDone.Invoke()

	writeError := func(label string, err error) {
		writeErrorFn.Invoke(fmt.Sprintf("%s Error: %v\r\n", label, err))
	}
	reportProgress := func(message string) {
		onConnectionProgress.Invoke(message)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds*float64(time.Second)))
	defer cancel()
	reportProgress(fmt.Sprintf("Connecting to %s…", strings.Split(s.host, ".")[0]))
	c, err := s.jsIPN.dialer.UserDial(ctx, "tcp", net.JoinHostPort(s.host, "22"))
	if err != nil {
		writeError("Dial", err)
		return
	}
	defer c.Close()

	config := &ssh.ClientConfig{
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Host keys are not used with Tailscale SSH, but we can use this
			// callback to know that the connection has been established.
			reportProgress("SSH connection established…")
			return nil
		},
		User: s.username,
	}

	reportProgress("Starting SSH client…")
	sshConn, _, _, err := ssh.NewClientConn(c, s.host, config)
	if err != nil {
		writeError("SSH Connection", err)
		return
	}
	defer sshConn.Close()

	sshClient := ssh.NewClient(sshConn, nil, nil)
	defer sshClient.Close()

	session, err := sshClient.NewSession()
	if err != nil {
		writeError("SSH Session", err)
		return
	}
	s.session = session
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		writeError("SSH Stdin", err)
		return
	}

	session.Stdout = termWriter{writeFn}
	session.Stderr = termWriter{writeFn}

	setReadFn.Invoke(js.FuncOf(func(this js.Value, args []js.Value) any {
		input := args[0].String()
		_, err := stdin.Write([]byte(input))
		if err != nil {
			writeError("Write Input", err)
		}
		return nil
	}))

	// We might have gotten a resize notification since we started opening the
	// session, pick up the latest size.
	if s.pendingResizeRows != 0 {
		rows = s.pendingResizeRows
	}
	if s.pendingResizeCols != 0 {
		cols = s.pendingResizeCols
	}
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

	onConnected.Invoke()
	err = session.Wait()
	if err != nil {
		writeError("Wait", err)
		return
	}
}

func (s *jsSSHSession) Close() error {
	if s.session == nil {
		// We never had a chance to open the session, ignore the close request.
		return nil
	}
	return s.session.Close()
}

func (s *jsSSHSession) Resize(rows, cols int) error {
	if s.session == nil {
		s.pendingResizeRows = rows
		s.pendingResizeCols = cols
		return nil
	}
	return s.session.WindowChange(rows, cols)
}

func (i *jsIPN) fetch(url string) js.Value {
	return makePromise(func() (any, error) {
		c := &http.Client{
			Transport: &http.Transport{
				DialContext: i.dialer.UserDial,
			},
		}
		res, err := c.Get(url)
		if err != nil {
			return nil, err
		}

		return map[string]any{
			"status":     res.StatusCode,
			"statusText": res.Status,
			"text": js.FuncOf(func(this js.Value, args []js.Value) any {
				return makePromise(func() (any, error) {
					defer res.Body.Close()
					buf := new(bytes.Buffer)
					if _, err := buf.ReadFrom(res.Body); err != nil {
						return nil, err
					}
					return buf.String(), nil
				})
			}),
			// TODO: populate a more complete JS Response object
		}, nil
	})
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
	Self      jsNetMapSelfNode   `json:"self"`
	Peers     []jsNetMapPeerNode `json:"peers"`
	LockedOut bool               `json:"lockedOut"`
}

type jsNetMapNode struct {
	Name       string   `json:"name"`
	Addresses  []string `json:"addresses"`
	MachineKey string   `json:"machineKey"`
	NodeKey    string   `json:"nodeKey"`
}

type jsNetMapSelfNode struct {
	jsNetMapNode
	MachineStatus string `json:"machineStatus"`
}

type jsNetMapPeerNode struct {
	jsNetMapNode
	Online              *bool `json:"online,omitempty"`
	TailscaleSSHEnabled bool  `json:"tailscaleSSHEnabled"`
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

func mapSliceView[T any, M any](a views.Slice[T], f func(T) M) []M {
	n := make([]M, a.Len())
	for i := range a.Len() {
		n[i] = f(a.At(i))
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

// makePromise handles the boilerplate of wrapping goroutines with JS promises.
// f is run on a goroutine and its return value is used to resolve the promise
// (or reject it if an error is returned).
func makePromise(f func() (any, error)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve := args[0]
		reject := args[1]
		go func() {
			if res, err := f(); err == nil {
				resolve.Invoke(res)
			} else {
				reject.Invoke(err.Error())
			}
		}()
		return nil
	})

	promiseConstructor := js.Global().Get("Promise")
	return promiseConstructor.New(handler)
}

const logPolicyStateKey = "log-policy"

func getOrCreateLogPolicyConfig(state ipn.StateStore) *logpolicy.Config {
	if configBytes, err := state.ReadState(logPolicyStateKey); err == nil {
		if config, err := logpolicy.ConfigFromBytes(configBytes); err == nil {
			return config
		} else {
			log.Printf("Could not parse log policy config: %v", err)
		}
	} else if err != ipn.ErrStateNotExist {
		log.Printf("Could not get log policy config from state store: %v", err)
	}
	config := logpolicy.NewConfig(logtail.CollectionNode)
	if err := state.WriteState(logPolicyStateKey, config.ToBytes()); err != nil {
		log.Printf("Could not save log policy config to state store: %v", err)
	}
	return config
}

// noCORSTransport wraps a RoundTripper and forces the no-cors mode on requests,
// so that we can use it with non-CORS-aware servers.
type noCORSTransport struct {
	http.RoundTripper
}

func (t *noCORSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("js.fetch:mode", "no-cors")
	resp, err := t.RoundTripper.RoundTrip(req)
	if err == nil {
		// In no-cors mode no response properties are returned. Populate just
		// the status so that callers do not think this was an error.
		resp.StatusCode = http.StatusOK
		resp.Status = http.StatusText(http.StatusOK)
	}
	return resp, err
}
