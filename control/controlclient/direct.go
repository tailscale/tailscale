// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/nacl/box"
	"inet.af/netaddr"
	"tailscale.com/health"
	"tailscale.com/log/logheap"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
	"tailscale.com/net/tlsdial"
	"tailscale.com/net/tshttpproxy"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/opt"
	"tailscale.com/types/persist"
	"tailscale.com/types/wgkey"
	"tailscale.com/util/systemd"
	"tailscale.com/version"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/monitor"
)

// Direct is the client that connects to a tailcontrol server for a node.
type Direct struct {
	httpc                  *http.Client // HTTP client used to talk to tailcontrol
	serverURL              string       // URL of the tailcontrol server
	timeNow                func() time.Time
	lastPrintMap           time.Time
	newDecompressor        func() (Decompressor, error)
	keepAlive              bool
	logf                   logger.Logf
	linkMon                *monitor.Mon // or nil
	discoPubKey            tailcfg.DiscoKey
	machinePrivKey         wgkey.Private
	debugFlags             []string
	keepSharerAndUserSplit bool

	mu           sync.Mutex // mutex guards the following fields
	serverKey    wgkey.Key
	persist      persist.Persist
	authKey      string
	tryingNewKey wgkey.Private
	expiry       *time.Time
	// hostinfo is mutated in-place while mu is held.
	hostinfo      *tailcfg.Hostinfo // always non-nil
	endpoints     []string
	everEndpoints bool   // whether we've ever had non-empty endpoints
	localPort     uint16 // or zero to mean auto
}

type Options struct {
	Persist           persist.Persist   // initial persistent data
	MachinePrivateKey wgkey.Private     // the machine key to use
	ServerURL         string            // URL of the tailcontrol server
	AuthKey           string            // optional node auth key for auto registration
	TimeNow           func() time.Time  // time.Now implementation used by Client
	Hostinfo          *tailcfg.Hostinfo // non-nil passes ownership, nil means to use default using os.Hostname, etc
	DiscoPublicKey    tailcfg.DiscoKey
	NewDecompressor   func() (Decompressor, error)
	KeepAlive         bool
	Logf              logger.Logf
	HTTPTestClient    *http.Client // optional HTTP client to use (for tests only)
	DebugFlags        []string     // debug settings to send to control
	LinkMonitor       *monitor.Mon // optional link monitor

	// KeepSharerAndUserSplit controls whether the client
	// understands Node.Sharer. If false, the Sharer is mapped to the User.
	KeepSharerAndUserSplit bool
}

type Decompressor interface {
	DecodeAll(input, dst []byte) ([]byte, error)
	Close()
}

// NewDirect returns a new Direct client.
func NewDirect(opts Options) (*Direct, error) {
	if opts.ServerURL == "" {
		return nil, errors.New("controlclient.New: no server URL specified")
	}
	if opts.MachinePrivateKey.IsZero() {
		return nil, errors.New("controlclient.New: no MachinePrivateKey specified")
	}
	opts.ServerURL = strings.TrimRight(opts.ServerURL, "/")
	serverURL, err := url.Parse(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	if opts.TimeNow == nil {
		opts.TimeNow = time.Now
	}
	if opts.Logf == nil {
		// TODO(apenwarr): remove this default and fail instead.
		// TODO(bradfitz): ... but then it shouldn't be in Options.
		opts.Logf = log.Printf
	}

	httpc := opts.HTTPTestClient
	if httpc == nil {
		dnsCache := &dnscache.Resolver{
			Forward:          dnscache.Get().Forward, // use default cache's forwarder
			UseLastGood:      true,
			LookupIPFallback: dnsfallback.Lookup,
		}
		dialer := netns.NewDialer()
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = tshttpproxy.ProxyFromEnvironment
		tshttpproxy.SetTransportGetProxyConnectHeader(tr)
		tr.TLSClientConfig = tlsdial.Config(serverURL.Host, tr.TLSClientConfig)
		tr.DialContext = dnscache.Dialer(dialer.DialContext, dnsCache)
		tr.DialTLSContext = dnscache.TLSDialer(dialer.DialContext, dnsCache, tr.TLSClientConfig)
		tr.ForceAttemptHTTP2 = true
		httpc = &http.Client{Transport: tr}
	}

	c := &Direct{
		httpc:                  httpc,
		machinePrivKey:         opts.MachinePrivateKey,
		serverURL:              opts.ServerURL,
		timeNow:                opts.TimeNow,
		logf:                   opts.Logf,
		newDecompressor:        opts.NewDecompressor,
		keepAlive:              opts.KeepAlive,
		persist:                opts.Persist,
		authKey:                opts.AuthKey,
		discoPubKey:            opts.DiscoPublicKey,
		debugFlags:             opts.DebugFlags,
		keepSharerAndUserSplit: opts.KeepSharerAndUserSplit,
		linkMon:                opts.LinkMonitor,
	}
	if opts.Hostinfo == nil {
		c.SetHostinfo(NewHostinfo())
	} else {
		c.SetHostinfo(opts.Hostinfo)
	}
	return c, nil
}

var osVersion func() string // non-nil on some platforms

func NewHostinfo() *tailcfg.Hostinfo {
	hostname, _ := os.Hostname()
	var osv string
	if osVersion != nil {
		osv = osVersion()
	}
	return &tailcfg.Hostinfo{
		IPNVersion: version.Long,
		Hostname:   hostname,
		OS:         version.OS(),
		OSVersion:  osv,
		Package:    packageType(),
		GoArch:     runtime.GOARCH,
	}
}

func packageType() string {
	switch runtime.GOOS {
	case "windows":
		if _, err := os.Stat(`C:\ProgramData\chocolatey\lib\tailscale`); err == nil {
			return "choco"
		}
	case "darwin":
		// Using tailscaled or IPNExtension?
		exe, _ := os.Executable()
		return filepath.Base(exe)
	}
	return ""
}

// SetHostinfo clones the provided Hostinfo and remembers it for the
// next update. It reports whether the Hostinfo has changed.
func (c *Direct) SetHostinfo(hi *tailcfg.Hostinfo) bool {
	if hi == nil {
		panic("nil Hostinfo")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if hi.Equal(c.hostinfo) {
		return false
	}
	c.hostinfo = hi.Clone()
	j, _ := json.Marshal(c.hostinfo)
	c.logf("HostInfo: %s", j)
	return true
}

// SetNetInfo clones the provided NetInfo and remembers it for the
// next update. It reports whether the NetInfo has changed.
func (c *Direct) SetNetInfo(ni *tailcfg.NetInfo) bool {
	if ni == nil {
		panic("nil NetInfo")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hostinfo == nil {
		c.logf("[unexpected] SetNetInfo called with no HostInfo; ignoring NetInfo update: %+v", ni)
		return false
	}
	if reflect.DeepEqual(ni, c.hostinfo.NetInfo) {
		return false
	}
	c.hostinfo.NetInfo = ni.Clone()
	return true
}

func (c *Direct) GetPersist() persist.Persist {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.persist
}

type LoginFlags int

const (
	LoginDefault     = LoginFlags(0)
	LoginInteractive = LoginFlags(1 << iota) // force user login and key refresh
)

func (c *Direct) TryLogout(ctx context.Context) error {
	c.logf("direct.TryLogout()")

	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO(crawshaw): Tell the server. This node key should be
	// immediately invalidated.
	//if !c.persist.PrivateNodeKey.IsZero() {
	//}
	c.persist = persist.Persist{}
	return nil
}

func (c *Direct) TryLogin(ctx context.Context, t *tailcfg.Oauth2Token, flags LoginFlags) (url string, err error) {
	c.logf("direct.TryLogin(token=%v, flags=%v)", t != nil, flags)
	return c.doLoginOrRegen(ctx, t, flags, false, "")
}

func (c *Direct) WaitLoginURL(ctx context.Context, url string) (newUrl string, err error) {
	c.logf("direct.WaitLoginURL")
	return c.doLoginOrRegen(ctx, nil, LoginDefault, false, url)
}

func (c *Direct) doLoginOrRegen(ctx context.Context, t *tailcfg.Oauth2Token, flags LoginFlags, regen bool, url string) (newUrl string, err error) {
	mustregen, url, err := c.doLogin(ctx, t, flags, regen, url)
	if err != nil {
		return url, err
	}
	if mustregen {
		_, url, err = c.doLogin(ctx, t, flags, true, url)
	}

	return url, err
}

func (c *Direct) doLogin(ctx context.Context, t *tailcfg.Oauth2Token, flags LoginFlags, regen bool, url string) (mustregen bool, newurl string, err error) {
	c.mu.Lock()
	persist := c.persist
	tryingNewKey := c.tryingNewKey
	serverKey := c.serverKey
	authKey := c.authKey
	hostinfo := c.hostinfo.Clone()
	backendLogID := hostinfo.BackendLogID
	expired := c.expiry != nil && !c.expiry.IsZero() && c.expiry.Before(c.timeNow())
	c.mu.Unlock()

	if c.machinePrivKey.IsZero() {
		return false, "", errors.New("controlclient.Direct requires a machine private key")
	}

	if expired {
		c.logf("Old key expired -> regen=true")
		systemd.Status("key expired; run 'tailscale up' to authenticate")
		regen = true
	}
	if (flags & LoginInteractive) != 0 {
		c.logf("LoginInteractive -> regen=true")
		regen = true
	}

	c.logf("doLogin(regen=%v, hasUrl=%v)", regen, url != "")
	if serverKey.IsZero() {
		var err error
		serverKey, err = loadServerKey(ctx, c.httpc, c.serverURL)
		if err != nil {
			return regen, url, err
		}

		c.mu.Lock()
		c.serverKey = serverKey
		c.mu.Unlock()
	}

	var oldNodeKey wgkey.Key
	if url != "" {
	} else if regen || persist.PrivateNodeKey.IsZero() {
		c.logf("Generating a new nodekey.")
		persist.OldPrivateNodeKey = persist.PrivateNodeKey
		key, err := wgkey.NewPrivate()
		if err != nil {
			c.logf("login keygen: %v", err)
			return regen, url, err
		}
		tryingNewKey = key
	} else {
		// Try refreshing the current key first
		tryingNewKey = persist.PrivateNodeKey
	}
	if !persist.OldPrivateNodeKey.IsZero() {
		oldNodeKey = persist.OldPrivateNodeKey.Public()
	}

	if tryingNewKey.IsZero() {
		log.Fatalf("tryingNewKey is empty, give up")
	}
	if backendLogID == "" {
		err = errors.New("hostinfo: BackendLogID missing")
		return regen, url, err
	}
	request := tailcfg.RegisterRequest{
		Version:    1,
		OldNodeKey: tailcfg.NodeKey(oldNodeKey),
		NodeKey:    tailcfg.NodeKey(tryingNewKey.Public()),
		Hostinfo:   hostinfo,
		Followup:   url,
	}
	c.logf("RegisterReq: onode=%v node=%v fup=%v",
		request.OldNodeKey.ShortString(),
		request.NodeKey.ShortString(), url != "")
	request.Auth.Oauth2Token = t
	request.Auth.Provider = persist.Provider
	request.Auth.LoginName = persist.LoginName
	request.Auth.AuthKey = authKey
	bodyData, err := encode(request, &serverKey, &c.machinePrivKey)
	if err != nil {
		return regen, url, err
	}
	body := bytes.NewReader(bodyData)

	u := fmt.Sprintf("%s/machine/%s", c.serverURL, c.machinePrivKey.Public().HexString())
	req, err := http.NewRequest("POST", u, body)
	if err != nil {
		return regen, url, err
	}
	req = req.WithContext(ctx)

	res, err := c.httpc.Do(req)
	if err != nil {
		return regen, url, fmt.Errorf("register request: %v", err)
	}
	if res.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return regen, url, fmt.Errorf("register request: http %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	resp := tailcfg.RegisterResponse{}
	if err := decode(res, &resp, &serverKey, &c.machinePrivKey); err != nil {
		c.logf("error decoding RegisterResponse with server key %s and machine key %s: %v", serverKey, c.machinePrivKey.Public(), err)
		return regen, url, fmt.Errorf("register request: %v", err)
	}
	// Log without PII:
	c.logf("RegisterReq: got response; nodeKeyExpired=%v, machineAuthorized=%v; authURL=%v",
		resp.NodeKeyExpired, resp.MachineAuthorized, resp.AuthURL != "")

	if resp.NodeKeyExpired {
		if regen {
			return true, "", fmt.Errorf("weird: regen=true but server says NodeKeyExpired: %v", request.NodeKey)
		}
		c.logf("server reports new node key %v has expired",
			request.NodeKey.ShortString())
		return true, "", nil
	}
	if persist.Provider == "" {
		persist.Provider = resp.Login.Provider
	}
	if persist.LoginName == "" {
		persist.LoginName = resp.Login.LoginName
	}

	// TODO(crawshaw): RegisterResponse should be able to mechanically
	// communicate some extra instructions from the server:
	//	- new node key required
	//	- machine key no longer supported
	//	- user is disabled

	if resp.AuthURL != "" {
		c.logf("AuthURL is %v", resp.AuthURL)
	} else {
		c.logf("No AuthURL")
	}

	c.mu.Lock()
	if resp.AuthURL == "" {
		// key rotation is complete
		persist.PrivateNodeKey = tryingNewKey
	} else {
		// save it for the retry-with-URL
		c.tryingNewKey = tryingNewKey
	}
	c.persist = persist
	c.mu.Unlock()

	if err != nil {
		return regen, "", err
	}
	if ctx.Err() != nil {
		return regen, "", ctx.Err()
	}
	return false, resp.AuthURL, nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// newEndpoints acquires c.mu and sets the local port and endpoints and reports
// whether they've changed.
//
// It does not retain the provided slice.
func (c *Direct) newEndpoints(localPort uint16, endpoints []string) (changed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Nothing new?
	if c.localPort == localPort && sameStrings(c.endpoints, endpoints) {
		return false // unchanged
	}
	c.logf("client.newEndpoints(%v, %v)", localPort, endpoints)
	c.localPort = localPort
	c.endpoints = append(c.endpoints[:0], endpoints...)
	if len(endpoints) > 0 {
		c.everEndpoints = true
	}
	return true // changed
}

// SetEndpoints updates the list of locally advertised endpoints.
// It won't be replicated to the server until a *fresh* call to PollNetMap().
// You don't need to restart PollNetMap if we return changed==false.
func (c *Direct) SetEndpoints(localPort uint16, endpoints []string) (changed bool) {
	// (no log message on function entry, because it clutters the logs
	//  if endpoints haven't changed. newEndpoints() will log it.)
	return c.newEndpoints(localPort, endpoints)
}

func inTest() bool { return flag.Lookup("test.v") != nil }

// PollNetMap makes a /map request to download the network map, calling cb with
// each new netmap.
//
// maxPolls is how many network maps to download; common values are 1
// or -1 (to keep a long-poll query open to the server).
func (c *Direct) PollNetMap(ctx context.Context, maxPolls int, cb func(*netmap.NetworkMap)) error {
	return c.sendMapRequest(ctx, maxPolls, cb)
}

// SendLiteMapUpdate makes a /map request to update the server of our latest state,
// but does not fetch anything. It returns an error if the server did not return a
// successful 200 OK response.
func (c *Direct) SendLiteMapUpdate(ctx context.Context) error {
	return c.sendMapRequest(ctx, 1, nil)
}

// cb nil means to omit peers.
func (c *Direct) sendMapRequest(ctx context.Context, maxPolls int, cb func(*netmap.NetworkMap)) error {
	c.mu.Lock()
	persist := c.persist
	serverURL := c.serverURL
	serverKey := c.serverKey
	hostinfo := c.hostinfo.Clone()
	backendLogID := hostinfo.BackendLogID
	localPort := c.localPort
	ep := append([]string(nil), c.endpoints...)
	everEndpoints := c.everEndpoints
	c.mu.Unlock()

	if persist.PrivateNodeKey.IsZero() {
		return errors.New("privateNodeKey is zero")
	}
	if backendLogID == "" {
		return errors.New("hostinfo: BackendLogID missing")
	}

	allowStream := maxPolls != 1
	c.logf("[v1] PollNetMap: stream=%v :%v ep=%v", allowStream, localPort, ep)

	vlogf := logger.Discard
	if Debug.NetMap {
		// TODO(bradfitz): update this to use "[v2]" prefix perhaps? but we don't
		// want to upload it always.
		vlogf = c.logf
	}

	request := &tailcfg.MapRequest{
		Version:    tailcfg.CurrentMapRequestVersion,
		KeepAlive:  c.keepAlive,
		NodeKey:    tailcfg.NodeKey(persist.PrivateNodeKey.Public()),
		DiscoKey:   c.discoPubKey,
		Endpoints:  ep,
		Stream:     allowStream,
		Hostinfo:   hostinfo,
		DebugFlags: c.debugFlags,
		OmitPeers:  cb == nil,
	}
	var extraDebugFlags []string
	if hostinfo != nil && c.linkMon != nil && ipForwardingBroken(hostinfo.RoutableIPs, c.linkMon.InterfaceState()) {
		extraDebugFlags = append(extraDebugFlags, "warn-ip-forwarding-off")
	}
	if health.RouterHealth() != nil {
		extraDebugFlags = append(extraDebugFlags, "warn-router-unhealthy")
	}
	if health.NetworkCategoryHealth() != nil {
		extraDebugFlags = append(extraDebugFlags, "warn-network-category-unhealthy")
	}
	if len(extraDebugFlags) > 0 {
		old := request.DebugFlags
		request.DebugFlags = append(old[:len(old):len(old)], extraDebugFlags...)
	}
	if c.newDecompressor != nil {
		request.Compress = "zstd"
	}
	// On initial startup before we know our endpoints, set the ReadOnly flag
	// to tell the control server not to distribute out our (empty) endpoints to peers.
	// Presumably we'll learn our endpoints in a half second and do another post
	// with useful results. The first POST just gets us the DERP map which we
	// need to do the STUN queries to discover our endpoints.
	// TODO(bradfitz): we skip this optimization in tests, though,
	// because the e2e tests are currently hyperspecific about the
	// ordering of things. The e2e tests need love.
	if len(ep) == 0 && !everEndpoints && !inTest() {
		request.ReadOnly = true
	}

	bodyData, err := encode(request, &serverKey, &c.machinePrivKey)
	if err != nil {
		vlogf("netmap: encode: %v", err)
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	machinePubKey := tailcfg.MachineKey(c.machinePrivKey.Public())
	t0 := time.Now()
	u := fmt.Sprintf("%s/machine/%s/map", serverURL, machinePubKey.HexString())

	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}

	res, err := c.httpc.Do(req)
	if err != nil {
		vlogf("netmap: Do: %v", err)
		return err
	}
	vlogf("netmap: Do = %v after %v", res.StatusCode, time.Since(t0).Round(time.Millisecond))
	if res.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("initial fetch failed %d: %.200s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	defer res.Body.Close()

	health.NoteMapRequestHeard(request)

	if cb == nil {
		io.Copy(ioutil.Discard, res.Body)
		return nil
	}

	// If we go more than pollTimeout without hearing from the server,
	// end the long poll. We should be receiving a keep alive ping
	// every minute.
	const pollTimeout = 120 * time.Second
	timeout := time.NewTimer(pollTimeout)
	timeoutReset := make(chan struct{})
	pollDone := make(chan struct{})
	defer close(pollDone)
	go func() {
		for {
			select {
			case <-pollDone:
				vlogf("netmap: ending timeout goroutine")
				return
			case <-timeout.C:
				c.logf("map response long-poll timed out!")
				cancel()
				return
			case <-timeoutReset:
				if !timeout.Stop() {
					select {
					case <-timeout.C:
					case <-pollDone:
						vlogf("netmap: ending timeout goroutine")
						return
					}
				}
				vlogf("netmap: reset timeout timer")
				timeout.Reset(pollTimeout)
			}
		}
	}()

	var lastDERPMap *tailcfg.DERPMap
	var lastUserProfile = map[tailcfg.UserID]tailcfg.UserProfile{}
	var lastParsedPacketFilter []filter.Match
	var collectServices bool

	// If allowStream, then the server will use an HTTP long poll to
	// return incremental results. There is always one response right
	// away, followed by a delay, and eventually others.
	// If !allowStream, it'll still send the first result in exactly
	// the same format before just closing the connection.
	// We can use this same read loop either way.
	var msg []byte
	var previousPeers []*tailcfg.Node // for delta-purposes
	for i := 0; i < maxPolls || maxPolls < 0; i++ {
		vlogf("netmap: starting size read after %v (poll %v)", time.Since(t0).Round(time.Millisecond), i)
		var siz [4]byte
		if _, err := io.ReadFull(res.Body, siz[:]); err != nil {
			vlogf("netmap: size read error after %v: %v", time.Since(t0).Round(time.Millisecond), err)
			return err
		}
		size := binary.LittleEndian.Uint32(siz[:])
		vlogf("netmap: read size %v after %v", size, time.Since(t0).Round(time.Millisecond))
		msg = append(msg[:0], make([]byte, size)...)
		if _, err := io.ReadFull(res.Body, msg); err != nil {
			vlogf("netmap: body read error: %v", err)
			return err
		}
		vlogf("netmap: read body after %v", time.Since(t0).Round(time.Millisecond))

		var resp tailcfg.MapResponse
		if err := c.decodeMsg(msg, &resp); err != nil {
			vlogf("netmap: decode error: %v")
			return err
		}

		if allowStream {
			health.GotStreamedMapResponse()
		}

		if pr := resp.PingRequest; pr != nil {
			go answerPing(c.logf, c.httpc, pr)
		}

		if resp.KeepAlive {
			vlogf("netmap: got keep-alive")
		} else {
			vlogf("netmap: got new map")
		}
		select {
		case timeoutReset <- struct{}{}:
			vlogf("netmap: sent timer reset")
		case <-ctx.Done():
			c.logf("[v1] netmap: not resetting timer; context done: %v", ctx.Err())
			return ctx.Err()
		}
		if resp.KeepAlive {
			continue
		}

		undeltaPeers(&resp, previousPeers)
		previousPeers = cloneNodes(resp.Peers) // defensive/lazy clone, since this escapes to who knows where
		for _, up := range resp.UserProfiles {
			lastUserProfile[up.ID] = up
		}

		if resp.DERPMap != nil {
			vlogf("netmap: new map contains DERP map")
			lastDERPMap = resp.DERPMap
		}
		if resp.Debug != nil {
			if resp.Debug.LogHeapPprof {
				go logheap.LogHeap(resp.Debug.LogHeapURL)
			}
			if resp.Debug.GoroutineDumpURL != "" {
				go dumpGoroutinesToURL(c.httpc, resp.Debug.GoroutineDumpURL)
			}
			setControlAtomic(&controlUseDERPRoute, resp.Debug.DERPRoute)
			setControlAtomic(&controlTrimWGConfig, resp.Debug.TrimWGConfig)
		}
		// Temporarily (2020-06-29) support removing all but
		// discovery-supporting nodes during development, for
		// less noise.
		if Debug.OnlyDisco {
			filtered := resp.Peers[:0]
			for _, p := range resp.Peers {
				if !p.DiscoKey.IsZero() {
					filtered = append(filtered, p)
				}
			}
			resp.Peers = filtered
		}
		if Debug.StripEndpoints {
			for _, p := range resp.Peers {
				// We need at least one endpoint here for now else
				// other code doesn't even create the discoEndpoint.
				// TODO(bradfitz): fix that and then just nil this out.
				p.Endpoints = []string{"127.9.9.9:456"}
			}
		}

		if pf := resp.PacketFilter; pf != nil {
			lastParsedPacketFilter = c.parsePacketFilter(pf)
		}

		if v, ok := resp.CollectServices.Get(); ok {
			collectServices = v
		}

		// Get latest localPort. This might've changed if
		// a lite map update occured meanwhile. This only affects
		// the end-to-end test.
		// TODO(bradfitz): remove the NetworkMap.LocalPort field entirely.
		c.mu.Lock()
		localPort = c.localPort
		c.mu.Unlock()

		nm := &netmap.NetworkMap{
			SelfNode:        resp.Node,
			NodeKey:         tailcfg.NodeKey(persist.PrivateNodeKey.Public()),
			PrivateKey:      persist.PrivateNodeKey,
			MachineKey:      machinePubKey,
			Expiry:          resp.Node.KeyExpiry,
			Name:            resp.Node.Name,
			Addresses:       resp.Node.Addresses,
			Peers:           resp.Peers,
			LocalPort:       localPort,
			User:            resp.Node.User,
			UserProfiles:    make(map[tailcfg.UserID]tailcfg.UserProfile),
			Domain:          resp.Domain,
			DNS:             resp.DNSConfig,
			Hostinfo:        resp.Node.Hostinfo,
			PacketFilter:    lastParsedPacketFilter,
			CollectServices: collectServices,
			DERPMap:         lastDERPMap,
			Debug:           resp.Debug,
		}
		addUserProfile := func(userID tailcfg.UserID) {
			if _, dup := nm.UserProfiles[userID]; dup {
				// Already populated it from a previous peer.
				return
			}
			if up, ok := lastUserProfile[userID]; ok {
				nm.UserProfiles[userID] = up
			}
		}
		addUserProfile(nm.User)
		magicDNSSuffix := nm.MagicDNSSuffix()
		nm.SelfNode.InitDisplayNames(magicDNSSuffix)
		for _, peer := range resp.Peers {
			peer.InitDisplayNames(magicDNSSuffix)
			if !peer.Sharer.IsZero() {
				if c.keepSharerAndUserSplit {
					addUserProfile(peer.Sharer)
				} else {
					peer.User = peer.Sharer
				}
			}
			addUserProfile(peer.User)
		}
		if resp.Node.MachineAuthorized {
			nm.MachineStatus = tailcfg.MachineAuthorized
		} else {
			nm.MachineStatus = tailcfg.MachineUnauthorized
		}
		if len(resp.DNS) > 0 {
			nm.DNS.Nameservers = resp.DNS
		}
		if len(resp.SearchPaths) > 0 {
			nm.DNS.Domains = resp.SearchPaths
		}
		if Debug.ProxyDNS {
			nm.DNS.Proxied = true
		}

		// Printing the netmap can be extremely verbose, but is very
		// handy for debugging. Let's limit how often we do it.
		// Code elsewhere prints netmap diffs every time, so this
		// occasional full dump, plus incremental diffs, should do
		// the job.
		now := c.timeNow()
		if now.Sub(c.lastPrintMap) >= 5*time.Minute {
			c.lastPrintMap = now
			c.logf("[v1] new network map[%d]:\n%s", i, nm.Concise())
		}

		c.mu.Lock()
		c.expiry = &nm.Expiry
		c.mu.Unlock()

		cb(nm)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

func decode(res *http.Response, v interface{}, serverKey *wgkey.Key, mkey *wgkey.Private) error {
	defer res.Body.Close()
	msg, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("%d: %v", res.StatusCode, string(msg))
	}
	return decodeMsg(msg, v, serverKey, mkey)
}

var debugMap, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_MAP"))

var jsonEscapedZero = []byte(`\u0000`)

func (c *Direct) decodeMsg(msg []byte, v interface{}) error {
	c.mu.Lock()
	serverKey := c.serverKey
	c.mu.Unlock()

	decrypted, err := decryptMsg(msg, &serverKey, &c.machinePrivKey)
	if err != nil {
		return err
	}
	var b []byte
	if c.newDecompressor == nil {
		b = decrypted
	} else {
		decoder, err := c.newDecompressor()
		if err != nil {
			return err
		}
		defer decoder.Close()
		b, err = decoder.DecodeAll(decrypted, nil)
		if err != nil {
			return err
		}
	}
	if debugMap {
		var buf bytes.Buffer
		json.Indent(&buf, b, "", "    ")
		log.Printf("MapResponse: %s", buf.Bytes())
	}

	if bytes.Contains(b, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in controlclient.Direct.decodeMsg into %T: %q", v, b)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil

}

func decodeMsg(msg []byte, v interface{}, serverKey *wgkey.Key, mkey *wgkey.Private) error {
	decrypted, err := decryptMsg(msg, serverKey, mkey)
	if err != nil {
		return err
	}
	if bytes.Contains(decrypted, jsonEscapedZero) {
		log.Printf("[unexpected] zero byte in controlclient decodeMsg into %T: %q", v, decrypted)
	}
	if err := json.Unmarshal(decrypted, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil
}

func decryptMsg(msg []byte, serverKey *wgkey.Key, mkey *wgkey.Private) ([]byte, error) {
	var nonce [24]byte
	if len(msg) < len(nonce)+1 {
		return nil, fmt.Errorf("response missing nonce, len=%d", len(msg))
	}
	copy(nonce[:], msg)
	msg = msg[len(nonce):]

	pub, pri := (*[32]byte)(serverKey), (*[32]byte)(mkey)
	decrypted, ok := box.Open(nil, msg, &nonce, pub, pri)
	if !ok {
		return nil, fmt.Errorf("cannot decrypt response (len %d + nonce %d = %d)", len(msg), len(nonce), len(msg)+len(nonce))
	}
	return decrypted, nil
}

func encode(v interface{}, serverKey *wgkey.Key, mkey *wgkey.Private) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if debugMap {
		if _, ok := v.(tailcfg.MapRequest); ok {
			log.Printf("MapRequest: %s", b)
		}
	}
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		panic(err)
	}
	pub, pri := (*[32]byte)(serverKey), (*[32]byte)(mkey)
	msg := box.Seal(nonce[:], b, &nonce, pub, pri)
	return msg, nil
}

func loadServerKey(ctx context.Context, httpc *http.Client, serverURL string) (wgkey.Key, error) {
	req, err := http.NewRequest("GET", serverURL+"/key", nil)
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("create control key request: %v", err)
	}
	req = req.WithContext(ctx)
	res, err := httpc.Do(req)
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("fetch control key: %v", err)
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<16))
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("fetch control key response: %v", err)
	}
	if res.StatusCode != 200 {
		return wgkey.Key{}, fmt.Errorf("fetch control key: %d: %s", res.StatusCode, string(b))
	}
	key, err := wgkey.ParseHex(string(b))
	if err != nil {
		return wgkey.Key{}, fmt.Errorf("fetch control key: %v", err)
	}
	return key, nil
}

// Debug contains temporary internal-only debug knobs.
// They're unexported to not draw attention to them.
var Debug = initDebug()

type debug struct {
	NetMap         bool
	ProxyDNS       bool
	OnlyDisco      bool
	Disco          bool
	StripEndpoints bool // strip endpoints from control (only use disco messages)
}

func initDebug() debug {
	use := os.Getenv("TS_DEBUG_USE_DISCO")
	return debug{
		NetMap:         envBool("TS_DEBUG_NETMAP"),
		ProxyDNS:       envBool("TS_DEBUG_PROXY_DNS"),
		StripEndpoints: envBool("TS_DEBUG_STRIP_ENDPOINTS"),
		OnlyDisco:      use == "only",
		Disco:          use == "only" || use == "" || envBool("TS_DEBUG_USE_DISCO"),
	}
}

func envBool(k string) bool {
	e := os.Getenv(k)
	if e == "" {
		return false
	}
	v, err := strconv.ParseBool(e)
	if err != nil {
		panic(fmt.Sprintf("invalid non-bool %q for env var %q", e, k))
	}
	return v
}

// undeltaPeers updates mapRes.Peers to be complete based on the provided previous peer list
// and the PeersRemoved and PeersChanged fields in mapRes.
// It then also nils out the delta fields.
func undeltaPeers(mapRes *tailcfg.MapResponse, prev []*tailcfg.Node) {
	if len(mapRes.Peers) > 0 {
		// Not delta encoded.
		if !nodesSorted(mapRes.Peers) {
			log.Printf("netmap: undeltaPeers: MapResponse.Peers not sorted; sorting")
			sortNodes(mapRes.Peers)
		}
		return
	}

	var removed map[tailcfg.NodeID]bool
	if pr := mapRes.PeersRemoved; len(pr) > 0 {
		removed = make(map[tailcfg.NodeID]bool, len(pr))
		for _, id := range pr {
			removed[id] = true
		}
	}
	changed := mapRes.PeersChanged

	if len(removed) == 0 && len(changed) == 0 {
		// No changes fast path.
		mapRes.Peers = prev
		return
	}

	if !nodesSorted(changed) {
		log.Printf("netmap: undeltaPeers: MapResponse.PeersChanged not sorted; sorting")
		sortNodes(changed)
	}
	if !nodesSorted(prev) {
		// Internal error (unrelated to the network) if we get here.
		log.Printf("netmap: undeltaPeers: [unexpected] prev not sorted; sorting")
		sortNodes(prev)
	}

	newFull := make([]*tailcfg.Node, 0, len(prev)-len(removed))
	for len(prev) > 0 && len(changed) > 0 {
		pID := prev[0].ID
		cID := changed[0].ID
		if removed[pID] {
			prev = prev[1:]
			continue
		}
		switch {
		case pID < cID:
			newFull = append(newFull, prev[0])
			prev = prev[1:]
		case pID == cID:
			newFull = append(newFull, changed[0])
			prev, changed = prev[1:], changed[1:]
		case cID < pID:
			newFull = append(newFull, changed[0])
			changed = changed[1:]
		}
	}
	newFull = append(newFull, changed...)
	for _, n := range prev {
		if !removed[n.ID] {
			newFull = append(newFull, n)
		}
	}
	sortNodes(newFull)

	if mapRes.PeerSeenChange != nil {
		peerByID := make(map[tailcfg.NodeID]*tailcfg.Node, len(newFull))
		for _, n := range newFull {
			peerByID[n.ID] = n
		}
		now := time.Now()
		for nodeID, seen := range mapRes.PeerSeenChange {
			if n, ok := peerByID[nodeID]; ok {
				if seen {
					n.LastSeen = &now
				} else {
					n.LastSeen = nil
				}
			}
		}
	}

	mapRes.Peers = newFull
	mapRes.PeersChanged = nil
	mapRes.PeersRemoved = nil
}

func nodesSorted(v []*tailcfg.Node) bool {
	for i, n := range v {
		if i > 0 && n.ID <= v[i-1].ID {
			return false
		}
	}
	return true
}

func sortNodes(v []*tailcfg.Node) {
	sort.Slice(v, func(i, j int) bool { return v[i].ID < v[j].ID })
}

func cloneNodes(v1 []*tailcfg.Node) []*tailcfg.Node {
	if v1 == nil {
		return nil
	}
	v2 := make([]*tailcfg.Node, len(v1))
	for i, n := range v1 {
		v2[i] = n.Clone()
	}
	return v2
}

// opt.Bool configs from control.
var (
	controlUseDERPRoute atomic.Value
	controlTrimWGConfig atomic.Value
)

func setControlAtomic(dst *atomic.Value, v opt.Bool) {
	old, ok := dst.Load().(opt.Bool)
	if !ok || old != v {
		dst.Store(v)
	}
}

// DERPRouteFlag reports the last reported value from control for whether
// DERP route optimization (Issue 150) should be enabled.
func DERPRouteFlag() opt.Bool {
	v, _ := controlUseDERPRoute.Load().(opt.Bool)
	return v
}

// TrimWGConfig reports the last reported value from control for whether
// we should do lazy wireguard configuration.
func TrimWGConfig() opt.Bool {
	v, _ := controlTrimWGConfig.Load().(opt.Bool)
	return v
}

// ipForwardingBroken reports whether the system's IP forwarding is disabled
// and will definitely not work for the routes provided.
//
// It should not return false positives.
func ipForwardingBroken(routes []netaddr.IPPrefix, state *interfaces.State) bool {
	if len(routes) == 0 {
		// Nothing to route, so no need to warn.
		return false
	}

	if runtime.GOOS != "linux" {
		// We only do subnet routing on Linux for now.
		// It might work on darwin/macOS when building from source, so
		// don't return true for other OSes. We can OS-based warnings
		// already in the admin panel.
		return false
	}

	localIPs := map[netaddr.IP]bool{}
	for _, addrs := range state.InterfaceIPs {
		for _, pfx := range addrs {
			localIPs[pfx.IP] = true
		}
	}

	v4Routes, v6Routes := false, false
	for _, r := range routes {
		// It's possible to advertise a route to one of the local
		// machine's local IPs. IP forwarding isn't required for this
		// to work, so we shouldn't warn for such exports.
		if r.IsSingleIP() && localIPs[r.IP] {
			continue
		}
		if r.IP.Is4() {
			v4Routes = true
		} else {
			v6Routes = true
		}
	}

	if v4Routes {
		out, err := ioutil.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if err != nil {
			// Try another way.
			out, err = exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
		}
		if err != nil {
			// Oh well, we tried. This is just for debugging.
			// We don't want false positives.
			// TODO: maybe we want a different warning for inability to check?
			return false
		}
		if strings.TrimSpace(string(out)) == "0" {
			return true
		}
	}
	if v6Routes {
		// Note: you might be wondering why we check only the state of
		// conf.all.forwarding, rather than per-interface forwarding
		// configuration. According to kernel documentation, it seems
		// that to actually forward packets, you need to enable
		// forwarding globally, and the per-interface forwarding
		// setting only alters other things such as how router
		// advertisements are handled. The kernel itself warns that
		// enabling forwarding per-interface and not globally will
		// probably not work, so I feel okay calling those configs
		// broken until we have proof otherwise.
		out, err := ioutil.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if err != nil {
			out, err = exec.Command("sysctl", "-n", "net.ipv6.conf.all.forwarding").Output()
		}
		if err != nil {
			// Oh well, we tried. This is just for debugging.
			// We don't want false positives.
			// TODO: maybe we want a different warning for inability to check?
			return false
		}
		if strings.TrimSpace(string(out)) == "0" {
			return true
		}
	}

	return false
}

func answerPing(logf logger.Logf, c *http.Client, pr *tailcfg.PingRequest) {
	if pr.URL == "" {
		logf("invalid PingRequest with no URL")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", pr.URL, nil)
	if err != nil {
		logf("http.NewRequestWithContext(%q): %v", pr.URL, err)
		return
	}
	if pr.Log {
		logf("answerPing: sending ping to %v ...", pr.URL)
	}
	t0 := time.Now()
	_, err = c.Do(req)
	d := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		logf("answerPing error: %v to %v (after %v)", err, pr.URL, d)
	} else if pr.Log {
		logf("answerPing complete to %v (after %v)", pr.URL, d)
	}
}
