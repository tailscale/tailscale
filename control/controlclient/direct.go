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
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/oauth2"
	"tailscale.com/net/tlsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/structs"
	"tailscale.com/version"
)

type Persist struct {
	_                 structs.Incomparable
	PrivateMachineKey wgcfg.PrivateKey
	PrivateNodeKey    wgcfg.PrivateKey
	OldPrivateNodeKey wgcfg.PrivateKey // needed to request key rotation
	Provider          string
	LoginName         string
}

func (p *Persist) Equals(p2 *Persist) bool {
	if p == nil && p2 == nil {
		return true
	}
	if p == nil || p2 == nil {
		return false
	}

	return p.PrivateMachineKey.Equal(p2.PrivateMachineKey) &&
		p.PrivateNodeKey.Equal(p2.PrivateNodeKey) &&
		p.OldPrivateNodeKey.Equal(p2.OldPrivateNodeKey) &&
		p.Provider == p2.Provider &&
		p.LoginName == p2.LoginName
}

func (p *Persist) Pretty() string {
	var mk, ok, nk wgcfg.Key
	if !p.PrivateMachineKey.IsZero() {
		mk = p.PrivateMachineKey.Public()
	}
	if !p.OldPrivateNodeKey.IsZero() {
		ok = p.OldPrivateNodeKey.Public()
	}
	if !p.PrivateNodeKey.IsZero() {
		nk = p.PrivateNodeKey.Public()
	}
	return fmt.Sprintf("Persist{m=%v, o=%v, n=%v u=%#v}",
		mk.ShortString(), ok.ShortString(), nk.ShortString(),
		p.LoginName)
}

// Direct is the client that connects to a tailcontrol server for a node.
type Direct struct {
	httpc           *http.Client // HTTP client used to talk to tailcontrol
	serverURL       string       // URL of the tailcontrol server
	timeNow         func() time.Time
	lastPrintMap    time.Time
	newDecompressor func() (Decompressor, error)
	keepAlive       bool
	logf            logger.Logf

	mu           sync.Mutex // mutex guards the following fields
	serverKey    wgcfg.Key
	persist      Persist
	authKey      string
	tryingNewKey wgcfg.PrivateKey
	expiry       *time.Time
	hostinfo     *tailcfg.Hostinfo // always non-nil
	endpoints    []string
	localPort    uint16 // or zero to mean auto
}

type Options struct {
	Persist         Persist           // initial persistent data
	ServerURL       string            // URL of the tailcontrol server
	AuthKey         string            // optional node auth key for auto registration
	TimeNow         func() time.Time  // time.Now implementation used by Client
	Hostinfo        *tailcfg.Hostinfo // non-nil passes ownership, nil means to use default using os.Hostname, etc
	NewDecompressor func() (Decompressor, error)
	KeepAlive       bool
	Logf            logger.Logf
	HTTPTestClient  *http.Client // optional HTTP client to use (for tests only)
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
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.ForceAttemptHTTP2 = true
		tr.TLSClientConfig = tlsdial.Config(serverURL.Host, tr.TLSClientConfig)
		httpc = &http.Client{Transport: tr}
	}

	c := &Direct{
		httpc:           httpc,
		serverURL:       opts.ServerURL,
		timeNow:         opts.TimeNow,
		logf:            opts.Logf,
		newDecompressor: opts.NewDecompressor,
		keepAlive:       opts.KeepAlive,
		persist:         opts.Persist,
		authKey:         opts.AuthKey,
	}
	if opts.Hostinfo == nil {
		c.SetHostinfo(NewHostinfo())
	} else {
		c.SetHostinfo(opts.Hostinfo)
	}
	return c, nil
}

func NewHostinfo() *tailcfg.Hostinfo {
	hostname, _ := os.Hostname()
	return &tailcfg.Hostinfo{
		IPNVersion: version.LONG,
		Hostname:   hostname,
		OS:         version.OS(),
	}
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

func (c *Direct) GetPersist() Persist {
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
	//if c.persist.PrivateNodeKey != (wgcfg.PrivateKey{}) {
	//}
	c.persist = Persist{
		PrivateMachineKey: c.persist.PrivateMachineKey,
	}
	return nil
}

func (c *Direct) TryLogin(ctx context.Context, t *oauth2.Token, flags LoginFlags) (url string, err error) {
	c.logf("direct.TryLogin(%v, %v)", t != nil, flags)
	return c.doLoginOrRegen(ctx, t, flags, false, "")
}

func (c *Direct) WaitLoginURL(ctx context.Context, url string) (newUrl string, err error) {
	c.logf("direct.WaitLoginURL")
	return c.doLoginOrRegen(ctx, nil, LoginDefault, false, url)
}

func (c *Direct) doLoginOrRegen(ctx context.Context, t *oauth2.Token, flags LoginFlags, regen bool, url string) (newUrl string, err error) {
	mustregen, url, err := c.doLogin(ctx, t, flags, regen, url)
	if err != nil {
		return url, err
	}
	if mustregen {
		_, url, err = c.doLogin(ctx, t, flags, true, url)
	}
	return url, err
}

func (c *Direct) doLogin(ctx context.Context, t *oauth2.Token, flags LoginFlags, regen bool, url string) (mustregen bool, newurl string, err error) {
	c.mu.Lock()
	persist := c.persist
	tryingNewKey := c.tryingNewKey
	serverKey := c.serverKey
	expired := c.expiry != nil && !c.expiry.IsZero() && c.expiry.Before(c.timeNow())
	c.mu.Unlock()

	if persist.PrivateMachineKey == (wgcfg.PrivateKey{}) {
		c.logf("Generating a new machinekey.")
		mkey, err := wgcfg.NewPrivateKey()
		if err != nil {
			log.Fatal(err)
		}
		persist.PrivateMachineKey = mkey
	}

	if expired {
		c.logf("Old key expired -> regen=true")
		regen = true
	}
	if (flags & LoginInteractive) != 0 {
		c.logf("LoginInteractive -> regen=true")
		regen = true
	}

	c.logf("doLogin(regen=%v, hasUrl=%v)", regen, url != "")
	if serverKey == (wgcfg.Key{}) {
		var err error
		serverKey, err = loadServerKey(ctx, c.httpc, c.serverURL)
		if err != nil {
			return regen, url, err
		}

		c.mu.Lock()
		c.serverKey = serverKey
		c.mu.Unlock()
	}

	var oldNodeKey wgcfg.Key
	if url != "" {
	} else if regen || persist.PrivateNodeKey == (wgcfg.PrivateKey{}) {
		c.logf("Generating a new nodekey.")
		persist.OldPrivateNodeKey = persist.PrivateNodeKey
		key, err := wgcfg.NewPrivateKey()
		if err != nil {
			c.logf("login keygen: %v", err)
			return regen, url, err
		}
		tryingNewKey = key
	} else {
		// Try refreshing the current key first
		tryingNewKey = persist.PrivateNodeKey
	}
	if persist.OldPrivateNodeKey != (wgcfg.PrivateKey{}) {
		oldNodeKey = persist.OldPrivateNodeKey.Public()
	}

	if tryingNewKey == (wgcfg.PrivateKey{}) {
		log.Fatalf("tryingNewKey is empty, give up")
	}
	if c.hostinfo.BackendLogID == "" {
		err = errors.New("hostinfo: BackendLogID missing")
		return regen, url, err
	}
	request := tailcfg.RegisterRequest{
		Version:    1,
		OldNodeKey: tailcfg.NodeKey(oldNodeKey),
		NodeKey:    tailcfg.NodeKey(tryingNewKey.Public()),
		Hostinfo:   c.hostinfo,
		Followup:   url,
	}
	c.logf("RegisterReq: onode=%v node=%v fup=%v",
		request.OldNodeKey.ShortString(),
		request.NodeKey.ShortString(), url != "")
	request.Auth.Oauth2Token = t
	request.Auth.Provider = persist.Provider
	request.Auth.LoginName = persist.LoginName
	request.Auth.AuthKey = c.authKey
	bodyData, err := encode(request, &serverKey, &persist.PrivateMachineKey)
	if err != nil {
		return regen, url, err
	}
	body := bytes.NewReader(bodyData)

	u := fmt.Sprintf("%s/machine/%s", c.serverURL, persist.PrivateMachineKey.Public().HexString())
	req, err := http.NewRequest("POST", u, body)
	if err != nil {
		return regen, url, err
	}
	req = req.WithContext(ctx)

	res, err := c.httpc.Do(req)
	if err != nil {
		return regen, url, fmt.Errorf("register request: %v", err)
	}
	c.logf("RegisterReq: returned.")
	resp := tailcfg.RegisterResponse{}
	if err := decode(res, &resp, &serverKey, &persist.PrivateMachineKey); err != nil {
		return regen, url, fmt.Errorf("register request: %v", err)
	}

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
		c.logf("AuthURL is %.20v...", resp.AuthURL)
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

var debugNetmap, _ = strconv.ParseBool(os.Getenv("TS_DEBUG_NETMAP"))

func (c *Direct) PollNetMap(ctx context.Context, maxPolls int, cb func(*NetworkMap)) error {
	c.mu.Lock()
	persist := c.persist
	serverURL := c.serverURL
	serverKey := c.serverKey
	hostinfo := c.hostinfo
	localPort := c.localPort
	ep := append([]string(nil), c.endpoints...)
	c.mu.Unlock()

	if hostinfo.BackendLogID == "" {
		return errors.New("hostinfo: BackendLogID missing")
	}

	allowStream := maxPolls != 1
	c.logf("PollNetMap: stream=%v :%v %v", maxPolls, localPort, ep)

	vlogf := logger.Discard
	if debugNetmap {
		vlogf = c.logf
	}

	request := tailcfg.MapRequest{
		Version:     4,
		IncludeIPv6: includeIPv6(),
		KeepAlive:   c.keepAlive,
		NodeKey:     tailcfg.NodeKey(persist.PrivateNodeKey.Public()),
		Endpoints:   ep,
		Stream:      allowStream,
		Hostinfo:    hostinfo,
	}
	if c.newDecompressor != nil {
		request.Compress = "zstd"
	}

	bodyData, err := encode(request, &serverKey, &persist.PrivateMachineKey)
	if err != nil {
		vlogf("netmap: encode: %v", err)
		return err
	}

	t0 := time.Now()
	u := fmt.Sprintf("%s/machine/%s/map", serverURL, persist.PrivateMachineKey.Public().HexString())
	req, err := http.NewRequest("POST", u, bytes.NewReader(bodyData))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req = req.WithContext(ctx)

	res, err := c.httpc.Do(req)
	if err != nil {
		vlogf("netmap: Do: %v", err)
		return err
	}
	vlogf("netmap: Do = %v after %v", res.StatusCode, time.Since(t0).Round(time.Millisecond))
	if res.StatusCode != 200 {
		msg, _ := ioutil.ReadAll(res.Body)
		res.Body.Close()
		return fmt.Errorf("initial fetch failed %d: %s",
			res.StatusCode, strings.TrimSpace(string(msg)))
	}
	defer res.Body.Close()

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

	// If allowStream, then the server will use an HTTP long poll to
	// return incremental results. There is always one response right
	// away, followed by a delay, and eventually others.
	// If !allowStream, it'll still send the first result in exactly
	// the same format before just closing the connection.
	// We can use this same read loop either way.
	var msg []byte
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
		if resp.KeepAlive {
			vlogf("netmap: got keep-alive")
			select {
			case timeoutReset <- struct{}{}:
				vlogf("netmap: sent keep-alive timer reset")
			case <-ctx.Done():
				c.logf("netmap: not resetting timer for keep-alive due to: %v", ctx.Err())
				return ctx.Err()
			}
			continue
		}
		vlogf("netmap: got new map")

		nm := &NetworkMap{
			NodeKey:      tailcfg.NodeKey(persist.PrivateNodeKey.Public()),
			PrivateKey:   persist.PrivateNodeKey,
			Expiry:       resp.Node.KeyExpiry,
			Addresses:    resp.Node.Addresses,
			Peers:        resp.Peers,
			LocalPort:    localPort,
			User:         resp.Node.User,
			UserProfiles: make(map[tailcfg.UserID]tailcfg.UserProfile),
			Domain:       resp.Domain,
			Roles:        resp.Roles,
			DNS:          resp.DNS,
			DNSDomains:   resp.SearchPaths,
			Hostinfo:     resp.Node.Hostinfo,
			PacketFilter: c.parsePacketFilter(resp.PacketFilter),
		}
		for _, profile := range resp.UserProfiles {
			nm.UserProfiles[profile.ID] = profile
		}
		if resp.Node.MachineAuthorized {
			nm.MachineStatus = tailcfg.MachineAuthorized
		} else {
			nm.MachineStatus = tailcfg.MachineUnauthorized
		}

		// Printing the netmap can be extremely verbose, but is very
		// handy for debugging. Let's limit how often we do it.
		// Code elsewhere prints netmap diffs every time, so this
		// occasional full dump, plus incremental diffs, should do
		// the job.
		now := c.timeNow()
		if now.Sub(c.lastPrintMap) >= 5*time.Minute {
			c.lastPrintMap = now
			c.logf("new network map[%d]:\n%s", i, nm.Concise())
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

func decode(res *http.Response, v interface{}, serverKey *wgcfg.Key, mkey *wgcfg.PrivateKey) error {
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

func (c *Direct) decodeMsg(msg []byte, v interface{}) error {
	mkey := c.persist.PrivateMachineKey
	serverKey := c.serverKey

	decrypted, err := decryptMsg(msg, &serverKey, &mkey)
	if err != nil {
		return err
	}
	var b []byte
	if c.newDecompressor == nil {
		b = decrypted
	} else {
		//decoder, err := zstd.NewReader(nil)
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
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil

}

func decodeMsg(msg []byte, v interface{}, serverKey *wgcfg.Key, mkey *wgcfg.PrivateKey) error {
	decrypted, err := decryptMsg(msg, serverKey, mkey)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(decrypted, v); err != nil {
		return fmt.Errorf("response: %v", err)
	}
	return nil
}

func decryptMsg(msg []byte, serverKey *wgcfg.Key, mkey *wgcfg.PrivateKey) ([]byte, error) {
	var nonce [24]byte
	if len(msg) < len(nonce)+1 {
		return nil, fmt.Errorf("response missing nonce, len=%d", len(msg))
	}
	copy(nonce[:], msg)
	msg = msg[len(nonce):]

	pub, pri := (*[32]byte)(serverKey), (*[32]byte)(mkey)
	decrypted, ok := box.Open(nil, msg, &nonce, pub, pri)
	if !ok {
		return nil, fmt.Errorf("cannot decrypt response")
	}
	return decrypted, nil
}

func encode(v interface{}, serverKey *wgcfg.Key, mkey *wgcfg.PrivateKey) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	const debugMapRequests = false
	if debugMapRequests {
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

func loadServerKey(ctx context.Context, httpc *http.Client, serverURL string) (wgcfg.Key, error) {
	req, err := http.NewRequest("GET", serverURL+"/key", nil)
	if err != nil {
		return wgcfg.Key{}, fmt.Errorf("create control key request: %v", err)
	}
	req = req.WithContext(ctx)
	res, err := httpc.Do(req)
	if err != nil {
		return wgcfg.Key{}, fmt.Errorf("fetch control key: %v", err)
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(io.LimitReader(res.Body, 1<<16))
	if err != nil {
		return wgcfg.Key{}, fmt.Errorf("fetch control key response: %v", err)
	}
	if res.StatusCode != 200 {
		return wgcfg.Key{}, fmt.Errorf("fetch control key: %d: %s", res.StatusCode, string(b))
	}
	key, err := wgcfg.ParseHexKey(string(b))
	if err != nil {
		return wgcfg.Key{}, fmt.Errorf("fetch control key: %v", err)
	}
	return key, nil
}

// includeIPv6 reports whether we should enable IPv6 for magicsock
// connections. This is only here temporarily (2020-03-26) as a
// opt-out in case there are problems.
func includeIPv6() bool {
	if e := os.Getenv("DEBUG_INCLUDE_IPV6"); e != "" {
		v, _ := strconv.ParseBool(e)
		return v
	}
	return true
}
