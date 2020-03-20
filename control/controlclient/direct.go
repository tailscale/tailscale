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
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/wgcfg"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/oauth2"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/version"
	"tailscale.com/wgengine/filter"
)

type Persist struct {
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
	tryingNewKey wgcfg.PrivateKey
	expiry       *time.Time
	hostinfo     *tailcfg.Hostinfo // always non-nil
	endpoints    []string
	localPort    uint16 // or zero to mean auto
}

type Options struct {
	Persist         Persist           // initial persistent data
	HTTPC           *http.Client      // HTTP client used to talk to tailcontrol
	ServerURL       string            // URL of the tailcontrol server
	TimeNow         func() time.Time  // time.Now implementation used by Client
	Hostinfo        *tailcfg.Hostinfo // non-nil passes ownership, nil means to use default using os.Hostname, etc
	NewDecompressor func() (Decompressor, error)
	KeepAlive       bool
	Logf            logger.Logf
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
	if opts.HTTPC == nil {
		opts.HTTPC = http.DefaultClient
	}
	if opts.TimeNow == nil {
		opts.TimeNow = time.Now
	}
	if opts.Logf == nil {
		// TODO(apenwarr): remove this default and fail instead.
		// TODO(bradfitz): ... but then it shouldn't be in Options.
		opts.Logf = log.Printf
	}
	c := &Direct{
		httpc:           opts.HTTPC,
		serverURL:       opts.ServerURL,
		timeNow:         opts.TimeNow,
		logf:            opts.Logf,
		newDecompressor: opts.NewDecompressor,
		keepAlive:       opts.KeepAlive,
		persist:         opts.Persist,
	}
	if opts.Hostinfo == nil {
		c.SetHostinfo(NewHostinfo())
	} else {
		c.SetHostinfo(opts.Hostinfo)
	}
	return c, nil
}

func hostinfoOS() string {
	os := runtime.GOOS
	switch os {
	case "darwin":
		if version.IsMobile() {
			return "iOS"
		} else {
			return "macOS"
		}
	default:
		return os
	}
}

func NewHostinfo() *tailcfg.Hostinfo {
	hostname, _ := os.Hostname()
	return &tailcfg.Hostinfo{
		IPNVersion: version.LONG,
		Hostname:   hostname,
		OS:         hostinfoOS(),
	}
}

// SetHostinfo clones the provided Hostinfo and remembers it for the
// next update.
func (c *Direct) SetHostinfo(hi *tailcfg.Hostinfo) {
	if hi == nil {
		panic("nil Hostinfo")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logf("Hostinfo: %v\n", hi)
	c.hostinfo = hi.Clone()
}

// SetNetInfo clones the provided NetInfo and remembers it for the
// next update.
func (c *Direct) SetNetInfo(ni *tailcfg.NetInfo) {
	if ni == nil {
		panic("nil NetInfo")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hostinfo == nil {
		c.logf("[unexpected] SetNetInfo called with no HostInfo; ignoring NetInfo update: %+v", ni)
		return
	}
	c.logf("NetInfo: %v\n", ni)
	c.hostinfo.NetInfo = ni.Clone()
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
	c.logf("direct.TryLogout()\n")

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
	c.logf("direct.TryLogin(%v, %v)\n", t != nil, flags)
	return c.doLoginOrRegen(ctx, t, flags, false, "")
}

func (c *Direct) WaitLoginURL(ctx context.Context, url string) (newUrl string, err error) {
	c.logf("direct.WaitLoginURL\n")
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
		c.logf("Generating a new machinekey.\n")
		mkey, err := wgcfg.NewPrivateKey()
		if err != nil {
			log.Fatal(err)
		}
		persist.PrivateMachineKey = mkey
	}

	if expired {
		c.logf("Old key expired -> regen=true\n")
		regen = true
	}
	if (flags & LoginInteractive) != 0 {
		c.logf("LoginInteractive -> regen=true\n")
		regen = true
	}

	c.logf("doLogin(regen=%v, hasUrl=%v)\n", regen, url != "")
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
		c.logf("Generating a new nodekey.\n")
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
		log.Fatalf("tryingNewKey is empty, give up\n")
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
	c.logf("RegisterReq: onode=%v node=%v fup=%v\n",
		request.OldNodeKey.ShortString(),
		request.NodeKey.ShortString(), url != "")
	request.Auth.Oauth2Token = t
	request.Auth.Provider = persist.Provider
	request.Auth.LoginName = persist.LoginName
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
	c.logf("RegisterReq: returned.\n")
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
		c.logf("AuthURL is %.20v...\n", resp.AuthURL)
	} else {
		c.logf("No AuthURL\n")
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
	c.logf("client.newEndpoints(%v, %v)\n", localPort, endpoints)
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
	c.logf("PollNetMap: stream=%v :%v %v\n", maxPolls, localPort, ep)

	request := tailcfg.MapRequest{
		Version:   4,
		KeepAlive: c.keepAlive,
		NodeKey:   tailcfg.NodeKey(persist.PrivateNodeKey.Public()),
		Endpoints: ep,
		Stream:    allowStream,
		Hostinfo:  hostinfo,
	}
	if c.newDecompressor != nil {
		request.Compress = "zstd"
	}

	bodyData, err := encode(request, &serverKey, &persist.PrivateMachineKey)
	if err != nil {
		return err
	}

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
		return err
	}
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
	defer close(timeoutReset)
	go func() {
		for {
			select {
			case <-timeout.C:
				c.logf("map response long-poll timed out!")
				cancel()
				return
			case _, ok := <-timeoutReset:
				if !ok {
					return // channel closed, shut down goroutine
				}
				if !timeout.Stop() {
					<-timeout.C
				}
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
		var siz [4]byte
		if _, err := io.ReadFull(res.Body, siz[:]); err != nil {
			return err
		}
		size := binary.LittleEndian.Uint32(siz[:])
		msg = append(msg[:0], make([]byte, size)...)
		if _, err := io.ReadFull(res.Body, msg); err != nil {
			return err
		}

		var resp tailcfg.MapResponse

		// Default filter if the key is missing from the incoming
		// json (ie. old tailcontrol server without PacketFilter
		// support). If even an empty PacketFilter is provided, this
		// will be overwritten.
		// TODO(apenwarr 2020-02-01): remove after tailcontrol is fully deployed.
		resp.PacketFilter = filter.MatchAllowAll.Clone()

		if err := c.decodeMsg(msg, &resp); err != nil {
			return err
		}
		if resp.KeepAlive {
			timeoutReset <- struct{}{}
			continue
		}

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
			PacketFilter: resp.PacketFilter,
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
