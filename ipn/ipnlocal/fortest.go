// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"crypto/tls"
	"net/http"

	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnauth"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/testenv"
	"tailscale.com/wgengine/filter"
)

// forTest is an unexported type to hide all the test-only
// methods on [LocalBackend] from godoc.
type forTest struct{ b *LocalBackend }

// ForTest returns a handle to test-only methods on b.
// The resulting type is unexported to make it very obvious
// in godoc that this is not stable API. This method panics
// if called outside of tests, which also centralizes all
// must-be-in-tests validation.
func (b *LocalBackend) ForTest() forTest {
	testenv.AssertInTest()
	return forTest{b}
}

// HandleC2N calls [LocalBackend.handleC2N], for use by feature/ packages that
// register C2N handlers and want to test them.
func (f forTest) HandleC2N(w http.ResponseWriter, r *http.Request) {
	f.b.handleC2N(w, r)
}

// SetIPServiceMappings overwrites the LocalBackend's IP-to-service mappings
// and propagates them to the netstack subsystem if registered.
func (f forTest) SetIPServiceMappings(m netmap.IPServiceMappings) {
	b := f.b
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ipVIPServiceMap = m
	if ns, ok := b.sys.Netstack.GetOK(); ok {
		ns.UpdateIPServiceMappings(m)
	}
}

// GetFilter returns the current packet filter.
func (f forTest) GetFilter() *filter.Filter {
	b := f.b
	// Take b.mu so the read serializes with [LocalBackend.setControlClientStatusLocked],
	// which installs the netmap and the filter at separate sub-steps. Without
	// this, a test thread that observes the new netmap (via [LocalBackend.NetMapWithPeers])
	// can race ahead of the filter store and read the previous filter.
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.currentNode().filterAtomic.Load()
}

// SetControlClientGetter sets the func that creates a control plane
// client. It can be called at most once, before Start.
func (f forTest) SetControlClientGetter(newControlClient func(controlclient.Options) (controlclient.Client, error)) {
	b := f.b
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.ccGen != nil {
		panic("invalid use of forTest.SetControlClientGetter after Start")
	}
	b.ccGen = newControlClient
}

// Peers returns all the current peers, sorted by Node.ID, for integration
// tests in another repo.
func (f forTest) Peers() []tailcfg.NodeView {
	return f.b.currentNode().PeersForTest()
}

// AwaitNodeKey returns a channel that is closed once a peer with the given
// node key first appears in the current netmap. If the peer is already
// present, the returned channel is already closed. See
// [nodeBackend.AwaitNodeKeyForTest].
func (f forTest) AwaitNodeKey(k key.NodePublic) <-chan struct{} {
	return f.b.currentNode().AwaitNodeKeyForTest(k)
}

// CurrentUser returns the current user and the associated WindowsUserID.
// It will be removed along with the rest of the "current user" functionality
// as we progress on the multi-user improvements (tailscale/corp#18342).
func (f forTest) CurrentUser() (ipn.WindowsUserID, ipnauth.Actor) {
	b := f.b
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pm.CurrentUserID(), b.currentUser
}

// ConfigureCerts sets a certificate retrieval function to be used by this
// local backend, skipping the usual ACME certificate registration.
func (f forTest) ConfigureCerts(getCert func(hostname string) (*TLSCertKeyPair, error)) {
	hook, ok := HookConfigureCertsForTest.GetOk()
	if !ok {
		panic("forTest.ConfigureCerts called without cert extension registered")
	}
	hook(f.b, getCert)
}

// GetACMETLSALPNCert returns the short-lived ACME tls-alpn-01 challenge
// certificate for hi, if any.
func (f forTest) GetACMETLSALPNCert(hi *tls.ClientHelloInfo) (*tls.Certificate, bool) {
	return f.b.getACMETLSALPNCert(hi)
}

// SetServeConfig installs sc as the backend's current
// [ipn.ServeConfig] without going through the validation in
// [LocalBackend.SetServeConfig]. It is intended for tests that need a
// specific serve config without first standing up the prerequisites
// (netmap, prefs, etc.).
func (f forTest) SetServeConfig(sc ipn.ServeConfigView) {
	b := f.b
	b.mu.Lock()
	defer b.mu.Unlock()
	b.serveConfig = sc
}

// SetNetMap installs nm as the backend's current netmap without going
// through control-plane plumbing. It is intended for tests that need a
// specific netmap (e.g. CertDomains, capabilities).
func (f forTest) SetNetMap(nm *netmap.NetworkMap) {
	b := f.b
	b.mu.Lock()
	defer b.mu.Unlock()
	b.currentNode().SetNetMap(nm)
}

// SetClock replaces b's clock with c, for tests that need
// time-dependent behavior to be deterministic.
func (f forTest) SetClock(c tstime.Clock) { f.b.clock = c }

// SetPrefs replaces the current prefs with newp.
func (f forTest) SetPrefs(newp *ipn.Prefs) {
	if newp == nil {
		panic("forTest.SetPrefs got nil prefs")
	}
	b := f.b
	b.mu.Lock()
	defer b.mu.Unlock()
	b.setPrefsLocked(newp)
}
