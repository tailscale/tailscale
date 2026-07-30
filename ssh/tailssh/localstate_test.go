// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"

	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
)

// localState implements ipnLocalBackend for testing.
type localState struct {
	sshEnabled   bool
	matchingRule *tailcfg.SSHRule
	varRoot      string // if empty, TailscaleVarRoot returns ""

	// caps, if non-empty, are advertised via NetMap().AllCaps. Used to gate
	// features like NodeAttrSSHEnvironmentVariables in tests.
	caps []tailcfg.NodeCapability

	// serverActions is a map of the action name to the action.
	// It is served for paths like https://unused/ssh-action/<action-name>.
	// The action name is the last part of the action URL.
	serverActions map[string]*tailcfg.SSHAction
}

func (ts *localState) Dialer() *tsdial.Dialer {
	return &tsdial.Dialer{}
}

func (ts *localState) ShouldRunSSH() bool {
	return ts.sshEnabled
}

func (ts *localState) NetMap() *netmap.NetworkMap {
	var policy *tailcfg.SSHPolicy
	if ts.matchingRule != nil {
		policy = &tailcfg.SSHPolicy{
			Rules: []*tailcfg.SSHRule{
				ts.matchingRule,
			},
		}
	}

	return &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{
			ID: 1,
		}).View(),
		SSHPolicy: policy,
		AllCaps:   set.SetOf(ts.caps),
	}
}

func (ts *localState) NetMapNoPeers() *netmap.NetworkMap { return ts.NetMap() }

func (ts *localState) WhoIs(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	if proto != "tcp" {
		return tailcfg.NodeView{}, tailcfg.UserProfile{}, false
	}

	return (&tailcfg.Node{
			ID:       2,
			StableID: "peer-id",
		}).View(), tailcfg.UserProfile{
			LoginName: "peer",
		}, true

}

func (ts *localState) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	k, ok := strings.CutPrefix(req.URL.Path, "/ssh-action/")
	if !ok {
		rec.WriteHeader(http.StatusNotFound)
	}
	a, ok := ts.serverActions[k]
	if !ok {
		rec.WriteHeader(http.StatusNotFound)
		return rec.Result(), nil
	}
	rec.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(rec).Encode(a); err != nil {
		return nil, err
	}
	return rec.Result(), nil
}

func (ts *localState) TailscaleVarRoot() string {
	return ts.varRoot
}

func (ts *localState) NodeKey() key.NodePublic {
	return key.NewNode().Public()
}
