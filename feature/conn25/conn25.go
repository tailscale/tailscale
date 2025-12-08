// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package conn25 registers the conn25 feature and implements its associated ipnext.Extension.
package conn25

import (
	"encoding/json"
	"net/http"

	"tailscale.com/appc"
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/logger"
)

// featureName is the name of the feature implemented by this package.
// It is also the [extension] name and the log prefix.
const featureName = "conn25"

func init() {
	feature.Register(featureName)
	newExtension := func(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
		e := &extension{
			conn: &appc.Conn25{},
		}
		return e, nil
	}
	ipnext.RegisterExtension(featureName, newExtension)
	ipnlocal.RegisterPeerAPIHandler("/v0/connector/transit-ip", handleConnectorTransitIP)
}

func handleConnectorTransitIP(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	e, ok := ipnlocal.GetExt[*extension](h.LocalBackend())
	if !ok {
		http.Error(w, "miswired", http.StatusInternalServerError)
		return
	}
	e.handleConnectorTransitIP(h, w, r)
}

// extension is an [ipnext.Extension] managing the connector on platforms
// that import this package.
type extension struct {
	conn *appc.Conn25
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string {
	return featureName
}

// Init implements [ipnext.Extension].
func (e *extension) Init(host ipnext.Host) error {
	return nil
}

// Shutdown implements [ipnlocal.Extension].
func (e *extension) Shutdown() error {
	return nil
}

func (e *extension) handleConnectorTransitIP(h ipnlocal.PeerAPIHandler, w http.ResponseWriter, r *http.Request) {
	const maxBodyBytes = 1024 * 1024
	defer r.Body.Close()
	if r.Method != "POST" {
		http.Error(w, "Method should be POST", http.StatusMethodNotAllowed)
		return
	}
	var req appc.ConnectorTransitIPRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes+1)).Decode(&req)
	if err != nil {
		http.Error(w, "Error decoding JSON", http.StatusBadRequest)
		return
	}
	resp := e.conn.HandleConnectorTransitIPRequest(h.Peer().ID(), req)
	bs, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		return
	}
	w.Write(bs)
}
