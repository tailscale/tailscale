// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
	"tailscale.com/util/dnsname"
)

type status struct {
	Status    *ipnstate.Status
	RaftState string
}

type monitor struct {
	ts  *tsnet.Server
	con *Consensus
	sg  statusGetter
}

func (m *monitor) getStatus(ctx context.Context) (status, error) {
	tStatus, err := m.sg.getStatus(ctx)
	if err != nil {
		return status{}, err
	}
	return status{Status: tStatus, RaftState: m.con.raft.State().String()}, nil
}

func serveMonitor(c *Consensus, ts *tsnet.Server, listenAddr string) (*http.Server, error) {
	ln, err := ts.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	m := &monitor{con: c, ts: ts, sg: &tailscaleStatusGetter{
		ts: ts,
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /full", m.handleFullStatus)
	mux.HandleFunc("GET /{$}", m.handleSummaryStatus)
	mux.HandleFunc("GET /netmap", m.handleNetmap)
	mux.HandleFunc("POST /dial", m.handleDial)
	srv := &http.Server{Handler: mux}
	go func() {
		err := srv.Serve(ln)
		log.Printf("MonitorHTTP stopped serving with error: %v", err)
	}()
	return srv, nil
}

func (m *monitor) handleFullStatus(w http.ResponseWriter, r *http.Request) {
	s, err := m.getStatus(r.Context())
	if err != nil {
		log.Printf("monitor: error getStatus: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(s); err != nil {
		log.Printf("monitor: error encoding full status: %v", err)
		return
	}
}

func (m *monitor) handleSummaryStatus(w http.ResponseWriter, r *http.Request) {
	s, err := m.getStatus(r.Context())
	if err != nil {
		log.Printf("monitor: error getStatus: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	lines := []string{}
	for _, p := range s.Status.Peer {
		if p.Online {
			name := dnsname.FirstLabel(p.DNSName)
			lines = append(lines, fmt.Sprintf("%s\t\t%d\t%d\t%t", name, p.RxBytes, p.TxBytes, p.Active))
		}
	}
	_, err = w.Write([]byte(fmt.Sprintf("RaftState: %s\n", s.RaftState)))
	if err != nil {
		log.Printf("monitor: error writing status: %v", err)
		return
	}

	slices.Sort(lines)
	for _, ln := range lines {
		_, err = w.Write([]byte(fmt.Sprintf("%s\n", ln)))
		if err != nil {
			log.Printf("monitor: error writing status: %v", err)
			return
		}
	}
}

func (m *monitor) handleNetmap(w http.ResponseWriter, r *http.Request) {
	lc, err := m.ts.LocalClient()
	if err != nil {
		log.Printf("monitor: error LocalClient: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	watcher, err := lc.WatchIPNBus(r.Context(), ipn.NotifyInitialNetMap)
	if err != nil {
		log.Printf("monitor: error WatchIPNBus: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	defer watcher.Close()

	n, err := watcher.Next()
	if err != nil {
		log.Printf("monitor: error watcher.Next: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "\t")
	if err := encoder.Encode(n); err != nil {
		log.Printf("monitor: error encoding netmap: %v", err)
		return
	}
}

func (m *monitor) handleDial(w http.ResponseWriter, r *http.Request) {
	var dialParams struct {
		Addr string
	}
	defer r.Body.Close()
	bs, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		log.Printf("monitor: error reading body: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	err = json.Unmarshal(bs, &dialParams)
	if err != nil {
		log.Printf("monitor: error unmarshalling json: %v", err)
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	c, err := m.ts.Dial(r.Context(), "tcp", dialParams.Addr)
	if err != nil {
		log.Printf("monitor: error dialing: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	c.Close()
	w.Write([]byte("ok\n"))
}
