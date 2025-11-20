// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_debug

package localapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/httpm"
)

func init() {
	Register("component-debug-logging", (*Handler).serveComponentDebugLogging)
	Register("debug", (*Handler).serveDebug)
	Register("debug-rotate-disco-key", (*Handler).serveDebugRotateDiscoKey)
	Register("dev-set-state-store", (*Handler).serveDevSetStateStore)
	Register("debug-bus-events", (*Handler).serveDebugBusEvents)
	Register("debug-bus-graph", (*Handler).serveEventBusGraph)
	Register("debug-derp-region", (*Handler).serveDebugDERPRegion)
	Register("debug-dial-types", (*Handler).serveDebugDialTypes)
	Register("debug-log", (*Handler).serveDebugLog)
	Register("debug-packet-filter-matches", (*Handler).serveDebugPacketFilterMatches)
	Register("debug-packet-filter-rules", (*Handler).serveDebugPacketFilterRules)
	Register("debug-peer-endpoint-changes", (*Handler).serveDebugPeerEndpointChanges)
	Register("debug-optional-features", (*Handler).serveDebugOptionalFeatures)
}

func (h *Handler) serveDebugPeerEndpointChanges(w http.ResponseWriter, r *http.Request) {
	if !h.PermitRead {
		http.Error(w, "status access denied", http.StatusForbidden)
		return
	}

	ipStr := r.FormValue("ip")
	if ipStr == "" {
		http.Error(w, "missing 'ip' parameter", http.StatusBadRequest)
		return
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		http.Error(w, "invalid IP", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	chs, err := h.b.GetPeerEndpointChanges(r.Context(), ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	e := json.NewEncoder(w)
	e.SetIndent("", "\t")
	e.Encode(chs)
}

func (h *Handler) serveComponentDebugLogging(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	component := r.FormValue("component")
	secs, _ := strconv.Atoi(r.FormValue("secs"))
	err := h.b.SetComponentDebugLogging(component, h.clock.Now().Add(time.Duration(secs)*time.Second))
	var res struct {
		Error string
	}
	if err != nil {
		res.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (h *Handler) serveDebugDialTypes(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug-dial-types access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := r.FormValue("ip")
	port := r.FormValue("port")
	network := r.FormValue("network")

	addr := ip + ":" + port
	if _, err := netip.ParseAddrPort(addr); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "invalid address %q: %v", addr, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var bareDialer net.Dialer

	dialer := h.b.Dialer()

	var peerDialer net.Dialer
	peerDialer.Control = dialer.PeerDialControlFunc()

	// Kick off a dial with each available dialer in parallel.
	dialers := []struct {
		name string
		dial func(context.Context, string, string) (net.Conn, error)
	}{
		{"SystemDial", dialer.SystemDial},
		{"UserDial", dialer.UserDial},
		{"PeerDial", peerDialer.DialContext},
		{"BareDial", bareDialer.DialContext},
	}
	type result struct {
		name string
		conn net.Conn
		err  error
	}
	results := make(chan result, len(dialers))

	var wg sync.WaitGroup
	for _, dialer := range dialers {
		dialer := dialer // loop capture

		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialer.dial(ctx, network, addr)
			results <- result{dialer.name, conn, err}
		}()
	}

	wg.Wait()
	for range len(dialers) {
		res := <-results
		fmt.Fprintf(w, "[%s] connected=%v err=%v\n", res.name, res.conn != nil, res.err)
		if res.conn != nil {
			res.conn.Close()
		}
	}
}

func (h *Handler) serveDebug(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasDebug {
		http.Error(w, "debug not supported in this build", http.StatusNotImplemented)
		return
	}
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// The action is normally in a POST form parameter, but
	// some actions (like "notify") want a full JSON body, so
	// permit some to have their action in a header.
	var action string
	switch v := r.Header.Get("Debug-Action"); v {
	case "notify":
		action = v
	default:
		action = r.FormValue("action")
	}
	var err error
	switch action {
	case "derp-set-homeless":
		h.b.MagicConn().SetHomeless(true)
	case "derp-unset-homeless":
		h.b.MagicConn().SetHomeless(false)
	case "rebind":
		err = h.b.DebugRebind()
	case "restun":
		err = h.b.DebugReSTUN()
	case "notify":
		var n ipn.Notify
		err = json.NewDecoder(r.Body).Decode(&n)
		if err != nil {
			break
		}
		h.b.DebugNotify(n)
	case "notify-last-netmap":
		h.b.DebugNotifyLastNetMap()
	case "break-tcp-conns":
		err = h.b.DebugBreakTCPConns()
	case "break-derp-conns":
		err = h.b.DebugBreakDERPConns()
	case "force-netmap-update":
		h.b.DebugForceNetmapUpdate()
	case "control-knobs":
		k := h.b.ControlKnobs()
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(k.AsDebugJSON())
		if err == nil {
			return
		}
	case "pick-new-derp":
		err = h.b.DebugPickNewDERP()
	case "force-prefer-derp":
		var n int
		err = json.NewDecoder(r.Body).Decode(&n)
		if err != nil {
			break
		}
		h.b.DebugForcePreferDERP(n)
	case "peer-relay-servers":
		servers := h.b.DebugPeerRelayServers().Slice()
		slices.SortFunc(servers, func(a, b netip.Addr) int {
			return a.Compare(b)
		})
		err = json.NewEncoder(w).Encode(servers)
		if err == nil {
			return
		}
	case "rotate-disco-key":
		err = h.b.DebugRotateDiscoKey()
	case "":
		err = fmt.Errorf("missing parameter 'action'")
	default:
		err = fmt.Errorf("unknown action %q", action)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "done\n")
}

func (h *Handler) serveDevSetStateStore(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := h.b.SetDevStateStore(r.FormValue("key"), r.FormValue("value")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "done\n")
}

func (h *Handler) serveDebugPacketFilterRules(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	nm := h.b.NetMap()
	if nm == nil {
		http.Error(w, "no netmap", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	enc.Encode(nm.PacketFilterRules)
}

func (h *Handler) serveDebugPacketFilterMatches(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	nm := h.b.NetMap()
	if nm == nil {
		http.Error(w, "no netmap", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	enc.Encode(nm.PacketFilter)
}

// debugEventError provides the JSON encoding of internal errors from event processing.
type debugEventError struct {
	Error string
}

// serveDebugBusEvents taps into the tailscaled/utils/eventbus and streams
// events to the client.
func (h *Handler) serveDebugBusEvents(w http.ResponseWriter, r *http.Request) {
	// Require write access (~root) as the logs could contain something
	// sensitive.
	if !h.PermitWrite {
		http.Error(w, "event bus access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.GET {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	bus, ok := h.LocalBackend().Sys().Bus.GetOK()
	if !ok {
		http.Error(w, "event bus not running", http.StatusNoContent)
		return
	}

	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	io.WriteString(w, `{"Event":"[event listener connected]\n"}`+"\n")
	f.Flush()

	mon := bus.Debugger().WatchBus()
	defer mon.Close()

	i := 0
	for {
		select {
		case <-r.Context().Done():
			fmt.Fprintf(w, `{"Event":"[event listener closed]\n"}`)
			return
		case <-mon.Done():
			return
		case event := <-mon.Events():
			data := eventbus.DebugEvent{
				Count: i,
				Type:  reflect.TypeOf(event.Event).String(),
				Event: event.Event,
				From:  event.From.Name(),
			}
			for _, client := range event.To {
				data.To = append(data.To, client.Name())
			}

			if msg, err := json.Marshal(data); err != nil {
				data.Event = debugEventError{Error: fmt.Sprintf(
					"failed to marshal JSON for %T", event.Event,
				)}
				if errMsg, err := json.Marshal(data); err != nil {
					fmt.Fprintf(w,
						`{"Count": %d, "Event":"[ERROR] failed to marshal JSON for %T\n"}`,
						i, event.Event)
				} else {
					w.Write(errMsg)
				}
			} else {
				w.Write(msg)
			}
			f.Flush()
			i++
		}
	}
}

// serveEventBusGraph taps into the event bus and dumps out the active graph of
// publishers and subscribers. It does not represent anything about the messages
// exchanged.
func (h *Handler) serveEventBusGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != httpm.GET {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}

	bus, ok := h.LocalBackend().Sys().Bus.GetOK()
	if !ok {
		http.Error(w, "event bus not running", http.StatusPreconditionFailed)
		return
	}

	debugger := bus.Debugger()
	clients := debugger.Clients()

	graph := map[string]eventbus.DebugTopic{}

	for _, client := range clients {
		for _, pub := range debugger.PublishTypes(client) {
			topic, ok := graph[pub.Name()]
			if !ok {
				topic = eventbus.DebugTopic{Name: pub.Name()}
			}
			topic.Publisher = client.Name()
			graph[pub.Name()] = topic
		}
		for _, sub := range debugger.SubscribeTypes(client) {
			topic, ok := graph[sub.Name()]
			if !ok {
				topic = eventbus.DebugTopic{Name: sub.Name()}
			}
			topic.Subscribers = append(topic.Subscribers, client.Name())
			graph[sub.Name()] = topic
		}
	}

	// The top level map is not really needed for the client, convert to a list.
	topics := eventbus.DebugTopics{}
	for _, v := range graph {
		topics.Topics = append(topics.Topics, v)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topics)
}

func (h *Handler) serveDebugLog(w http.ResponseWriter, r *http.Request) {
	if !buildfeatures.HasLogTail {
		http.Error(w, feature.ErrUnavailable.Error(), http.StatusNotImplemented)
		return
	}
	if !h.PermitRead {
		http.Error(w, "debug-log access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	defer h.b.TryFlushLogs() // kick off upload after we're done logging

	type logRequestJSON struct {
		Lines  []string
		Prefix string
	}

	var logRequest logRequestJSON
	if err := json.NewDecoder(r.Body).Decode(&logRequest); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	prefix := logRequest.Prefix
	if prefix == "" {
		prefix = "debug-log"
	}
	logf := logger.WithPrefix(h.logf, prefix+": ")

	// We can write logs too fast for logtail to handle, even when
	// opting-out of rate limits. Limit ourselves to at most one message
	// per 20ms and a burst of 60 log lines, which should be fast enough to
	// not block for too long but slow enough that we can upload all lines.
	logf = logger.SlowLoggerWithClock(r.Context(), logf, 20*time.Millisecond, 60, h.clock.Now)

	for _, line := range logRequest.Lines {
		logf("%s", line)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveDebugOptionalFeatures(w http.ResponseWriter, r *http.Request) {
	of := &apitype.OptionalFeatures{
		Features: feature.Registered(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(of)
}

func (h *Handler) serveDebugRotateDiscoKey(w http.ResponseWriter, r *http.Request) {
	if !h.PermitWrite {
		http.Error(w, "debug access denied", http.StatusForbidden)
		return
	}
	if r.Method != httpm.POST {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if err := h.b.DebugRotateDiscoKey(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, "done\n")
}
