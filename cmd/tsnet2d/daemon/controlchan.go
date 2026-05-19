// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"tailscale.com/tsnet2/proto"
)

// serveControl runs the control-channel RPC loop on c until the client
// disconnects or an error occurs.
func (d *Daemon) serveControl(c net.Conn) {
	fr := proto.NewFrameReader(c)
	fw := proto.NewFrameWriter(c)
	for {
		f, err := fr.Next()
		if err != nil {
			if err != io.EOF {
				d.logf("daemon: control read: %v", err)
			}
			return
		}
		go d.handleControlFrame(fw, f)
	}
}

// handleControlFrame dispatches a single RPC and writes a reply.
func (d *Daemon) handleControlFrame(fw *proto.FrameWriter, f *proto.Frame) {
	ctx, cancel := context.WithCancel(d.shutdownCtx)
	defer cancel()

	resp := &proto.Frame{ID: f.ID}
	result, err := d.dispatch(ctx, f.Method, f.Params)
	if err != nil {
		resp.Error = err.Error()
	} else if result != nil {
		b, mErr := json.Marshal(result)
		if mErr != nil {
			resp.Error = fmt.Sprintf("daemon: marshal result: %v", mErr)
		} else {
			resp.Result = b
		}
	}
	if err := fw.Write(resp); err != nil {
		d.logf("daemon: control write: %v", err)
	}
}

func (d *Daemon) dispatch(ctx context.Context, method string, paramsRaw []byte) (any, error) {
	switch method {
	case proto.MethodStart:
		var p proto.StartParams
		if err := proto.UnmarshalParams(paramsRaw, &p); err != nil {
			return nil, err
		}
		d.initMu.Lock()
		defer d.initMu.Unlock()
		if err := d.startBackendLocked(p); err != nil {
			return nil, err
		}
		return struct{}{}, nil

	case proto.MethodUp:
		ts, err := d.tsServer()
		if err != nil {
			return nil, err
		}
		st, err := ts.Up(ctx)
		if err != nil {
			return nil, err
		}
		out := proto.UpResult{}
		ip4, ip6 := ts.TailscaleIPs()
		if ip4.IsValid() {
			out.TailscaleIPs = append(out.TailscaleIPs, ip4)
		}
		if ip6.IsValid() {
			out.TailscaleIPs = append(out.TailscaleIPs, ip6)
		}
		if st != nil && st.Self != nil {
			out.NodeName = st.Self.HostName
		}
		out.CertDomains = ts.CertDomains()
		return out, nil

	case proto.MethodClose:
		go d.Close()
		return struct{}{}, nil

	case proto.MethodTailscaleIPs:
		ts, err := d.tsServer()
		if err != nil {
			return nil, err
		}
		ip4, ip6 := ts.TailscaleIPs()
		r := proto.TailscaleIPsResult{}
		if ip4.IsValid() {
			r.V4 = ip4.String()
		}
		if ip6.IsValid() {
			r.V6 = ip6.String()
		}
		return r, nil

	case proto.MethodCertDomains:
		ts, err := d.tsServer()
		if err != nil {
			return proto.CertDomainsResult{}, nil
		}
		return proto.CertDomainsResult{Domains: ts.CertDomains()}, nil

	case proto.MethodRegisterListener:
		var p proto.RegisterListenerParams
		if err := proto.UnmarshalParams(paramsRaw, &p); err != nil {
			return nil, err
		}
		ts, err := d.tsServer()
		if err != nil {
			return nil, err
		}
		ln, err := ts.Listen(p.Network, p.Addr)
		if err != nil {
			return nil, fmt.Errorf("tsnet.Listen(%q, %q): %w", p.Network, p.Addr, err)
		}
		id := newID()
		rl := &regListener{id: id, ln: ln, addr: ln.Addr().String()}
		d.lmu.Lock()
		d.listeners[id] = rl
		d.lmu.Unlock()
		go d.acceptLoop(rl)
		return proto.RegisterListenerResult{ListenerID: id, Addr: rl.addr}, nil

	case proto.MethodUnregisterListener:
		var p proto.UnregisterListenerParams
		if err := proto.UnmarshalParams(paramsRaw, &p); err != nil {
			return nil, err
		}
		d.lmu.Lock()
		rl, ok := d.listeners[p.ListenerID]
		if ok {
			delete(d.listeners, p.ListenerID)
		}
		d.lmu.Unlock()
		if ok {
			rl.ln.Close() // unblocks acceptLoop
		}
		return struct{}{}, nil
	}
	return nil, fmt.Errorf("daemon: unknown method %q", method)
}

// (ensureStarted/awaitRunning were removed: backend-started state is
// checked via tsServer(), and "wait until Running" is handled inside
// tsnet.Server.Up.)
