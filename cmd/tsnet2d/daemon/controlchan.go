// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"tailscale.com/ipn"
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
		if err := d.ensureStarted(); err != nil {
			return nil, err
		}
		if err := d.awaitRunning(ctx); err != nil {
			return nil, err
		}
		ip4, ip6 := d.tailscaleIPs()
		out := proto.UpResult{}
		if ip4.IsValid() {
			out.TailscaleIPs = append(out.TailscaleIPs, ip4)
		}
		if ip6.IsValid() {
			out.TailscaleIPs = append(out.TailscaleIPs, ip6)
		}
		if d.lb != nil {
			st := d.lb.StatusWithoutPeers()
			if st != nil && st.Self != nil {
				out.NodeName = st.Self.HostName
			}
			if nm := d.lb.NetMapNoPeers(); nm != nil {
				out.CertDomains = append(out.CertDomains, nm.DNS.CertDomains...)
			}
		}
		return out, nil

	case proto.MethodClose:
		go d.Close()
		return struct{}{}, nil

	case proto.MethodTailscaleIPs:
		ip4, ip6 := d.tailscaleIPs()
		r := proto.TailscaleIPsResult{}
		if ip4.IsValid() {
			r.V4 = ip4.String()
		}
		if ip6.IsValid() {
			r.V6 = ip6.String()
		}
		return r, nil

	case proto.MethodCertDomains:
		if d.lb == nil {
			return proto.CertDomainsResult{}, nil
		}
		nm := d.lb.NetMapNoPeers()
		if nm == nil {
			return proto.CertDomainsResult{}, nil
		}
		return proto.CertDomainsResult{Domains: append([]string(nil), nm.DNS.CertDomains...)}, nil

	case proto.MethodRegisterListener:
		var p proto.RegisterListenerParams
		if err := proto.UnmarshalParams(paramsRaw, &p); err != nil {
			return nil, err
		}
		if err := d.ensureStarted(); err != nil {
			return nil, err
		}
		key, addr, err := listenAddrFor(p.Network, p.Addr)
		if err != nil {
			return nil, err
		}
		id := newID()
		rl := &regListener{id: id, key: key, address: addr}
		d.lmu.Lock()
		if _, dup := d.listenerByKey[key]; dup {
			d.lmu.Unlock()
			return nil, fmt.Errorf("daemon: listener already registered for %v", key)
		}
		d.listeners[id] = rl
		d.listenerByKey[key] = rl
		d.lmu.Unlock()
		return proto.RegisterListenerResult{ListenerID: id, Addr: addr}, nil

	case proto.MethodUnregisterListener:
		var p proto.UnregisterListenerParams
		if err := proto.UnmarshalParams(paramsRaw, &p); err != nil {
			return nil, err
		}
		d.lmu.Lock()
		rl, ok := d.listeners[p.ListenerID]
		if ok {
			delete(d.listeners, p.ListenerID)
			if cur, ok := d.listenerByKey[rl.key]; ok && cur == rl {
				delete(d.listenerByKey, rl.key)
			}
		}
		d.lmu.Unlock()
		return struct{}{}, nil
	}
	return nil, fmt.Errorf("daemon: unknown method %q", method)
}

func (d *Daemon) ensureStarted() error {
	d.initMu.Lock()
	defer d.initMu.Unlock()
	if !d.started {
		return errors.New("daemon: backend not started; call Start first")
	}
	return d.startErr
}

// awaitRunning blocks until the LocalBackend reaches ipn.Running or
// ctx expires.
func (d *Daemon) awaitRunning(ctx context.Context) error {
	if d.lb == nil {
		return errors.New("daemon: no LocalBackend")
	}
	st := d.lb.State()
	if st == ipn.Running {
		return nil
	}
	// Watch until we see Running.
	d.lb.WatchNotifications(ctx, ipn.NotifyInitialState, nil, func(n *ipn.Notify) (keepGoing bool) {
		if n.State != nil {
			st = *n.State
			if st == ipn.Running {
				return false
			}
		}
		return true
	})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if st != ipn.Running {
		return fmt.Errorf("daemon: backend ended in state %v", st)
	}
	return nil
}
