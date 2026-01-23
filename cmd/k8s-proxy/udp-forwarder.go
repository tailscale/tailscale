// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// k8s-proxy proxies between tailnet and Kubernetes cluster traffic.
// Currently, it only supports proxying tailnet clients to the Kubernetes API
// server.
package main

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/tailcfg"
)

type udpForwarder struct {
	listener net.PacketConn
	backend  string
	connMap  map[netip.AddrPort]*natEntry
	timeout  time.Duration
	l        *zap.SugaredLogger
	m        sync.Mutex
}

type natEntry struct {
	conn      net.Conn
	timestamp atomic.Int64
	cancel    context.CancelFunc
}

func (f *udpForwarder) run(ctx context.Context) error {
	buf := make([]byte, 65535)

	// TODO: Cleanup goroutine
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, addr, err := f.listener.ReadFrom(buf)
		if err != nil {
			f.l.Errorf("failed to read from listener: %v", err)
			return err
		}

		addrp, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			f.l.Errorf("failed to parse address as address and port: %v", err)
			return err
		}

		f.m.Lock()
		var entry *natEntry
		entry, ok := f.connMap[addrp]
		if !ok {
			c, err := net.Dial("udp", f.backend)
			if err != nil {
				f.l.Errorf("failed to dial: %v", err)
				f.m.Unlock()
				return err
			}

			entryCtx, cancel := context.WithCancel(ctx)

			entry = &natEntry{
				conn:      c,
				cancel:    cancel,
				timestamp: atomic.Int64{},
			}
			f.connMap[addrp] = entry

			go func(ctx context.Context, ne *natEntry) {
				defer ne.conn.Close()
				buf := make([]byte, 65535)

				for {
					select {
					case <-ctx.Done():
						f.l.Infof("context for relay with address %q done, exiting", addrp.String())
						return
					default:
					}

					n, err := ne.conn.Read(buf)
					if err != nil {
						f.l.Errorf("failed to read from connection with address %q: %v", addrp.String(), err)
						return
					}

					ne.timestamp.Store(time.Now().Unix())

					_, err = f.listener.WriteTo(buf[:n], net.UDPAddrFromAddrPort(addrp))
					if err != nil {
						f.l.Errorf("failed to write response to address %q: %v", addrp.String(), err)
						return
					}
				}
			}(entryCtx, entry)
		}
		f.m.Unlock()

		_, err = entry.conn.Write(buf[:n])
		if err != nil {
			f.l.Errorf("failed to write bytes to %q: %v", f.backend, err)
			return err
		}

		entry.timestamp.Store(time.Now().Unix())
	}
}

func SetTCPForwardingForService(ctx context.Context, cfg *conf.Config, serveConfig *ipn.ServeConfig, lc *local.Client, magicDNSSuffix string) error {
	for _, rule := range cfg.Parsed.L4Proxies {
		if rule.Proto != "tcp" {
			continue
		}

		svcName := tailcfg.ServiceName(rule.ServiceName)

		serveConfig.SetTCPForwardingForService(
			rule.ListenPort,
			rule.Backend,
			false, // terminateTLS
			svcName,
			0, // proxyProtocol
			magicDNSSuffix,
		)

	}

	return lc.SetServeConfig(ctx, serveConfig)
}
