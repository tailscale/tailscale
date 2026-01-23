// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
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

	f.l.Infof("UDP forwarder started, listening on %s, forwarding to %s", f.listener.LocalAddr().String(), f.backend)

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

		f.l.Debugf("Received %d bytes from %s", n, addr.String())

		addrp, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			f.l.Errorf("failed to parse address as address and port: %v", err)
			return err
		}

		f.m.Lock()
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

func setupL4Proxies(ctx context.Context, ts *tsnet.Server, lc *local.Client, logger *zap.SugaredLogger, cfg *conf.Config, group *errgroup.Group) (err error) {
	sc := &ipn.ServeConfig{}
	sc.Services = make(map[tailcfg.ServiceName]*ipn.ServiceConfig)

	// Store proxies to start later
	udpProxies := []ingressservices.Config{}

	// Build up the ServeConfig
	for _, p := range cfg.Parsed.L4Proxy.Ingress {
		// Register empty service config to trigger IP assignment
		for _, m := range p.Mappings() {
			if sc.Services[tailcfg.ServiceName(m.TailscaleServiceName)] == nil {
				sc.Services[tailcfg.ServiceName(m.TailscaleServiceName)] = &ipn.ServiceConfig{}
			}
		}
		udpProxies = append(udpProxies, p)

		status, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("error getting local client status: %w", err)
		}
		err = setTCPForwardingForProxy(p, status.CurrentTailnet.MagicDNSSuffix, sc, lc, logger)
		if err != nil {
			return fmt.Errorf("failed to set tcp forwarding for services: %w", err)
		}
	}

	// Apply the ServeConfig
	logger.Infof("Applying ServeConfig...")
	err = lc.SetServeConfig(ctx, sc)
	if err != nil {
		logger.Errorf("Failed to set ServeConfig: %v", err)
		return err
	}

	// Setup the UDP Forwarders
	for _, p := range udpProxies {
		status, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("error getting status: %w", err)
		}

		// We can validate that the Service IP is in this node's capmap, to ensure that the advertisement was successful
		found := false
		serviceIPMaps, err := tailcfg.UnmarshalNodeCapJSON[tailcfg.ServiceIPMappings](status.Self.CapMap, tailcfg.NodeAttrServiceHost)
		if err != nil {
			return fmt.Errorf("error unmarshaling service IP mappings: %w", err)
		}
		if len(serviceIPMaps) == 0 {
			logger.Warnf("no service IP mappings found for this node")
		} else {
			for _, m := range p.Mappings() {
				ipMatches := false
				for serviceName, addrs := range serviceIPMaps[0] {
					if string(serviceName) == m.TailscaleServiceName {
						found = true
						if len(addrs) == 0 {
							logger.Warnf("service %s has no assigned VIP addresses", m.TailscaleServiceName)
							break
						}
						// Check if the configured IP is in the capmap. There can be scenarios where it isn't (no autoapproval, tag problems)
						if slices.Contains(addrs, m.TailscaleServiceIP) {
							ipMatches = true
							logger.Infof("Found matching VIP %s for service %s in capmap", m.TailscaleServiceIP, m.TailscaleServiceName)
						}
						if !ipMatches {
							logger.Warnf("Service %s configured with IP %s, but capmap reports %v. Routing may not work.",
								m.TailscaleServiceName, m.TailscaleServiceIP, addrs)
						}
						break
					}
				}
				if !found {
					logger.Warnf("Tailscale Service %q not found in capmap. Routing may not work.", m.TailscaleServiceName)
				}
			}
		}

		fs, err := setupUDPForwardingForProxy(ts, p, logger)
		if err != nil {
			return fmt.Errorf("failed to setup udp forwarding: %w", err)
		}

		for _, f := range fs {
			group.Go(func() error {
				logger.Infof("Starting UDP forwarder goroutine for %s (%v)", f.backend, f.listener.LocalAddr())
				return f.run(ctx)
			})

			logger.Infof("successfully created UDP listener on %s", f.listener.LocalAddr())
		}

	}

	logger.Infof("Successfully applied ServeConfig and started all L4 proxies")
	return nil
}

func setTCPForwardingForProxy(p ingressservices.Config, magicDNSSuffix string, serveConfig *ipn.ServeConfig, lc *local.Client, logger *zap.SugaredLogger) error {
	for _, m := range p.Mappings() {
		for _, port := range m.Ports {
			svcName := tailcfg.ServiceName(m.TailscaleServiceName)
			logger.Infof("Setting TCP forwarding for service=%s, port=%d, backend=%s", svcName, port, m.ClusterIP)

			serveConfig.SetTCPForwardingForService(
				port,
				m.ClusterIP.String(),
				false,
				svcName,
				0,
				magicDNSSuffix,
			)
		}
	}

	return nil
}

func setupUDPForwardingForProxy(ts *tsnet.Server, p ingressservices.Config, logger *zap.SugaredLogger) (fs []*udpForwarder, err error) {
	for _, m := range p.Mappings() {
		for _, port := range m.Ports {
			f := &udpForwarder{
				l:       logger.Named(fmt.Sprintf("udp-forwarder-%v", m.ClusterIP)),
				backend: fmt.Sprintf("%s:%d", m.ClusterIP.String(), port),
				connMap: make(map[netip.AddrPort]*natEntry),
			}
			listenAddr := fmt.Sprintf("%s:%d", m.TailscaleServiceIP, port)
			logger.Infof("Attempting to listen on UDP address: %s", listenAddr)

			f.listener, err = ts.ListenPacket("udp", listenAddr)
			if err != nil {
				logger.Warnf("Failed to listen on %s: %v", listenAddr, err)
				return nil, err
			}

			fs = append(fs, f)
		}
	}

	return
}
