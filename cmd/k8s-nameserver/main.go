// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

// k8s-nameserver is a simple nameserver implementation meant to be used with
// k8s-operator to allow to resolve magicDNS names of Tailscale nodes in a
// Kubernetes cluster.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	operatorutils "tailscale.com/k8s-operator"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

const (
	defaultDNSConfigDir = "/config"
	defaultDNSFile      = "dns.json"
	udpEndpoint         = ":1053"

	kubeletMountedConfigLn = "..data"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.Printf

	res := resolver.New(logger, nil, nil, &tsdial.Dialer{Logf: logger}, nil)

	var configReader configReaderFunc = func() ([]byte, error) {
		if contents, err := os.ReadFile(filepath.Join(defaultDNSConfigDir, defaultDNSFile)); err == nil {
			return contents, nil

		} else if os.IsNotExist(err) {
			return nil, nil

		} else {
			return nil, err
		}
	}

	c := make(chan string)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("error creating a new configfile watcher: %v", err)
	}
	defer watcher.Close()
	// kubelet mounts configmap to a Pod using a series of symlinks, one of
	// which is <mount-dir>/..data that Kubernetes recommends consumers to
	// use if they need to monitor changes
	// https://github.com/kubernetes/kubernetes/blob/v1.28.1/pkg/volume/util/atomic_writer.go#L39-L61
	// TODO (irbekrm): we need e2e tests to make sure that this keeps working for new kube versions etc
	toWatch := filepath.Join(defaultDNSConfigDir, kubeletMountedConfigLn)
	go func() {
		logger("starting file watch for %s", defaultDNSConfigDir)
		if err != nil {
			log.Fatalf("error starting a new configfile watcher: %v", err)
		}
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					logger("watcher finished")
					cancel()
					return
				}

				if event.Name == toWatch {
					msg := fmt.Sprintf("config update received: %s", event)
					logger(msg)
					c <- msg
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					logger("errors watcher finished: %v", err)
					cancel()
					return
				}
				if err != nil {
					logger("error watching directory: %w", err)
					cancel()
					return
				}
			}
		}
	}()
	if err = watcher.Add(defaultDNSConfigDir); err != nil {
		log.Fatalf("failed setting up file watch for DNS config: %v", err)
	}

	ns := &nameserver{
		configReader:  configReader,
		configWatcher: c,
		logger:        logger,
		res:           res,
	}

	if err := ns.run(ctx, cancel); err != nil {
		log.Fatalf("error running nameserver: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", udpEndpoint)
	if err != nil {
		log.Fatalf("error resolving UDP address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("error opening udp connection: %v", err)
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	logger("k8s-nameserver listening on: %v", addr)

	for {
		payloadBuff := make([]byte, 10000)
		metadataBuff := make([]byte, 512)
		_, _, _, addr, err := conn.ReadMsgUDP(payloadBuff, metadataBuff)
		if err != nil {
			logger(fmt.Sprintf("error reading UDP message: %v", err))
			continue
		}
		dnsAnswer, err := ns.query(ctx, payloadBuff, addr.AddrPort())
		if err != nil {
			// reply with the dnsAnswer anyway- in some cases
			// resolver might have written some useful data there
		}
		conn.WriteToUDP(dnsAnswer, addr)
	}
}

type nameserver struct {
	configReader  configReaderFunc
	configWatcher <-chan string
	res           *resolver.Resolver
	logger        logger.Logf
}

type configReaderFunc func() ([]byte, error)

// run ensures that resolver configuration is up to date with regards to its
// source. will update config once before returning and keep monitoring it in a
// thread.
func (n *nameserver) run(ctx context.Context, cancelF context.CancelFunc) error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				n.logger("nameserver exiting")
				return
			case <-n.configWatcher:
				// TODO (irbekrm): this does not actually log anything
				n.logger("attempting to update resolver config...")
				if err := n.updateResolverConfig(); err != nil {
					n.logger("error updating resolver config: %w", err)
					cancelF()
				}
				// TODO (irbekrm): this does not actually log anything
				n.logger("successfully updated resolver config")
			}
		}
	}()
	if err := n.updateResolverConfig(); err != nil {
		return fmt.Errorf("error updating resolver config: %w", err)
	}
	n.logger("successfully updated resolver config")
	return nil
}

func (n *nameserver) query(ctx context.Context, payload []byte, add netip.AddrPort) ([]byte, error) {
	return n.res.Query(ctx, payload, "udp", add)
}

func (n *nameserver) updateResolverConfig() error {
	dnsCfgBytes, err := n.configReader()
	if err != nil {
		n.logger("error reading config: %v", err)
		return err
	}
	if dnsCfgBytes == nil || len(dnsCfgBytes) < 1 {
		n.logger("no DNS config provided")
		return nil
	}
	dnsCfg := &operatorutils.TSHosts{}
	err = json.Unmarshal(dnsCfgBytes, dnsCfg)
	if err != nil {
		n.logger("error unmarshaling json: %v", err)
		return err
	}
	if dnsCfg.Hosts == nil || len(dnsCfg.Hosts) < 1 {
		n.logger("no host records found")
	}
	c := resolver.Config{}

	// Ensure that queries for ts.net subdomains are never forwarded to
	// external resolvers
	c.LocalDomains = []dnsname.FQDN{"ts.net", "ts.net."}

	c.Hosts = make(map[dnsname.FQDN][]netip.Addr)
	for fqdn, ips := range dnsCfg.Hosts {
		fqdn, err := dnsname.ToFQDN(fqdn)
		if err != nil {
			n.logger("invalid DNS config: cannot convert %s to FQDN: %v", fqdn, err)
			return err
		}
		for _, ip := range ips {
			ip, err := netip.ParseAddr(ip)
			if err != nil {
				n.logger("invalid DNS config: cannot convert %s to netip.Addr: %v", ip, err)
				return err
			}
			c.Hosts[fqdn] = []netip.Addr{ip}
		}
	}
	// resolver will lock config so this is safe
	n.res.SetConfig(c)

	// TODO (irbekrm): get a diff and log when/if resolver config is actually being changed

	return nil
}
