// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/fsnotify/fsnotify"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsdial"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

const (
	defaultDNSConfigDir = "/tmp/dns"
	defaultDNSFile      = "dnsconfig.json"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := log.Printf

	res := resolver.New(logger, nil, nil, &tsdial.Dialer{Logf: logger})

	var configReader configReaderFunc = func() ([]byte, error) {
		return os.ReadFile(fmt.Sprintf("%s/%s", defaultDNSConfigDir, defaultDNSFile))
	}

	c := make(chan string)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer watcher.Close()
	go func() {
		logger("starting file watch for %s", defaultDNSConfigDir)
		for {
			select {
			// TODO (irbekrm): it appears like we get a whole bunch
			// of different events (except for the WRITE one that
			// fsnotify recommends watching) on an update. They also
			// come with a delay. Figure out if we can add a
			// reliable filter to only trigger update once and
			// whether we can speed this up a bit.
			case event, ok := <-watcher.Events:
				if !ok {
					logger("watcher finished")
					cancel()
					return
				}
				// it seems like an update to the file has a
				// potential to produce different types of
				// events, but only one per configmap update.
				// fsnotify docs suggest to only react to Write
				// events, however we should be safe to react to
				// other events too as we run in a container and
				// there shouldn't be random changes to file
				// metadata
				msg := fmt.Sprintf("new file event: %v", event)
				c <- msg

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
	err = watcher.Add(defaultDNSConfigDir)
	if err != nil {
		panic(err)
	}

	ns := &nameserver{
		configReader:  configReader,
		configWatcher: c,
		logger:        logger,
		res:           *res, // TODO (irbekrm): linter error here
	}

	if err := ns.run(ctx, cancel); err != nil {
		panic(fmt.Errorf("error running nameserver: %w", err))
	}

	addr, err := net.ResolveUDPAddr("udp", ":1053")
	if err != nil {
		panic("error resolving UDP address")
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(fmt.Sprintf("error opening udp connection: %v", err))
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
			panic(err)
		}
		logger("query is %#+v", string(payloadBuff))
		dnsAnswer, err := ns.query(ctx, payloadBuff, addr.AddrPort())
		if err != nil {
			logger("error doing DNS query: %v", err)
			// reply with the dnsAnswer anyway- in some cases
			// resolver might have written some useful data there
		}
		conn.WriteToUDP(dnsAnswer, addr)
	}
}

type nameserver struct {
	configReader  configReaderFunc
	configWatcher <-chan string
	res           resolver.Resolver
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
				n.logger("attempting to update resolver config...")
				if err := n.updateResolverConfig(); err != nil {
					n.logger("error updating resolver config: %w", err)
					cancelF()
				}
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
	return n.res.Query(ctx, payload, add)
}

func (n *nameserver) updateResolverConfig() error {
	dnsCfgBytes, err := n.configReader()
	if err != nil {
		n.logger("error reading config: %v", err)
		return err
	}
	dnsCfgM := make(map[string]string)
	err = json.Unmarshal(dnsCfgBytes, &dnsCfgM)
	if err != nil {
		n.logger("error unmarshaling json: %v", err)
		return err
	}
	c := resolver.Config{}
	c.Hosts = make(map[dnsname.FQDN][]netip.Addr)
	for key, val := range dnsCfgM {
		fqdn, err := dnsname.ToFQDN(key)
		if err != nil {
			n.logger("invalid DNS config: cannot convert %s to FQDN: %v", key, err)
			return err
		}
		ip, err := netip.ParseAddr(val)
		if err != nil {
			n.logger("invalid DNS config: cannot convert %s to netip.Addr: %v", val, err)
			return err
		}
		c.Hosts[fqdn] = []netip.Addr{ip}
	}
	// resolver will lock config so this is safe
	n.res.SetConfig(c)

	// TODO (irbekrm): get a diff and log when/if resolver config is actually being changed

	return nil
}
