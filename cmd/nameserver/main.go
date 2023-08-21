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
	defaultDNSConfigDir = "/config"
	defaultDNSFile      = "dns.json"
)

type nameserver struct {
	// config file holds FQDN to IP address mappings
	configFilePath string
	res            resolver.Resolver
	logf           logger.Logf
}

func main() {
	logger := log.Printf

	res := resolver.New(logger, nil, nil, &tsdial.Dialer{Logf: logger})

	ns := &nameserver{
		configFilePath: fmt.Sprintf("%s/%s", defaultDNSConfigDir, defaultDNSFile),
		logf:           logger,
		res:            *res, // TODO (irbekrm): linter error here
	}

	// ensure resolver config is updated before starting to serve
	err := ns.updateResolverConfig()
	if err != nil {
		logger("error updating resolver conf: %v", err)
		panic(err)
	}
	logger("Hosts configured")

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger("error starting file watcher: %v", err)
	}
	defer watcher.Close()
	go func() {
		logger("starting DNS file watch")
		for {
			logger("in DNS file watch...")
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
				logger("a %v event detected, updating DNS config...", event)
				// resolver locks config on updates so this is safe
				err := ns.updateResolverConfig()
				if err != nil {
					logger("error updating resolver conf: %v", err)
					continue
				}
				logger("Hosts updated")
			case err, ok := <-watcher.Errors:
				if !ok {
					logger("watcher finished")
					return
				}
				if err != nil {
					logger("error watching DNS config: %v", err)
				}
			}
		}

	}()
	err = watcher.Add(defaultDNSConfigDir)
	if err != nil {
		panic(fmt.Sprintf("error setting up DNS config watch: %v", err))
	}

	addr, err := net.ResolveUDPAddr("udp", ":53")
	if err != nil {
		panic("error resolving UDP address")
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(fmt.Sprintf("error opening udp connection: %v", err))
	}
	defer conn.Close()
	logger("nameserver listening on: %v", addr)

	for {
		payloadBuff := make([]byte, 10000)
		metadataBuff := make([]byte, 512)
		_, _, _, addr, err := conn.ReadMsgUDP(payloadBuff, metadataBuff)
		if err != nil {
			logger("error reading from UDP socket: %v", err)
			continue
		}
		dnsAnswer, err := ns.res.Query(context.Background(), payloadBuff, addr.AddrPort())
		if err != nil {
			logger("error doing DNS query: %v", err)
			// reply with the dnsAnswer anyway- in some cases
			// resolver might have written some useful data there
		}
		conn.WriteToUDP(dnsAnswer, addr)
	}
}

func (n *nameserver) updateResolverConfig() error {
	// file is mounted to pod from a configmap so it cannot not exist
	dnsCfgBytes, err := os.ReadFile(n.configFilePath)
	if err != nil {
		n.logf("error reading configFile: %v", err)
		return err
	}
	dnsCfgM := make(map[string]string)
	err = json.Unmarshal(dnsCfgBytes, &dnsCfgM)
	if err != nil {
		n.logf("error unmarshaling json: %v", err)
		return err
	}
	c := resolver.Config{}
	c.Hosts = make(map[dnsname.FQDN][]netip.Addr)
	// TODO (irbekrm): ensure that it handles the case of empty configmap
	for key, val := range dnsCfgM {
		fqdn, err := dnsname.ToFQDN(key)
		if err != nil {
			n.logf("invalid DNS config: cannot convert %s to FQDN: %v", key, err)
			return err
		}
		ip, err := netip.ParseAddr(val)
		if err != nil {
			n.logf("invalid DNS config: cannot convert %s to netip.Addr: %v", val, err)
			return err
		}
		c.Hosts[fqdn] = []netip.Addr{ip}
	}
	// resolver will lock config so this is safe
	n.res.SetConfig(c)

	// TODO (irbekrm): get a diff and log when/if resolver config is actually being changed

	return nil
}
