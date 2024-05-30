// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// k8s-nameserver is a simple nameserver implementation meant to be used with
// k8s-operator to allow to resolve magicDNS names associated with tailnet
// proxies in cluster.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/net/dns/dnsmessage"
	"k8s.io/utils/pointer"
	"tailscale.com/ipn/store/kubestore"
	operatorutils "tailscale.com/k8s-operator"
	"tailscale.com/tsnet"
	"tailscale.com/types/nettype"
	"tailscale.com/util/dnsname"
)

const (
	// addr is the the address that the UDP and TCP listeners will listen on.
	addr = ":53"

	defaultDNSConfigDir    = "/config"
	kubeletMountedConfigLn = "..data"
)

// nameserver is a simple nameserver that responds to DNS queries for A records
// for ts.net domain names over UDP or TCP. It serves DNS responses from
// in-memory IPv4 host records. It is intended to be deployed on Kubernetes with
// a ConfigMap mounted at /config that should contain the host records. It
// dynamically reconfigures its in-memory mappings as the contents of the
// mounted ConfigMap changes.
type nameserver struct {
	// configReader returns the latest desired configuration (host records)
	// for the nameserver. By default it gets set to a reader that reads
	// from a Kubernetes ConfigMap mounted at /config, but this can be
	// overridden in tests.
	configReader configReaderFunc
	// configWatcher is a watcher that returns an event when the desired
	// configuration has changed and the nameserver should update the
	// in-memory records.
	configWatcher <-chan string
	proxies       []string

	mu         sync.Mutex // protects following
	serviceIPs map[dnsname.FQDN][]netip.Addr
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// state always in 'dnsrecords' Secret
	kubeStateStore, err := kubestore.New(log.Printf, *pointer.StringPtr("nameserver-state"))
	if err != nil {
		log.Fatalf("error starting kube state store: %v", err)
	}
	ts := tsnet.Server{
		Logf:     log.Printf,
		Hostname: "dns-server",
		Dir:      "/tmp",
		Store:    kubeStateStore,
	}
	if _, err := ts.Up(ctx); err != nil {
		log.Fatalf("ts.Up: %v", err)
	}
	defer ts.Close()

	// hardcoded for this prototype
	proxies := []string{"proxies-0", "proxies-1", "proxies-2", "proxies-3"}
	c := ensureWatcherForServiceConfigMaps(ctx, proxies)

	ns := &nameserver{
		configReader:  configMapConfigReader,
		configWatcher: c,
		proxies:       proxies,
	}

	ns.runServiceRecordsReconciler(ctx)

	var wg sync.WaitGroup

	udpListener, err := ts.Listen("udp", addr)
	if err != nil {
		log.Fatalf("failed listening on udp port :53")
	}
	defer udpListener.Close()
	wg.Add(1)
	go func() {
		ns.serveDNS(udpListener)
	}()
	log.Printf("Listening for DNS on UDP %s", udpListener.Addr())

	tcpListener, err := ts.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed listening on tcp port :53")
	}
	defer tcpListener.Close()
	wg.Add(1)
	go func() {
		ns.serveDNS(tcpListener)
	}()
	log.Printf("Listening for DNS on TCP %s", tcpListener.Addr())
	wg.Wait()
}

func (c *nameserver) serveDNS(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("serveDNS accept: %v", err)
			return
		}
		go c.handleServiceName(conn.(nettype.ConnPacketConn))
	}
}

var tsMBox = dnsmessage.MustNewName("support.tailscale.com.")

func (ns *nameserver) handleServiceName(conn nettype.ConnPacketConn) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("handeServiceName: read failed: %v\n ", err)
		return
	}
	var msg dnsmessage.Message
	err = msg.Unpack(buf[:n])
	if err != nil {
		log.Printf("handleServiceName: dnsmessage unpack failed: %v\n ", err)
		return
	}
	resp, err := ns.generateDNSResponse(&msg)
	if err != nil {
		log.Printf("handleServiceName: DNS response generation failed: %v\n", err)
		return
	}
	if len(resp) == 0 {
		return
	}
	_, err = conn.Write(resp)
	if err != nil {
		log.Printf("handleServiceName: write failed: %v\n", err)
	}
}

func (ns *nameserver) generateDNSResponse(req *dnsmessage.Message) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil,
		dnsmessage.Header{
			ID:            req.Header.ID,
			Response:      true,
			Authoritative: true,
		})
	b.EnableCompression()

	if len(req.Questions) == 0 {
		return b.Finish()
	}
	q := req.Questions[0]
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}

	var err error
	switch q.Type {
	case dnsmessage.TypeA:
		log.Printf("query for an A record")
		var fqdn dnsname.FQDN
		fqdn, err = dnsname.ToFQDN(q.Name.String())
		if err != nil {
			log.Print("format error")
			return nil, err
		}

		log.Print("locking service IPs")
		ns.mu.Lock()
		ips := ns.serviceIPs[fqdn]
		ns.mu.Unlock()
		log.Print("unlocking service IPs")

		if ips == nil || len(ips) == 0 {
			log.Printf("nameserver has no IPs for %s", fqdn)
			// NXDOMAIN?
			return nil, fmt.Errorf("no address found for %s", fqdn)
		}

		// return a random IP
		i := rand.Intn(len(ips))
		ip := ips[i]
		log.Printf("produced IP address %s", ip)
		err = b.AResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 5},
			dnsmessage.AResource{A: ip.As4()},
		)
	case dnsmessage.TypeSOA:
		err = b.SOAResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.SOAResource{NS: q.Name, MBox: tsMBox, Serial: 2023030600,
				Refresh: 120, Retry: 120, Expire: 120, MinTTL: 60},
		)
	case dnsmessage.TypeNS:
		err = b.NSResource(
			dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: 120},
			dnsmessage.NSResource{NS: tsMBox},
		)
	}
	if err != nil {
		return nil, err
	}
	return b.Finish()
}

func (n *nameserver) runServiceRecordsReconciler(ctx context.Context) {
	log.Print("updating nameserver's records from the provided services configuration...")
	if err := n.resetServiceRecords(); err != nil { // ensure records are up to date before the nameserver starts
		log.Fatalf("error setting nameserver's records: %v", err)
	}
	log.Print("nameserver's records were updated")
	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Printf("context cancelled, exiting records reconciler")
				return
			case <-n.configWatcher:
				log.Print("configuration update detected, resetting records")
				if err := n.resetServiceRecords(); err != nil {
					log.Fatalf("error resetting records: %v", err)
				}
				log.Print("nameserver records were reset")
			}
		}
	}()
}

func (n *nameserver) resetServiceRecords() error {
	ip4 := make(map[dnsname.FQDN][]netip.Addr)
	for _, proxy := range n.proxies {
		dnsCfgBytes, err := proxyConfigReader(proxy)
		if err != nil {
			log.Printf("error reading proxy config for %s configuration: %v", proxy, err)
			return err
		}
		if dnsCfgBytes == nil || len(dnsCfgBytes) == 0 {
			log.Printf("configuration for proxy %s is empty; do nothing", proxy)
			continue
		}
		proxyCfg := &operatorutils.ProxyConfig{}

		err = json.Unmarshal(dnsCfgBytes, proxyCfg)
		if err != nil {
			return fmt.Errorf("error unmarshalling proxy config: %v\n", err)
		}
		for _, svc := range proxyCfg.Services {
			log.Printf("adding record for Service %s", svc.FQDN)
			ip4[dnsname.FQDN(svc.FQDN)] = append(ip4[dnsname.FQDN(svc.FQDN)], svc.V4ServiceIPs...)
		}
	}
	log.Printf("after update DNS records are %#+v", ip4)
	n.mu.Lock()
	n.serviceIPs = ip4
	n.mu.Unlock()
	return nil
}

// ensureWatcherForServiceConfigMaps sets up a new file watcher for the
// ConfigMaps containing records for Services served by the operator proxies.
func ensureWatcherForServiceConfigMaps(ctx context.Context, proxies []string) chan string {
	c := make(chan string)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("error creating a new watcher for the services ConfigMap: %v", err)
	}
	go func() {
		defer watcher.Close()
		log.Printf("starting file watch for %s", "/services/")
		for {
			select {
			case <-ctx.Done():
				log.Print("context cancelled, exiting ConfigMap watcher")
				return
			case event, ok := <-watcher.Events:
				if !ok {
					log.Fatal("watcher finished; exiting")
				}
				// kubelet mounts configmap to a Pod using a series of symlinks, one of
				// which is <mount-dir>/..data that Kubernetes recommends consumers to
				// use if they need to monitor changes
				// https://github.com/kubernetes/kubernetes/blob/v1.28.1/pkg/volume/util/atomic_writer.go#L39-L61
				if strings.HasSuffix(event.Name, kubeletMountedConfigLn) {
					msg := fmt.Sprintf("ConfigMap update received: %s", event)
					log.Print(msg)
					n := path.Dir(event.Name)
					base := path.Base(n)
					c <- base // which proxy's ConfigMap should be updated
				}
			case err, ok := <-watcher.Errors:
				if err != nil {
					log.Fatalf("[unexpected] error watching services configuration: %v", err)
				}
				if !ok {
					log.Fatalf("[unexpected] errors watcher exited")
				}
			}
		}
	}()
	for _, name := range proxies {
		if err = watcher.Add(filepath.Join("/services", name)); err != nil {
			log.Fatalf("failed setting up a watcher for config for %s : %v", name, err)
		}
	}
	return c
}

// configReaderFunc is a function that returns the desired nameserver configuration.
type configReaderFunc func() ([]byte, error)

// configMapConfigReader reads the desired nameserver configuration from a
// records.json file in a ConfigMap mounted at /config.
var configMapConfigReader configReaderFunc = func() ([]byte, error) {
	if contents, err := os.ReadFile(filepath.Join(defaultDNSConfigDir, operatorutils.DNSRecordsCMKey)); err == nil {
		return contents, nil
	} else if os.IsNotExist(err) {
		return nil, nil
	} else {
		return nil, err
	}
}

func proxyConfigReader(proxy string) ([]byte, error) {
	path := filepath.Join("/services", proxy, "proxyConfig")
	if bs, err := os.ReadFile(path); err == nil {
		return bs, err
	} else if os.IsNotExist(err) {
		log.Printf("path %s does not exist", path)
		return nil, nil
	} else {
		return nil, fmt.Errorf("error reading %s: %w", path, err)
	}
}
