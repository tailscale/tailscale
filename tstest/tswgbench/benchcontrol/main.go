// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The benchcontrol command runs a self-contained Tailscale control plane
// for benchmarking real tailscaled processes (as tstest/tswgbench's
// TestLeanSubnetRouter does with TSWG_SUBNET_TAILSCALED): a test control
// server (tstest/integration/testcontrol), with DERP and STUN servers on
// the same IP, that authorizes every node and enables every subnet route
// a node advertises, as a tailnet with auto-approvers would.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"slices"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

var flagAddr = flag.String("addr", "127.0.0.1:9911", "IP:port to serve control on; the DERP and STUN servers also run on that IP")

func main() {
	flag.Parse()
	host, _, err := net.SplitHostPort(*flagAddr)
	if err != nil {
		log.Fatalf("invalid --addr %q: %v", *flagAddr, err)
	}
	var t fakeTB
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, host)
	control := &testcontrol.Server{
		DERPMap:          derpMap,
		ExplicitBaseURL:  "http://" + *flagAddr,
		AllNodesSameUser: true,
	}
	go approveRoutes(control)
	log.Printf("listening on %s", *flagAddr)
	log.Fatal(http.ListenAndServe(*flagAddr, control))
}

// approveRoutes enables, every second, the subnet routes each node
// advertises (testcontrol otherwise ignores them).
func approveRoutes(control *testcontrol.Server) {
	approved := map[key.NodePublic]string{}
	for range time.Tick(time.Second) {
		for _, n := range control.AllNodes() {
			if !n.Hostinfo.Valid() {
				continue
			}
			routes := n.Hostinfo.RoutableIPs().AsSlice()
			s := ""
			for _, r := range routes {
				s += r.String() + " "
			}
			if approved[n.Key] == s {
				continue
			}
			approved[n.Key] = s
			log.Printf("enabling routes of %s (%s): %v", n.Name, n.Key.ShortString(), routes)
			control.SetSubnetRoutes(n.Key, slices.Clone(routes))
		}
	}
}

// fakeTB is enough of a testing.TB for integration.RunDERPAndSTUN.
type fakeTB struct {
	*testing.T
}

func (fakeTB) Cleanup(func())               {}
func (fakeTB) Error(args ...any)            { log.Fatal(args...) }
func (fakeTB) Errorf(f string, args ...any) { log.Fatalf(f, args...) }
func (fakeTB) Fail()                        { log.Fatal("failed") }
func (fakeTB) FailNow()                     { log.Fatal("failed") }
func (fakeTB) Failed() bool                 { return false }
func (fakeTB) Fatal(args ...any)            { log.Fatal(args...) }
func (fakeTB) Fatalf(f string, args ...any) { log.Fatalf(f, args...) }
func (fakeTB) Helper()                      {}
func (fakeTB) Log(args ...any)              { log.Print(args...) }
func (fakeTB) Logf(f string, args ...any)   { log.Printf(f, args...) }
func (fakeTB) Name() string                 { return "benchcontrol" }
func (fakeTB) Setenv(key, value string)     { panic("not supported") }
func (fakeTB) Skip(args ...any)             { log.Fatal("skip") }
func (fakeTB) SkipNow()                     { log.Fatal("skip") }
func (fakeTB) Skipf(f string, args ...any)  { log.Fatal("skip") }
func (fakeTB) Skipped() bool                { return false }
func (fakeTB) TempDir() string              { panic("not supported") }
