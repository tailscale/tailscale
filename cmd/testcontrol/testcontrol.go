// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Program testcontrol runs a simple test control server.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

var (
	flagNFake     = flag.Int("nfake", 0, "number of fake nodes to add to network")
	flagAddr      = flag.String("addr", "127.0.0.1:9911", "IP:port to listen on; the DERP and STUN servers also run on that IP")
	flagSSHPolicy = flag.String("ssh-policy", "", "optional path to a JSON (or HuJSON) file holding a tailcfg.SSHPolicy to send to all nodes; it also grants them the SSH capability")
)

func main() {
	flag.Parse()

	host, _, err := net.SplitHostPort(*flagAddr)
	if err != nil {
		log.Fatalf("invalid --addr %q: %v", *flagAddr, err)
	}

	var t fakeTB
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, host)

	control := &testcontrol.Server{
		DERPMap:         derpMap,
		ExplicitBaseURL: "http://" + *flagAddr,
	}
	if *flagSSHPolicy != "" {
		pol, err := loadSSHPolicy(*flagSSHPolicy)
		if err != nil {
			log.Fatalf("loading --ssh-policy: %v", err)
		}
		control.SSHPolicy = pol
	}
	for range *flagNFake {
		control.AddFakeNode()
	}
	mux := http.NewServeMux()
	mux.Handle("/", control)
	log.Printf("listening on %s", *flagAddr)
	err = http.ListenAndServe(*flagAddr, mux)
	log.Fatal(err)
}

func loadSSHPolicy(path string) (*tailcfg.SSHPolicy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err = hujson.Standardize(b)
	if err != nil {
		return nil, err
	}
	pol := new(tailcfg.SSHPolicy)
	if err := json.Unmarshal(b, pol); err != nil {
		return nil, err
	}
	return pol, nil
}

type fakeTB struct {
	*testing.T
}

func (t fakeTB) Cleanup(_ func()) {}
func (t fakeTB) Error(args ...any) {
	t.Fatal(args...)
}
func (t fakeTB) Errorf(format string, args ...any) {
	t.Fatalf(format, args...)
}
func (t fakeTB) Fail() {
	t.Fatal("failed")
}
func (t fakeTB) FailNow() {
	t.Fatal("failed")
}
func (t fakeTB) Failed() bool {
	return false
}
func (t fakeTB) Fatal(args ...any) {
	log.Fatal(args...)
}
func (t fakeTB) Fatalf(format string, args ...any) {
	log.Fatalf(format, args...)
}
func (t fakeTB) Helper() {}
func (t fakeTB) Log(args ...any) {
	log.Print(args...)
}
func (t fakeTB) Logf(format string, args ...any) {
	log.Printf(format, args...)
}
func (t fakeTB) Name() string {
	return "faketest"
}
func (t fakeTB) Setenv(key string, value string) {
	panic("not implemented")
}
func (t fakeTB) Skip(args ...any) {
	t.Fatal("skipped")
}
func (t fakeTB) SkipNow() {
	t.Fatal("skipnow")
}
func (t fakeTB) Skipf(format string, args ...any) {
	t.Logf(format, args...)
	t.Fatal("skipped")
}
func (t fakeTB) Skipped() bool {
	return false
}
func (t fakeTB) TempDir() string {
	panic("not implemented")
}
