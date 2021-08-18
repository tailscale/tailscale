// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Program testcontrol runs a simple test control server.
package main

import (
	"flag"
	"log"
	"net/http"
	"testing"

	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/logger"
)

var (
	flagNFake = flag.Int("nfake", 0, "number of fake nodes to add to network")
)

func main() {
	flag.Parse()

	var t fakeTB
	derpMap := integration.RunDERPAndSTUN(t, logger.Discard, "127.0.0.1")

	control := &testcontrol.Server{
		DERPMap:         derpMap,
		ExplicitBaseURL: "http://127.0.0.1:9911",
	}
	for i := 0; i < *flagNFake; i++ {
		control.AddFakeNode()
	}
	mux := http.NewServeMux()
	mux.Handle("/", control)
	addr := "127.0.0.1:9911"
	log.Printf("listening on %s", addr)
	err := http.ListenAndServe(addr, mux)
	log.Fatal(err)
}

type fakeTB struct {
	*testing.T
}

func (t fakeTB) Cleanup(_ func()) {}
func (t fakeTB) Error(args ...interface{}) {
	t.Fatal(args...)
}
func (t fakeTB) Errorf(format string, args ...interface{}) {
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
func (t fakeTB) Fatal(args ...interface{}) {
	log.Fatal(args...)
}
func (t fakeTB) Fatalf(format string, args ...interface{}) {
	log.Fatalf(format, args...)
}
func (t fakeTB) Helper() {}
func (t fakeTB) Log(args ...interface{}) {
	log.Print(args...)
}
func (t fakeTB) Logf(format string, args ...interface{}) {
	log.Printf(format, args...)
}
func (t fakeTB) Name() string {
	return "faketest"
}
func (t fakeTB) Setenv(key string, value string) {
	panic("not implemented")
}
func (t fakeTB) Skip(args ...interface{}) {
	t.Fatal("skipped")
}
func (t fakeTB) SkipNow() {
	t.Fatal("skipnow")
}
func (t fakeTB) Skipf(format string, args ...interface{}) {
	t.Logf(format, args...)
	t.Fatal("skipped")
}
func (t fakeTB) Skipped() bool {
	return false
}
func (t fakeTB) TempDir() string {
	panic("not implemented")
}
