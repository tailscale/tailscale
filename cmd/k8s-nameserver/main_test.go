// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"log"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsdial"
)

func TestNameserver(t *testing.T) {

	// Setup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hostConfig := "{\"foo.bar.ts.net.\": \"10.20.30.40\"}"

	var mockConfigReader configReaderFunc = func() ([]byte, error) {
		return []byte(hostConfig), nil
	}
	configWatcher := make(chan string)
	logger := log.Printf
	res := resolver.New(logger, nil, nil, &tsdial.Dialer{Logf: logger})

	ns := &nameserver{
		configReader:  mockConfigReader,
		configWatcher: configWatcher,
		logger:        logger,
		res:           *res,
	}
	assert.NoError(t, ns.run(ctx, cancel), "error running nameserver")

	// Test that nameserver can resolve a DNS name from provided hosts config

	wantedResponse := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 0x0,
			Response:           true,
			OpCode:             0,
			Authoritative:      true,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			AuthenticData:      false,
			CheckingDisabled:   false,
			RCode:              dnsmessage.RCodeSuccess,
		},

		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:   dnsmessage.MustNewName("foo.bar.ts.net."),
				Type:   dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				TTL:    0x258,
				Length: 0x4,
			},
			Body: &dnsmessage.AResource{
				A: [4]byte{10, 20, 30, 40},
			},
		}},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("foo.bar.ts.net."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Additionals: []dnsmessage.Resource{},
		Authorities: []dnsmessage.Resource{},
	}
	testQuery := dnsmessage.Message{
		Header: dnsmessage.Header{Authoritative: true},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("foo.bar.ts.net."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	testAddr, err := netip.ParseAddrPort("10.40.30.20:0")
	assert.NoError(t, err, "error parsing IP address")
	packedTestQuery, err := testQuery.Pack()
	assert.NoError(t, err, "error parsing DNS query")
	answer, err := ns.query(ctx, packedTestQuery, testAddr)
	assert.NoError(t, err, "error querying nameserver")
	var gotResponse dnsmessage.Message
	assert.NoError(t, gotResponse.Unpack(answer), "error unpacking DNS answer")
	assert.Equal(t, gotResponse, wantedResponse)

	// Test that nameserver's hosts config gets dynamically updated

	newHostConfig := "{\"baz.bar.ts.net.\": \"10.40.30.20\"}"
	var newMockConfigReader configReaderFunc = func() ([]byte, error) {
		return []byte(newHostConfig), nil
	}
	ns.configReader = newMockConfigReader

	timeout := 3 * time.Second
	timer := time.NewTimer(timeout)
	select {
	case <-timer.C:
		t.Fatalf("nameserver failed to process config update within %v", timeout)
	case configWatcher <- "config update":
	}
	wantedResponse = dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 0x0,
			Response:           true,
			OpCode:             0,
			Authoritative:      true,
			Truncated:          false,
			RecursionDesired:   false,
			RecursionAvailable: false,
			AuthenticData:      false,
			CheckingDisabled:   false,
			RCode:              dnsmessage.RCodeSuccess,
		},

		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:   dnsmessage.MustNewName("baz.bar.ts.net."),
				Type:   dnsmessage.TypeA,
				Class:  dnsmessage.ClassINET,
				TTL:    0x258,
				Length: 0x4,
			},
			Body: &dnsmessage.AResource{
				A: [4]byte{10, 40, 30, 20},
			},
		}},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("baz.bar.ts.net."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
		Additionals: []dnsmessage.Resource{},
		Authorities: []dnsmessage.Resource{},
	}
	testQuery = dnsmessage.Message{
		Header: dnsmessage.Header{Authoritative: true},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName("baz.bar.ts.net."),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}
	packedTestQuery, err = testQuery.Pack()
	assert.NoError(t, err, "error parsing DNS query")

	// retry a couple times as the nameserver will have eventually processed
	// the update
	assert.Eventually(t, func() bool {
		answer, err = ns.query(ctx, packedTestQuery, testAddr)
		assert.NoError(t, err, "error querying nameserver")
		gotResponse = dnsmessage.Message{}

		assert.NoError(t, gotResponse.Unpack(answer), "error unpacking DNS answer")
		if reflect.DeepEqual(wantedResponse, gotResponse) {
			return true
		}
		return false
	}, time.Second*5, time.Second)
}
