// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package isoping

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

// Tests if our stddev calculation is within reason
// Must do some rounding to a certain significant digit
// Currently only need 6 digits for the testing.
func sigDigs(x float64, digs int) float64 {
	return math.Round(x*math.Pow10(digs)) / math.Pow10(digs)
}

// TestOnepass_stddev tests if the function receives the same answer as in
// the C implementation of this function.
func TestOnepass_stddev(t *testing.T) {
	t.Parallel()

	answer := sigDigs(onepass_stddev(12, 2, 3), 6)
	expected := 2.309401
	answer2 := sigDigs(onepass_stddev(12023232232, 212, 321), 6)
	expected2 := 6129.649279
	if answer != expected {
		t.Errorf("got %v, expected %v", answer, expected)
	}
	if answer2 != expected2 {
		t.Errorf("got %v, expected %v", answer2, expected2)
	}
}

// TestUstimeCast tests if casting was correct
// sanity check, probably will be removed for redundancy
func TestUstimeCast(t *testing.T) {
	t.Parallel()

	var num uint64 = 11471851221
	var expected uint32 = 2881916629
	if uint32(num) != expected {
		t.Errorf("expected %v, got : %v", expected, uint32(num))
	}
}

// TestValidInitialPacket will send a packet via UDP, and check if it matches
// The size and the Magic number field that needs to be equal.
// This mocks the initial packet sent in Isoping.
func TestValidInitialPacket(t *testing.T) {
	client := Isoping{IsServer: false}
	client.Start("[::]:4948")

	server := Isoping{IsServer: true}
	server.Start()
	defer server.Conn.Close()

	buf, err := client.generateInitialPacket()
	if err != nil {
		t.Error(err)
	}

	// Client writes to the server, server tries to read it.
	p := make([]byte, binary.Size(server.Rx))
	if _, err := client.Conn.Write(buf.Bytes()); err != nil {
		t.Error(err)
	}

	got, rxaddr, err := server.Conn.ReadFromUDP(p)
	if err != nil {
		t.Error(err)
	}

	buffer := bytes.NewBuffer(p)
	defer buffer.Reset()

	err = binary.Read(buffer, binary.BigEndian, &server.Rx)
	if err != nil {
		t.Error(err)
	}

	if got != binary.Size(server.Rx) || server.Rx.Magic != MAGIC {
		t.Error("received Rx is not proper")
	}

	t.Logf("Proper Packet received from %v\n", rxaddr)
}

func TestMainLoop(t *testing.T) {
	server := Isoping{}
	server.Start()
	defer server.Conn.Close()
	server.MainLoop()
}

func TestStartClient(t *testing.T) {
	client := Isoping{}
	client.Start("[::]:4948")
	defer client.Conn.Close()
	client.MainLoop()
}
