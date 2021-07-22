// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package isoping

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"strconv"
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
	tests := []struct {
		name  string
		input []int64
		out   float64
	}{

		{
			name:  "basic1",
			input: []int64{12, 2, 3},
			out:   2.309401,
		},
		{

			name:  "basic2",
			input: []int64{12023232232, 212, 321},
			out:   6129.649279,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttAns := sigDigs(onePassStddev(tt.input[0], tt.input[1], tt.input[2]), 6)
			if ttAns != tt.out {
				t.Errorf("got %v, expected %v", ttAns, tt.out)
			}
		})
	}

}

// TestUstimeCast tests if casting was correct
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
	t.Parallel()

	server := NewInstance()
	server.StartServer(":0")
	defer server.Conn.Close()
	serverPort := server.Conn.LocalAddr().(*net.UDPAddr).Port

	client := NewInstance()
	client.StartClient(":" + strconv.Itoa(serverPort))

	buf, err := client.generateInitialPacket()
	if err != nil {
		t.Error(err)
	}

	// Client writes to the server, server tries to read it.
	p := make([]byte, binary.Size(server.Rx))
	if _, err := client.Conn.Write(buf.Bytes()); err != nil {
		t.Error(err)
	}

	got, _, err := server.Conn.ReadFromUDP(p)
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
}
