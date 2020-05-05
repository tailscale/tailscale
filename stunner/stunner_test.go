// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stunner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"testing"
	"time"

	"gortc.io/stun"
)

func TestStun(t *testing.T) {
	conn1, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()
	conn2, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	stunServers := []string{
		conn1.LocalAddr().String(), conn2.LocalAddr().String(),
	}

	epCh := make(chan string, 16)

	localConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := &Stunner{
		Send:     localConn.WriteTo,
		Endpoint: func(server, ep string, d time.Duration) { epCh <- ep },
		Servers:  stunServers,
		MaxTries: map[string]int{
			stunServers[0]: 2,
			stunServers[1]: 2,
		},
	}

	stun1Err := make(chan error)
	go func() {
		stun1Err <- startSTUN(conn1, s.Receive)
	}()
	stun2Err := make(chan error)
	go func() {
		stun2Err <- startSTUNDrop1(conn2, s.Receive)
	}()

	errCh := make(chan error)
	go func() {
		errCh <- s.Run(context.Background())
	}()

	var eps []string
	select {
	case ep := <-epCh:
		eps = append(eps, ep)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("missing first endpoint response")
	}
	select {
	case ep := <-epCh:
		eps = append(eps, ep)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("missing second endpoint response")
	}
	sort.Strings(eps)
	if want := "1.2.3.4:1234"; eps[0] != want {
		t.Errorf("eps[0]=%q, want %q", eps[0], want)
	}
	if want := "4.5.6.7:4567"; eps[1] != want {
		t.Errorf("eps[1]=%q, want %q", eps[1], want)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func startSTUNDrop1(conn net.PacketConn, writeTo func([]byte, *net.UDPAddr)) error {
	if _, _, err := conn.ReadFrom(make([]byte, 1024)); err != nil {
		return fmt.Errorf("first stun server read failed: %v", err)
	}
	req := new(stun.Message)
	res := new(stun.Message)

	p := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(p)
	if err != nil {
		return err
	}
	p = p[:n]
	if !stun.IsMessage(p) {
		return errors.New("not a STUN message")
	}
	if _, err := req.Write(p); err != nil {
		return err
	}
	mappedAddr := &stun.XORMappedAddress{
		IP:   net.ParseIP("1.2.3.4"),
		Port: 1234,
	}
	software := stun.NewSoftware("endpointer")
	err = res.Build(req, stun.BindingSuccess, software, mappedAddr, stun.Fingerprint)
	if err != nil {
		return err
	}
	writeTo(res.Raw, addr.(*net.UDPAddr))
	return nil
}

func startSTUN(conn net.PacketConn, writeTo func([]byte, *net.UDPAddr)) error {
	req := new(stun.Message)
	res := new(stun.Message)

	p := make([]byte, 1024)
	n, addr, err := conn.ReadFrom(p)
	if err != nil {
		return err
	}
	p = p[:n]
	if !stun.IsMessage(p) {
		return errors.New("not a STUN message")
	}
	if _, err := req.Write(p); err != nil {
		return err
	}
	mappedAddr := &stun.XORMappedAddress{
		IP:   net.ParseIP("4.5.6.7"),
		Port: 4567,
	}
	software := stun.NewSoftware("endpointer")
	err = res.Build(req, stun.BindingSuccess, software, mappedAddr, stun.Fingerprint)
	if err != nil {
		return err
	}
	writeTo(res.Raw, addr.(*net.UDPAddr))
	return nil
}

// TODO: test retry timeout (overwrite the retryDurations)
// TODO: test canceling context passed to Run
// TODO: test sending bad packets
