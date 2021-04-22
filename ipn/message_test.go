// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"bytes"
	"context"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

func TestReadWrite(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	buf := bytes.Buffer{}
	err := WriteMsg(&buf, []byte("Test string1"))
	if err != nil {
		t.Fatalf("write1: %v\n", err)
	}
	err = WriteMsg(&buf, []byte(""))
	if err != nil {
		t.Fatalf("write2: %v\n", err)
	}
	err = WriteMsg(&buf, []byte("Test3"))
	if err != nil {
		t.Fatalf("write3: %v\n", err)
	}

	b, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("read1 error: %v", err)
	}
	if want, got := "Test string1", string(b); want != got {
		t.Fatalf("read1: %#v != %#v\n", want, got)
	}
	b, err = ReadMsg(&buf)
	if err != nil {
		t.Fatalf("read2 error: %v", err)
	}
	if want, got := "", string(b); want != got {
		t.Fatalf("read2: %#v != %#v\n", want, got)
	}
	b, err = ReadMsg(&buf)
	if err != nil {
		t.Fatalf("read3 error: %v", err)
	}
	if want, got := "Test3", string(b); want != got {
		t.Fatalf("read3: %#v != %#v\n", want, got)
	}

	b, err = ReadMsg(&buf)
	if err == nil {
		t.Fatalf("read4: expected error, got %#v\n", b)
	}
}

func TestClientServer(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	b := &FakeBackend{}
	var bs *BackendServer
	var bc *BackendClient
	serverToClientCh := make(chan []byte, 16)
	defer close(serverToClientCh)
	go func() {
		for b := range serverToClientCh {
			bc.GotNotifyMsg(b)
		}
	}()
	serverToClient := func(b []byte) {
		serverToClientCh <- append([]byte{}, b...)
	}
	clientToServer := func(b []byte) {
		bs.GotCommandMsg(context.TODO(), b)
	}
	slogf := func(fmt string, args ...interface{}) {
		t.Logf("s: "+fmt, args...)
	}
	clogf := func(fmt string, args ...interface{}) {
		t.Logf("c: "+fmt, args...)
	}
	bs = NewBackendServer(slogf, b, serverToClient)
	// Verify that this doesn't break bs's callback:
	NewBackendServer(slogf, b, nil)
	bc = NewBackendClient(clogf, clientToServer)

	ch := make(chan Notify, 256)
	notify := func(n Notify) { ch <- n }
	h, err := NewHandle(bc, clogf, notify, Options{
		Prefs: &Prefs{
			ControlURL: "http://example.com/fake",
		},
	})
	if err != nil {
		t.Fatalf("NewHandle error: %v\n", err)
	}

	notes := Notify{}
	nn := []Notify{}
	processNote := func(n Notify) {
		nn = append(nn, n)
		if n.State != nil {
			t.Logf("state change: %v", *n.State)
			notes.State = n.State
		}
		if n.Prefs != nil {
			notes.Prefs = n.Prefs
		}
		if n.NetMap != nil {
			notes.NetMap = n.NetMap
		}
		if n.Engine != nil {
			notes.Engine = n.Engine
		}
		if n.BrowseToURL != nil {
			notes.BrowseToURL = n.BrowseToURL
		}
	}
	notesState := func() State {
		if notes.State != nil {
			return *notes.State
		}
		return NoState
	}

	flushUntil := func(wantFlush State) {
		t.Helper()
		timer := time.NewTimer(1 * time.Second)
	loop:
		for {
			select {
			case n := <-ch:
				processNote(n)
				if notesState() == wantFlush {
					break loop
				}
			case <-timer.C:
				t.Fatalf("timeout waiting for state %v, got %v", wantFlush, notes.State)
			}
		}
		timer.Stop()
	loop2:
		for {
			select {
			case n := <-ch:
				processNote(n)
			default:
				break loop2
			}
		}
		if got, want := h.State(), notesState(); got != want {
			t.Errorf("h.State()=%v, notes.State=%v (on flush until %v)\n", got, want, wantFlush)
		}
	}

	flushUntil(NeedsLogin)

	h.StartLoginInteractive()
	flushUntil(Running)
	if notes.NetMap == nil && h.NetMap() != nil {
		t.Errorf("notes.NetMap == nil while h.NetMap != nil\nnotes:\n%v", nn)
	}

	h.UpdatePrefs(func(p *Prefs) {
		p.WantRunning = false
	})
	flushUntil(Stopped)

	h.Logout()
	flushUntil(NeedsLogin)

	h.Login(&tailcfg.Oauth2Token{
		AccessToken: "google_id_token",
		TokenType:   GoogleIDTokenType,
	})
	flushUntil(Running)
}
