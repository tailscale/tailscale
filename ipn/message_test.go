// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipn

import (
	"bytes"
	"testing"

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

func TestNilBackend(t *testing.T) {
	var called *Notify
	bs := NewBackendServer(t.Logf, nil, func(n Notify) {
		called = &n
	})
	bs.SendErrorMessage("Danger, Will Robinson!")
	if called == nil {
		t.Errorf("expect callback to be called, wasn't")
	}
	if called.ErrMessage == nil || *called.ErrMessage != "Danger, Will Robinson!" {
		t.Errorf("callback got wrong error: %v", called.ErrMessage)
	}
}
