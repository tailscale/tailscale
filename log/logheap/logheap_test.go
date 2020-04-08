// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logheap

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestLogHeap(t *testing.T) {
	var buf bytes.Buffer
	if err := logHeap(&buf); err != nil {
		t.Fatal(err)
	}
	t.Logf("Got line: %s", buf.Bytes())

	var ll logLine
	if err := json.Unmarshal(buf.Bytes(), &ll); err != nil {
		t.Fatal(err)
	}

	zr, err := gzip.NewReader(bytes.NewReader(ll.Pprof.Heap))
	if err != nil {
		t.Fatal(err)
	}
	rawProto, err := ioutil.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	// Just sanity check it. Too lazy to properly decode the protobuf. But see that
	// it contains an expected sample name.
	if !bytes.Contains(rawProto, []byte("alloc_objects")) {
		t.Errorf("raw proto didn't contain `alloc_objects`: %q", rawProto)
	}
}
