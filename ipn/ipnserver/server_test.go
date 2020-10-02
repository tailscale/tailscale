// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnserver_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/safesocket"
	"tailscale.com/wgengine"
)

func TestRunMultipleAccepts(t *testing.T) {
	t.Skipf("TODO(bradfitz): finish this test, once other fires are out")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	td := t.TempDir()
	socketPath := filepath.Join(td, "tailscale.sock")

	logf := func(format string, args ...interface{}) {
		format = strings.TrimRight(format, "\n")
		println(fmt.Sprintf(format, args...))
		t.Logf(format, args...)
	}

	connect := func() {
		for i := 1; i <= 2; i++ {
			logf("connect %d ...", i)
			c, err := safesocket.Connect(socketPath, 0)
			if err != nil {
				t.Fatalf("safesocket.Connect: %v\n", err)
			}
			clientToServer := func(b []byte) {
				ipn.WriteMsg(c, b)
			}
			bc := ipn.NewBackendClient(logf, clientToServer)
			prefs := ipn.NewPrefs()
			bc.SetPrefs(prefs)
			c.Close()
		}
	}

	logTriggerTestf := func(format string, args ...interface{}) {
		logf(format, args...)
		if strings.HasPrefix(format, "Listening on ") {
			connect()
		}
	}

	eng, err := wgengine.NewFakeUserspaceEngine(logf, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	opts := ipnserver.Options{
		SocketPath: socketPath,
	}
	t.Logf("pre-Run")
	err = ipnserver.Run(ctx, logTriggerTestf, "dummy_logid", ipnserver.FixedEngine(eng), opts)
	t.Logf("ipnserver.Run = %v", err)
}
