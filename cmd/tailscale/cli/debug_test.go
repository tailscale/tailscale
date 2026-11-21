// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"context"
	"io"
	"runtime"
	"testing"

	"tailscale.com/paths"
	"tailscale.com/tstest"
)

func TestLocalCredsSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("tests the Linux Unix socket output")
	}
	for _, socket := range []string{paths.DefaultTailscaledSocket(), "local/foo.sock", ""} {
		t.Run(socket, func(t *testing.T) {
			var out bytes.Buffer
			tstest.Replace[io.Writer](t, &Stdout, &out)
			tstest.Replace(t, &localClient.Socket, paths.DefaultTailscaledSocket())
			tstest.Replace(t, &localClient.UseSocketOnly, false)
			if err := newRootCmd().ParseAndRun(context.Background(), []string{"--socket", socket, "debug", "local-creds"}); err != nil {
				t.Fatal(err)
			}
			want := socket
			if want == "" {
				want = paths.DefaultTailscaledSocket()
			}
			want = "curl --unix-socket " + want + " http://local-tailscaled.sock/localapi/v0/status\n"
			if got := out.String(); got != want {
				t.Errorf("output = %q; want %q", got, want)
			}
		})
	}
}
