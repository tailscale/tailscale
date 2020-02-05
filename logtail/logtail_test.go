// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package logtail

import (
	"context"
	"testing"
)

func TestFastShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	l := Log(Config{
		BaseURL: "http://localhost:1234",
	})
	l.Shutdown(ctx)
}
