// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tailscaled program is the Tailscale daemon. It's configured
// and controlled via either the tailscale CLI program or GUIs.
package main // import "tailscale.com/cmd/tailscaled"

import "tailscale.com/cmd/tailscaled/tailscaled"

// Don't add any new imports or code to this file. The real
// code is in tailscale.com/cmd/tailscale/tailscaled as a package
// so things can depend on it for dependency reasons.
// (Go programs can't import package main so we split the real code
// off where we could have a dummy package empty import it)

func main() {
	tailscaled.Main()
}
