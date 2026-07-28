// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_captiveportal

package cli

// Import the netcheck captive portal hook package so that the netcheck
// command also probes for captive portals during its report.
import _ "tailscale.com/feature/captiveportal/netcheckhook"
