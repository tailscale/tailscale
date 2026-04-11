// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux || js) && !ts_omit_webrtc

package condregister

import _ "tailscale.com/feature/webrtc"
