// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ((linux && !android) || (android && !cgo)) && !ts_omit_androidbin

package condregister

import _ "tailscale.com/feature/androidbin"
