// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (ts_aws || (linux && (arm64 || amd64) && !android)) && !ts_omit_aws

package condregister

import _ "tailscale.com/ipn/store/awsstore"
