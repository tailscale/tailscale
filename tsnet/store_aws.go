// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Register the "arn:" state store prefix so that TS_STATE=arn:<arn>
// and Store via store.New work in tsnet when running on AWS.

//go:build (ts_aws || (linux && (arm64 || amd64) && !android)) && !ts_omit_aws

package tsnet

import _ "tailscale.com/ipn/store/awsstore"
