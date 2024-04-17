// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (ts_aws || (linux && (arm64 || amd64))) && !ts_omit_aws

package store

import (
	"tailscale.com/ipn/store/awsstore"
)

func init() {
	registerAvailableExternalStores = append(registerAvailableExternalStores, registerAWSStore)
}

func registerAWSStore() {
	Register("arn:", awsstore.New)
}
