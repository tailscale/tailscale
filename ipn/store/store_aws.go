// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (ts_aws || (linux && (arm64 || amd64))) && !ts_omit_aws

package store

import (
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/awsstore"
	"tailscale.com/types/logger"
)

func init() {
	registerAvailableExternalStores = append(registerAvailableExternalStores, registerAWSStore)
}

func registerAWSStore() {
	Register("arn:", func(logf logger.Logf, arg string) (ipn.StateStore, error) {
		ssmARN, opts, err := awsstore.ParseARNAndOpts(arg)
		if err != nil {
			return nil, err
		}
		return awsstore.New(logf, ssmARN, opts...)
	})
}
