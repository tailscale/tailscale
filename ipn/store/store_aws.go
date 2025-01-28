// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (ts_aws || (linux && (arm64 || amd64))) && !ts_omit_aws

package store

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"net/url"
	"strings"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/awsstore"
	"tailscale.com/types/logger"
)

func init() {
	registerAvailableExternalStores = append(registerAvailableExternalStores, registerAWSStore)
}

func registerAWSStore() {
	Register("arn:", func(logf logger.Logf, arg string) (ipn.StateStore, error) {
		var (
			ssmARN = arg
			kmsKey string
		)

		// Find where the query string begins, if at all.
		if idx := strings.Index(arg, "?"); idx >= 0 {

			ssmARN = arg[:idx]
			queryString := arg[idx+1:]
			q, err := url.ParseQuery(queryString)
			if err != nil {
				return nil, err
			}

			// kmsKeyID is the ?kmsKey=... parameter.
			kmsKey = q.Get("kmsKey")
			// We allow an ARN, a key ID, or an alias name for kmsKeyID.
			// If it doesn't look like an ARN and doesn't have a '/',
			// prepend "alias/" for KMS alias references.
			if kmsKey != "" &&
				!strings.Contains(kmsKey, "/") &&
				!arn.IsARN(kmsKey) {
				kmsKey = "alias/" + kmsKey
			}
		}

		return awsstore.New(logf, ssmARN, kmsKey)
	})
}
