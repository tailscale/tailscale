// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (ts_aws || (linux && (arm64 || amd64))) && !ts_omit_aws

package store

import (
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
        // Extract the KMS key ID if present
        kmsKeyID := ""
        parts := strings.SplitN(arg, "?kmsKey=", 2)
        ssmARN := parts[0]

        if len(parts) == 2 {
            kmsKeyID = parts[1]

			// We allow an arn, a key ID, or an alias name.
            if !strings.Contains(kmsKeyID, "/") &&
               !strings.HasPrefix(kmsKeyID, "arn:aws:kms:") {
                kmsKeyID = "alias/" + kmsKeyID
            }
        }

        return awsstore.New(logf, ssmARN, kmsKeyID)
    })
}
