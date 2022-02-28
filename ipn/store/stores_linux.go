// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package store

import (
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/awsstore"
	"tailscale.com/ipn/store/kubestore"
	"tailscale.com/types/logger"
)

func init() {
	registerAvailableExternalStores = registerExternalStores
}

func registerExternalStores() {
	Register("kube:", func(logf logger.Logf, path string) (ipn.StateStore, error) {
		secretName := strings.TrimPrefix(path, "kube:")
		return kubestore.New(logf, secretName)
	})
	Register("arn:", awsstore.New)
}
