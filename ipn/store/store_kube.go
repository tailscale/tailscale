// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build (ts_kube || (linux && (arm64 || amd64))) && !ts_omit_kube

package store

import (
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/ipn/store/kubestore"
	"tailscale.com/types/logger"
)

func init() {
	registerAvailableExternalStores = append(registerAvailableExternalStores, registerKubeStore)
}

func registerKubeStore() {
	Register("kube:", func(logf logger.Logf, path string) (ipn.StateStore, error) {
		secretName := strings.TrimPrefix(path, "kube:")
		return kubestore.New(logf, secretName)
	})
}
