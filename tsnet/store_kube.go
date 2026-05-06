// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Register the "kube:" state store prefix so that TS_STATE=kube:<secret>
// and Store via store.New work in tsnet when running on Kubernetes.

//go:build (ts_kube || (linux && (arm64 || amd64) && !android)) && !ts_omit_kube

package tsnet

import _ "tailscale.com/ipn/store/kubestore"
