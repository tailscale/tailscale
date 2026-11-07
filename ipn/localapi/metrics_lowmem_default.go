// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_lowmem_metrics

package localapi

import "net/http"

func writeLowMemoryMetrics(http.ResponseWriter) {}
