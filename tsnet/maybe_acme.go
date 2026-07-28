// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package tsnet

// Link in the ACME/TLS-cert feature so [Server.CertDomains],
// [Server.ListenTLS], and related cert-fetch paths work out of the box.
// Build with the ts_omit_acme tag to omit it.

import _ "tailscale.com/feature/acme"
