// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package qnap

import "tailscale.com/release/dist"

// Targets defines the dist.Targets for QNAP devices.
//
// If signingServerURL is non-empty, these targets will be signed for QNAP app store
// release using the signing server. The server protocol is simple. The builder uploads
// the QNAP package's SHA in an HTTP POST, and the signing server responds with the
// signature. This is analogous to the signature generated locally in [qbuild].
//
// [qbuild]: https://github.com/qnap-dev/QDK/blob/18208315614677fc9a6493e90b60f6eb0c90e6e9/shared/bin/qbuild#L1016
func Targets(signingServerURL string) []dist.Target {
	return []dist.Target{
		&target{
			arch: "x86",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "386",
			},
			signingServerURL: signingServerURL,
		},
		&target{
			arch: "x86_ce53xx",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "386",
			},
			signingServerURL: signingServerURL,
		},
		&target{
			arch: "x86_64",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "amd64",
			},
			signingServerURL: signingServerURL,
		},
		&target{
			arch: "arm-x31",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm",
			},
			signingServerURL: signingServerURL,
		},
		&target{
			arch: "arm-x41",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm",
			},
			signingServerURL: signingServerURL,
		},
		&target{
			arch: "arm-x19",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm",
			},
			signingServerURL: signingServerURL,
		},
		&target{
			arch: "arm_64",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm64",
			},
			signingServerURL: signingServerURL,
		},
	}
}
