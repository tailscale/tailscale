// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package qnap

import "tailscale.com/release/dist"

// Targets defines the dist.Targets for QNAP devices.
//
// If privateKeyPath and certificatePath are both provided non-empty,
// these targets will be signed for QNAP app store release with built.
func Targets(privateKeyPath, certificatePath string) []dist.Target {
	var signerInfo *signer
	if privateKeyPath != "" && certificatePath != "" {
		signerInfo = &signer{privateKeyPath, certificatePath}
	}
	return []dist.Target{
		&target{
			arch: "x86",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "386",
			},
			signer: signerInfo,
		},
		&target{
			arch: "x86_ce53xx",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "386",
			},
			signer: signerInfo,
		},
		&target{
			arch: "x86_64",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "amd64",
			},
			signer: signerInfo,
		},
		&target{
			arch: "arm-x31",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm",
			},
			signer: signerInfo,
		},
		&target{
			arch: "arm-x41",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm",
			},
			signer: signerInfo,
		},
		&target{
			arch: "arm-x19",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm",
			},
			signer: signerInfo,
		},
		&target{
			arch: "arm_64",
			goenv: map[string]string{
				"GOOS":   "linux",
				"GOARCH": "arm64",
			},
			signer: signerInfo,
		},
	}
}
