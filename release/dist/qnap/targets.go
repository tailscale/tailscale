// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package qnap

import (
	"slices"

	"tailscale.com/release/dist"
)

// Targets defines the dist.Targets for QNAP devices.
//
// If all parameters are provided non-empty, then the build will be signed using
// a Google Cloud hosted key.
//
// gcloudCredentialsBase64 is the JSON credential for connecting to Google Cloud, base64 encoded.
// gcloudKeyring is the full path to the Google Cloud keyring containing the signing key.
// keyName is the name of the key.
// certificateBase64 is the PEM certificate to use in the signature, base64 encoded.
func Targets(gcloudCredentialsBase64, gcloudProject, gcloudKeyring, keyName, certificateBase64 string) []dist.Target {
	var signerInfo *signer
	if !slices.Contains([]string{gcloudCredentialsBase64, gcloudProject, gcloudKeyring, keyName, certificateBase64}, "") {
		signerInfo = &signer{
			gcloudCredentialsBase64: gcloudCredentialsBase64,
			gcloudProject:           gcloudProject,
			gcloudKeyring:           gcloudKeyring,
			keyName:                 keyName,
			certificateBase64:       certificateBase64,
		}
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
