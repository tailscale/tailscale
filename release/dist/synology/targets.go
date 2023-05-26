// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package synology

import "tailscale.com/release/dist"

func Targets(forPackageCenter bool) []dist.Target {
	var ret []dist.Target
	for _, dsmVersion := range []int{6, 7} {
		ret = append(ret,
			&target{
				filenameArch:    "x86_64",
				dsmMajorVersion: dsmVersion,
				goenv: map[string]string{
					"GOOS":   "linux",
					"GOARCH": "amd64",
				},
				packageCenter: forPackageCenter,
			},
			&target{
				filenameArch:    "i686",
				dsmMajorVersion: dsmVersion,
				goenv: map[string]string{
					"GOOS":   "linux",
					"GOARCH": "386",
				},
				packageCenter: forPackageCenter,
			},
			&target{
				filenameArch:    "armv8",
				dsmMajorVersion: dsmVersion,
				goenv: map[string]string{
					"GOOS":   "linux",
					"GOARCH": "arm64",
				},
				packageCenter: forPackageCenter,
			})

		// On older ARMv5 and ARMv7 platforms, synology used a whole
		// mess of SoC-specific target names, even though the packages
		// built for each are identical apart from metadata.
		for _, v5Arch := range []string{"armv5", "88f6281", "88f6282"} {
			ret = append(ret, &target{
				filenameArch:    v5Arch,
				dsmMajorVersion: dsmVersion,
				goenv: map[string]string{
					"GOOS":   "linux",
					"GOARCH": "arm",
					"GOARM":  "5",
				},
				packageCenter: forPackageCenter,
			})
		}
		for _, v7Arch := range []string{"armv7", "alpine", "armada370", "armada375", "armada38x", "armadaxp", "comcerto2k", "monaco", "hi3535"} {
			ret = append(ret, &target{
				filenameArch:    v7Arch,
				dsmMajorVersion: dsmVersion,
				goenv: map[string]string{
					"GOOS":   "linux",
					"GOARCH": "arm",
					"GOARM":  "7",
				},
				packageCenter: forPackageCenter,
			})
		}
	}
	return ret
}
