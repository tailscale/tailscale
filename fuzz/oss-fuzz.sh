#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# This script builds all of Tailscale's OSS-Fuzz fuzz targets.
#
# It is invoked by the google/oss-fuzz project configuration for tailscale:
#   projects/tailscale/build.sh runs:  bash -x ./fuzz/oss-fuzz.sh
#
# The script relies on the OSS-Fuzz base-builder environment, in particular
# the compile_native_go_fuzzer_v2 helper that turns native Go fuzz targets
# (`func FuzzXxx(f *testing.F)`) into libFuzzer binaries placed in $OUT.

set -euxo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." # repository root

# go-118-fuzz-build_v2 (used by compile_native_go_fuzzer_v2) overlays a custom
# testing/fuzz.go onto $GOROOT. When GOTOOLCHAIN=auto downloads the toolchain that gomod
# requires into GOMODCACHE, Go refuses to overlay any file beneath it. Copy such a downloaded
# toolchain to a writable temp dir so overlays work for any go.mod version.
#
# The copy is also rebuilt below against the same toolchain, so this script stays correct as
# tailscale's required Go version changes without editing anything here.
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Pin go-118-fuzz-build to an immutable commit. Fetch by SHA rather than tracking the v2
# branch so upstream rewrites can't silently change or break this build.
#
# Keep in sync with oss-fuzz's infra/base-images/base-builder/install_go.sh (the v2 checkout).
fuzzbuild_ref=fc5dc53b9db8a38c394c53d6e439a1410cf8fc19

goroot=$(go env GOROOT)
gomodcache=$(go env GOMODCACHE)
if [[ "$goroot" == "$gomodcache"* ]]; then
	cp -r "$goroot/." "$tmpdir/goroot"
	# Toolchain files are read-only; make them writable so cleanup works for any user.
	chmod -R u+rwX "$tmpdir/goroot"
	export GOROOT="$tmpdir/goroot"
	export PATH="$GOROOT/bin:$PATH"
	export GOTOOLCHAIN=local
fi

# go-118-fuzz-build_v2 embeds x/tools/go/packages compiled with whatever Go built it. If that
# differs from the active toolchain (e.g. after a GOTOOLCHAIN download), its source-processing
# packages diverge from `go list`/the compiler, producing errors like "unknown field rfd".
# Rebuild it with the now-active toolchain so they always match.
prepare() {
	git clone --depth 1 https://github.com/AdamKorcz/go-118-fuzz-build "$tmpdir/v2"
	(
		cd "$tmpdir/v2"
		git fetch --depth 1 origin "$fuzzbuild_ref"
		git checkout -q FETCH_HEAD
		GOFLAGS=-mod=mod go build -o "$tmpdir/bin/go-118-fuzz-build_v2" .
	)
	export PATH="$tmpdir/bin:$PATH"

	GOFLAGS=-mod=mod go get github.com/AdamKorcz/go-118-fuzz-build/testing@$fuzzbuild_ref
}

build_fuzzers() {
	compile_native_go_fuzzer_v2 tailscale.com/disco FuzzDiscoParse disco_parse_fuzzer
	compile_native_go_fuzzer_v2 tailscale.com/net/stun FuzzParseResponse stun_parser_response_fuzzer
	compile_native_go_fuzzer_v2 tailscale.com/net/stun FuzzParseBindingRequest stun_parser_request_fuzzer
	compile_native_go_fuzzer_v2 tailscale.com/net/dns/resolver FuzzClampEDNSSize dns_clamp_edns_size
	compile_native_go_fuzzer_v2 tailscale.com/net/traffic FuzzNodeHasherCompare traffic_node_hasher_compare
	compile_native_go_fuzzer_v2 tailscale.com/net/traffic FuzzSortNodes traffic_sort_nodes

	compile_native_go_fuzzer_v2 tailscale.com/tailcfg FuzzNodeIsRouter tailcfg_node_isrouter

	compile_native_go_fuzzer_v2 tailscale.com/types/geo FuzzPointSphericalAngleTo geo_spherical_angle_to

	compile_native_go_fuzzer_v2 tailscale.com/util/cobs FuzzRoundtrip cobs_roundtrip
	compile_native_go_fuzzer_v2 tailscale.com/util/cobs FuzzMostlyBijective cobs_mostly_bijective
	compile_native_go_fuzzer_v2 tailscale.com/util/def FuzzBool def_bool
	compile_native_go_fuzzer_v2 tailscale.com/util/def FuzzDuration def_duration
	compile_native_go_fuzzer_v2 tailscale.com/util/nocasemaps FuzzAppendToLower nocase_append_tolower
	compile_native_go_fuzzer_v2 tailscale.com/util/safediff FuzzDiff safediff_diff

	compile_native_go_fuzzer_v2 tailscale.com/wgengine/netlog FuzzQuotedLen netlog_quoted_len
}

prepare
build_fuzzers
