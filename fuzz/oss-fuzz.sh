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

prepare() {
	go get github.com/AdamKorcz/go-118-fuzz-build/testing
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
