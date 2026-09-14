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

# Sibling _test.go files hidden from go-118-fuzz-build_v2 during a build;
# restored by the EXIT trap below. See build_fuzzer.
hidden_test_files=()

restore_hidden_test_files() {
	local f
	for f in "${hidden_test_files[@]:+${hidden_test_files[@]}}"; do
		mv "$f.__hidden__" "$f"
	done
	hidden_test_files=()
}

trap 'restore_hidden_test_files; rm -rf "$tmpdir"' EXIT

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

# Wraps compile_native_go_fuzzer_v2, working around go-118-fuzz-build_v2
# (fc5dc53b) overlaying every sibling _test.go in the fuzzer's directory onto a
# virtual non-test path (<base>_libFuzzer.go). Siblings declaring an external
# test package (package foo_test) then collide with the fuzzer's package
# ("found packages foo (..) and foo_test (..) in ..."). Such files are a
# different package and can never be referenced from the fuzzer, so hide them
# for the duration of the build and restore them afterwards.
#
# Rather than inferring each file's package by grepping its package clause or
# function signature (order- and formatting-dependent), ask `go list` directly:
# .XTestGoFiles are exactly the external-package (_test) files that collide, so
# hide precisely those. Internal test files (.TestGoFiles, same package as the
# fuzzer) stay put because they may define helpers the fuzz target calls.
build_fuzzer() {
	local path=$1 function=$2 name=$3
	local dir rel f
	# Use the same -tags gofuzz view as compile_native_go_fuzzer_v2 so the
	# hidden file set matches what the build actually sees.
	dir=$(go list -tags gofuzz -f '{{.Dir}}' "$path")
	while IFS= read -r rel; do
		[ -n "$rel" ] || continue
		f="$dir/$rel"
		mv "$f" "$f.__hidden__"
		hidden_test_files+=("$f")
	done < <(go list -tags gofuzz -f '{{range .XTestGoFiles}}{{.}}{{"\n"}}{{end}}' "$path")
	compile_native_go_fuzzer_v2 "$path" "$function" "$name"
	restore_hidden_test_files
}

build_fuzzers() {
	# control (controlbase, tsp)
	build_fuzzer tailscale.com/control/controlbase FuzzWholeMessageLocked controlbase_whole_message_locked
	build_fuzzer tailscale.com/control/controlbase FuzzDecryptLocked controlbase_decrypt_locked
	build_fuzzer tailscale.com/control/controlbase FuzzConnRead controlbase_conn_read
	build_fuzzer tailscale.com/control/controlbase FuzzConnWrite controlbase_conn_write
	build_fuzzer tailscale.com/control/tsp FuzzFramedReader tsp_framed_reader
	build_fuzzer tailscale.com/control/tsp FuzzBoundedReader tsp_bounded_reader

	# derp (top-level)
	build_fuzzer tailscale.com/derp FuzzReadFrameHeader derp_read_frame_header
	build_fuzzer tailscale.com/derp FuzzReadFrame derp_read_frame
	build_fuzzer tailscale.com/derp FuzzRecvTimeout derp_recv_timeout
	build_fuzzer tailscale.com/derp FuzzRecvServerKey derp_recv_server_key

	# disco (top-level)
	build_fuzzer tailscale.com/disco FuzzDiscoParse disco_parse_fuzzer

	# net (dnscache, dns/resolver, packet, portmapper, stun, traffic)
	build_fuzzer tailscale.com/net/dnscache FuzzGetDNSQueryCacheKey dnscache_get_dns_query_cache_key
	build_fuzzer tailscale.com/net/dnscache FuzzAsciiLowerName dnscache_ascii_lower_name
	build_fuzzer tailscale.com/net/dns/resolver FuzzClampEDNSSize dns_clamp_edns_size
	build_fuzzer tailscale.com/net/packet FuzzParsedDecode packet_parsed_decode
	build_fuzzer tailscale.com/net/packet FuzzDecode4 packet_decode4
	build_fuzzer tailscale.com/net/packet FuzzDecode6 packet_decode6
	build_fuzzer tailscale.com/net/packet FuzzDecode6Fragment packet_decode6_fragment
	build_fuzzer tailscale.com/net/packet FuzzIP4Checksum packet_ip4_checksum
	build_fuzzer tailscale.com/net/packet FuzzChecksumBytes packet_checksum_bytes
	build_fuzzer tailscale.com/net/packet FuzzICMP6Checksum packet_icmp6_checksum
	build_fuzzer tailscale.com/net/packet FuzzGeneveDecode packet_geneve_decode
	build_fuzzer tailscale.com/net/portmapper FuzzParsePCPResponse portmapper_parse_pcp_response
	build_fuzzer tailscale.com/net/portmapper FuzzParsePCPMapResponse portmapper_parse_pcp_map_response
	build_fuzzer tailscale.com/net/stun FuzzParseResponse stun_parser_response_fuzzer
	build_fuzzer tailscale.com/net/stun FuzzParseBindingRequest stun_parser_request_fuzzer
	build_fuzzer tailscale.com/net/stun FuzzMappedAddress stun_mapped_address
	build_fuzzer tailscale.com/net/stun FuzzForeachAttr stun_foreach_attr
	build_fuzzer tailscale.com/net/stun FuzzXorMappedAddress stun_xor_mapped_address
	build_fuzzer tailscale.com/net/traffic FuzzNodeHasherCompare traffic_node_hasher_compare
	build_fuzzer tailscale.com/net/traffic FuzzSortNodes traffic_sort_nodes

	# tailcfg (top-level)
	build_fuzzer tailscale.com/tailcfg FuzzNodeIsRouter tailcfg_node_isrouter

	# tka (top-level)
	build_fuzzer tailscale.com/tka FuzzAUMUnserializeValidate tka_aum_unserialize_validate
	build_fuzzer tailscale.com/tka FuzzNodeKeySignatureUnserialize tka_node_key_signature_unserialize

	# types (geo, key)
	build_fuzzer tailscale.com/types/geo FuzzPointSphericalAngleTo geo_spherical_angle_to
	build_fuzzer tailscale.com/types/key FuzzParseHex key_parse_hex
	build_fuzzer tailscale.com/types/key FuzzFromHexChar key_from_hex_char
	build_fuzzer tailscale.com/types/key FuzzNodePublicUnmarshalBinary key_node_public_unmarshal_binary
	build_fuzzer tailscale.com/types/key FuzzOpen key_open

	# util (cobs, def, nocasemaps, safediff, zstdframe)
	build_fuzzer tailscale.com/util/cobs FuzzRoundtrip cobs_roundtrip
	build_fuzzer tailscale.com/util/cobs FuzzMostlyBijective cobs_mostly_bijective
	build_fuzzer tailscale.com/util/def FuzzBool def_bool
	build_fuzzer tailscale.com/util/def FuzzDuration def_duration
	build_fuzzer tailscale.com/util/nocasemaps FuzzAppendToLower nocase_append_tolower
	build_fuzzer tailscale.com/util/safediff FuzzDiff safediff_diff
	build_fuzzer tailscale.com/util/zstdframe FuzzNextSize zstdframe_next_size

	# wgengine (netlog)
	build_fuzzer tailscale.com/wgengine/netlog FuzzQuotedLen netlog_quoted_len
}

prepare
build_fuzzers
