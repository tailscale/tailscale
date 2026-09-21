#!/bin/bash
# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# macos-dns-cache-check.sh checks whether the macOS system resolver
# (mDNSResponder) agrees with Tailscale about the IP addresses of every
# peer in the tailnet, and flushes the macOS DNS caches if it doesn't.
#
# mDNSResponder negatively caches NXDOMAIN/NODATA answers for far longer
# than the DNS response asked for. When a new node joins the tailnet
# shortly after a Mac has already tried to resolve its MagicDNS name,
# the Mac keeps answering "no such host" long after Tailscale itself
# knows the peer, which looks to the user like the new node doesn't
# exist. This script detects that state and clears it.
#
# It runs "tailscale status --json", then asks mDNSResponder (via
# dscacheutil, which uses the same lookup path as every other macOS
# app; dig and host bypass it) for the A/AAAA records of each peer's
# DNSName and compares the answers to the peer's TailscaleIPs. If any
# peer mismatches, it flushes both cache layers: the Directory Services
# cache (dscacheutil -flushcache) and mDNSResponder's own cache
# (killall -HUP mDNSResponder), then re-checks the peers that failed.
#
# Usage: sudo ./macos-dns-cache-check.sh [-n] [-v]
#   -n  check only; report mismatches but don't flush (doesn't need root)
#   -v  verbose; print every peer, not just the mismatched ones
#
# Exit status: 0 if everything matches (or matched after the flush),
# 3 if -n found mismatches, 4 if mismatches remain after the flush,
# 1 or 2 on usage or environment errors.

set -u

check_only=0
verbose=0
while getopts "nv" opt; do
	case "$opt" in
	n) check_only=1 ;;
	v) verbose=1 ;;
	*)
		echo "usage: sudo $0 [-n] [-v]" >&2
		exit 2
		;;
	esac
done

if [ "$(uname -s)" != "Darwin" ]; then
	echo "$0: this script only works on macOS" >&2
	exit 1
fi

if [ "$check_only" = 0 ] && [ "$(id -u)" != 0 ]; then
	echo "$0: must run as root (via sudo) to be able to flush the DNS caches; use -n to only check" >&2
	exit 1
fi

# find_tailscale prints the path of the tailscale CLI. Under sudo the
# PATH is usually reset, so also look in the places the various macOS
# distributions put it.
find_tailscale() {
	if command -v tailscale >/dev/null 2>&1; then
		command -v tailscale
		return 0
	fi
	for p in \
		/Applications/Tailscale.app/Contents/MacOS/Tailscale \
		/opt/homebrew/bin/tailscale \
		/usr/local/bin/tailscale; do
		if [ -x "$p" ]; then
			echo "$p"
			return 0
		fi
	done
	return 1
}

tailscale=$(find_tailscale) || {
	echo "$0: can't find the tailscale CLI" >&2
	exit 1
}

# tailscale_status runs "tailscale status --json". The App Store
# variant of the macOS client only lets the CLI talk to the GUI when
# the CLI runs as the same user as the GUI, so when we're under sudo
# try the invoking user first and fall back to root (which is what the
# tailscaled and standalone variants want).
tailscale_status() {
	if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
		if out=$(sudo -u "$SUDO_USER" "$tailscale" status --json 2>/dev/null) && [ -n "$out" ]; then
			printf '%s\n' "$out"
			return 0
		fi
	fi
	"$tailscale" status --json
}

status_json=$(tailscale_status) || {
	echo "$0: tailscale status --json failed" >&2
	exit 1
}

# peers_from_status reads the status JSON on stdin and prints a header
# line with the backend state, a tab, and whether MagicDNS is on, then
# one line per peer: the DNSName, a tab, and the comma-separated
# TailscaleIPs. jq only ships with recent macOS versions, so fall back
# to JavaScript for Automation, which every macOS has.
peers_from_status() {
	if command -v jq >/dev/null 2>&1; then
		jq -r '
			"\(.BackendState)\t\(.CurrentTailnet.MagicDNSEnabled // false)",
			((.Peer // {})[] |
				select(.DNSName != "" and (.TailscaleIPs // [] | length) > 0) |
				"\(.DNSName)\t\(.TailscaleIPs | join(","))")'
		return
	fi
	osascript -l JavaScript -e '
		ObjC.import("Foundation");
		function run() {
			const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
			const st = JSON.parse($.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js);
			const magic = !!(st.CurrentTailnet && st.CurrentTailnet.MagicDNSEnabled);
			const out = [st.BackendState + "\t" + magic];
			const peers = st.Peer || {};
			for (const k in peers) {
				const p = peers[k];
				if (!p.DNSName || !p.TailscaleIPs || p.TailscaleIPs.length === 0) {
					continue;
				}
				out.push(p.DNSName + "\t" + p.TailscaleIPs.join(","));
			}
			return out.join("\n");
		}'
}

peers=$(printf '%s' "$status_json" | peers_from_status) || {
	echo "$0: failed to parse tailscale status output" >&2
	exit 1
}

header=$(printf '%s\n' "$peers" | head -n 1)
peers=$(printf '%s\n' "$peers" | tail -n +2)
IFS=$'\t' read -r backend_state magic_dns <<<"$header"

if [ "$backend_state" != "Running" ]; then
	echo "Tailscale is not running (state: $backend_state); nothing to check." >&2
	exit 1
fi
if [ "$magic_dns" != "true" ]; then
	echo "MagicDNS is not enabled on this tailnet; peer names aren't expected to resolve." >&2
	exit 1
fi
if [ -z "$peers" ]; then
	echo "No peers with DNS names; nothing to check."
	exit 0
fi

# resolve prints the IPs that the macOS resolver returns for a name,
# one per line, sorted and lowercased. It prints nothing if the name
# doesn't resolve, which is what a negatively cached name looks like.
resolve() {
	dscacheutil -q host -a name "$1" 2>/dev/null |
		awk '$1 == "ip_address:" || $1 == "ipv6_address:" { print tolower($2) }' |
		sort -u
}

# expected_ips prints a comma-separated IP list one per line, sorted
# and lowercased, to match the output format of resolve.
expected_ips() {
	printf '%s\n' "$1" | tr ',' '\n' | tr 'A-Z' 'a-z' | sort -u
}

# oneline joins the lines of its argument (or stdin) with single
# spaces, for printing an IP list.
oneline() {
	if [ $# -gt 0 ]; then
		printf '%s\n' "$1"
	else
		cat
	fi | tr '\n' ' ' | sed 's/ *$//'
}

# check_peer compares the resolver's answer for a peer against what
# Tailscale says. It prints nothing and returns 0 if they match.
# Otherwise it prints a one-line description of the mismatch and
# returns 1 (no answer at all), 2 (some expected IPs missing), or
# 3 (unexpected IPs returned, possibly in addition to missing ones).
check_peer() {
	name=$1
	want=$(expected_ips "$2")
	got=$(resolve "$name")

	if [ -z "$got" ]; then
		echo "$name: NO ANSWER (want $(oneline "$want"))"
		return 1
	fi
	if [ "$got" = "$want" ]; then
		return 0
	fi
	missing=$(comm -23 <(echo "$want") <(echo "$got") | oneline)
	extra=$(comm -13 <(echo "$want") <(echo "$got") | oneline)
	desc=""
	if [ -n "$missing" ]; then
		desc="missing $missing"
	fi
	if [ -n "$extra" ]; then
		desc="${desc:+$desc; }unexpected $extra"
	fi
	echo "$name: $desc"
	if [ -n "$extra" ]; then
		return 3
	fi
	return 2
}

# check_all runs check_peer for each peer in the list on stdin and sets
# the global counters and the list of mismatched peers.
check_all() {
	total=0
	ok=0
	n_noanswer=0
	n_missing=0
	n_unexpected=0
	bad_peers=""
	while IFS=$'\t' read -r name ips; do
		[ -z "$name" ] && continue
		name=${name%.}
		total=$((total + 1))
		desc=$(check_peer "$name" "$ips")
		rc=$?
		case $rc in
		0)
			ok=$((ok + 1))
			[ "$verbose" = 1 ] && echo "$name: ok ($(printf '%s\n' "$ips" | tr ',' ' '))"
			continue
			;;
		1) n_noanswer=$((n_noanswer + 1)) ;;
		2) n_missing=$((n_missing + 1)) ;;
		3) n_unexpected=$((n_unexpected + 1)) ;;
		esac
		echo "MISMATCH $desc"
		bad_peers="${bad_peers}${name}	${ips}
"
	done
}

echo "Checking $(printf '%s\n' "$peers" | wc -l | tr -d ' ') peers against the macOS resolver..."
check_all <<<"$peers"
mismatched=$((total - ok))

echo "Checked $total peers: $ok ok, $mismatched mismatched" \
	"($n_noanswer no answer, $n_missing missing addresses, $n_unexpected unexpected addresses)."
if [ "$mismatched" = 0 ]; then
	echo "The macOS DNS cache agrees with Tailscale; not flushing."
	exit 0
fi
if [ "$check_only" = 1 ]; then
	echo "Not flushing (-n). Run without -n as root to flush the macOS DNS caches."
	exit 3
fi

echo "Flushing the macOS DNS caches..."
dscacheutil -flushcache || echo "$0: dscacheutil -flushcache failed" >&2
killall -HUP mDNSResponder || echo "$0: killall -HUP mDNSResponder failed" >&2

# mDNSResponder takes a moment to come back after the HUP; give it a
# beat before re-querying so we don't just measure the restart.
sleep 2

echo "Re-checking the $mismatched mismatched peers..."
check_all <<<"$bad_peers"
still_bad=$((total - ok))
if [ "$still_bad" = 0 ]; then
	echo "All $total previously mismatched peers now resolve correctly."
	exit 0
fi
echo "$still_bad of $total previously mismatched peers still don't resolve correctly after the flush." \
	"This is probably not the mDNSResponder cache; check 'tailscale dns status'."
exit 4
