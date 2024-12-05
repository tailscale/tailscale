#!/usr/bin/env bash
#
# This is a fake tailscale daemon that records its arguments, symlinks a
# fake LocalAPI socket into place, and does nothing until terminated.
#
# It is used by main_test.go to test the behavior of containerboot.

set -eu

echo $0 $@ >>$TS_TEST_RECORD_ARGS

socket=""
while [[ $# -gt 0 ]]; do
	case $1 in
		--socket=*)
			socket="${1#--socket=}"
			shift
			;;
		--socket)
			shift
			socket="$1"
			shift
			;;
		*)
			shift
			;;
	esac
done

if [[ -z "$socket" ]]; then
	echo "didn't find socket path in args"
	exit 1
fi

ln -s "$TS_TEST_SOCKET" "$socket"
trap 'rm -f "$socket"' EXIT

while sleep 10; do :; done
