#!/bin/sh
#
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# check_license_headers.sh checks that all Go files in the given
# directory tree have a correct-looking Tailscale license header.

check_file() {
    got=$1

    want=$(cat <<EOF
// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
EOF
    )
    if [ "$got" = "$want" ]; then
        return 0
    fi
    return 1
}

if [ $# != 1 ]; then
    echo "Usage: $0 rootdir" >&2
    exit 1
fi

fail=0
for file in $(find $1 -name '*.go' -not -path '*/.git/*'); do
    case $file in
        $1/tempfork/*)
            # Skip, tempfork of third-party code
        ;;
        $1/wgengine/router/ifconfig_windows.go)
            # WireGuard copyright.
        ;;
        $1/cmd/tailscale/cli/authenticode_windows.go)
            # WireGuard copyright.
        ;;
		*_string.go)
			# Generated file from go:generate stringer
		;;
		$1/control/controlbase/noiseexplorer_test.go)
			# Noiseexplorer.com copyright.
		;;
        */zsyscall_windows.go)
            # Generated syscall wrappers
        ;;
        *)
            header="$(head -2 $file)"
            if ! check_file "$header"; then
                fail=1
                echo "${file#$1/} doesn't have the right copyright header:"
                echo "$header" | sed -e 's/^/    /g'
            fi
            ;;
    esac
done

if [ $fail -ne 0 ]; then
    exit 1
fi
