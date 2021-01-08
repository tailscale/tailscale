#!/bin/sh
#
# Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
#
# check_license_headers.sh checks that all Go files in the given
# directory tree have a correct-looking Tailscale license header.

check_file() {
    got=$1

    for year in `seq 2019 2021`; do
        want=$(cat <<EOF
// Copyright (c) $year Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
EOF
        )
        if [ "$got" = "$want" ]; then
            return 0
        fi
    done
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
        *)
            header="$(head -3 $file)"
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
