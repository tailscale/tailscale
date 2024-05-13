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
for file in $(find $1 \( -name '*.go' -or -name '*.tsx' -or -name '*.ts' -not -name '*.config.ts' \) -not -path '*/.git/*' -not -path '*/node_modules/*'); do
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
        $1/util/winutil/subprocess_windows_test.go)
            # Subprocess test harness code
        ;;
        $1/util/winutil/testdata/testrestartableprocesses/main.go)
            # Subprocess test harness code
        ;;
        *$1/k8s-operator/apis/v1alpha1/zz_generated.deepcopy.go)
            # Generated kube deepcopy funcs file starts with a Go build tag + an empty line
            header="$(head -5 $file | tail -n+3 )"
        ;;
        $1/derp/xdp/bpf_bpfe*.go)
            # Generated eBPF management code
        ;;
        *)
           header="$(head -2 $file)"
        ;;
    esac
    if [ ! -z "$header" ]; then
            if ! check_file "$header"; then
                fail=1
                echo "${file#$1/} doesn't have the right copyright header:"
                echo "$header" | sed -e 's/^/    /g'
            fi
    fi
done

if [ $fail -ne 0 ]; then
    exit 1
fi
