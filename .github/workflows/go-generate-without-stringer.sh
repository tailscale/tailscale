#!/usr/bin/env sh
#
# This is a temporary hack to work around
# https://github.com/golang/go/issues/51629 , wherein the stringer
# generator doesn't work with generics.
#
# This script is the equivalent of `go generate ./...`, except that it
# only runs generate on packages that don't try to use stringer.

set -e

find . -name '*.go' | xargs grep -l go:generate | xargs -n1 dirname | sort -u | while read dir; do
	if ! egrep "cmd/(stringer|cloner)" $dir/*.go; then
		set -x
		go generate -tags=hermetic $dir
		set +x
	fi
done
