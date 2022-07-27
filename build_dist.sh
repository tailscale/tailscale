#!/usr/bin/env sh
#
# Runs `go build` with flags configured for binary distribution. All
# it does differently from `go build` is burn git commit and version
# information into the binaries, so that we can track down user
# issues.
#
# If you're packaging Tailscale for a distro, please consider using
# this script, or executing equivalent commands in your
# distro-specific build system.

set -eu

IFS=".$IFS" read -r major minor patch <VERSION.txt
git_hash=$(git rev-parse HEAD)
if ! git diff-index --quiet HEAD; then
	git_hash="${git_hash}-dirty"
fi
base_hash=$(git rev-list --max-count=1 HEAD -- VERSION.txt)
change_count=$(git rev-list --count HEAD "^$base_hash")
short_hash=$(echo "$git_hash" | cut -c1-9)

if expr "$minor" : "[0-9]*[13579]$" >/dev/null; then
	patch="$change_count"
	change_suffix=""
elif [ "$change_count" != "0" ]; then
	change_suffix="-$change_count"
else
	change_suffix=""
fi

long_suffix="$change_suffix-t$short_hash"
MINOR="$major.$minor"
SHORT="$MINOR.$patch"
LONG="${SHORT}$long_suffix"
GIT_HASH="$git_hash"

if [ "$1" = "shellvars" ]; then
	cat <<EOF
VERSION_MINOR="$MINOR"
VERSION_SHORT="$SHORT"
VERSION_LONG="$LONG"
VERSION_GIT_HASH="$GIT_HASH"
EOF
	exit 0
fi

tags=""
ldflags="-X tailscale.com/version.Long=${LONG} -X tailscale.com/version.Short=${SHORT} -X tailscale.com/version.GitCommit=${GIT_HASH}"

# build_dist.sh arguments must precede go build arguments.
while [ "$#" -gt 1 ]; do
	case "$1" in
	--extra-small)
		shift
		ldflags="$ldflags -w -s"
		tags="${tags:+$tags,}ts_omit_aws"
		;;
	--box)
		shift
		tags="${tags:+$tags,}ts_include_cli"
		;;
	*)
		break
		;;
	esac
done

exec ./tool/go build ${tags:+-tags=$tags} -ldflags "$ldflags" "$@"
