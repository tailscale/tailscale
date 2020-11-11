#!/bin/sh
set -eu

# Return the commitid of the given ref in the given repo dir. If the worktree
# or index is dirty, also appends -dirty.
#
# $ git_hash_dirty ../.. HEAD
# 1be01ddc6e430ca3aa9beea3587d16750efb3241-dirty
git_hash_dirty() {
    (
        cd "$1"
        x=$(git rev-parse HEAD)
        if ! git diff-index --quiet HEAD; then
            x="$x-dirty"
        fi
        echo "$x"
    )
}

case $# in
    0|1)
        # extra_hash_or_dir is either:
        #   - a git commitid
        # or
        #   - the path to a git repo from which to calculate the real hash.
        #
        # It gets embedded as an additional commit hash in built
        # binaries, to help us locate the exact set of tools and code
        # that were used.
        extra_hash_or_dir="${1:-}"
        if [ -z "$extra_hash_or_dir" ]; then
            # Nothing, empty extra hash is fine.
            extra_hash=""
        elif [ -d "$extra_hash_or_dir/.git" ]; then
            extra_hash=$(git_hash_dirty "$extra_hash_or_dir" HEAD)
        elif ! expr "$extra_hash_or_dir" : "^[0-9a-f]*$"; then
            echo "Invalid extra hash '$extra_hash_or_dir', must be a git commit or path to a git repo" >&2
            exit 1
        else
            extra_hash="$extra_hash_or_dir"
        fi

        # Load the base version and optional corresponding git hash
        # from the VERSION file. If there is no git hash in the file,
        # we use the hash of the last change to the VERSION file.
        version_file="$(dirname $0)/../VERSION.txt"
        IFS=".$IFS" read -r major minor patch base_git_hash <"$version_file"
        if [ -z "$base_git_hash" ]; then
            base_git_hash=$(git rev-list --max-count=1 HEAD -- "$version_file")
        fi

        git_hash=$(git_hash_dirty . HEAD)
        # The number of extra commits between the release base to git_hash.
        change_count=$(git rev-list --count HEAD "^$base_git_hash")
        ;;
    6)
        # Test mode: rather than run git commands and whatnot, take in
        # all the version pieces as arguments.
        git_hash=$1
        extra_hash=$2
        major=$3
        minor=$4
        patch=$5
        change_count=$6
        ;;
    *)
        echo "Usage: $0 [extra-git-commitid-or-dir]"
        exit 1
esac

# Shortened versions of git hashes, so that they fit neatly into an
# "elongated" but still human-readable version number.
short_git_hash=$(echo "$git_hash" | cut -c1-9)
short_extra_hash=$(echo "$extra_hash" | cut -c1-9)

# Convert major/minor/patch/change_count into an adjusted
# major/minor/patch. This block is where all our policies on
# versioning are.
if expr "$minor" : "[0-9]*[13579]$" >/dev/null; then
    # Odd minor numbers are unstable builds.
    if [ "$patch" != "0" ]; then
        # This is a fatal error, because a non-zero patch number
        # indicates that we created an unstable VERSION.txt in violation
        # of our versioning policy, and we want to blow up loudly to
        # get that fixed.
        echo "Unstable release $major.$minor.$patch has a non-zero patch number, which is not allowed" >&2
        exit 1
    fi
    patch="$change_count"
    change_suffix=""
elif [ "$change_count" != "0" ]; then
    # Even minor numbers are stable builds, but stable builds are
    # supposed to have a zero change count. Therefore, we're currently
    # describing a commit that's on a release branch, but hasn't been
    # tagged as a patch release yet.
    #
    # We used to change the version number to 0.0.0 in that case, but that
    # caused some features to get disabled due to the low version number.
    # Instead, add yet another suffix to the version number, with a change
    # count.
    change_suffix="-$change_count"
else
    # Even minor number with no extra changes.
    change_suffix=""
fi

# Hack for 1.1: add 1000 to the patch number. We switched from using
# the proprietary repo's change_count over to using the OSS repo's
# change_count, and this was necessary to avoid a backwards jump in
# release numbers.
if [ "$major.$minor" = "1.1" ]; then
    patch="$((patch + 1000))"
fi

# At this point, the version number correctly reflects our
# policies. All that remains is to output the various vars that other
# code can use to embed version data.
if [ -z "$extra_hash" ]; then
    long_version_suffix="$change_suffix-t$short_git_hash"
else
    long_version_suffix="$change_suffix-t$short_git_hash-g$short_extra_hash"
fi
cat <<EOF
VERSION_SHORT="$major.$minor.$patch"
VERSION_LONG="$major.$minor.$patch$long_version_suffix"
VERSION_GIT_HASH="$git_hash"
VERSION_EXTRA_HASH="$extra_hash"
VERSION_XCODE="$((major + 100)).$minor.$patch"
VERSION_WINRES="$major,$minor,$patch,0"
EOF
