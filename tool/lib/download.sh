#!/usr/bin/env bash
# Shared download helper for tool wrapper scripts.
#
# Usage: source this file, then call:
#   download_tool --verify-sha256=SHA256 [--args=ARGS] <url> <dest> [<name>]
#
# --verify-sha256=SHA256 is required: the download is checked against SHA256
# (typically from select_sha256) before it is extracted or executed, and a
# missing or empty value fails closed.
#
# --args=ARGS forwards ARGS verbatim to the extraction tool (tar for .tar.gz,
# unzip for .zip); not permitted for binary downloads.
#
# <dest> is always a cache directory. For .tar.gz and .zip URLs the archive is
# extracted there. For any other URL <name> is required and the binary is
# placed at <dest>/<name>.
#
# The existing <dest> is only removed after a successful download, so a
# transient network failure leaves the previously cached version intact.

# select_sha256 <key> <key>=<sha256>...
#
# Prints the SHA256 whose <key> (typically "$OS-$ARCH") matches the first
# argument, for use with download_tool --verify-sha256. Fails if no entry
# matches, so wrapper scripts fail closed on platforms without a pinned hash.
#
# Usage:
#   want_hash=$(select_sha256 "${HOST_OS}-${HOST_ARCH}" \
#       darwin-arm64=0e8b... \
#       linux-amd64=cd6a...)
select_sha256() {
    local key="$1"
    shift
    local entry
    for entry in "$@"; do
        if [[ "${entry%%=*}" == "$key" ]]; then
            echo "${entry#*=}"
            return 0
        fi
    done
    echo "select_sha256: no pinned SHA256 for ${key}; update the caller's hash table" >&2
    return 1
}

# file_sha256 <file>
#
# Prints the hex SHA256 of <file>. Uses sha256sum (GNU coreutils, present on
# Linux) when available, else shasum -a 256 (present on macOS, which does not
# ship sha256sum). Fails if neither tool is found, so verification never
# silently degrades.
file_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{ print $1 }'
    else
        echo "file_sha256: neither sha256sum nor shasum found; cannot verify download" >&2
        return 1
    fi
}

download_tool() {
    local extra_args=
    local verify_sha256=
    while [[ "${1:-}" == --* ]]; do
        case "$1" in
            --args=*)
                extra_args="${1#--args=}"
                shift
                ;;
            --verify-sha256=*)
                verify_sha256="${1#--verify-sha256=}"
                shift
                ;;
            *)
                echo "download_tool: unknown option: $1" >&2
                return 1
                ;;
        esac
    done

    if [[ $# -lt 2 ]]; then
        echo "usage: download_tool --verify-sha256=SHA256 [--args=ARGS] <url> <dest> [<name>]" >&2
        return 1
    fi
    # Require an integrity hash before fetching anything, so a caller that
    # forgets --verify-sha256 (or passes an empty value) fails closed rather
    # than downloading and running an unverified artifact.
    if [[ -z "$verify_sha256" ]]; then
        echo "download_tool: --verify-sha256 is required with a non-empty hash" >&2
        return 1
    fi
    local url="$1"
    local dest="$2"
    local tmpfile
    mkdir -p "$dest"
    tmpfile=$(mktemp "${dest}.XXXXXX")

    # --http1.1: when running on GitHub in CI, curl sometimes fails with
    # INTERNAL_ERROR after finishing the download. The most common cause of
    # INTERNAL_ERROR is glitches in intermediate hosts' handling of HTTP/2
    # forwarding, so forcing HTTP 1.1 often fixes the issue. See
    # https://github.com/tailscale/tailscale/issues/8988
    if ! curl -f -L --http1.1 --retry 5 --retry-max-time 120 -o "$tmpfile" "$url"; then
        rm -f "$tmpfile"
        return 1
    fi

    local got_sha256=
    got_sha256=$(file_sha256 "$tmpfile")
    if [[ "$got_sha256" != "$verify_sha256" ]]; then
        echo "SHA256 mismatch, want $verify_sha256 got $got_sha256"
        rm -f "$tmpfile"
        return 1
    fi

    if [[ "$url" == *.tar.gz ]]; then
        rm -rf "$dest"
        mkdir -p "$dest"
        if [[ -n "$extra_args" ]]; then
          tar "${extra_args[@]}" -xf "$tmpfile" -C "$dest"
        else
          tar -xf "$tmpfile" -C "$dest"
        fi
        rm -f "$tmpfile"
    elif [[ "$url" == *.zip ]]; then
        rm -rf "$dest"
        mkdir -p "$dest"
        if [[ -n "$extra_args" ]]; then
          unzip -q "${extra_args[@]}" "$tmpfile" -d "$dest"
        else
          unzip -q "$tmpfile" -d "$dest"
        fi
        rm -f "$tmpfile"
    else
        if [[ -n "$extra_args" ]]; then
            echo "download_tool: --args is not permitted for binary downloads" >&2
            rm -f "$tmpfile"
            return 1
        fi
        if [[ $# -lt 3 ]]; then
            echo "usage: download_tool <url> <dest> <name>  (<name> required for non-archive URLs)" >&2
            rm -f "$tmpfile"
            return 1
        fi
        local name="$3"
        chmod +x "$tmpfile"
        mv "$tmpfile" "${dest}/${name}"
    fi
}