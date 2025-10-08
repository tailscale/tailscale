#!/bin/sh
# Updates SRI hashes for flake.nix.

set -eu

OUT=$(mktemp -d -t nar-hash-XXXXXX)
rm -rf "$OUT"

./tool/go mod vendor -o "$OUT"
./tool/go run tailscale.com/cmd/nardump --sri "$OUT" >go.mod.sri
rm -rf "$OUT"

GOOUT=$(mktemp -d -t gocross-XXXXXX)
GOREV=$(xargs < ./go.toolchain.rev)
TARBALL="$GOOUT/go-$GOREV.tar.gz"
curl -Ls -o "$TARBALL" "https://github.com/tailscale/go/archive/$GOREV.tar.gz"
tar -xzf "$TARBALL" -C "$GOOUT"
./tool/go run tailscale.com/cmd/nardump --sri "$GOOUT/go-$GOREV" > go.toolchain.rev.sri
rm -rf "$GOOUT"

# nix-direnv only watches the top-level nix file for changes. As a
# result, when we change a referenced SRI file, we have to cause some
# change to shell.nix and flake.nix as well, so that nix-direnv
# notices and reevaluates everything. Sigh.
perl -pi -e "s,# nix-direnv cache busting line:.*,# nix-direnv cache busting line: $(cat go.mod.sri)," shell.nix
perl -pi -e "s,# nix-direnv cache busting line:.*,# nix-direnv cache busting line: $(cat go.mod.sri)," flake.nix
