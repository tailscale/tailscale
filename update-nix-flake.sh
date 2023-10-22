#!/bin/sh
# Updates SRI hashes for flake.nix.

set -eu

REV=$(cat go.toolchain.rev)

OUT=$(mktemp -d -t nar-hash-XXXXXX)
rm -rf $OUT

./tool/go mod vendor -o $OUT
./tool/go run tailscale.com/cmd/nardump --sri $OUT >go.mod.sri
rm -rf $OUT

# nix-direnv only watches the top-level nix file for changes. As a
# result, when we change a referenced SRI file, we have to cause some
# change to shell.nix and flake.nix as well, so that nix-direnv
# notices and reevaluates everything. Sigh.
perl -pi -e "s,# nix-direnv cache busting line:.*,# nix-direnv cache busting line: $(cat go.mod.sri)," shell.nix
perl -pi -e "s,# nix-direnv cache busting line:.*,# nix-direnv cache busting line: $(cat go.mod.sri)," flake.nix
