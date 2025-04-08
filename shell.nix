# This is a shell.nix file used to describe the environment that
# tailscale needs for development.
#
# For more information about this and why this file is useful, see here:
# https://nixos.org/guides/nix-pills/developing-with-nix-shell.html
#
# Also look into direnv: https://direnv.net/, this can make it so that you can
# automatically get your environment set up when you change folders into the
# project.
(import (
  let
    lock = builtins.fromJSON (builtins.readFile ./flake.lock);
  in fetchTarball {
    url = "https://github.com/edolstra/flake-compat/archive/${lock.nodes.flake-compat.locked.rev}.tar.gz";
    sha256 = lock.nodes.flake-compat.locked.narHash; }
) {
  src =  ./.;
}).shellNix
# nix-direnv cache busting line: sha256-av4kr09rjNRmag94ziNjJuI/cg8b8lAD3Tk24t/ezH4=
