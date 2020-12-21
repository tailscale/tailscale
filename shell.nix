# This is a shell.nix file used to describe the environment that tailscale needs
# for development. This includes a lot of the basic tools that you need in order
# to get started. We hope this file will be useful for users of Nix on macOS or
# Linux.
#
# For more information about this and why this file is useful, see here:
# https://nixos.org/guides/nix-pills/developing-with-nix-shell.html
#
# Also look into direnv: https://direnv.net/, this can make it so that you can
# automatically get your environment set up when you change folders into the
# project.
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  # This specifies the tools that are needed for people to get started with
  # development. These tools include:
  #  - The Go compiler toolchain (and all additional tooling with it)
  #  - goimports, a robust formatting tool for Go source code
  #  - gopls, the language server for Go to increase editor integration
  #  - git, the version control program (used in some scripts)
  buildInputs = with pkgs; [
    go goimports gopls git
  ];
}
