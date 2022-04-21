# TODO(tom): Use system nixpkgs exclusively once 1.18 is in a stable release.
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

{
	pkgs ? import <nixpkgs> {},
	nixosUnstable ? import (fetchTarball https://github.com/NixOS/nixpkgs/archive/refs/heads/nixpkgs-unstable.tar.gz) { },
	tailscale-go-rev ? "710a0d861098c07540ad073bb73a42ce81bf54a8",
	tailscale-go-sha ? "sha256-hnyddxiyqMFHGwV3I4wkBcYNd56schYFi0SL5/0PnMI=",
}:
let
	tailscale-go = pkgs.lib.overrideDerivation nixosUnstable.go_1_18 (attrs: rec {
		name = "tailscale-go-${version}";
		version = tailscale-go-rev;
		src = pkgs.fetchFromGitHub {
		  owner = "tailscale";
		  repo = "go";
		  rev = tailscale-go-rev;
		  sha256 = tailscale-go-sha;
		};
		nativeBuildInputs = attrs.nativeBuildInputs ++ [ pkgs.git ];
		# Remove dependency on xcbuild as that causes iOS/macOS builds to fail.
		propagatedBuildInputs = [];
		checkPhase = "";
		# Our forked tailscale reads this env var to embed the git hash
		# into the Go build version.
		TAILSCALE_TOOLCHAIN_REV = tailscale-go-rev;
	});
in
	pkgs.mkShell {
	  # This specifies the tools that are needed for people to get started with
	  # development. These tools include:
	  #  - The Go compiler toolchain (and all additional tooling with it)
	  #  - gotools for goimports, a robust formatting tool for Go source code
	  #  - gopls, the language server for Go to increase editor integration
	  #  - git, the version control program (used in some scripts)
	  buildInputs = [
	    pkgs.git
	    nixosUnstable.gotools nixosUnstable.gopls
	    tailscale-go
	  ];
	}
