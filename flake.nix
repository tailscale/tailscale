# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
# flake.nix describes a Nix source repository that provides
# development builds of Tailscale and the fork of the Go compiler
# toolchain that Tailscale maintains. It also provides a development
# environment for working on tailscale, for use with "nix develop".
#
# For more information about this and why this file is useful, see:
# https://wiki.nixos.org/wiki/Flakes
#
# Also look into direnv: https://direnv.net/, this can make it so that you can
# automatically get your environment set up when you change folders into the
# project.
#
# WARNING: currently, the packages provided by this flake are brittle,
# and importing this flake into your own Nix configs is likely to
# leave you with broken builds periodically.
#
# The issue is that building Tailscale binaries uses the buildGoModule
# helper from nixpkgs. This helper demands to know the content hash of
# all of the Go dependencies of this repo, in the form of a Nix SRI
# hash. This hash isn't automatically kept in sync with changes made
# to go.mod yet, and so every time we update go.mod while hacking on
# Tailscale, this flake ends up with a broken build due to hash
# mismatches.
#
# Right now, this flake is intended for use by Tailscale developers,
# who are aware of this mismatch and willing to live with it. At some
# point, we'll add automation to keep the hashes more in sync, at
# which point this caveat should go away.
#
# See https://github.com/tailscale/tailscale/issues/6845 for tracking
# how to fix this mismatch.
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/default";
    # Used by shell.nix as a compat shim.
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = {
    self,
    nixpkgs,
    systems,
    flake-compat,
  }: let
    goVersion = nixpkgs.lib.fileContents ./go.toolchain.version;
    toolChainRev = nixpkgs.lib.fileContents ./go.toolchain.rev;
    flakeHashes = builtins.fromJSON (builtins.readFile ./flakehashes.json);
    gitHash = flakeHashes.toolchain.sri;
    eachSystem = f:
      nixpkgs.lib.genAttrs (import systems) (system:
        f (import nixpkgs {
          system = system;
          overlays = [
            (final: prev: {
              go_1_26 = prev.go_1_26.overrideAttrs (old: {
                version = goVersion;
                src = prev.fetchFromGitHub {
                  owner = "tailscale";
                  repo = "go";
                  rev = toolChainRev;
                  sha256 = gitHash;
                };
                # The Tailscale Go fork carries a placeholder in
                # src/runtime/debug/mod.go that must be replaced with
                # the actual toolchain git rev at build time. Without
                # this, binaries report an empty tailscale.toolchain.rev
                # and the runtime assertion in
                # assert_ts_toolchain_match.go panics.
                postPatch =
                  (old.postPatch or "")
                  + ''
                    substituteInPlace src/runtime/debug/mod.go \
                      --replace-fail "TAILSCALE_GIT_REV_TO_BE_REPLACED_AT_BUILD_TIME" "${toolChainRev}"
                  '';
              });
            })
          ];
        }));

    # tailscaleRev is the git commit at which this flake was imported,
    # or the empty string when building from a local checkout of the
    # tailscale repo.
    tailscaleRev = self.rev or "";
    lib = nixpkgs.lib;
  in {
    # tailscale takes a nixpkgs package set, and builds Tailscale from
    # the same commit as this flake. IOW, it provides "tailscale built
    # from HEAD", where HEAD is "whatever commit you imported the
    # flake at".
    #
    # This is currently unfortunately brittle, because we have to
    # specify vendorHash, and that sha changes any time we alter
    # go.mod. We don't want to force a nix dependency on everyone
    # hacking on Tailscale, so this flake is likely to have broken
    # builds periodically until someone comes through and manually
    # fixes them up. I sure wish there was a way to express "please
    # just trust the local go.mod, vendorHash has no benefit here",
    # but alas.
    #
    # So really, this flake is for tailscale devs to dogfood with, if
    # you're an end user you should be prepared for this flake to not
    # build periodically.
    packages = eachSystem (pkgs: rec {
      default = pkgs.buildGo126Module {
        name = "tailscale";
        pname = "tailscale";
        meta.mainProgram = "tailscaled";

        src = ./.;
        vendorHash = flakeHashes.vendor.sri;
        nativeBuildInputs = [pkgs.makeWrapper pkgs.installShellFiles];
        ldflags = ["-X tailscale.com/version.gitCommitStamp=${tailscaleRev}"];
        env.CGO_ENABLED = 0;
        subPackages = [
          "cmd/tailscale"
          "cmd/tailscaled"
        ];
        doCheck = false;

        # NOTE: We strip the ${PORT} and $FLAGS because they are unset in the
        # environment and cause issues (specifically the unset PORT). At some
        # point, there should be a NixOS module that allows configuration of these
        # things, but for now, we hardcode the default of port 41641 (taken from
        # ./cmd/tailscaled/tailscaled.defaults).
        postInstall =
          pkgs.lib.optionalString pkgs.stdenv.isLinux ''
            wrapProgram $out/bin/tailscaled --prefix PATH : ${pkgs.lib.makeBinPath [pkgs.iproute2 pkgs.iptables pkgs.getent pkgs.shadow]}
            wrapProgram $out/bin/tailscale --suffix PATH : ${pkgs.lib.makeBinPath [pkgs.procps]}

            sed -i \
              -e "s#/usr/sbin#$out/bin#" \
              -e "/^EnvironmentFile/d" \
              -e 's/''${PORT}/41641/' \
              -e 's/$FLAGS//' \
              ./cmd/tailscaled/tailscaled.service

            install -D -m0444 -t $out/lib/systemd/system ./cmd/tailscaled/tailscaled.service
          ''
          + pkgs.lib.optionalString (pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform) ''
            installShellCompletion --cmd tailscale \
              --bash <($out/bin/tailscale completion bash) \
              --fish <($out/bin/tailscale completion fish) \
              --zsh <($out/bin/tailscale completion zsh)
          '';
      };
      tailscale = default;
    });

    overlays.default = final: prev: {
      tailscale = self.packages.${prev.stdenv.hostPlatform.system}.default;
    };

    nixosModules = {
      tailscale = import ./nixos/default.nix self;
      # Module that disables upstream nixpkgs tailscale and uses this one.
      # This is the recommended import for most users.
      override = {
        imports = [(import ./nixos/default.nix self)];
        # Disable both upstream modules: tailscale.nix defines individual
        # options under services.tailscale.* that conflict with our submodule,
        # and tailscale-derper.nix nests its options under services.tailscale.derper
        # which forces evaluation of our submodule and causes infinite recursion.
        disabledModules = [
          "services/networking/tailscale.nix"
          "services/networking/tailscale-derper.nix"
        ];
      };
      default = self.nixosModules.override;
    };

    checks = eachSystem (pkgs: {
      single = import ./nixos/tests/single.nix {
        inherit self pkgs;
        inherit (pkgs) lib;
      };
      multi = import ./nixos/tests/multi.nix {
        inherit self pkgs;
        inherit (pkgs) lib;
      };
      shared-services = import ./nixos/tests/shared-services.nix {
        inherit self pkgs;
        inherit (pkgs) lib;
      };
    });

    devShells = eachSystem (pkgs: {
      default = pkgs.mkShell {
        packages = with pkgs; [
          curl
          git
          gopls
          gotools
          graphviz
          perl
          go_1_26
          yarn

          # qemu and e2fsprogs are needed for natlab
          qemu
          e2fsprogs
        ];
      };
    });
  };
}
# nix-direnv cache busting line: sha256-ruRbOB2W9snyOYY0+6OD5IndI/JJKqrhTuPlBsKikRc=
