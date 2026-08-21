# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Test flake for the macOS multi-instance Tailscale module.
# Consumed by run.sh on a macOS CI runner. Lives in its own flake so the
# parent tailscale flake does not take a runtime dependency on nix-darwin.
{
  inputs = {
    parent.url = "path:../../../..";
    nix-darwin = {
      url = "github:LnL7/nix-darwin";
      inputs.nixpkgs.follows = "parent/nixpkgs";
    };
  };

  outputs = {
    nix-darwin,
    parent,
    ...
  }: let
    mkSystem = system:
      nix-darwin.lib.darwinSystem {
        inherit system;
        modules = [
          parent.darwinModules.default
          ({...}: {
            system.primaryUser = "runner";
            # Required by recent nix-darwin to bound state-version compat.
            system.stateVersion = 5;
            # DeterminateSystems Nix manages the install itself; let
            # nix-darwin stand aside on /etc/nix/nix.conf and friends.
            nix.enable = false;
            services.tailscales = {
              alpha = {
                enable = true;
                authKeyFile = "/tmp/ts-ci/alpha.key";
                extraUpFlags = ["--login-server=http://127.0.0.1:8080"];
              };
              beta = {
                enable = true;
                authKeyFile = "/tmp/ts-ci/beta.key";
                extraUpFlags = ["--login-server=http://127.0.0.1:8080"];
              };
            };
          })
        ];
      };
  in {
    darwinConfigurations = {
      ci-mac-aarch64 = mkSystem "aarch64-darwin";
      ci-mac-x86_64 = mkSystem "x86_64-darwin";
    };
  };
}
