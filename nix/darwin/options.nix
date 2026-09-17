# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Top-level option declarations for the Tailscale nix-darwin module.
# Declares services.tailscales (plural only) — secondary userspace
# tailscaled instances that coexist with the official Tailscale GUI app.
self: {
  lib,
  pkgs,
  ...
}: let
  inherit (lib) literalExpression mkEnableOption mkOption types;

  instanceModule = import ./instance.nix {inherit self lib pkgs;};
in {
  options.services.tailscales = mkOption {
    type = types.attrsOf (types.submodule ({name, ...}: {
      imports = [instanceModule];
    }));
    default = {};
    description = ''
      Multiple Tailscale userspace instances, each managed as a per-user
      launchd LaunchAgent.

      Each attribute name becomes the instance identifier and drives the
      launchd label, state directory, socket path, and CLI wrapper name.

      All instances run in **userspace networking** mode (no TUN, no kernel
      state, no root). This lets them coexist freely with the official
      Tailscale GUI app and with each other.

      Per instance you get:

      - `com.tailscale.tailscaled-<name>` LaunchAgent running tailscaled
      - `tailscale-<name>` CLI wrapper in the system path
      - State under `~/Library/Application Support/Tailscale-<name>`
      - Socket at `~/Library/Caches/Tailscale-<name>/tsd.sock`
      - Logs at `~/Library/Logs/Tailscale-<name>.log`

      Example:
      ```nix
      services.tailscales = {
        headscale = {
          enable = true;
          authKeyFile = "/Users/alice/.config/tailscale/hs.key";
          extraUpFlags = [ "--login-server=https://hs.example.com" ];
        };
        personal.enable = true;
      };
      ```
    '';
    example = literalExpression ''
      {
        headscale = {
          enable = true;
          authKeyFile = "/Users/alice/.config/tailscale/hs.key";
          extraUpFlags = [ "--login-server=https://hs.example.com" ];
        };
        personal.enable = true;
      }
    '';
  };
}
