# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Top-level option declarations for the Tailscale NixOS module.
# Declares both services.tailscale (singular) and services.tailscales (plural).
self: {
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkDefault mkOption types;

  instanceModule = import ./instance.nix {inherit self lib pkgs;};
in {
  options = {
    services.tailscale = mkOption {
      type = types.submodule {
        imports = [instanceModule];
      };
      default = {};
      description = ''
        Tailscale VPN client daemon (single instance).
        Backward-compatible with the upstream nixpkgs module.
        For running multiple Tailscale instances, use
        `services.tailscales` instead.
      '';
    };

    services.tailscales = mkOption {
      type = types.attrsOf (types.submodule ({name, ...}: {
        imports = [instanceModule];
        # Override defaults for multi-instance safety.
        config = {
          port = mkDefault 0;
          networkingMode = mkDefault "userspace";
          interfaceName = mkDefault "ts-${name}";
        };
      }));
      default = {};
      description = ''
        Multiple Tailscale VPN instances. Each attribute name becomes the
        instance identifier, used to derive systemd service names, state
        directories, and CLI wrapper names.

        Instances default to userspace networking mode to avoid conflicts
        with resources shared by the TUN interface (routing table 52,
        fwmarks, iptables chains).

        Example:
        ```nix
        services.tailscales = {
          personal = {
            enable = true;
            authKeyFile = "/run/secrets/personal-ts-key";
          };
          work = {
            enable = true;
            authKeyFile = "/run/secrets/work-ts-key";
            extraUpFlags = [ "--login-server=https://hs.work.com" ];
          };
        };
        ```
      '';
    };
  };
}
