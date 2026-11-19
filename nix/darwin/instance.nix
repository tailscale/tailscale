# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Per-instance options for a userspace Tailscale daemon under launchd.
# Used as a submodule by services.tailscales.<name>.
{
  self,
  lib,
  pkgs,
}: let
  inherit (lib)
    literalExpression
    mkEnableOption
    mkOption
    types
    ;
in {
  options = {
    enable = mkEnableOption "Tailscale userspace instance";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.tailscale;
      defaultText = literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.tailscale";
      description = "Tailscale package providing tailscaled and tailscale.";
    };

    port = mkOption {
      type = types.port;
      default = 0;
      description = ''
        UDP port for incoming WireGuard tunnel traffic.
        Default 0 (automatic). Each instance needs a unique port or 0.
      '';
    };

    authKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/Users/alice/.config/tailscale/personal.key";
      description = ''
        Path to a file containing a Tailscale auth key. When set, the
        instance will run `tailscale up` on startup via a bootstrap
        LaunchAgent.

        The file must be readable by the user running the agent. Keep
        the file outside the Nix store and chmod 600.
      '';
    };

    authKeyParameters = mkOption {
      description = ''
        Extra parameters appended to the auth key as URL query string.
        See <https://tailscale.com/kb/1215/oauth-clients#registering-new-nodes-using-oauth-credentials>.
      '';
      type = types.submodule {
        options = {
          ephemeral = mkOption {
            type = types.nullOr types.bool;
            default = null;
            description = "Whether to register as an ephemeral node.";
          };
          preauthorized = mkOption {
            type = types.nullOr types.bool;
            default = null;
            description = "Whether to skip manual device approval.";
          };
          baseURL = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Base URL of the coordination server.";
          };
        };
      };
      default = {};
    };

    extraUpFlags = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["--login-server=https://hs.example.com" "--hostname=mac"];
      description = ''
        Extra flags to pass to `tailscale up`.
        Only used when `authKeyFile` is set.
      '';
    };

    extraSetFlags = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["--accept-routes"];
      description = "Extra flags to pass to `tailscale set`.";
    };

    extraDaemonFlags = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["--verbose=1"];
      description = "Extra flags to pass to `tailscaled`.";
    };

    environmentFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Optional shell-format file sourced before exec'ing tailscaled.
        Useful for setting `TS_*` environment variables without baking
        them into the Nix store.
      '';
    };

    services = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          endpoints = mkOption {
            type = types.attrsOf types.str;
            description = ''
              Endpoint mappings for this Tailscale Service.

              Keys use `"tcp:PORT"` or `"tcp:START-END"`. Values use
              `"http://host:port"`, `"https://host:port"`,
              `"https+insecure://host:port"`, `"tcp://host:port"`, or
              `"tls-terminated-tcp://host:port"`.
            '';
            example = {
              "tcp:443" = "https://localhost:8443";
            };
          };

          advertised = mkOption {
            type = types.nullOr types.bool;
            default = null;
            description = ''
              Whether the service accepts new connections.
              When null (the default), the service is advertised.
            '';
          };
        };
      });
      default = {};
      description = ''
        Tailscale Services configuration. Service names are without the
        `svc:` prefix (it is added automatically).

        Services must be pre-defined in the Tailscale admin console.
        The host must use tag-based identity.

        See <https://tailscale.com/docs/features/tailscale-services>.
      '';
      example = literalExpression ''
        {
          prometheus.endpoints."tcp:443" = "http://localhost:9090";
        }
      '';
    };
  };
}
