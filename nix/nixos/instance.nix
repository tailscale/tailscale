# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Per-instance option definitions for a Tailscale daemon.
# Used as a submodule by both:
#   services.tailscale       (singular, backward-compatible)
#   services.tailscales.<n>  (plural, attrsOf submodule)
#
# Receives `self`, `lib`, and `pkgs` from the importing module
# via closure (see options.nix).
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
    enable = mkEnableOption "Tailscale client daemon";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.tailscale;
      defaultText = literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.tailscale";
      description = "The Tailscale package to use.";
    };

    port = mkOption {
      type = types.port;
      default = 41641;
      description = ''
        UDP port for incoming WireGuard tunnel traffic.
        Set to 0 for automatic port selection.
        When running multiple instances, each must use a unique port or 0.
      '';
    };

    interfaceName = mkOption {
      type = types.str;
      default = "tailscale0";
      description = ''
        Name of the TUN network interface.
        Only used when `networkingMode` is `"tun"`.
        Each TUN-mode instance must have a unique interface name.
      '';
    };

    networkingMode = mkOption {
      type = types.enum ["tun" "userspace"];
      default = "tun";
      description = ''
        Networking mode for this Tailscale instance.

        `"tun"` creates a TUN device and manages routes via the system
        routing table. This provides full functionality (exit nodes, subnet
        routers, MagicDNS, etc.) but only **one** TUN-mode instance can
        run at a time due to hardcoded routing table number (52), fwmark
        values, and iptables/nftables chain names in the Tailscale daemon.

        `"userspace"` does not create a network interface. Multiple
        userspace instances can coexist safely. Userspace mode provides a
        SOCKS5/HTTP proxy for accessing the tailnet instead of system-level
        routing.

        See <https://tailscale.com/kb/1112/userspace-networking>
      '';
    };

    proxy = mkOption {
      type = types.nullOr (types.enum ["off" "socks" "http" "both"]);
      default = null;
      example = "socks";
      description = ''
        Run an outbound proxy for accessing the tailnet without a TUN
        interface (the usual access method in userspace networking mode,
        also works in tun mode).

        `null` or `"off"` disables it. `"socks"` runs a SOCKS5 server,
        `"http"` an outbound HTTP proxy, `"both"` runs both on the same
        `proxyListenAddress` (tailscaled routes SOCKS-looking connections
        to SOCKS and the rest to HTTP).

        Run `tailscale-proxies` on the host to list the active proxy
        addresses across all instances.

        See <https://tailscale.com/kb/1112/userspace-networking>
      '';
    };

    proxyListenAddress = mkOption {
      type = types.str;
      default = "localhost:1055";
      example = "0.0.0.0:1055";
      description = ''
        `[ip]:port` the proxy binds to. Both proxies share this address
        when `proxy = "both"`. Defaults to localhost to keep it off the
        wire. Must be unique across enabled instances.
      '';
    };

    permitCertUid = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = ''
        Username or UID allowed to fetch Tailnet TLS certificates
        via `tailscale cert`.
      '';
    };

    disableTaildrop = mkOption {
      type = types.bool;
      default = false;
      description = "Disable Tailscale Taildrop file sending/receiving.";
    };

    disableUpstreamLogging = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Disable upstream debug logging to Tailscale's log server.
        Equivalent to passing `--no-logs-no-support` to the daemon.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Open the firewall for Tailscale's UDP port.
        Recommended to allow direct WireGuard connections.
      '';
    };

    useRoutingFeatures = mkOption {
      type = types.enum [
        "none"
        "client"
        "server"
        "both"
      ];
      default = "none";
      example = "server";
      description = ''
        Enables settings required for Tailscale's routing features like
        subnet routers and exit nodes.

        To use these features, you will still need to call
        `tailscale up --advertise-exit-node` or similar.

        When set to `"client"` or `"both"`, reverse path filtering will be
        set to loose instead of strict.

        When set to `"server"` or `"both"`, IP forwarding will be enabled.

        Only effective when `networkingMode` is `"tun"`.

        See <https://tailscale.com/kb/1019/subnets#enable-ip-forwarding>
        See <https://github.com/tailscale/tailscale/issues/3310>
      '';
    };

    authKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/tailscale_key";
      description = ''
        Path to a file containing a Tailscale auth key. When set, the
        instance will automatically authenticate on startup via a
        `tailscaled-autoconnect` oneshot service.
      '';
    };

    authKeyParameters = mkOption {
      description = ''
        Extra parameters to append to the auth key.
        See <https://tailscale.com/kb/1215/oauth-clients#registering-new-nodes-using-oauth-credentials>
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
      example = ["--ssh" "--accept-routes"];
      description = ''
        Extra flags to pass to `tailscale up`.
        Only used when `authKeyFile` is set.
      '';
    };

    extraSetFlags = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["--advertise-exit-node" "--shields-up"];
      description = "Extra flags to pass to `tailscale set`.";
    };

    extraDaemonFlags = mkOption {
      type = types.listOf types.str;
      default = [];
      example = ["--verbose=1"];
      description = "Extra flags to pass to the `tailscaled` daemon.";
    };

    cleanup = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Whether to run `tailscaled --cleanup` on service stop to remove
        iptables rules, routes, and the TUN device.
      '';
    };

    services = mkOption {
      type = types.attrsOf (types.submodule {
        options = {
          endpoints = mkOption {
            type = types.attrsOf types.str;
            description = ''
              Endpoint mappings for this service.

              Keys use the format `"tcp:PORT"` or `"tcp:START-END"` for
              port ranges. Only TCP is supported as the transport protocol.

              Values specify the local target using a URI:
              `"http://host:port"`, `"https://host:port"`,
              `"https+insecure://host:port"`, `"tcp://host:port"`,
              or `"tls-terminated-tcp://host:port"`.
            '';
            example = {
              "tcp:443" = "https://localhost:8443";
              "tcp:5432" = "tcp://localhost:5432";
            };
          };

          advertised = mkOption {
            type = types.nullOr types.bool;
            default = null;
            description = ''
              Whether the service accepts new connections.
              When null (the default), the service is advertised.
              Set to false to configure endpoints without advertising.
            '';
          };
        };
      });
      default = {};
      description = ''
        Tailscale Services configuration. Service names are specified
        without the `svc:` prefix (it is added automatically).

        When using `services.tailscales` (multi-instance), any services
        defined under `services.tailscale.services` are automatically
        merged into all plural instances as shared services. Per-instance
        services with the same name take precedence over shared ones.

        Services must be pre-defined in the Tailscale admin console.
        The host must use tag-based identity.

        See <https://tailscale.com/docs/features/tailscale-services>
      '';
      example = literalExpression ''
        {
          prometheus = {
            endpoints."tcp:443" = "http://localhost:9090";
          };
          postgres = {
            endpoints."tcp:5432" = "tcp://localhost:5432";
          };
        }
      '';
    };
  };
}
