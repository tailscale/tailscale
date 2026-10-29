# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# services.tailscale.derper, ported from nixpkgs' tailscale-derper.nix.
# Upstream sets services.tailscale.enable from a top-level mkIf on its own
# options, which recurses through our services.tailscale submodule, so the
# options and that definition live inside the submodule instead.
self: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) literalExpression mkEnableOption mkIf mkOption types;

  cfg = config.services.tailscale.derper;
in {
  options.services.tailscale = mkOption {
    type = types.submodule ({config, ...}: {
      options.derper = {
        enable = mkEnableOption "Tailscale Derper. See upstream doc <https://tailscale.com/kb/1118/custom-derp-servers> how to configure it on clients";

        domain = mkOption {
          type = types.str;
          description = "Domain name under which the derper server is reachable.";
        };

        configureNginx = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether to enable nginx reverse proxy for derper.
            When enabled, nginx will proxy requests to the derper service.
          '';
        };

        openFirewall = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether to open the firewall for the specified port.
            Derper requires the used ports to be opened, otherwise it doesn't work as expected.
          '';
        };

        package = mkOption {
          type = types.package;
          default = self.packages.${pkgs.stdenv.hostPlatform.system}.derper;
          defaultText = literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.derper";
          description = "The derper package to use.";
        };

        stunPort = mkOption {
          type = types.port;
          default = 3478;
          description = ''
            STUN port to listen on.
            See online docs <https://tailscale.com/kb/1118/custom-derp-servers#prerequisites> on how to configure a different external port.
          '';
        };

        port = mkOption {
          type = types.port;
          default = 8010;
          description = "The port the derper process will listen on. This is not the port tailscale will connect to.";
        };

        verifyClients = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Whether to verify clients against a locally running tailscale daemon if they are allowed to connect to this node or not.
          '';
        };
      };

      config.enable = mkIf (config.derper.enable && config.derper.verifyClients) true;
    });
  };

  config = mkIf cfg.enable {
    networking.firewall = mkIf cfg.openFirewall {
      # port 80 and 443 are opened by nginx already when configureNginx is true
      allowedUDPPorts = [cfg.stunPort];
    };

    services.nginx = mkIf cfg.configureNginx {
      enable = true;
      virtualHosts."${cfg.domain}" = {
        addSSL = true; # this cannot be forceSSL as derper sends some information over port 80, too.
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString cfg.port}";
          proxyWebsockets = true;
          extraConfig = ''
            proxy_buffering off;
            proxy_read_timeout 3600s;
          '';
        };
      };
    };

    systemd.services.tailscale-derper = {
      serviceConfig = {
        ExecStart =
          "${cfg.package}/bin/derper -a :${toString cfg.port} -c /var/lib/derper/derper.key -hostname=${cfg.domain} -stun-port ${toString cfg.stunPort}"
          + lib.optionalString cfg.verifyClients " -verify-clients";
        DynamicUser = true;
        Restart = "always";
        RestartSec = "5sec"; # don't crash loop immediately
        StateDirectory = "derper";
        Type = "simple";

        CapabilityBoundingSet = [""];
        DeviceAllow = null;
        LockPersonality = true;
        NoNewPrivileges = true;
        MemoryDenyWriteExecute = true;
        PrivateDevices = true;
        PrivateUsers = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = ["@system-service"];
      };
      wantedBy = ["multi-user.target"];
    };
  };
}
