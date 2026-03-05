# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Config generation for the Tailscale NixOS module.
# Generates systemd services, networking config, and CLI wrappers
# for all enabled Tailscale instances (both singular and plural).
#
# IMPORTANT: This module's config must NOT use `mkMerge (mapAttrsToList ...)`
# at the top-level config structure, as that causes infinite recursion with
# the NixOS module system. Instead, each option path (systemd.services,
# environment.systemPackages, etc.) is assigned directly, with `mkMerge`
# used INSIDE the values to combine singular and plural instance contributions.
# This lets the module system determine which option paths are defined without
# evaluating any thunks that reference config.services.tailscale(s).
self: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib)
    any
    attrValues
    boolToString
    concatMap
    concatStringsSep
    escapeShellArg
    escapeShellArgs
    filterAttrs
    mapAttrsToList
    mkIf
    mkMerge
    mkOverride
    optional
    optionalAttrs
    optionals
    optionalString
    pipe
    ;

  singularCfg = config.services.tailscale;
  pluralCfg = config.services.tailscales;

  # Derive all paths and names for an instance.
  instanceMeta = name: let
    isDefault = name == "default";
  in {
    svcName =
      if isDefault
      then "tailscaled"
      else "tailscaled-${name}";
    stateDir =
      if isDefault
      then "tailscale"
      else "tailscale-${name}";
    runtimeDir =
      if isDefault
      then "tailscale"
      else "tailscale-${name}";
    cacheDir =
      if isDefault
      then "tailscale"
      else "tailscale-${name}";
    socketPath =
      if isDefault
      then "/run/tailscale/tailscaled.sock"
      else "/run/tailscale-${name}/tailscaled.sock";
    wrapperName =
      if isDefault
      then null
      else "tailscale-${name}";
    inherit isDefault;
  };

  # Build the --tun argument based on networking mode.
  tunArg = cfg:
    if cfg.networkingMode == "userspace"
    then "userspace-networking"
    else cfg.interfaceName;

  # Build the full daemon flags list.
  daemonFlags = name: cfg: let
    meta = instanceMeta name;
  in
    [
      "--tun=${tunArg cfg}"
      "--statedir=/var/lib/${meta.stateDir}"
      "--socket=${meta.socketPath}"
    ]
    ++ cfg.extraDaemonFlags;

  # Build auth key query parameters string.
  # Only includes parameters the user explicitly set (non-null).
  authKeyParams = cfg:
    pipe cfg.authKeyParameters [
      (filterAttrs (_: v: v != null))
      (mapAttrsToList (k: v:
        "${k}=${
          if (builtins.isBool v)
          then (boolToString v)
          else (toString v)
        }"))
      (builtins.concatStringsSep "&")
      (params:
        if params != ""
        then "?${params}"
        else "")
    ];

  # Generate systemd services for a single instance.
  mkInstanceServices = name: cfg: let
    meta = instanceMeta name;
    flags = daemonFlags name cfg;
    # For plural instances, merge shared services from the singular config.
    # Per-instance services override shared definitions with the same name.
    effServices =
      if meta.isDefault
      then cfg.services
      else singularCfg.services // cfg.services;
  in
    {
      # ── Main tailscaled daemon ──
      ${meta.svcName} = {
        description =
          "Tailscale node agent"
          + optionalString (!meta.isDefault) " (${name})";
        wantedBy = ["multi-user.target"];
        wants = ["network-pre.target"];
        after =
          [
            "network-pre.target"
            "NetworkManager.service"
            "systemd-resolved.service"
          ]
          ++ optional
          config.networking.networkmanager.enable
          "NetworkManager-wait-online.service";

        path =
          [
            (builtins.dirOf config.security.wrapperDir)
            pkgs.iproute2
            pkgs.iptables
            pkgs.procps
            pkgs.getent
            pkgs.shadow
            pkgs.kmod
          ]
          ++ optional
          config.networking.resolvconf.enable
          config.networking.resolvconf.package;

        serviceConfig =
          {
            ExecStart = concatStringsSep " " ([
                "${cfg.package}/bin/tailscaled"
                "--port=${toString cfg.port}"
              ]
              ++ flags);

            Environment =
              optionals (cfg.permitCertUid != null) [
                "TS_PERMIT_CERT_UID=${cfg.permitCertUid}"
              ]
              ++ optionals cfg.disableTaildrop [
                "TS_DISABLE_TAILDROP=true"
              ]
              ++ optionals cfg.disableUpstreamLogging [
                "TS_NO_LOGS_NO_SUPPORT=true"
              ];

            Restart = "on-failure";
            RuntimeDirectory = meta.runtimeDir;
            RuntimeDirectoryMode = "0755";
            StateDirectory = meta.stateDir;
            StateDirectoryMode = "0700";
            CacheDirectory = meta.cacheDir;
            CacheDirectoryMode = "0750";
            Type = "notify";
          }
          // optionalAttrs cfg.cleanup {
            ExecStopPost = "${cfg.package}/bin/tailscaled --cleanup";
          };

        stopIfChanged = false;
      };
    }
    # ── Auto-connect service (when authKeyFile is set) ──
    // optionalAttrs (cfg.authKeyFile != null) {
      "${meta.svcName}-autoconnect" = {
        description =
          "Tailscale auto-connect"
          + optionalString (!meta.isDefault) " (${name})";
        after = ["${meta.svcName}.service"];
        wants = ["${meta.svcName}.service"];
        wantedBy = ["multi-user.target"];

        serviceConfig = {
          Type = "notify";
        };

        path = [cfg.package pkgs.jq];

        enableStrictShellChecks = true;

        script = let
          socket = escapeShellArg meta.socketPath;
          params = authKeyParams cfg;
          flagsStr = escapeShellArgs cfg.extraUpFlags;
        in ''
          getState() {
            tailscale --socket=${socket} status --json --peers=false | jq -r '.BackendState'
          }

          lastState=""
          while state="$(getState)"; do
            if [[ "$state" != "$lastState" ]]; then
              # https://github.com/tailscale/tailscale/blob/v1.72.1/ipn/backend.go#L24-L32
              case "$state" in
                NeedsLogin|NeedsMachineAuth|Stopped)
                  echo "Server needs authentication, sending auth key"
                  tailscale --socket=${socket} up --auth-key "$(cat ${escapeShellArg (toString cfg.authKeyFile)})${params}" ${flagsStr}
                  ;;
                Running)
                  echo "Tailscale is running"
                  systemd-notify --ready
                  exit 0
                  ;;
                *)
                  echo "Waiting for Tailscale State = Running or systemd timeout"
                  ;;
              esac
              echo "State = $state"
            fi
            lastState="$state"
            sleep .5
          done
        '';
      };
    }
    # ── Set service (when extraSetFlags is set) ──
    // optionalAttrs (cfg.extraSetFlags != []) {
      "${meta.svcName}-set" = {
        description =
          "Tailscale set"
          + optionalString (!meta.isDefault) " (${name})";
        after = [
          "${meta.svcName}.service"
          "${meta.svcName}-autoconnect.service"
        ];
        wants = ["${meta.svcName}.service"];
        wantedBy = ["multi-user.target"];

        serviceConfig.Type = "oneshot";
        path = [cfg.package];

        script = ''
          tailscale --socket=${escapeShellArg meta.socketPath} set ${escapeShellArgs cfg.extraSetFlags}
        '';
      };
    };

  # Generate a CLI wrapper package for a named instance.
  mkCliWrapper = name: cfg: let
    meta = instanceMeta name;
  in
    optionalAttrs (meta.wrapperName != null) {
      ${meta.wrapperName} = pkgs.writeShellScriptBin meta.wrapperName ''
        exec ${cfg.package}/bin/tailscale --socket=${escapeShellArg meta.socketPath} "$@"
      '';
    };
in {
  config = mkMerge [
    # ── Option paths are statically visible here ──
    # The module system can see keys (assertions, systemd, environment,
    # networking) without evaluating any thunks that reference
    # config.services.tailscale(s), avoiding infinite recursion.
    {
      # ── Assertions ──
      # All assertion VALUES are lazy thunks; only evaluated when
      # config.assertions is accessed (after all options are resolved).
      assertions = let
        singularTun =
          singularCfg.enable
          && singularCfg.networkingMode == "tun";
        pluralTunNames = lib.filter (
          name: let
            inst = pluralCfg.${name};
          in
            inst.enable && inst.networkingMode == "tun"
        ) (builtins.attrNames pluralCfg);
        allTunNames =
          (
            if singularTun
            then ["default"]
            else []
          )
          ++ pluralTunNames;
        hasConflictingDefault =
          singularCfg.enable
          && (
            if pluralCfg ? "default"
            then pluralCfg.default.enable
            else false
          );
      in
        [
          {
            assertion = builtins.length allTunNames <= 1;
            message = ''
              At most one Tailscale instance can use TUN networking mode.
              Configured TUN-mode instances: ${concatStringsSep ", " allTunNames}.

              The Tailscale daemon uses hardcoded routing table 52, fwmark
              values (0x40000/0x80000), and iptables chain names (ts-forward,
              ts-input, ts-postrouting) that conflict when multiple
              TUN-mode instances run simultaneously.

              Set `networkingMode = "userspace"` for additional instances.
            '';
          }
          {
            assertion = !hasConflictingDefault;
            message = ''
              Cannot enable both `services.tailscale` and
              `services.tailscales.default` simultaneously. They create
              conflicting instances with the same service name and paths.
            '';
          }
        ]
        ++ (
          if singularCfg.enable
          then [
            {
              assertion =
                singularCfg.networkingMode == "tun"
                || singularCfg.useRoutingFeatures == "none";
              message = ''
                services.tailscale: `useRoutingFeatures` requires
                `networkingMode = "tun"`. Userspace networking does not
                support IP forwarding or subnet routing.
              '';
            }
          ]
          else []
        )
        ++ concatMap (
          name: let
            cfg = pluralCfg.${name};
          in
            if cfg.enable
            then [
              {
                assertion =
                  cfg.networkingMode == "tun"
                  || cfg.useRoutingFeatures == "none";
                message = ''
                  services.tailscales.${name}: `useRoutingFeatures` requires
                  `networkingMode = "tun"`. Userspace networking does not
                  support IP forwarding or subnet routing.
                '';
              }
            ]
            else []
        ) (builtins.attrNames pluralCfg);

      # ── Systemd services (singular + plural merged) ──
      systemd.services = mkMerge [
        (mkIf singularCfg.enable
          (mkInstanceServices "default" singularCfg))
        (mkMerge (mapAttrsToList (
            name: cfg:
              mkIf cfg.enable (mkInstanceServices name cfg)
          )
          pluralCfg))
      ];

      # ── Packages ──
      environment.systemPackages = mkMerge [
        (mkIf singularCfg.enable [singularCfg.package])
        (mkMerge (mapAttrsToList (
            name: cfg:
              mkIf cfg.enable
              ([cfg.package] ++ attrValues (mkCliWrapper name cfg))
          )
          pluralCfg))
      ];

      # ── DHCP exclusion (TUN mode only) ──
      networking.dhcpcd.denyInterfaces = mkMerge [
        (mkIf
          (singularCfg.enable && singularCfg.networkingMode == "tun")
          [singularCfg.interfaceName])
        (mkMerge (mapAttrsToList (
            name: cfg:
              mkIf (cfg.enable && cfg.networkingMode == "tun")
              [cfg.interfaceName]
          )
          pluralCfg))
      ];

      # ── Firewall ──
      networking.firewall.allowedUDPPorts = mkMerge [
        (mkIf
          (singularCfg.enable && singularCfg.openFirewall && singularCfg.port != 0)
          [singularCfg.port])
        (mkMerge (mapAttrsToList (
            name: cfg:
              mkIf (cfg.enable && cfg.openFirewall && cfg.port != 0)
              [cfg.port]
          )
          pluralCfg))
      ];

      # ── systemd-networkd (TUN mode only) ──
      systemd.network.networks = mkMerge [
        (mkIf
          (singularCfg.enable
            && config.networking.useNetworkd
            && singularCfg.networkingMode == "tun")
          {
            "50-tailscale-default" = {
              matchConfig.Name = singularCfg.interfaceName;
              linkConfig = {
                Unmanaged = true;
                ActivationPolicy = "manual";
              };
            };
          })
        (mkMerge (mapAttrsToList (
            name: cfg:
              mkIf
              (cfg.enable
                && config.networking.useNetworkd
                && cfg.networkingMode == "tun")
              {
                "50-tailscale-${name}" = {
                  matchConfig.Name = cfg.interfaceName;
                  linkConfig = {
                    Unmanaged = true;
                    ActivationPolicy = "manual";
                  };
                };
              }
          )
          pluralCfg))
      ];
    }

    # ── Global IP forwarding (conditional on any instance needing it) ──
    (mkIf (let
      singularNeeds =
        singularCfg.enable
        && (singularCfg.useRoutingFeatures == "server"
          || singularCfg.useRoutingFeatures == "both");
      pluralNeeds = any
        (inst:
          inst.enable
          && (inst.useRoutingFeatures == "server"
            || inst.useRoutingFeatures == "both"))
        (attrValues pluralCfg);
    in
      singularNeeds || pluralNeeds) {
      boot.kernel.sysctl = {
        "net.ipv4.conf.all.forwarding" = mkOverride 97 true;
        "net.ipv6.conf.all.forwarding" = mkOverride 97 true;
      };
    })

    # ── Reverse path filtering (conditional) ──
    (mkIf (let
      singularNeeds =
        singularCfg.enable
        && (singularCfg.useRoutingFeatures == "client"
          || singularCfg.useRoutingFeatures == "both");
      pluralNeeds = any
        (inst:
          inst.enable
          && (inst.useRoutingFeatures == "client"
            || inst.useRoutingFeatures == "both"))
        (attrValues pluralCfg);
    in
      singularNeeds || pluralNeeds) {
      networking.firewall.checkReversePath = "loose";
    })
  ];
}
