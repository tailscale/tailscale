# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Config generation for the Tailscale nix-darwin module.
# Produces per-instance LaunchAgents, bootstrap scripts, CLI wrappers,
# and serve-config JSON. All instances run as userspace tailscaled
# under the primary user — no LaunchDaemons, no root.
self: {
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib)
    attrNames
    boolToString
    concatMapStringsSep
    concatStringsSep
    escapeShellArg
    escapeShellArgs
    filterAttrs
    mapAttrs'
    mapAttrsToList
    mkMerge
    nameValuePair
    optionalAttrs
    optionalString
    pipe
    ;

  pluralCfg = config.services.tailscales;
  enabledInstances = filterAttrs (_: cfg: cfg.enable) pluralCfg;

  user = config.system.primaryUser;
  homeDir = "/Users/${user}";

  instanceMeta = name: rec {
    daemonLabel = "com.tailscale.tailscaled-${name}";
    bootstrapLabel = "com.tailscale.tailscale-${name}-bootstrap";
    stateDir = "${homeDir}/Library/Application Support/Tailscale-${name}";
    cacheDir = "${homeDir}/Library/Caches/Tailscale-${name}";
    socketPath = "${cacheDir}/tsd.sock";
    logPath = "${homeDir}/Library/Logs/Tailscale-${name}.log";
    logDir = "${homeDir}/Library/Logs";
    wrapperName = "tailscale-${name}";
  };

  daemonFlags = name: cfg: let
    meta = instanceMeta name;
  in
    escapeShellArgs (
      [
        "--tun=userspace-networking"
        "--statedir=${meta.stateDir}"
        "--socket=${meta.socketPath}"
        "--port=${toString cfg.port}"
      ]
      ++ cfg.extraDaemonFlags
    );

  # Build "?k=v&k=v" query string from non-null authKeyParameters.
  authKeyParams = cfg:
    pipe cfg.authKeyParameters [
      (filterAttrs (_: v: v != null))
      (mapAttrsToList (k: v:
        "${k}=${
          if (builtins.isBool v)
          then (boolToString v)
          else (toString v)
        }"))
      (concatStringsSep "&")
      (params:
        if params != ""
        then "?${params}"
        else "")
    ];

  # Serve config JSON, prefixing "svc:" and omitting null `advertised`.
  mkServeConfigFile = name: servicesAttr:
    pkgs.writeText "tailscale-services-${name}.json"
    (builtins.toJSON {
      version = "0.0.1";
      services =
        mapAttrs' (
          svcName: svcCfg:
            nameValuePair "svc:${svcName}" (
              {inherit (svcCfg) endpoints;}
              // optionalAttrs (svcCfg.advertised != null) {
                inherit (svcCfg) advertised;
              }
            )
        )
        servicesAttr;
    });

  # Wrapper invoked by the daemon LaunchAgent. Creates required
  # directories (launchd has no RuntimeDirectory/StateDirectory),
  # sources optional environment file, then exec's tailscaled.
  mkDaemonScript = name: cfg: let
    meta = instanceMeta name;
    flagsStr = daemonFlags name cfg;
  in
    pkgs.writeShellScript "tailscaled-${name}-launch" ''
      set -eu
      mkdir -p ${escapeShellArg meta.stateDir}
      mkdir -p ${escapeShellArg meta.cacheDir}
      mkdir -p ${escapeShellArg meta.logDir}
      ${optionalString (cfg.environmentFile != null) ''
        if [ -f ${escapeShellArg (toString cfg.environmentFile)} ]; then
          . ${escapeShellArg (toString cfg.environmentFile)}
        fi
      ''}
      exec ${cfg.package}/bin/tailscaled ${flagsStr}
    '';

  # Bootstrap LaunchAgent: replaces the autoconnect / set / serve-config
  # systemd oneshots from the NixOS module. launchd has no After=,
  # so this script polls the socket until the daemon answers, then runs
  # the configuration steps sequentially.
  mkBootstrapScript = name: cfg: let
    meta = instanceMeta name;
    socket = escapeShellArg meta.socketPath;
    params = authKeyParams cfg;
    upFlags = escapeShellArgs cfg.extraUpFlags;
    setFlags = escapeShellArgs cfg.extraSetFlags;
    serveJson =
      if cfg.services != {}
      then mkServeConfigFile name cfg.services
      else null;
    svcNames = attrNames cfg.services;
  in
    pkgs.writeShellScript "tailscale-${name}-bootstrap" ''
      set -eu
      ts=${cfg.package}/bin/tailscale

      # Wait up to 2 minutes for the daemon socket.
      for _ in $(seq 1 120); do
        if "$ts" --socket=${socket} status >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done

      ${optionalString (cfg.authKeyFile != null) ''
        if [ -r ${escapeShellArg (toString cfg.authKeyFile)} ]; then
          key=$(cat ${escapeShellArg (toString cfg.authKeyFile)})
          "$ts" --socket=${socket} up --reset \
            --auth-key "$key${params}" ${upFlags}
        else
          echo "authKeyFile ${toString cfg.authKeyFile} not readable, skipping autoconnect" >&2
        fi
      ''}

      ${optionalString (cfg.extraSetFlags != []) ''
        "$ts" --socket=${socket} set ${setFlags}
      ''}

      ${optionalString (serveJson != null) ''
        "$ts" --socket=${socket} serve set-config --all ${serveJson}
        ${concatMapStringsSep "\n" (svc: ''
          "$ts" --socket=${socket} serve advertise svc:${escapeShellArg svc}'')
        svcNames}
      ''}
    '';

  mkCliWrapper = name: cfg: let
    meta = instanceMeta name;
  in
    pkgs.writeShellScriptBin meta.wrapperName ''
      exec ${cfg.package}/bin/tailscale --socket=${escapeShellArg meta.socketPath} "$@"
    '';

  mkDaemonAgent = name: cfg: let
    meta = instanceMeta name;
    script = mkDaemonScript name cfg;
  in {
    ${meta.daemonLabel} = {
      serviceConfig = {
        Label = meta.daemonLabel;
        ProgramArguments = ["${script}"];
        RunAtLoad = true;
        KeepAlive = true;
        ProcessType = "Background";
        StandardOutPath = meta.logPath;
        StandardErrorPath = meta.logPath;
      };
    };
  };

  mkBootstrapAgent = name: cfg: let
    meta = instanceMeta name;
    script = mkBootstrapScript name cfg;
    needed =
      cfg.authKeyFile
      != null
      || cfg.extraSetFlags != []
      || cfg.services != {};
  in
    optionalAttrs needed {
      ${meta.bootstrapLabel} = {
        serviceConfig = {
          Label = meta.bootstrapLabel;
          ProgramArguments = ["${script}"];
          RunAtLoad = true;
          # Re-run on crash, not on clean exit.
          KeepAlive.SuccessfulExit = false;
          StandardOutPath = meta.logPath;
          StandardErrorPath = meta.logPath;
        };
      };
    };
in {
  config = mkMerge [
    {
      # Socket path must stay under macOS sockaddr_un.sun_path (104).
      # Fail fast at eval time on overlong derived paths.
      assertions = mapAttrsToList (name: _: {
        assertion = builtins.stringLength (instanceMeta name).socketPath < 100;
        message = ''
          services.tailscales.${name}: derived socket path
          "${(instanceMeta name).socketPath}"
          exceeds 100 characters. macOS Unix-socket paths must fit in 104
          bytes (sockaddr_un.sun_path). Pick a shorter instance name.
        '';
      }) enabledInstances;

      launchd.user.agents = mkMerge (
        (mapAttrsToList mkDaemonAgent enabledInstances)
        ++ (mapAttrsToList mkBootstrapAgent enabledInstances)
      );

      environment.systemPackages = mkMerge (
        mapAttrsToList (name: cfg: [
          cfg.package
          (mkCliWrapper name cfg)
        ])
        enabledInstances
      );
    }
  ];
}
