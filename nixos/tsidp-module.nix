self: {
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.tsidp;
  inherit
    (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
in {
  # tsidp config options
  options.services.tsidp = {
    enable = mkEnableOption "Enable tsidp service";

    dataDir = mkOption {
      type = types.path;
      default = "/var/lib/tsidp";
      description = "Directory where tsidp stores its data.";
    };

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.system}.tailscale;
      description = "The Tailscale package to use for tsidp.";
    };

    hostname = mkOption {
      type = types.str;
      default = "tsidp";
      description = "The hostname for the tsidp service appears as on the tailnet.";
    };

    funnel = mkOption {
      type = types.bool;
      default = false;
      description = "Use Tailscale Funnel to make tsidp available on the public internet.";
    };

    useLocalTailscale = mkOption {
      type = types.bool;
      default = false;
      description = "Use local tailscaled instead of tsnet.";
    };

    port = mkOption {
      type = types.nullOr types.port;
      default = null;
      description = "The port on which tsidp listens for incoming connections.";
    };

    localPort = mkOption {
      type = types.nullOr types.ints.s16;
      default = null;
      description = "The local port on which tsidp listens for incoming connections on localhost.";
    };

    verbose = mkOption {
      type = types.bool;
      default = false;
      description = "Enable verbose logging for tsidp.";
    };

    serviceRestartMode = mkOption {
      type = types.enum [
        "always"
        "on-failure"
      ];
      default = "always";
      description = "The systemd service restart mode for tsidp.";
    };

    serviceRestartInterval = mkOption {
      type = types.int;
      default = 5;
      description = "Systemd RestartSec for tsidp service.";
    };

    user = mkOption {
      type = types.str;
      default = "tsidp";
      description = "The user under which the tsidp service runs.";
    };

    group = mkOption {
      type = types.str;
      default = "tsidp";
      description = "The group under which the tsidp service runs.";
    };
  };

  config = mkIf cfg.enable {
    # tsidp service configuration
    users.users = mkIf (config.services.tsidp.user == "tsidp") {
      tsidp = {
        name = "tsidp";
        group = cfg.group;
        isSystemUser = true;
        description = "Tailscale Identity Provider (tsidp) User.";
      };
    };
    users.groups = mkIf (cfg.group == "tsidp") {tsidp = {};};

    systemd.services.tsidp = {
      description = "Tailscale Identity Provider (tsidp)";
      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      after = ["network-online.target"];
      environment = {
        TAILSCALE_USE_WIP_CODE = "1";
      };
      serviceConfig = {
        Type = "simple";
        Restart = "${cfg.serviceRestartMode}";
        RestartSec = cfg.serviceRestartInterval;
        StateDirectory = "tsidp";
        User = "${cfg.user}";
        ExecStart = "${cfg.pkg}/bin/tsidp --dir ${cfg.dataDir} --hostname ${cfg.hostname}${lib.optionalString cfg.verbose " --verbose"}${lib.optionalString cfg.funnel " --funnel"}${lib.optionalString cfg.useLocalTailscale " --use-local-tailscaled"}${lib.optionalString (cfg.port != null) " --port ${builtins.toString cfg.port}"}${lib.optionalString (cfg.localPort != null) " --local-port ${builtins.toString cfg.localPort}"}";
      };
    };
  };
}
