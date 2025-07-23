self: {
  config,
  lib,
  ...
}: let
  cfg = config.services.tailscale;
  inherit
    (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;
in {
  # Tailscale config options
  options.services.tailscale = {
    enable = mkEnabledOption "Enable Tailscale service";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.system}.tailscale;
      description = "The Tailscale package to use.";
    };

    port = mkOption {
      type = types.port;
      default = 41641;
      description = "The port Tailscale listens on.";
    };

    interface = mkOption {
      type = types.str;
      default = "tailscale0";
      description = "The network interface Tailscale uses.";
    };

    permitCertUid = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = "Username or UID allowed to fetch tailnet TLS certificates";
    };

    disableTaildrop = mkOption {
      type = types.bool;
      default = false;
      description = "Disable Tailscale Taildrop feature.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open the firewall for Tailscale traffic. Recommended true to allow for direct connections.";
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
        Enables settings required for Tailscale's routing features like subnet routers and exit nodes.

        To use these these features, you will still need to call `sudo tailscale up` with the relevant flags like `--advertise-exit-node` and `--exit-node`.

        When set to `client` or `both`, reverse path filtering will be set to loose instead of strict.
        When set to `server` or `both`, IP forwarding will be enabled allowing proper packet forwarding for exit node or subnet router functionality.

        See https://tailscale.com/kb/1019/subnets#enable-ip-forwarding for packet forwarding
        See https://github.com/tailscale/tailscale/issues/3310 for reverse path filtering
      '';
    };

    authKeyFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/run/secrets/tailscale_key";
      description = ''
        Path to a file containing a Tailscale auth key. If set, this will be used to automatically authenticate the Tailscale client.
        The file should contain a single line with the auth key.
        This is useful for automated setups where you want to avoid manual authentication.
      '';
    };

    extraUpFlags = mkOption {
      description = ''
        Extra flags to pass to {command}`tailscale up`. Only applied if `authKeyFile` is specified.";
      '';
      type = types.listOf types.str;
      default = [];
      example = ["--ssh" "--accept-routes"];
    };

    extraSetFlags = mkOption {
      description = "Extra flags to pass to {command}`tailscale set`.";
      type = types.listOf types.str;
      default = [];
      example = ["--advertise-exit-node" "--shields-up"];
    };

    extraDaemonFlags = mkOption {
      description = "Extra flags to pass to {command}`tailscaled`.";
      type = types.listOf types.str;
      default = [];
      example = ["--no-logs-no-support" "-encrypt-state"];
    };

    RuntimeDirectory = mkOption {
      type = types.str;
      default = "tailscale";
      description = "The runtime directory for Tailscale. This is where Tailscale will store its state.";
    };

    StateDirectory = mkOption {
      type = types.str;
      default = "tailscale";
      description = "The state directory for Tailscale. This is where Tailscale will store its persistent state.";
    };

    CacheDirectory = mkOption {
      type = types.str;
      default = "tailscale";
      description = "The cache directory for Tailscale. This is where Tailscale will store its cache.";
    };

    Cleanup = mkOption {
      type = types.bool;
      default = true;
      description = "Whether to clean up Tailscale state on post stop.";
    };
  };

  config = mkIf cfg.enable {
    environment.systemPackages = [cfg.package];

    boot.kernel.sysctl = mkIf (cfg.useRoutingFeatures == "server" || cfg.useRoutingFeatures == "both") {
      "net.ipv4.conf.all.forwarding" = mkOverride 97 true;
      "net.ipv6.conf.all.forwarding" = mkOverride 97 true;
    };

    networking.firewall.allowedUDPPorts = mkIf cfg.openFirewall [cfg.port];

    networking.firewall.checkReversePath = mkIf (
      cfg.useRoutingFeatures == "client" || cfg.useRoutingFeatures == "both"
    ) "loose";

    networking.dhcpcd.denyInterfaces = [cfg.interfaceName];

    systemd.network.networks."50-tailscale" = mkIf config.networking.useNetworkd {
      matchConfig = {
        Name = cfg.interfaceName;
      };
      linkConfig = {
        Unmanaged = true;
        ActivationPolicy = "manual";
      };
    };

    systemd.packages = [cfg.package];
    systemd.services.tailscaled = {
      wantedBy = ["multi-user.target"];
      wants = ["network-pre.target"];
      after = ["network-pre.target" "NetworkManager.service" "systemd-resolved.service"];
      path =
        [
          (builtins.dirOf config.security.wrapperDir)
          pkgs.iproute2
          pkgs.procps
          pkgs.getent
          pkgs.shadow
        ]
        ++ lib.optional config.networking.resolvconf.enable config.networking.resolvconf.package;

      serviceConfig = {
        Environment =
          [
            "PORT=${toString cfg.port}"
            ''"FLAGS=--tun ${lib.escapeShellArg cfg.interfaceName} ${lib.concatStringsSep " " cfg.extraDaemonFlags}" ${lib.optionalString (cfg.authKeyFile != null) " --auth-key file:${cfg.authKeyFile}"}''
          ]
          ++ (lib.optionals (cfg.permitCertUid != null) [
            "TS_PERMIT_CERT_UID=${cfg.permitCertUid}"
          ])
          ++ (lib.optionals (cfg.disableTaildrop) [
            "TS_DISABLE_TAILDROP=true"
          ]);

        Restart = "on-failure";
        StateDirectory = cfg.StateDirectory;
        StateDirectoryMode = "0700";
        RuntimeDirectory = cfg.RuntimeDirectory;
        RuntimeDirectoryMode = "0755";
        CacheDirectory = cfg.CacheDirectory;
        CacheDirectoryMode = "0750";
        Type = "notify";
      };

      stopIfChanged = false;
    };

    systemd.services.tailscaled-set = mkIf (cfg.extraSetFlags != []) {
      after = ["tailscaled.service"];
      wants = ["tailscaled.service"];
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        Type = "oneshot";
      };
      script = ''
        ${lib.getExe cfg.package} set ${escapeShellArgs cfg.extraSetFlags}
      '';
    };
  };
}
