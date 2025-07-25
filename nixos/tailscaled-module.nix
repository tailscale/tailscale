{
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

    port = mkOption {
      type = types.port;
      default = 41641;
      description = "The port Tailscale listens on.";
    };
  };
}
