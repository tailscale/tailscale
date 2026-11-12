# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# NixOS VM test: services.tailscale.derper under the override module.
# Verifies the derper unit serves and verifyClients enables tailscaled.
{
  self,
  pkgs,
  lib,
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-derper";

  nodes.machine = {
    imports = [self.nixosModules.override];
    services.tailscale.derper = {
      enable = true;
      domain = "derp.test";
      # nginx would need a certificate; derper itself is under test.
      configureNginx = false;
      verifyClients = true;
    };
  };

  testScript = ''
    machine.wait_for_unit("tailscale-derper.service")
    machine.wait_for_unit("tailscaled.service")
    machine.wait_for_open_port(8010)
  '';
}
