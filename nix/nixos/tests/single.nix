# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# NixOS VM test: single Tailscale instance connecting to Headscale.
# Verifies the basic module functionality, peer-to-peer connectivity,
# and service restart resilience.
{
  self,
  pkgs,
  lib,
  headscale,
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-single-instance";

  nodes = let
    peerConfig = {
      imports = [
        self.nixosModules.override
        headscale.nixosModules.testkit-peer
      ];
      services.tailscale.openFirewall = true;
    };
  in {
    peer1 = peerConfig;
    peer2 = peerConfig;
    headscale.imports = [headscale.nixosModules.testkit];
  };

  testScript = ''
    start_all()

    authkey = headscale.succeed("hs-authkey testuser").strip()

    peer1.succeed(f"hs-join {authkey}")
    peer2.succeed(f"hs-join {authkey}")

    # Verify peer-to-peer connectivity
    peer1.wait_until_succeeds("tailscale ping peer2", timeout=60)
    peer2.wait_until_succeeds("tailscale ping peer1", timeout=60)

    # Verify tailscale status
    peer1.succeed("tailscale status")
    peer2.succeed("tailscale status")

    # Test service restart resilience
    peer1.succeed("systemctl restart tailscaled")
    peer1.wait_for_unit("tailscaled.service")
    peer1.wait_until_succeeds("tailscale ping peer2", timeout=60)
  '';
}
