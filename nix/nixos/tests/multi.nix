# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# NixOS VM test: multiple Tailscale instances on the same host
# connecting to different Headscale coordination servers.
# Verifies per-instance isolation (sockets, state dirs, service names),
# CLI wrappers, and independent operation.
{
  self,
  pkgs,
  lib,
  headscale,
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-multi-instance";

  nodes = let
    # Distinct prefixes so the client's two instances can't be handed the
    # same address by their independent control servers.
    mkHeadscaleNode = ipv4Prefix: {
      imports = [headscale.nixosModules.testkit];
      services.headscale.settings.prefixes.v4 = ipv4Prefix;
    };
  in {
    headscale1 = mkHeadscaleNode "100.64.0.0/24";
    headscale2 = mkHeadscaleNode "100.64.1.0/24";

    # Client running two Tailscale instances (userspace mode by default)
    client = {
      imports = [self.nixosModules.override];
      services.tailscales = {
        net1.enable = true;
        net2.enable = true;
      };
    };

    # A peer on headscale1's network (TUN mode, single instance)
    peer1 = {
      imports = [self.nixosModules.override];
      services.tailscale = {
        enable = true;
        openFirewall = true;
      };
    };
  };

  testScript = ''
    start_all()

    # Wait for client's tailscaled instances
    client.wait_for_unit("tailscaled-net1.service")
    client.wait_for_unit("tailscaled-net2.service")
    peer1.wait_for_unit("tailscaled.service")

    authkey1 = headscale1.succeed("hs-authkey user1").strip()
    authkey2 = headscale2.succeed("hs-authkey user2").strip()

    # Join client's instances to their respective headscale servers.
    client.succeed(
        f"tailscale-net1 up --login-server http://headscale1 --auth-key {authkey1}"
    )
    client.succeed(
        f"tailscale-net2 up --login-server http://headscale2 --auth-key {authkey2}"
    )

    # Join peer1 to headscale1. Not hs-join: it hardcodes http://headscale
    # and the tailscale CLI rejects a repeated --login-server.
    peer1.succeed(
        f"tailscale up --timeout=60s --login-server http://headscale1 --auth-key {authkey1}"
    )

    # Verify both instances are connected
    client.wait_until_succeeds("tailscale-net1 status", timeout=60)
    client.wait_until_succeeds("tailscale-net2 status", timeout=60)

    # Verify socket isolation
    client.succeed("test -S /run/tailscale-net1/tailscaled.sock")
    client.succeed("test -S /run/tailscale-net2/tailscaled.sock")

    # Verify state directory isolation
    client.succeed("test -d /var/lib/tailscale-net1")
    client.succeed("test -d /var/lib/tailscale-net2")

    # Get tailscale IPs from both instances
    ip_net1 = client.succeed("tailscale-net1 ip -4").strip()
    ip_net2 = client.succeed("tailscale-net2 ip -4").strip()

    # Verify the IPs are different (different tailnets)
    assert ip_net1 != ip_net2, f"Expected different IPs, got {ip_net1} for both"

    # Verify net1 can reach peer1 via tailscale ping
    client.wait_until_succeeds("tailscale-net1 ping peer1", timeout=60)

    # Test that restarting one instance doesn't affect the other
    client.succeed("systemctl restart tailscaled-net1")
    client.wait_for_unit("tailscaled-net1.service")
    client.succeed("tailscale-net2 status")
    client.wait_until_succeeds("tailscale-net1 status", timeout=30)
  '';
}
