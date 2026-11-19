# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# NixOS VM test: single Tailscale instance connecting to Headscale.
# Verifies the basic module functionality, unattended join through
# autoconnect with set and serve-config applied (at boot, after logout and
# after key expiry), peer-to-peer connectivity, and restart resilience.
{
  self,
  pkgs,
  lib,
  headscale,
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-single-instance";

  nodes = {
    peer1 = {
      imports = [
        self.nixosModules.override
        headscale.nixosModules.testkit-peer
      ];
      services.tailscale.openFirewall = true;
    };

    # Joins unattended: the test drops the key in /tmp/shared before boot.
    peer2 = {
      imports = [self.nixosModules.override];
      services.tailscale = {
        enable = true;
        openFirewall = true;
        authKeyFile = "/tmp/shared/authkey";
        extraUpFlags = ["--login-server=http://headscale"];
        # An up flag applied by set: re-auth must not trip `up`'s check
        # for unmentioned non-default settings.
        extraSetFlags = ["--accept-routes"];
        relayServerPort = 40000;
        services = {
          demo.endpoints."tcp:5432" = "tcp://localhost:5432";
          hidden = {
            endpoints."tcp:5433" = "tcp://localhost:5433";
            advertised = false;
          };
        };
      };
      environment.systemPackages = [pkgs.jq];
    };

    headscale.imports = [headscale.nixosModules.testkit];
  };

  testScript = ''
    headscale.start()
    peer1.start()

    authkey = headscale.succeed("hs-authkey testuser").strip()
    (peer2.shared_dir / "authkey").write_text(authkey)
    peer2.start()

    peer1.succeed(f"hs-join {authkey}")

    # A unit that never ran also reads Result=success, so key on its main
    # process having exited after SINCE. A (re)start resets the stamp to 0.
    def exit_stamp(machine, unit):
        return machine.succeed(
            f"systemctl show -p ExecMainExitTimestampMonotonic --value {unit}"
        ).strip()

    def ran_ok(machine, unit, since="0"):
        machine.wait_until_succeeds(
            f's=$(systemctl show -p ExecMainExitTimestampMonotonic --value {unit}); '
            f'test "$s" != 0 && test "$s" != {since}'
        )
        machine.succeed(f"systemctl show -p Result --value {unit} | grep -x success")

    # The units that turn peer2's config into node state, in order.
    units = [
        "tailscaled-autoconnect.service",
        "tailscaled-set.service",
        "tailscaled-serve-config.service",
    ]

    def stamps():
        return {u: exit_stamp(peer2, u) for u in units}

    def applied(since):
        """All of peer2's units re-ran after SINCE and their settings hold."""
        for u in units:
            ran_ok(peer2, u, since.get(u, "0"))
        peer2.succeed("tailscale status")
        peer2.succeed(
            "tailscale debug prefs | jq -e '.RouteAll and .RelayServerPort == 40000"
            " and .AdvertiseServices == [\"svc:demo\"]'"
        )

    with subtest("boot: autoconnect joins, set and serve-config apply"):
        applied({})

    with subtest("peer-to-peer connectivity"):
        peer1.wait_until_succeeds("tailscale ping peer2", timeout=60)
        peer2.wait_until_succeeds("tailscale ping peer1", timeout=60)

    with subtest("restart resilience"):
        peer1.succeed("systemctl restart tailscaled")
        peer1.wait_for_unit("tailscaled.service")
        peer1.wait_until_succeeds("tailscale ping peer2", timeout=60)

    with subtest("logout: autoconnect logs back in, state re-applied"):
        before = stamps()
        peer2.succeed("tailscale logout")
        peer2.succeed("systemctl restart tailscaled")
        applied(before)
        peer2.wait_until_succeeds("tailscale ping peer1", timeout=60)

    # Prefs survive key expiry, unlike logout, so a plain `up` would refuse
    # over the set unit's --accept-routes.
    with subtest("key expiry: autoconnect re-authenticates, state re-applied"):
        import json
        nodes = json.loads(headscale.succeed("headscale nodes list -o json"))
        node_id = next(n["id"] for n in nodes if n["givenName"] == "peer2")
        headscale.succeed(f"headscale nodes expire --identifier {node_id}")
        peer2.wait_until_fails("tailscale status")
        before = stamps()
        peer2.succeed("systemctl restart tailscaled")
        applied(before)
  '';
}
