# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# NixOS VM test: userspace Tailscale instances exposing SOCKS5/HTTP proxies.
# Verifies proxy daemon flags take effect, the `tailscale-proxies` lister,
# per-instance proxy address isolation, and reaching a peer through the proxy.
{
  self,
  pkgs,
  lib,
  headscale,
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-proxy";

  nodes = {
    # Client running two userspace instances with different proxy modes,
    # each on its own listen address.
    client = {
      imports = [self.nixosModules.override];
      services.tailscales = {
        socks = {
          enable = true;
          proxy = "socks";
          proxyListenAddress = "localhost:1055";
        };
        both = {
          enable = true;
          proxy = "both";
          proxyListenAddress = "localhost:1056";
        };
      };
      environment.systemPackages = [pkgs.curl];
    };

    # A peer serving HTTP, reachable only over the tailnet.
    peer1 = {
      imports = [
        self.nixosModules.override
        headscale.nixosModules.testkit-peer
      ];
      services.tailscale.openFirewall = true;
      services.nginx = {
        enable = true;
        virtualHosts.peer1.locations."/".return = "200 'hello-from-peer1'";
      };
    };

    headscale.imports = [headscale.nixosModules.testkit];
  };

  testScript = ''
    start_all()

    client.wait_for_unit("tailscaled-socks.service")
    client.wait_for_unit("tailscaled-both.service")

    authkey = headscale.succeed("hs-authkey testuser").strip()

    client.succeed(
        f"tailscale-socks up --login-server http://headscale --auth-key {authkey}"
    )
    client.succeed(
        f"tailscale-both up --login-server http://headscale --auth-key {authkey}"
    )
    peer1.succeed(f"hs-join {authkey}")

    client.wait_until_succeeds("tailscale-socks status", timeout=60)
    client.wait_until_succeeds("tailscale-both status", timeout=60)

    # Proxy listeners are up on their configured addresses.
    client.wait_for_open_port(1055)
    client.wait_for_open_port(1056)

    # tailscale-proxies lists both instances and their addresses.
    proxies = client.succeed("tailscale-proxies")
    assert "socks" in proxies and "localhost:1055" in proxies, proxies
    assert "both" in proxies and "localhost:1056" in proxies, proxies

    # --json output is machine-readable and covers both instances.
    import json
    entries = json.loads(client.succeed("tailscale-proxies --json"))
    by_addr = {e["address"]: e for e in entries}
    assert by_addr["localhost:1055"]["proxy"] == "socks", entries
    assert by_addr["localhost:1056"]["proxy"] == "both", entries

    peer1_ip = peer1.succeed("tailscale ip -4").strip()

    # Reach peer1's HTTP server through the SOCKS5 proxy.
    client.wait_until_succeeds(
        f"curl --fail --proxy socks5h://localhost:1055 http://{peer1_ip}/ | grep hello-from-peer1",
        timeout=60,
    )

    # The "both" instance answers HTTP-proxy requests on the same port.
    client.wait_until_succeeds(
        f"curl --fail --proxy http://localhost:1056 http://{peer1_ip}/ | grep hello-from-peer1",
        timeout=60,
    )

    # ...and SOCKS5 on that same port too.
    client.succeed(
        f"curl --fail --proxy socks5h://localhost:1056 http://{peer1_ip}/ | grep hello-from-peer1"
    )
  '';
}
