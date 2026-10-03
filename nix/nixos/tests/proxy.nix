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
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-proxy";

  nodes = let
    tls-cert = pkgs.runCommand "selfSignedCerts" {
      buildInputs = [pkgs.openssl];
    } ''
      openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
        -nodes -out cert.pem -keyout key.pem \
        -subj '/CN=headscale' -addext "subjectAltName=DNS:headscale"
      mkdir -p $out
      cp key.pem cert.pem $out
    '';

    headscalePort = 8080;
    stunPort = 3478;
  in {
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
      security.pki.certificateFiles = ["${tls-cert}/cert.pem"];
      environment.systemPackages = [pkgs.curl];
    };

    # A peer serving HTTP, reachable only over the tailnet.
    peer1 = {
      imports = [self.nixosModules.override];
      services.tailscale = {
        enable = true;
        openFirewall = true;
      };
      security.pki.certificateFiles = ["${tls-cert}/cert.pem"];
      services.nginx = {
        enable = true;
        virtualHosts.peer1.locations."/".return = "200 'hello-from-peer1'";
      };
    };

    headscale = {
      services.headscale = {
        enable = true;
        port = headscalePort;
        settings = {
          server_url = "https://headscale";
          prefixes.v4 = "100.64.0.0/10";
          derp.server = {
            enabled = true;
            region_id = 999;
            stun_listen_addr = "0.0.0.0:${toString stunPort}";
          };
          dns = {
            base_domain = "tailnet";
            override_local_dns = false;
          };
        };
      };

      services.nginx = {
        enable = true;
        virtualHosts.headscale = {
          addSSL = true;
          sslCertificate = "${tls-cert}/cert.pem";
          sslCertificateKey = "${tls-cert}/key.pem";
          locations."/" = {
            proxyPass = "http://127.0.0.1:${toString headscalePort}";
            proxyWebsockets = true;
          };
        };
      };

      networking.firewall = {
        allowedTCPPorts = [80 443];
        allowedUDPPorts = [stunPort];
      };
      environment.systemPackages = [pkgs.headscale];
    };
  };

  testScript = ''
    start_all()

    headscale.wait_for_unit("headscale")
    headscale.wait_for_open_port(443)

    client.wait_for_unit("tailscaled-socks.service")
    client.wait_for_unit("tailscaled-both.service")
    peer1.wait_for_unit("tailscaled.service")

    # headscale CLI uses numeric user IDs: first user gets ID 1.
    headscale.succeed("headscale users create testuser")
    authkey = headscale.succeed(
        "headscale preauthkeys create -u 1 --reusable"
    ).strip()

    client.succeed(
        f"tailscale-socks up --login-server 'https://headscale' --auth-key {authkey}"
    )
    client.succeed(
        f"tailscale-both up --login-server 'https://headscale' --auth-key {authkey}"
    )
    peer1.succeed(
        f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
    )

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
