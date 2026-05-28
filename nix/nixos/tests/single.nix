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
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-single-instance";

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

    peerConfig = {
      imports = [self.nixosModules.override];
      services.tailscale = {
        enable = true;
        openFirewall = true;
      };
      security.pki.certificateFiles = ["${tls-cert}/cert.pem"];
    };
  in {
    peer1 = peerConfig;
    peer2 = peerConfig;

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

    # Wait for headscale
    headscale.wait_for_unit("headscale")
    headscale.wait_for_open_port(443)

    # Verify our tailscaled service starts on peers
    peer1.wait_for_unit("tailscaled.service")
    peer2.wait_for_unit("tailscaled.service")

    # Create user and auth key.
    # headscale CLI uses numeric user IDs: first user gets ID 1.
    headscale.succeed("headscale users create testuser")
    authkey = headscale.succeed(
        "headscale preauthkeys create -u 1 --reusable"
    ).strip()

    # Join peers to tailnet
    peer1.execute(
        f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
    )
    peer2.execute(
        f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
    )

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
