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
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-multi-instance";

  nodes = let
    mkCert = hostname:
      pkgs.runCommand "selfSignedCerts-${hostname}" {
        buildInputs = [pkgs.openssl];
      } ''
        openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
          -nodes -out cert.pem -keyout key.pem \
          -subj '/CN=${hostname}' \
          -addext "subjectAltName=DNS:${hostname}"
        mkdir -p $out
        cp key.pem cert.pem $out
      '';

    cert1 = mkCert "headscale1";
    cert2 = mkCert "headscale2";

    headscalePort = 8080;
    stunPort = 3478;

    mkHeadscaleNode = {
      hostname,
      cert,
      ipv4Prefix,
    }: {
      services.headscale = {
        enable = true;
        port = headscalePort;
        settings = {
          server_url = "https://${hostname}";
          prefixes.v4 = ipv4Prefix;
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
        virtualHosts.${hostname} = {
          addSSL = true;
          sslCertificate = "${cert}/cert.pem";
          sslCertificateKey = "${cert}/key.pem";
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
  in {
    headscale1 = mkHeadscaleNode {
      hostname = "headscale1";
      cert = cert1;
      ipv4Prefix = "100.64.0.0/24";
    };
    headscale2 = mkHeadscaleNode {
      hostname = "headscale2";
      cert = cert2;
      ipv4Prefix = "100.64.1.0/24";
    };

    # Client running two Tailscale instances (userspace mode by default)
    client = {
      imports = [self.nixosModules.override];
      services.tailscales = {
        net1.enable = true;
        net2.enable = true;
      };
      security.pki.certificateFiles = [
        "${cert1}/cert.pem"
        "${cert2}/cert.pem"
      ];
    };

    # A peer on headscale1's network (TUN mode, single instance)
    peer1 = {
      imports = [self.nixosModules.override];
      services.tailscale = {
        enable = true;
        openFirewall = true;
      };
      security.pki.certificateFiles = ["${cert1}/cert.pem"];
    };
  };

  testScript = ''
    start_all()

    # Wait for both headscale servers
    headscale1.wait_for_unit("headscale")
    headscale1.wait_for_open_port(443)
    headscale2.wait_for_unit("headscale")
    headscale2.wait_for_open_port(443)

    # Wait for client's tailscaled instances
    client.wait_for_unit("tailscaled-net1.service")
    client.wait_for_unit("tailscaled-net2.service")

    # Wait for peer1's tailscaled
    peer1.wait_for_unit("tailscaled.service")

    # Create users and auth keys on both headscale servers.
    # headscale CLI uses numeric user IDs: first user gets ID 1.
    headscale1.succeed("headscale users create user1")
    authkey1 = headscale1.succeed(
        "headscale preauthkeys create -u 1 --reusable"
    ).strip()

    headscale2.succeed("headscale users create user2")
    authkey2 = headscale2.succeed(
        "headscale preauthkeys create -u 1 --reusable"
    ).strip()

    # Join client's instances to their respective headscale servers.
    # Use succeed() to ensure the commands don't fail silently.
    client.succeed(
        f"tailscale-net1 up --login-server 'https://headscale1' --auth-key {authkey1}"
    )
    client.succeed(
        f"tailscale-net2 up --login-server 'https://headscale2' --auth-key {authkey2}"
    )

    # Join peer1 to headscale1
    peer1.succeed(
        f"tailscale up --login-server 'https://headscale1' --auth-key {authkey1}"
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
