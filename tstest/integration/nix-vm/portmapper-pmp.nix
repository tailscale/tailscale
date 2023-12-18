# To run:
#   1. Put a Tailscale auth key for the test tailnet in ./tailscale-test.key
#   2. Run the Nix test:
#         nix-build --show-trace --option sandbox false ./pmp-epoch.nix
#   3. On success, the command builds and exits successfully.
#   3. On an error, the command exits with a non-zero exit code and prints the error; for example:
#         error: builder for '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-vm-test-run-tailscale-test.drv' failed with exit code 1;
#                last 10 log lines:
#                       > Test "Foo" failed with error: "bar"
#
let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-unstable";
  pkgs = import nixpkgs { config = {}; overlays = []; };
  inherit (pkgs) lib;

  # Set debug = true to do the following:
  #   1. Boots VMs sequentially so that output isn't interleaved
  #   2. Prints the output of various commands
  #   3. Enables debug logging from tailscaled (--verbose 2)
  debug = true;

  authKey = lib.fileContents ./tailscale-test.key;

  usePatched = true;
  tsOverlay = self: super: if (!usePatched) then {} else {
    tailscale = super.tailscale.override {
      buildGoModule = args: super.buildGoModule (args // {
        version = "2024-01-04";
        src = super.pkgs.fetchFromGitHub {
          owner = "tailscale";
          repo = "tailscale";
          rev = "10c595d962a43fa1c01642e1ea295b7eb98e74a6";
          hash = "sha256-tY3kxXtvz/Bw05yYeZvRe5Laz7Js2exwzXCWWVCKAG8=";
        };
        vendorHash = "sha256-uMVRdgO/HTs0CKqWPUFEL/rFvzio1vblTUaz5Cgi+5Q=";
      });
    };
  };

in pkgs.nixosTest {
  name = "pmp-epoch";

  nodes = {
    # This is our fake "router" that runs miniupnp
    router = { config, lib, pkgs, ... }: {
      networking.nameservers = [ "8.8.8.8" "8.8.4.4" ];

      # Trust the internal interface so that portmapping packets aren't blocked.
      networking.firewall.trustedInterfaces = [ "eth1" ];

      environment.systemPackages = with pkgs; [
        iproute2
        iptables
        tcpdump
        vim
      ];

      services.miniupnpd = {
        enable = true;
        externalInterface = "eth0";
        internalIPs = [ "eth1" ];

        upnp = false;
        natpmp = true;

        # We need to provide an external IP to portmap to; we could use STUN to
        # discover what the "real" IP is, but that doesn't work in all cases
        # and we don't actually care what it is.
        appendConfig = ''
          ext_ip=1.1.1.1
        '';
      };

      # NAT from our eth1 internal interface to the external eth0.
      networking.nat = {
        enable = true;
        internalIPs = [ "192.168.1.0/24" ];
        externalInterface = "eth0";
      };
    };

    client = { config, lib,  pkgs, ... }: {
      networking.nameservers = [ "8.8.8.8" "8.8.4.4" ];

      nixpkgs.overlays = [ tsOverlay ];
      services.tailscale = {
        enable = true;
        authKeyFile = pkgs.writeText "ts.key" authKey;
      };

      environment.systemPackages = with pkgs; [ iproute2 ];

      # Don't start Tailscale automatically; we need to start it only after we
      # take eth0 down on boot.
      systemd.services = {
        tailscaled-autoconnect.wantedBy = lib.mkForce [];
        tailscaled.wantedBy = lib.mkForce [];
      };
    };

  };

  testScript = ''
    debug = ${if debug then "True" else "False"}

    def dprint(*args, **kwargs):
      if debug:
        print(*args, **kwargs)

    def print_network_debug(client):
      with subtest("Network Debugging Information"):
        client.sleep(5)
        print(client.succeed("ip addr"))
        print(client.succeed("ip route"))
        print(client.succeed("echo 'route get' && ip route get 8.8.8.8 || true"))
        print(client.succeed("echo 'resolv.conf' && cat /etc/resolv.conf"))

    def wait_and_get_ts_ip(client):
      # NOTE: can't wait for "tailscaled-autoconnect.service" since a oneshot
      # service never actually "starts"; wait multi-user.target and then wait
      # until we have a valid IP
      client.wait_for_unit("multi-user.target")
      client.wait_until_succeeds("tailscale ip -4 | egrep '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'")

      # Verify that we have an IP address
      ip = client.succeed("tailscale ip -4").strip()
      return ip

    # Start the router first
    print_network_debug(router)
    router.wait_for_unit("multi-user.target")

    # Wait for an IP, then restart miniupnpd to ensure that it knows about our external IP
    router.wait_until_succeeds("ip addr show dev eth0 | grep '10.0.2.'")
    router.succeed("systemctl restart miniupnpd.service")
    router.wait_for_unit("miniupnpd.service")

    # Start the client
    client.wait_for_unit("multi-user.target")

    # Disable the eth0 interface for the client and set up a route through our router.
    with subtest("Route traffic through eth1"):
      client.succeed("ip link set eth0 down")
      client.succeed("ip route add default via 192.168.1.2 dev eth1 src 192.168.1.1")
      client.succeed("ping -c1 8.8.8.8")

    # Start Tailscale
    with subtest("Start Tailscale"):
      client.succeed("systemctl start tailscaled.service")
      client.succeed("systemctl start tailscaled-autoconnect.service")
      client_ip = wait_and_get_ts_ip(client)
      dprint(f"client Tailscale IP: {client_ip}")

    # Run the netcheck from the client and verify that we have NAT-PMP support.
    with subtest("Portmapping"):
      portmap = client.succeed("tailscale debug portmap").strip()
      assert "PMP:true" in portmap, f"Tailscale portmap output does not have NAT-PMP support:\n{portmap}"

    # TODO(andrew-d): we should restart miniupnpd and then verify we re-acquire
    # a lease due to the epoch decreasing
  '';
}

