# Setup: ensure the test tailnet has a SplitDNS entry for the 'testDomain'
# domain, below, set to the nameserver address in the 'addrs' attrset.
#
# To run:
#   1. Put a Tailscale auth key for the test tailnet in ./tailscale-test.key
#   2. Run the Nix test:
#         nix-build --show-trace --option sandbox false ./tailscale-test.nix
#   3. On success, the command builds and exits successfully.
#   3. On an error, the command exits with a non-zero exit code and prints the error; for example:
#         error: builder for '/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-vm-test-run-tailscale-test.drv' failed with exit code 1;
#                last 10 log lines:
#                       > Test "Verify the client can make a request to a SplitDNS domain" failed with error: "command `curl --fail -vv --proxy socks5h://localhost:1055 http://bla.foo.bar/file.txt` failed (exit code 97)"
#
# The 'usePatched' variable controls whether to use the standard NixOS upstream
# Tailscale build, or a patched version specified in 'tsOverlay'. This is
# useful for testing out a fix or patch for an issue.
#
let
  nixpkgs = fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-unstable";
  pkgs = import nixpkgs { config = {}; overlays = []; };
  inherit (pkgs) lib;

  # Set debug = true to do the following:
  #   1. Boots VMs sequentially so that output isn't interleaved
  #   2. Prints the output of various commands
  #   3. Enables debug logging from tailscaled (--verbose 2)
  debug = false;

  authKey = lib.fileContents ./tailscale-test.key;

  # These are addresses assigned by the host; see 'ipInterfaces' in
  # nixos/lib/testing/network.nix for more details
  addrs = {
    nameserver = "192.168.1.1";
    tunclient  = "192.168.1.2";
    userclient = "192.168.1.3";
    webserver  = "192.168.1.4";
  };

  socksPort = 1055;
  testDomain = "foo.bar";
  queryAddr = "bla.${testDomain}";

  usePatched = false;
  tsOverlay = self: super: if (!usePatched) then {} else {
    tailscale = super.tailscale.override {
      buildGoModule = args: super.buildGoModule (args // {
        version = "2023-12-13";
        src = super.pkgs.fetchFromGitHub {
          owner = "itszero";
          repo = "tailscale";
          rev = "5cb309e8880ffa067975392b5c1493a660b301f1";
          hash = "sha256-sOTknrJ09P/4rG/YZQ7BhapVr6FN0rjaD/IwemSHXHs=";
        };
        vendorHash = "sha256-Y7Z72ZwTcsdeI8DTqc6kDBlYNvQjNsRgD4D3fTsBoiQ=";
      });
    };
  };

in pkgs.nixosTest {
  name = "splitdns";

  nodes = {
    # This is the nameserver that we're querying.
    nameserver = { config, lib, ... } : {
      networking.firewall.allowedUDPPorts = [ 53 ];
      networking.firewall.allowedTCPPorts = [ 53 ];

      environment.systemPackages = with pkgs; [ dnsutils ];

      services.dnsmasq = {
        enable = true;
        resolveLocalQueries = false;
        settings = {
          "domain-needed" = true;
          "bogus-priv" = true;
          "expand-hosts" = true;

          "listen-address" = [ "127.0.0.1" addrs.nameserver ];
          "bind-interfaces" = true;

          "server" = ["8.8.8.8" "8.8.4.4"];

          "address=/${queryAddr}/${addrs.webserver}" = true;
        };
      };
    };

    # This is a basic webserver that our nameserver points to.
    webserver = { config, lib, pkgs, ... } : {
      networking.firewall.allowedTCPPorts = [ 80 443 ];

      services.lighttpd = {
        enable = true;
        document-root = pkgs.runCommand "document-root" {} ''
          mkdir -p "$out"
          echo "i am the webserver" > "$out/file.txt"
        '';
      };
    };

    # This is the Tailscale client node that makes the query
    userclient = { config, lib, pkgs, ... }: {
      networking = {
        nameservers = [ "8.8.8.8" "8.8.4.4" ];
      };

      environment.systemPackages = with pkgs; [ dnsutils ];

      # Use our patched Tailscale
      nixpkgs.overlays = [ tsOverlay ];

      services.tailscale = {
        enable = true;
        interfaceName = "userspace-networking"; # redundant due to the ExecStart override below, but for clarity
        authKeyFile = pkgs.writeText "ts.key" authKey;
        extraUpFlags = [
          "--accept-dns"
        ];
      };

      # Run in userspace-networking mode
      systemd.services.tailscaled.serviceConfig.ExecStart = lib.mkForce [
        # Clear existing ExecStart
        ""

        # Override with new one that runs a SOCKS5 server
        (lib.concatStringsSep " " ([
          "${pkgs.tailscale}/bin/tailscaled"
            "--state=/var/lib/tailscale/tailscaled.state"
            "--socket=/run/tailscale/tailscaled.sock"
            "--socks5-server=localhost:${toString socksPort}"
            "--port=${toString config.services.tailscale.port}"
            "--tun=userspace-networking"
        ] ++ lib.optional debug "--verbose=2"))
      ];
    };

    tunclient = { config, lib,  pkgs, ... }: {
      # Use systemd-networkd and systemd-resolved to verify that we can
      # correctly program that.
      networking = {
        useNetworkd = true;
        nameservers = [ "8.8.8.8" "8.8.4.4" ];
      };

      systemd.network.enable = true;
      services.resolved = {
        enable = true;
        fallbackDns = [ "8.8.8.8" "8.8.4.4" ];
      };

      # for 'dig'
      environment.systemPackages = with pkgs; [ dnsutils ];

      # Use our patched Tailscale
      nixpkgs.overlays = [ tsOverlay ];

      services.tailscale = {
        enable = true;
        authKeyFile = pkgs.writeText "ts.key" authKey;
        extraUpFlags = [
          "--accept-dns"
        ];
      };

      # Run in userspace-networking mode
      systemd.services.tailscaled.serviceConfig.ExecStart = lib.mkForce [
        # Clear existing ExecStart
        ""

        # Override with new one that runs a SOCKS5 server
        (lib.concatStringsSep " " ([
          "${pkgs.tailscale}/bin/tailscaled"
            "--state=/var/lib/tailscale/tailscaled.state"
            "--socket=/run/tailscale/tailscaled.sock"
            "--port=${toString config.services.tailscale.port}"
            "--tun=tailscale0"
        ] ++ lib.optional debug "--verbose=2"))
      ];
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

    if not debug:
      start_all()

    # Wait for the webserver to start
    webserver.wait_for_unit("lighttpd.service")
    res = webserver.succeed("curl --fail http://localhost/file.txt").strip()
    assert "i am the webserver" in res, f"bad server response: '{res}'"

    # Wait for the nameserver to start
    nameserver.wait_for_unit("dnsmasq.service")

    # Verify that our DNS settings (on the nameserver) succeed.
    output = nameserver.succeed("dig +short ${queryAddr} @${addrs.nameserver}").strip()
    dprint("dig output:", output)
    assert output == "${addrs.webserver}", f"bad dig result: '{output}'"

    def assert_dns(client, nameserver, addr, want):
      for flag in ["+ignore", "+tcp"]:
        output = client.succeed(f"dig +short {flag} {addr} @{nameserver}").strip()
        dprint("client dig output:", output)
        assert output == want, f"bad dig result with flag '{flag}': '{output}'"

    # Wait for Tailscale to start on the client node
    with subtest("userspace-networking"):
      userclient.wait_for_unit("tailscaled.service")

      if debug:
        print_network_debug(userclient)

      # NOTE: can't wait for "tailscaled-autoconnect.service" since a oneshot
      # service never actually "starts"; wait multi-user.target and then wait
      # until we have a valid IP
      userclient.wait_for_unit("multi-user.target")
      userclient.wait_until_succeeds("tailscale ip -4 | egrep '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'")

      # Verify that we have an IP address
      ip = userclient.succeed("tailscale ip -4")
      print("Tailscale IP:", ip)

      # Make a request through our SOCKS5 proxy to example.com to verify it succeeds
      with subtest("Verify the client can make a request to a non-split domain"):
        output = userclient.succeed("curl --fail --silent --show-error --proxy socks5h://localhost:${toString socksPort} http://example.com").strip()
        dprint("example.com:", output)
        assert "<title>Example Domain</title>" in output, f"bad server response: '{output}'"

      with subtest("Verify the client can contact the nameserver"):
        assert_dns(userclient, "${addrs.nameserver}", "${queryAddr}", "${addrs.webserver}")

      # TODO: this should succeed but does not
      if True:
        with subtest("Verify the client can make a request to a SplitDNS domain"):
          output = userclient.succeed("curl --fail -vv --proxy socks5h://localhost:${toString socksPort} http://${queryAddr}/file.txt").strip()
          print("${queryAddr}:", output)

    with subtest("TUN mode"):
      tunclient.wait_for_unit("tailscaled.service")

      if debug:
        print_network_debug(tunclient)

      # NOTE: can't wait for "tailscaled-autoconnect.service" since a oneshot
      # service never actually "starts"; wait multi-user.target and then wait
      # until we have a valid IP
      tunclient.wait_for_unit("multi-user.target")
      tunclient.wait_until_succeeds("tailscale ip -4 | egrep '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'")

      # Verify that we have an IP address
      ip = tunclient.succeed("tailscale ip -4")
      print("Tailscale IP:", ip)

      # Make a request to example.com to verify it succeeds
      with subtest("Verify the client can make a request to a non-split domain"):
        output = tunclient.succeed("curl --fail --silent --show-error http://example.com").strip()
        dprint("example.com:", output)
        assert "<title>Example Domain</title>" in output, f"bad server response: '{output}'"

      with subtest("Verify the client can contact the nameserver"):
        assert_dns(tunclient, "${addrs.nameserver}", "${queryAddr}", "${addrs.webserver}")

      # TODO: this should succeed but does not
      if True:
        with subtest("Verify the client can make a request to a SplitDNS domain"):
          output = tunclient.succeed("curl --fail -vv http://${queryAddr}/file.txt").strip()
          print("${queryAddr}:", output)
  '';
}
