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

  testFile = pkgs.writeText "test.txt" ''
    This is a test file that we are copying from one client to another via taildrop!
  '';

in pkgs.nixosTest {
  name = "taildrop";

  nodes = {
    # This is the Tailscale client node that makes the query
    client1 = { config, lib, pkgs, ... }: {
      networking.nameservers = [ "8.8.8.8" "8.8.4.4" ];

      services.tailscale = {
        enable = true;
        authKeyFile = pkgs.writeText "ts.key" authKey;
      };

      # TODO: verbosity
    };

    client2 = { config, lib,  pkgs, ... }: {
      networking.nameservers = [ "8.8.8.8" "8.8.4.4" ];
      services.tailscale = {
        enable = true;
        authKeyFile = pkgs.writeText "ts.key" authKey;
      };

      # TODO: verbosity
    };
  };

  testScript = ''
    import base64

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

    if not debug:
      start_all()

    # Wait for each client to start
    client1_ip = wait_and_get_ts_ip(client1)
    client2_ip = wait_and_get_ts_ip(client2)

    # Send a file from client1 to client2
    source_file = "${testFile}"
    with open(source_file, "rb") as f:
      contents = f.read()
    contents_b64 = base64.b64encode(contents).decode()

    client1.copy_from_host(source_file, "/tmp/copied-file.txt")
    client1.succeed(f"tailscale file cp /tmp/copied-file.txt {client2_ip}:")

    # Grab the file on client2, and then move to host
    client2.succeed("mkdir /tmp/taildrop && tailscale file get -wait -verbose /tmp/taildrop")
    got_contents_b64 = client2.succeed("cat /tmp/taildrop/copied-file.txt | base64").strip()
    got_contents = base64.b64decode(got_contents_b64)

    assert contents == got_contents, f"Mismatched contents after Taildrop:\ngot: {got_contents!r}"
  '';
}
