# This is a NixOS module to allow a machine to act as an integration test
# runner. This is used for the end-to-end VM test suite.

{ lib, config, pkgs, ... }:

{
  # The GitHub Actions self-hosted runner service.
  services.github-runner = {
    enable = true;
    url = "https://github.com/tailscale/tailscale";
    replace = true;
    extraLabels = [ "vm_integration_test" ];

    # Justifications for the packages:
    extraPackages = with pkgs; [
      # The test suite is written in Go.
      go

      # This contains genisoimage, which is needed to create cloud-init
      # seeds.
      cdrkit

      # This package is the virtual machine hypervisor we use in tests.
      qemu

      # This package contains tools like `ssh-keygen`.
      openssh

      # The C complier so cgo builds work.
      gcc

      # The package manager Nix, just in case.
      nix

      # Used to generate a NixOS image for testing.
      nixos-generators

      # Used to extract things.
      gnutar

      # Used to decompress things.
      lzma
    ];

    # Customize this to include your GitHub username so we can track
    # who is running which node.
    name = "YOUR-GITHUB-USERNAME-tstest-integration-vms";

    # Replace this with the path to the GitHub Actions runner token on
    # your disk.
    tokenFile = "/run/decrypted/ts-oss-ghaction-token";
  };

  # A user account so there is a home directory and so they have kvm
  # access. Please don't change this account name.
  users.users.ghrunner = {
    createHome = true;
    isSystemUser = true;
    extraGroups = [ "kvm" ];
  };

  # The default github-runner service sets a lot of isolation features
  # that attempt to limit the damage that malicious code can use.
  # Unfortunately we rely on some "dangerous" features to do these tests,
  # so this shim will peel some of them away.
  systemd.services.github-runner = {
    serviceConfig = {
      # We need access to /dev to poke /dev/kvm.
      PrivateDevices = lib.mkForce false;

      # /dev/kvm is how qemu creates a virtual machine with KVM.
      DeviceAllow = lib.mkForce [ "/dev/kvm" ];

      # Ensure the service has KVM permissions with the `kvm` group.
      ExtraGroups = [ "kvm" ];

      # The service runs as a dynamic user by default. This makes it hard
      # to persistently store things in /var/lib/ghrunner. This line
      # disables the dynamic user feature.
      DynamicUser = lib.mkForce false;

      # Run this service as our ghrunner user.
      User = "ghrunner";

      # We need access to /var/lib/ghrunner to store VM images.
      ProtectSystem = lib.mkForce null;
    };
  };
}
