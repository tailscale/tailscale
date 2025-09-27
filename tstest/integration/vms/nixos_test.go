// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !plan9

package vms

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"tailscale.com/types/logger"
)

var (
	verboseNixOutput = flag.Bool("verbose-nix-output", false, "if set, use verbose nix output (lots of noise)")
)

/*
   NOTE(Xe): Okay, so, at a high level testing NixOS is a lot different than
   other distros due to NixOS' determinism. Normally NixOS wants packages to
   be defined in either an overlay, a custom packageOverrides or even
   yolo-inline as a part of the system configuration. This is going to have
   us take a different approach compared to other distributions. The overall
   plan here is as following:

   1. make the binaries as normal
   2. template in their paths as raw strings to the nixos system module
   3. run `nixos-generators -f qcow -o $CACHE_DIR/tailscale/nixos/version -c generated-config.nix`
   4. pass that to the steps that make the virtual machine

   It doesn't really make sense for us to use a premade virtual machine image
   for this as that will make it harder to deterministically create the image.
*/

const nixosConfigTemplate = `
# NOTE(Xe): This template is going to be heavily commented.

# All NixOS modules are functions. Here is the function prelude for this NixOS
# module that defines the system. It is a function that takes in an attribute
# set (effectively a map[string]nix.Value) and destructures it to some variables:
{
  # other NixOS settings as defined in other modules
  config,

  # nixpkgs, which is basically the standard library of NixOS
  pkgs,

  # the path to some system-scoped NixOS modules that aren't imported by default
  modulesPath,

  # the rest of the arguments don't matter
  ...
}:

# Nix's syntax was inspired by Haskell and other functional languages, so the
# let .. in pattern is used to create scoped variables:
let
  # Define the package (derivation) for Tailscale based on the binaries we
  # just built for this test:
  testTailscale = pkgs.stdenv.mkDerivation {
    # The name of the package. This usually includes a version however it
    # doesn't matter here.
    name = "tailscale-test";

    # The path on disk to the "source code" of the package, in this case it is
    # the path to the binaries that are built. This needs to be the raw
    # unquoted slash-separated path, not a string containing the path because Nix
    # has a special path type.
    src = {{.BinPath}};

    # We only need to worry about the install phase because we've already
    # built the binaries.
    phases = "installPhase";

    # We need to wrap tailscaled such that it has iptables in its $PATH.
    nativeBuildInputs = [ pkgs.makeWrapper ];

    # The install instructions for this package ('' ''defines a multi-line string).
    # The with statement lets us bring in values into scope as if they were
    # defined in the current scope.
    installPhase = with pkgs; ''
      # This is bash.

      # Make the output folders for the package (systemd unit and binary folders).
      mkdir -p $out/bin

      # Install tailscale{,d}
      cp $src/tailscale $out/bin/tailscale
      cp $src/tailscaled $out/bin/tailscaled

      # Wrap tailscaled with the ip and iptables commands.
      wrapProgram $out/bin/tailscaled --prefix PATH : ${
        lib.makeBinPath [ iproute2 iptables ]
      }

      # Install systemd unit.
      cp $src/systemd/tailscaled.service .
      sed -i -e "s#/usr/sbin#$out/bin#" -e "/^EnvironmentFile/d" ./tailscaled.service
      install -D -m0444 -t $out/lib/systemd/system ./tailscaled.service
    '';
  };
in {
  # This is a QEMU VM. This module has a lot of common qemu VM settings so you
  # don't have to set them manually.
  imports = [ (modulesPath + "/profiles/qemu-guest.nix") ];

  # We need virtio support to boot.
  boot.initrd.availableKernelModules =
    [ "ata_piix" "uhci_hcd" "virtio_pci" "sr_mod" "virtio_blk" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ ];
  boot.extraModulePackages = [ ];

  # Curl is needed for one of the steps in cloud-final
  systemd.services.cloud-final.path = with pkgs; [ curl ];

  # Curl is needed for one of the integration tests
  environment.systemPackages = with pkgs; [ curl nix bash squid openssl daemonize ];

  # yolo, this vm can sudo freely.
  security.sudo.wheelNeedsPassword = false;

  # nix considers squid insecure, but this is fine for a test.
  nixpkgs.config.permittedInsecurePackages = [ "squid-7.0.1" ];

  # Enable cloud-init so we can set VM hostnames and the like the same as other
  # distros. This will also take care of SSH keys. It's pretty handy.
  services.cloud-init = {
    enable = true;
    ext4.enable = true;
  };

  # We want sshd running.
  services.openssh.enable = true;

  # Tailscale settings:
  services.tailscale = {
    # We want Tailscale to start at boot.
    enable = true;

    # Use the Tailscale package we just assembled.
    package = testTailscale;
  };

  # Override TS_LOG_TARGET to our private logcatcher.
  systemd.services.tailscaled.environment."TS_LOG_TARGET" = "{{.LogTarget}}";
}`

func (h *Harness) copyUnit(t *testing.T) {
	t.Helper()

	data, err := os.ReadFile("../../../cmd/tailscaled/tailscaled.service")
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(h.binaryDir, "systemd"), 0755)
	err = os.WriteFile(filepath.Join(h.binaryDir, "systemd", "tailscaled.service"), data, 0666)
	if err != nil {
		t.Fatal(err)
	}
}

func (h *Harness) makeNixOSImage(t *testing.T, d Distro, cdir string) string {
	if d.Name == "nixos-unstable" {
		t.Skip("https://github.com/NixOS/nixpkgs/issues/131098")
	}

	h.copyUnit(t)
	dir := t.TempDir()
	fname := filepath.Join(dir, d.Name+".nix")
	fout, err := os.Create(fname)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := template.Must(template.New("base.nix").Parse(nixosConfigTemplate))
	err = tmpl.Execute(fout, struct {
		BinPath   string
		LogTarget string
	}{
		BinPath:   h.binaryDir,
		LogTarget: h.loginServerURL,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = fout.Close()
	if err != nil {
		t.Fatal(err)
	}

	outpath := filepath.Join(cdir, "nixos")
	os.MkdirAll(outpath, 0755)

	t.Cleanup(func() {
		os.RemoveAll(filepath.Join(outpath, d.Name)) // makes the disk image a candidate for GC
	})

	cmd := exec.Command("nixos-generate", "-f", "qcow", "-o", filepath.Join(outpath, d.Name), "-c", fname)
	if *verboseNixOutput {
		cmd.Stdout = logger.FuncWriter(t.Logf)
		cmd.Stderr = logger.FuncWriter(t.Logf)
	} else {
		fname := fmt.Sprintf("nix-build-%s-%s", os.Getenv("GITHUB_RUN_NUMBER"), strings.Replace(t.Name(), "/", "-", -1))
		t.Logf("writing nix logs to %s", fname)
		fout, err := os.Create(fname)
		if err != nil {
			t.Fatalf("can't make log file for nix build: %v", err)
		}
		cmd.Stdout = fout
		cmd.Stderr = fout
		defer fout.Close()
	}
	cmd.Env = append(os.Environ(), "NIX_PATH=nixpkgs="+d.URL)
	cmd.Dir = outpath
	t.Logf("running %s %#v", "nixos-generate", cmd.Args)
	if err := cmd.Run(); err != nil {
		t.Fatalf("error while making NixOS image for %s: %v", d.Name, err)
	}

	if !*verboseNixOutput {
		t.Log("done")
	}

	return filepath.Join(outpath, d.Name, "nixos.qcow2")
}
