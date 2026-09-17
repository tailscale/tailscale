# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# NixOS VM test: Tailscale Services shared services propagation.
# Verifies that services defined under services.tailscale.services
# are merged into all plural instances, that per-instance services
# coexist with shared ones, and that per-instance overrides win.
#
# These tests verify module evaluation and systemd unit generation
# only — they do not require a running coordination server since
# headscale does not support Tailscale Services.
{
  self,
  pkgs,
  lib,
}:
pkgs.testers.runNixOSTest {
  name = "tailscale-shared-services";

  nodes = {
    # Node 1: Shared services only, two plural instances, singular disabled.
    # Both instances should get the shared prometheus service.
    sharedOnly = {
      imports = [self.nixosModules.override];
      services.tailscale.services.prometheus = {
        endpoints."tcp:443" = "http://localhost:9090";
      };
      services.tailscales = {
        net1.enable = true;
        net2.enable = true;
      };
    };

    # Node 2: Shared + per-instance services.
    # net1 should get both prometheus (shared) and postgres (own).
    sharedPlusOwn = {
      imports = [self.nixosModules.override];
      services.tailscale.services.prometheus = {
        endpoints."tcp:443" = "http://localhost:9090";
      };
      services.tailscales.net1 = {
        enable = true;
        services.postgres = {
          endpoints."tcp:5432" = "tcp://localhost:5432";
        };
      };
    };

    # Node 3: Per-instance overrides a shared service.
    # net1 should get prometheus with the per-instance endpoint,
    # NOT the shared one.
    override = {
      imports = [self.nixosModules.override];
      services.tailscale.services.prometheus = {
        endpoints."tcp:443" = "http://localhost:9090";
      };
      services.tailscales.net1 = {
        enable = true;
        services.prometheus = {
          endpoints."tcp:443" = "https://localhost:9191";
        };
      };
    };

    # Node 4: Singular instance only, no plural.
    # Should work as before — services on the singular instance only.
    singularOnly = {
      imports = [self.nixosModules.override];
      services.tailscale = {
        enable = true;
        services.prometheus = {
          endpoints."tcp:443" = "http://localhost:9090";
        };
      };
    };
  };

  testScript = ''
    import json

    start_all()

    #
    # Helper: find the JSON config file for a serve-config unit.
    # NixOS wraps the script attribute into a separate executable referenced
    # by ExecStart, so we resolve the script path from the unit, then read
    # the script to find the JSON config path.
    #
    def get_serve_config(machine, unit_name):
        """Read the serve-config JSON for a given systemd unit."""
        # NixOS wraps the script into a store executable referenced by
        # ExecStart.  Use systemctl show to get the wrapper path, read
        # the wrapper, then extract the JSON config path from the
        # set-config --all invocation.
        exec_start = machine.succeed(
            f"systemctl show -p ExecStart --value {unit_name}"
        ).strip()
        # Format: { path=/nix/store/...; argv[]=/nix/store/... ; ... }
        script_path = exec_start.split("path=")[1].split(";")[0].strip()
        script_content = machine.succeed(f"cat {script_path}")
        # Find: set-config --all /nix/store/...-tailscale-services-<name>.json
        for line in script_content.splitlines():
            if "set-config --all" in line:
                config_path = line.split("set-config --all ")[-1].strip()
                break
        else:
            raise Exception(f"set-config --all not found in {script_path}")
        raw = machine.succeed(f"cat {config_path}")
        return json.loads(raw)

    #
    # Node 1: sharedOnly — shared services propagate to both plural instances.
    #
    with subtest("shared services propagate to all plural instances"):
        sharedOnly.wait_for_unit("tailscaled-net1.service")
        sharedOnly.wait_for_unit("tailscaled-net2.service")

        # Both serve-config units should exist
        sharedOnly.succeed("systemctl cat tailscaled-net1-serve-config.service")
        sharedOnly.succeed("systemctl cat tailscaled-net2-serve-config.service")

        # No singular serve-config (singular instance is disabled)
        sharedOnly.fail("systemctl cat tailscaled-serve-config.service")

        # Both should have the shared prometheus service
        cfg1 = get_serve_config(sharedOnly, "tailscaled-net1-serve-config.service")
        cfg2 = get_serve_config(sharedOnly, "tailscaled-net2-serve-config.service")

        assert "svc:prometheus" in cfg1["services"], f"net1 missing svc:prometheus: {cfg1}"
        assert cfg1["services"]["svc:prometheus"]["endpoints"]["tcp:443"] == "http://localhost:9090", \
            f"net1 wrong endpoint: {cfg1}"

        assert "svc:prometheus" in cfg2["services"], f"net2 missing svc:prometheus: {cfg2}"
        assert cfg2["services"]["svc:prometheus"]["endpoints"]["tcp:443"] == "http://localhost:9090", \
            f"net2 wrong endpoint: {cfg2}"

    #
    # Node 2: sharedPlusOwn — shared + per-instance services coexist.
    #
    with subtest("shared and per-instance services coexist"):
        sharedPlusOwn.wait_for_unit("tailscaled-net1.service")

        sharedPlusOwn.succeed("systemctl cat tailscaled-net1-serve-config.service")

        cfg = get_serve_config(sharedPlusOwn, "tailscaled-net1-serve-config.service")

        assert "svc:prometheus" in cfg["services"], f"missing svc:prometheus: {cfg}"
        assert cfg["services"]["svc:prometheus"]["endpoints"]["tcp:443"] == "http://localhost:9090", \
            f"wrong prometheus endpoint: {cfg}"

        assert "svc:postgres" in cfg["services"], f"missing svc:postgres: {cfg}"
        assert cfg["services"]["svc:postgres"]["endpoints"]["tcp:5432"] == "tcp://localhost:5432", \
            f"wrong postgres endpoint: {cfg}"

    #
    # Node 3: override — per-instance overrides shared definition.
    #
    with subtest("per-instance services override shared definitions"):
        override.wait_for_unit("tailscaled-net1.service")

        override.succeed("systemctl cat tailscaled-net1-serve-config.service")

        cfg = get_serve_config(override, "tailscaled-net1-serve-config.service")

        assert "svc:prometheus" in cfg["services"], f"missing svc:prometheus: {cfg}"
        # Per-instance endpoint should win
        assert cfg["services"]["svc:prometheus"]["endpoints"]["tcp:443"] == "https://localhost:9191", \
            f"expected per-instance override, got: {cfg}"

    #
    # Node 4: singularOnly — singular instance is unaffected.
    #
    with subtest("singular instance services work independently"):
        singularOnly.wait_for_unit("tailscaled.service")

        singularOnly.succeed("systemctl cat tailscaled-serve-config.service")

        cfg = get_serve_config(singularOnly, "tailscaled-serve-config.service")

        assert "svc:prometheus" in cfg["services"], f"missing svc:prometheus: {cfg}"
        assert cfg["services"]["svc:prometheus"]["endpoints"]["tcp:443"] == "http://localhost:9090", \
            f"wrong endpoint: {cfg}"
  '';
}
