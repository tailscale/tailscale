# Tailscale darwin module tests

## Automated: `eval.nix`

A pure-eval test that stubs the nix-darwin option surface (`launchd.user.agents`,
`system.primaryUser`, `environment.systemPackages`, `assertions`) and evaluates
the module against a sample configuration. It asserts the expected
LaunchAgent labels are produced, that bootstrap agents are only created when
needed, that CLI wrappers land in `environment.systemPackages`, and that the
generated daemon scripts embed the expected paths and flags.

Runs on Linux and macOS via:

```
nix flake check
```

## Automated: end-to-end (`ci/`)

`ci/` contains a self-contained test that brings up a real Headscale on
loopback, applies a sample nix-darwin configuration via
`nix run github:LnL7/nix-darwin`, and verifies that two userspace
tailscaled instances register against separate Headscale users and stay
isolated.

It runs on every PR via `.github/workflows/nix.yml` on a `macos-latest`
GitHub Actions runner. To run it locally on a Mac with Nix installed:

```
cd nix/darwin/tests/ci
bash run.sh
```

`run.sh` cleans up after itself via a `trap` (boots out the LaunchAgents
and kills Headscale). The first run is slow because it builds Tailscale
and Headscale from source.

## Manual: integration on a Mac

The module is intended to be used inside an existing nix-darwin
configuration. The official Tailscale GUI app continues to run on
`/var/run/tailscaled.socket`; this module's instances live on
per-user sockets under `~/Library/Caches/Tailscale-<name>/tsd.sock` and
do not interact with the GUI's daemon.

Minimal example flake:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    nix-darwin.url = "github:LnL7/nix-darwin";
    tailscale.url = "github:tailscale/tailscale";
  };

  outputs = { self, nixpkgs, nix-darwin, tailscale, ... }: {
    darwinConfigurations.mymac = nix-darwin.lib.darwinSystem {
      system = "aarch64-darwin";
      modules = [
        tailscale.darwinModules.default
        {
          system.primaryUser = "alice";
          services.tailscales = {
            headscale = {
              enable = true;
              authKeyFile = "/Users/alice/.config/tailscale/hs.key";
              extraUpFlags = [ "--login-server=https://hs.example.com" ];
            };
            personal.enable = true;
          };
        }
      ];
    };
  };
}
```

### Verification checklist

After `darwin-rebuild switch --flake .#mymac`:

1. `launchctl list | grep com.tailscale.tailscaled-` — both daemon agents listed.
2. `ls -la ~/Library/Caches/Tailscale-*/tsd.sock` — per-instance sockets present.
3. `tailscale-headscale status` and `tailscale-personal status` each
   report the right tailnet.
4. The GUI Tailscale app still shows its own tailnet — `tailscale status`
   (the GUI app's CLI) is unaffected.
5. Tailscale Services (if configured): `tailscale-<name> serve status`
   reports the configured endpoints; advertised services appear in the
   coordination-server admin.
6. Logs: `tail -f ~/Library/Logs/Tailscale-<name>.log`.

### Known limitations

- LaunchAgents stop when the user logs out (this is launchd's normal
  behaviour). For instances that must survive logout, a future iteration
  will need to support LaunchDaemons.
- No firewall integration — macOS PF and `socketfilterfw` are out of scope.
  Userspace tailscaled does not require inbound ports for DERP-only
  operation, and the default `port = 0` opens nothing.
