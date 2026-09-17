# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Eval-only test for the Tailscale darwin module.
# Stubs the nix-darwin options the module touches (launchd.user.agents,
# system.primaryUser, environment.systemPackages, assertions) so we can
# evaluate it on any platform without taking a runtime dependency on
# nix-darwin. Asserts that the expected LaunchAgent labels appear and
# that the per-instance daemon script embeds the right paths/flags.
{
  self,
  pkgs,
  lib,
}: let
  # Minimal stand-in for the nix-darwin option surface our module uses.
  darwinStub = {
    lib,
    config,
    ...
  }: {
    options = {
      launchd.user.agents = lib.mkOption {
        type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
        default = {};
      };
      environment.systemPackages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [];
      };
      system.primaryUser = lib.mkOption {
        type = lib.types.str;
        default = "testuser";
      };
      assertions = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            assertion = lib.mkOption {type = lib.types.bool;};
            message = lib.mkOption {type = lib.types.str;};
          };
        });
        default = [];
      };
    };
  };

  evaluated = lib.evalModules {
    modules = [
      darwinStub
      (import ../default.nix self)
      {
        system.primaryUser = "alice";
        services.tailscales = {
          headscale = {
            enable = true;
            extraUpFlags = ["--login-server=https://hs.example.com"];
          };
          personal = {
            enable = true;
            extraSetFlags = ["--accept-routes"];
            services.demo.endpoints."tcp:443" = "http://localhost:9090";
          };
          disabled.enable = false;
        };
      }
    ];
    specialArgs = {inherit pkgs;};
  };

  cfg = evaluated.config;

  agentNames = lib.attrNames cfg.launchd.user.agents;
  packageNames = map (p: p.pname or p.name) cfg.environment.systemPackages;

  # Resolve the script (first ProgramArguments entry) for a label.
  scriptOf = label:
    builtins.head cfg.launchd.user.agents.${label}.serviceConfig.ProgramArguments;

  # Failing assertions surface as eval-time errors via throw.
  check = cond: msg:
    if cond
    then null
    else throw "darwin eval-test: ${msg}";

  checks = [
    (check (cfg.launchd.user.agents ? "com.tailscale.tailscaled-headscale")
      "expected daemon agent for headscale")
    (check (cfg.launchd.user.agents ? "com.tailscale.tailscaled-personal")
      "expected daemon agent for personal")
    # headscale has no authKey/serve/set → no bootstrap agent.
    (check (!(cfg.launchd.user.agents ? "com.tailscale.tailscale-headscale-bootstrap"))
      "headscale should have no bootstrap agent (no auth/set/serve config)")
    # personal has extraSetFlags + services → bootstrap agent expected.
    (check (cfg.launchd.user.agents ? "com.tailscale.tailscale-personal-bootstrap")
      "personal should have a bootstrap agent (extraSetFlags + services configured)")
    (check (!(cfg.launchd.user.agents ? "com.tailscale.tailscaled-disabled"))
      "disabled instance should produce no daemon agent")
    # CLI wrapper packages installed.
    (check (lib.any (n: n == "tailscale-headscale") packageNames)
      "expected tailscale-headscale CLI wrapper in systemPackages")
    (check (lib.any (n: n == "tailscale-personal") packageNames)
      "expected tailscale-personal CLI wrapper in systemPackages")
    # Module-level assertions must all hold for valid inputs.
    (check (lib.all (a: a.assertion) cfg.assertions)
      "all module assertions must hold for valid inputs")
  ];
in
  pkgs.runCommand "tailscale-darwin-eval-test" {
    agents = lib.concatStringsSep "\n" agentNames;
    headscaleDaemon = "${scriptOf "com.tailscale.tailscaled-headscale"}";
    personalDaemon = "${scriptOf "com.tailscale.tailscaled-personal"}";
    personalBootstrap = "${scriptOf "com.tailscale.tailscale-personal-bootstrap"}";
    # Force eval of all check assertions.
    forceChecks = builtins.toJSON checks;
  } ''
    echo "agents:"
    echo "$agents"

    for f in "$headscaleDaemon" "$personalDaemon"; do
      grep -q -- '--tun=userspace-networking' "$f" \
        || { echo "missing --tun=userspace-networking in $f" >&2; exit 1; }
    done

    grep -q -- 'Tailscale-headscale' "$headscaleDaemon" \
      || { echo "missing Tailscale-headscale path in headscale daemon" >&2; exit 1; }
    grep -q -- 'Tailscale-personal' "$personalDaemon" \
      || { echo "missing Tailscale-personal path in personal daemon" >&2; exit 1; }

    # personal bootstrap must invoke `set` and `serve set-config`.
    grep -q -- 'set --accept-routes' "$personalBootstrap" \
      || { echo "bootstrap missing extraSetFlags invocation" >&2; exit 1; }
    grep -q -- 'serve set-config' "$personalBootstrap" \
      || { echo "bootstrap missing serve set-config invocation" >&2; exit 1; }
    grep -q -- 'serve advertise svc:demo' "$personalBootstrap" \
      || { echo "bootstrap missing serve advertise for demo svc" >&2; exit 1; }

    touch "$out"
  ''
