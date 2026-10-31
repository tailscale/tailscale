# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# Eval-only test for the Tailscale NixOS module. Evaluates NixOS systems
# with the override module and checks assertions (firing and not), the
# generated units, flags, ordering, firewall, networkd and serve config.
# Checks throw at eval time, so `nix flake check --no-build` enforces them.
{
  self,
  pkgs,
  lib,
}: let
  inherit (lib) any elem filter hasInfix;

  base = {
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "/dev/null";
      fsType = "ext4";
    };
    system.stateVersion = lib.trivial.release;
  };

  eval = module:
    # Path concatenation, not interpolation: "${pkgs.path}" re-copies nixpkgs
    # into the store, which flake check cannot realise on a fresh store.
    (import (pkgs.path + "/nixos/lib/eval-config.nix") {
      inherit pkgs;
      system = null;
      modules = [self.nixosModules.override base module];
    })
    .config;

  failing = c: map (a: a.message) (filter (a: !a.assertion) c.assertions);
  fires = c: needle: any (hasInfix needle) (failing c);
  clean = c: failing c == [];

  units = c: c.systemd.services;
  has = c: u: (units c) ? ${u};
  unit = c: u: (units c).${u};
  exec = c: u: (unit c u).serviceConfig.ExecStart;
  env = c: u: (unit c u).serviceConfig.Environment;
  script = c: u: (unit c u).script;
  udp = c: lib.sort lib.lessThan c.networking.firewall.allowedUDPPorts;
  pkgNames = c: map (p: p.pname or p.name) c.environment.systemPackages;
  sysctl = c: k: c.boot.kernel.sysctl.${k} or false;

  # Path the module should generate for these services, compared by store
  # path so no build is needed.
  serveFile = name: services:
    toString (pkgs.writeText "tailscale-services-${name}.json"
      (builtins.toJSON {
        version = "0.0.1";
        inherit services;
      }));
  serveConfigOf = c: u: toString (builtins.head (unit c u).restartTriggers);

  check = cond: msg:
    if cond
    then null
    else throw "nixos eval-test: ${msg}";

  prom = {endpoints."tcp:443" = "http://localhost:9090";};
  promJson = {"svc:prometheus".endpoints."tcp:443" = "http://localhost:9090";};

  # ── Configurations ──

  singular = eval {
    networking.networkmanager.enable = true;
    services.tailscale = {
      enable = true;
      openFirewall = true;
      permitCertUid = "caddy";
      disableTaildrop = true;
      disableUpstreamLogging = true;
    };
  };

  plural = eval {
    services.tailscales = {
      a = {
        enable = true;
        openFirewall = true;
        proxy = "socks";
        proxyListenAddress = "localhost:1080";
        cleanup = false;
      };
      b = {
        enable = true;
        openFirewall = true;
        port = 41700;
        proxy = "both";
        proxyListenAddress = "localhost:1081";
      };
      off.enable = false;
    };
  };

  autoconnect = eval {
    services.tailscale = {
      enable = true;
      openFirewall = true;
      authKeyFile = "/run/keys/ts";
      authKeyParameters = {
        ephemeral = true;
        preauthorized = false;
        baseURL = "https://api.example";
      };
      extraUpFlags = ["--ssh"];
      extraSetFlags = ["--accept-routes"];
      relayServerPort = 40000;
    };
    services.tailscales.x = {
      enable = true;
      openFirewall = true;
      authKeyFile = "/run/keys/x";
      relayServerPort = "";
    };
  };

  twoTun = eval {
    services.tailscale.enable = true;
    services.tailscales.x = {
      enable = true;
      networkingMode = "tun";
    };
  };

  # Upstream's way to skip TUN; must not count as TUN, and routing features
  # stay allowed (netstack routes in userspace).
  upstreamUserspace = eval {
    services.tailscale = {
      enable = true;
      interfaceName = "userspace-networking";
      useRoutingFeatures = "both";
    };
    services.tailscales.x = {
      enable = true;
      networkingMode = "tun";
      useRoutingFeatures = "server";
    };
  };

  defaultClash = eval {
    services.tailscale.enable = true;
    services.tailscales.default.enable = true;
  };

  proxyClash = eval {
    services.tailscales = {
      a = {
        enable = true;
        proxy = "socks";
        proxyListenAddress = "localhost:1055";
      };
      b = {
        enable = true;
        proxy = "http";
        proxyListenAddress = "localhost:1055";
      };
    };
  };

  # Ephemeral ports, disabled instances and proxy = "off" never clash.
  proxyNoClash = eval {
    services.tailscales = {
      a = {
        enable = true;
        proxy = "socks";
        proxyListenAddress = "localhost:0";
      };
      b = {
        enable = true;
        proxy = "socks";
        proxyListenAddress = "localhost:0";
      };
      c = {
        enable = true;
        proxy = "off";
      };
      d = {
        enable = true;
        proxy = "socks";
      };
      e = {
        enable = false;
        proxy = "socks";
      };
    };
  };

  networkd = eval {
    networking.useNetworkd = true;
    services.tailscale.enable = true;
    services.tailscales = {
      t = {
        enable = true;
        networkingMode = "tun";
        interfaceName = "ts-t";
      };
      u.enable = true;
    };
  };

  # Disabled singular still feeds shared services to plural instances.
  sharedOnly = eval {
    services.tailscale.services.prometheus = prom;
    services.tailscales = {
      net1.enable = true;
      net2.enable = true;
    };
  };

  sharedPlusOwn = eval {
    services.tailscale.services.prometheus = prom;
    services.tailscales.net1 = {
      enable = true;
      services.postgres = {
        endpoints."tcp:5432" = "tcp://localhost:5432";
        advertised = false;
      };
    };
  };

  # Per-instance replaces the shared service of the same name wholesale.
  serveOverride = eval {
    services.tailscale.services.prometheus = prom;
    services.tailscales.net1 = {
      enable = true;
      services.prometheus.endpoints."tcp:8443" = "https://localhost:9191";
    };
  };

  # Upstream nixpkgs spellings, mixed with ours, plus a raw servicesFile.
  serveCompat = eval {
    services.tailscale = {
      enable = true;
      serve = {
        enable = true;
        services.prometheus = prom;
      };
      services.grafana.endpoints."tcp:3000" = "http://localhost:3000";
    };
    services.tailscales.net1 = {
      enable = true;
      servicesFile = "/run/secrets/services.json";
    };
  };

  serveConfigFileAlias = eval {
    services.tailscale = {
      enable = true;
      serve.configFile = "/run/secrets/serve.json";
    };
  };

  derper = eval {
    services.tailscale.derper = {
      enable = true;
      domain = "derp.example";
      verifyClients = true;
    };
  };

  noDerper = eval {services.tailscale.derper.domain = "derp.example";};

  checks = [
    # ── Singular instance ──
    (check (clean singular) "singular: assertions must hold")
    (check (exec singular "tailscaled"
      == "${singular.services.tailscale.package}/bin/tailscaled --port=41641 --tun=tailscale0 --statedir=/var/lib/tailscale --socket=/run/tailscale/tailscaled.sock")
    "singular: ExecStart")
    (check (env singular "tailscaled"
      == ["TS_PERMIT_CERT_UID=caddy" "TS_DISABLE_TAILDROP=true" "TS_NO_LOGS_NO_SUPPORT=true"])
    "singular: Environment")
    (check ((unit singular "tailscaled").serviceConfig.ExecStopPost
      == "${singular.services.tailscale.package}/bin/tailscaled --cleanup")
    "singular: cleanup on stop")
    (check ((unit singular "tailscaled").serviceConfig.Type == "notify") "singular: Type=notify")
    (check (!(unit singular "tailscaled").stopIfChanged) "singular: restart in one step on switch")
    (check ((unit singular "tailscaled").wantedBy == ["multi-user.target"]) "singular: wantedBy")
    (check (elem "network-online.target" (unit singular "tailscaled").wants) "singular: wants network-online")
    (check (elem "network-online.target" (unit singular "tailscaled").after) "singular: after network-online")
    (check (elem "NetworkManager-wait-online.service" (unit singular "tailscaled").after)
      "singular: after NetworkManager-wait-online with NetworkManager")
    (check (!(has singular "tailscaled-autoconnect")) "singular: no autoconnect without authKeyFile")
    (check (!(has singular "tailscaled-set")) "singular: no set unit without set flags")
    (check (!(has singular "tailscaled-serve-config")) "singular: no serve-config without services")
    (check (udp singular == [41641]) "singular: openFirewall opens the port")
    (check (elem "tailscale0" singular.networking.dhcpcd.denyInterfaces) "singular: dhcpcd ignores tailscale0")
    (check (!(elem "tailscale-proxies" (pkgNames singular))) "singular: no proxy lister without proxies")
    (check (!(sysctl singular "net.ipv4.conf.all.forwarding")) "singular: no forwarding by default")

    # ── Plural instances ──
    (check (clean plural) "plural: assertions must hold")
    (check (!(has plural "tailscaled")) "plural: singular disabled")
    (check (!(has plural "tailscaled-off")) "plural: disabled instance has no unit")
    (check (exec plural "tailscaled-a"
      == "${plural.services.tailscales.a.package}/bin/tailscaled --port=0 --tun=userspace-networking --statedir=/var/lib/tailscale-a --socket=/run/tailscale-a/tailscaled.sock --socks5-server=localhost:1080")
    "plural: a ExecStart (userspace, port 0, socks)")
    (check (hasInfix "--socks5-server=localhost:1081 --outbound-http-proxy-listen=localhost:1081" (exec plural "tailscaled-b"))
      "plural: b runs both proxies on one address")
    (check (hasInfix "--port=41700" (exec plural "tailscaled-b")) "plural: b port")
    (check (!((unit plural "tailscaled-a").serviceConfig ? ExecStopPost)) "plural: cleanup = false drops ExecStopPost")
    (check ((unit plural "tailscaled-a").serviceConfig.RuntimeDirectory == "tailscale-a") "plural: runtime dir")
    (check ((unit plural "tailscaled-a").serviceConfig.StateDirectory == "tailscale-a") "plural: state dir")
    (check (udp plural == [41700]) "plural: port 0 is not opened")
    (check (plural.networking.dhcpcd.denyInterfaces == []) "plural: userspace instances leave dhcpcd alone")
    (check (elem "tailscale-a" (pkgNames plural) && elem "tailscale-b" (pkgNames plural)) "plural: CLI wrappers")
    (check (!(elem "tailscale-off" (pkgNames plural))) "plural: no wrapper for disabled instance")
    (check (elem "tailscale-proxies" (pkgNames plural)) "plural: proxy lister installed")
    (check (plural.services.tailscales.a.interfaceName == "ts-a") "plural: interface name default")

    # ── Autoconnect and set ──
    (check (clean autoconnect) "autoconnect: assertions must hold")
    (check ((unit autoconnect "tailscaled-autoconnect").serviceConfig.Type == "notify") "autoconnect: Type=notify")
    (check ((unit autoconnect "tailscaled-autoconnect").wantedBy == ["tailscaled.service"])
      "autoconnect: wanted by tailscaled, not multi-user (offline boots)")
    (check (elem "tailscaled.service" (unit autoconnect "tailscaled-autoconnect").after) "autoconnect: after tailscaled")
    (check (hasInfix "up --reset --auth-key \"$(cat /run/keys/ts)?baseURL=https://api.example&ephemeral=true&preauthorized=false\" --ssh" (script autoconnect "tailscaled-autoconnect"))
      "autoconnect: auth key, parameters and up flags")
    (check (hasInfix "tailscale --socket=/run/tailscale/tailscaled.sock status" (script autoconnect "tailscaled-autoconnect"))
      "autoconnect: singular socket")
    (check (hasInfix "--socket=/run/tailscale-x/tailscaled.sock up --reset --auth-key \"$(cat /run/keys/x)\"" (script autoconnect "tailscaled-x-autoconnect"))
      "autoconnect: plural socket, no parameters")
    (check (hasInfix "set --accept-routes '--relay-server-port=40000'" (script autoconnect "tailscaled-set"))
      "set: extraSetFlags then relayServerPort")
    (check (hasInfix "--socket=/run/tailscale-x/tailscaled.sock set '--relay-server-port='" (script autoconnect "tailscaled-x-set"))
      "set: relayServerPort \"\" disables")
    (check ((unit autoconnect "tailscaled-set").wantedBy == ["tailscaled.service"]) "set: wanted by tailscaled")
    (check (elem "tailscaled-autoconnect.service" (unit autoconnect "tailscaled-set").after) "set: after autoconnect")
    (check (udp autoconnect == [40000 41641]) "firewall: relay port opened, \"\" and port 0 skipped")

    # ── Assertions ──
    (check (fires twoTun "At most one Tailscale instance can use TUN") "assert: two TUN instances")
    (check (clean upstreamUserspace) "assert: userspace-networking is userspace; routing features allowed")
    (check (upstreamUserspace.services.tailscale.networkingMode == "userspace") "userspace-networking implies userspace")
    (check (!(elem "userspace-networking" upstreamUserspace.networking.dhcpcd.denyInterfaces))
      "userspace-networking: not handed to dhcpcd")
    (check (sysctl upstreamUserspace "net.ipv4.conf.all.forwarding") "routing: server enables forwarding")
    (check (sysctl upstreamUserspace "net.ipv6.conf.all.forwarding") "routing: server enables v6 forwarding")
    (check (upstreamUserspace.networking.firewall.checkReversePath == "loose") "routing: client loosens rpfilter")
    (check (fires defaultClash "Cannot enable both") "assert: singular and tailscales.default")
    (check (fires proxyClash "share a proxy listen address: localhost:1055") "assert: shared proxy address")
    (check (clean proxyNoClash) "assert: :0, off and disabled proxies never clash")

    # ── networkd ──
    (check (networkd.systemd.network.networks."50-tailscale".matchConfig.Name == "tailscale0")
      "networkd: singular unit named like upstream")
    (check (networkd.systemd.network.networks."50-tailscale".linkConfig.Unmanaged) "networkd: unmanaged")
    (check (networkd.systemd.network.networks."50-tailscale-t".matchConfig.Name == "ts-t") "networkd: plural TUN unit")
    (check (!(networkd.systemd.network.networks ? "50-tailscale-u")) "networkd: no unit for userspace")

    # ── Tailscale Services ──
    (check (!(has sharedOnly "tailscaled-serve-config")) "serve: disabled singular has no unit")
    (check (serveConfigOf sharedOnly "tailscaled-net1-serve-config" == serveFile "net1" promJson) "serve: shared to net1")
    (check (serveConfigOf sharedOnly "tailscaled-net2-serve-config" == serveFile "net2" promJson) "serve: shared to net2")
    (check (serveConfigOf sharedPlusOwn "tailscaled-net1-serve-config"
      == serveFile "net1" (promJson
        // {
          "svc:postgres" = {
            endpoints."tcp:5432" = "tcp://localhost:5432";
            advertised = false;
          };
        }))
    "serve: shared plus own, advertised = false kept")
    (check (serveConfigOf serveOverride "tailscaled-net1-serve-config"
      == serveFile "net1" {"svc:prometheus".endpoints."tcp:8443" = "https://localhost:9191";})
    "serve: per-instance replaces shared wholesale")
    (check (serveConfigOf serveCompat "tailscaled-serve-config"
      == serveFile "default" (promJson // {"svc:grafana".endpoints."tcp:3000" = "http://localhost:3000";}))
    "serve: serve.services alias merges with services")
    (check (serveConfigOf serveCompat "tailscaled-net1-serve-config" == "/run/secrets/services.json")
      "serve: servicesFile wins over shared")
    (check (hasInfix "set-config --all /run/secrets/services.json" (script serveCompat "tailscaled-net1-serve-config"))
      "serve: servicesFile applied")
    (check (serveConfigOf serveConfigFileAlias "tailscaled-serve-config" == "/run/secrets/serve.json")
      "serve: serve.configFile alias")
    (check (!(has serveCompat "tailscale-serve")) "serve: upstream tailscale-serve.nix disabled")
    (check ((unit serveCompat "tailscaled-serve-config").aliases == ["tailscale-serve.service"])
      "serve: singular unit aliased to upstream name")
    (check ((unit serveCompat "tailscaled-net1-serve-config").aliases == []) "serve: no alias on plural")
    (check (!(hasInfix "serve advertise" (script sharedPlusOwn "tailscaled-net1-serve-config")))
      "serve: no advertise after set-config (would override advertised = false)")
    (check (hasInfix "--socket=/run/tailscale-net1/tailscaled.sock serve set-config --all" (script sharedOnly "tailscaled-net1-serve-config"))
      "serve: per-instance socket")
    (check ((unit sharedOnly "tailscaled-net1-serve-config").wantedBy == ["tailscaled-net1.service"])
      "serve: wanted by its tailscaled, not multi-user")
    (check (elem "tailscaled-net1-set.service" (unit sharedOnly "tailscaled-net1-serve-config").after)
      "serve: after the set unit")
    (check ((unit sharedOnly "tailscaled-net1-serve-config").partOf == ["tailscaled-net1.service"])
      "serve: restarts with tailscaled (re-applies after autoconnect's up --reset)")

    # ── Derper ──
    (check derper.services.tailscale.enable "derper: verifyClients enables tailscaled")
    (check (hasInfix "/bin/derper -a :8010 -c /var/lib/derper/derper.key -hostname=derp.example -stun-port 3478 -verify-clients" (exec derper "tailscale-derper"))
      "derper: ExecStart")
    (check (derper.services.nginx.virtualHosts."derp.example".locations."/".proxyPass == "http://127.0.0.1:8010")
      "derper: nginx proxies to derper")
    (check (elem 3478 (udp derper)) "derper: STUN port opened")
    (check (!(has noDerper "tailscale-derper")) "derper: off by default")
    (check (!noDerper.services.tailscale.enable) "derper: off leaves tailscaled off")
  ];
in
  pkgs.runCommand "tailscale-nixos-eval-test" {
    # Evaluating this attribute runs every check.
    checks = builtins.toJSON checks;
  } ''
    touch "$out"
  ''
