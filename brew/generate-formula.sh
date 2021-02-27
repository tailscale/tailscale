#!/usr/bin/env sh
#set -u # TODO(mkramlich): recreate

# TODO(mkramlich): in form where the url is a .git, the url can also have a tag arg, like: tag: "v1.5.0"

cat <<TEMPLATE
# typed: false
# frozen_string_literal: true

# Homebrew formula for Tailscale
class Tailscale < Formula
  desc "Easiest, secure, crossplatform WireGuard Go-based VPN w/oauth2, 2FA/SSO"
  homepage "https://www.tailscale.com"
TEMPLATE

if [ "$FORMULA_TYPE" = "tarball" ]; then
	cat <<TEMPLATE2
  url "$URL"
  sha256 "$SHA256"
TEMPLATE2
elif [ "$FORMULA_TYPE" = "commit" ]; then
	cat <<TEMPLATE3
  url "$URL",
      revision: "$REVISION"
  version "$VERSION" # TODO(mkramlich): WIP, so not necessarily; brew required a version
TEMPLATE3
else
	exit 1
fi

cat <<TEMPLATE4
  license "BSD-3-Clause"
  head "$HEAD",
       branch: "$BRANCH"

  depends_on "go" => :build

  def install
    ENV["GOPATH"] = buildpath
    tailscale_path = buildpath/"src/github.com/tailscale/tailscale"
    tailscale_path.install buildpath.children
    cd tailscale_path do
      # build the exes with version strings equiv to the tailscale repo's build_dist.sh:
      ldflags = prepare_ldflags
      system "go", "build", "-o", ".", "-tags", "xversion", "-ldflags", ldflags, "tailscale.com/cmd/tailscale"
      system "go", "build", "-o", ".", "-tags", "xversion", "-ldflags", ldflags, "tailscale.com/cmd/tailscaled"
      bin.install "tailscale"
      bin.install "tailscaled"
    end
  end

  def prepare_ldflags
    ver_props = prepare_ver_props
    vl  = ver_props["VERSION_LONG"]
    vs  = ver_props["VERSION_SHORT"]
    vgh = ver_props["VERSION_GIT_HASH"]
    vl  = "tailscale.com/version.Long=#{vl}"
    vs  = "tailscale.com/version.Short=#{vs}"
    vgh = "tailscale.com/version.GitCommit=#{vgh}"
    "-X #{vl} -X #{vs} -X #{vgh}"
  end

  def prepare_ver_props
    distvers = Utils.safe_popen_read("./version/version.sh")
    lines = distvers.split("\n")
    ver_props = {}
    lines.each do |line|
      parts = line.split("=")
      key = parts.at(0)
      val = parts.at(1).delete('"') # cuz version.sh emits each prop with double-quotes enclosing each val
      # system "echo adding to ver_props for go builds: key #{key}, val #{val}"
      ver_props[key] = val
    end
    ver_props
  end

  def post_install
    (var/"run/tailscale").mkpath
    (var/"lib/tailscale").mkpath
  end

  def caveats
    <<~EOS
      To have launchd start tailscale now and restart at boot:
        sudo brew services start tailscale
      NOTE: The caveat message below with 'restart at login' is incorrect, but we can't suppress it. Requires sudo.
    EOS
  end

  plist_options manual: "sudo tailscaled --socket=#{HOMEBREW_PREFIX}/run/tailscale/tailscaled.sock --state=#{HOMEBREW_PREFIX}/lib/tailscale/tailscaled.state"

  def plist
    <<~EOS
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
        <dict>
          <key>KeepAlive</key>
          <dict>
            <key>SuccessfulExit</key>
            <false/>
            <key>NetworkState</key>
            <true/>
          </dict>
          <key>Label</key>
          <string>#{plist_name}</string>
          <key>ProgramArguments</key>
          <array>
            <string>#{opt_bin}/tailscaled</string>
            <string>--socket=#{var}/run/tailscale/tailscaled.sock</string>
            <string>--state=#{var}/lib/tailscale/tailscaled.state</string>
          </array>
          <key>RunAtLoad</key>
          <true/>
          <key>WorkingDirectory</key>
          <string>#{var}/lib/tailscale</string>
          <key>StandardErrorPath</key>
          <string>#{var}/log/tailscale/tailscaled-stderr.log</string>
          <key>StandardOutPath</key>
          <string>#{var}/log/tailscale/tailscaled-stdout.log</string>
        </dict>
      </plist>
    EOS
  end

  test do
    system bin/"tailscale", "version"
    system bin/"tailscaled", "-version"
    system bin/"tailscale", "netcheck"
  end
end
TEMPLATE4
