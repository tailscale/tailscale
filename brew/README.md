# Tailscale Mac Homebrew Maintainer Guide


***********
*** WIP ***
***********


Homebrew packaging of the non-IPNExtension, unsandboxed tailscale{d} releases for macOS/darwin.
    
So the public can "brew install" tailscale and start it as a global boot daemon via brew services.


## Platforms Supported

These platform versions and permutations have been tested and are known to work well:

| role        | brew                        | golang                | os                     | arch               | repo       |
| ----------- | --------------------------- | --------------------- | ---------------------- | ------------------ | ---------- |
| maintainer: | Homebrew 3.0.1-120-g5ca03ab | go1.15.8 darwin/amd64 | macOS Catalina 10.15.3 | Intel 64-bit       |            |
|             |   w/ ruby 2.6.3p62          |                       | macOS Big Sur 11.x (?) | Apple M1 ARM64 (?) |            |
|             |                             |                       |                        |                    |            |
|             |                             |                       |                        |                    |            |
| pkg target: | Homebrew 3.0.1-120-g5ca03ab | go1.15.8 darwin/amd64 | macOS Catalina 10.15.3 | Intel 64-bit       | tailscale: |
|             |   w/ ruby 2.6.3p62          |                       | macOS Big Sur 11.x (?) | Apple M1 ARM64 (?) | 188bb14269 |
|             |                             |                       |                        |                    | HEAD       |
|             |                             |                       |                        |                    | likely 1.5 |


## Directory Contents

| type               | name                         | purpose                                                        |
| ------------------ | ---------------------------- | -------------------------------------------------------------- |
| formulae           | tailscale.rb                 | The default packaging "formula" in Ruby, based on a            |
|                    |                              | a pinned commit from the tailscale/tailscale GitHub repo       |
|                    |                              |                                                                |
|                    | tailscale.*.rb               | Alternate formulae (mainly used for testing now,               |
|                    |                              | and includes some variants based on tagged release source      |
|                    |                              | tarballs, and local test standin candidates)                   |
|                    |                              |                                                                |
| maintainer scripts | vars.sh                      | role for brew like version/version.sh for build_dist.sh        |
|                    | generate-formulae.sh         | regenerates all formulae (default, plus some alternates)       |
|                    | generate-formula.sh          | generates formula from an embedded template, to stdout         |
|                    | make-test-source-tarball.sh  |                                                                |
|                    | serve-tarball.sh             |                                                                |
|                    | dl-tarball-sha.sh            |                                                                |
|                    | test.sh                      | tests all supported permutations                               |
|                    | install-start-with-checks.sh | install test run for maintainer                                |
|                    | up.sh                        |                                                                |
|                    | status.sh                    |                                                                |
|                    | stop-uninstall-wipe.sh       | closing counterpart to the install*.sh script                  |
|                    | search-interesting.sh        | nice to keep these on maintainer's radar                       |
|                    |                              |                                                                |
| subdirs            | brew/local/                  | .gitignored tree created and used during brew maintenance work |


## Use Cases

For the ultimate endusers (ONLY ONCE READY & AVAIL)...

```
brew install tailscale
sudo brew services start tailscale
```

TODO(mkramlich): add context, details, variants to the above

For an early adopter who wants to try an unofficial sneak preview of a local brew install of the WIP formula:

```
git clone https://github.com/mkramlich/tailscale
cd tailscale
git switch mkramlich/macos-brew
brew install --formula brew/tailscale.rb # default formula draws from a recent good commit from tailscale/tailscale
sudo brew services start tailscale
# tailscaled is now running and registered as a global boot daemon (via launchctl/launchd)
brew/up.sh # then do your auth
# tailscaled is now authorized and providing normal service to your VPN
```

For maintainers...

All scripts assume you are in the cloned repo root, just above brew/
	(EXCEPT make-test-source-tarball.sh, TODO)

To edit the formula source, regen and retest:

```
# modify the template fragments inside generate-formula.sh
#   and/or the var values in brew/vars.sh or brew/generate-formulae.sh
brew/generate-formulae.sh
brew/serve-tarball.sh # ensure running in background; only needed for the local source tarball test in test.sh
brew/test.sh # this is very WIP, but generally the goal is if it exits 0 then the tests are green
```

TODO(mkramlich): flesh out much further; topics: formula vs bottle, sudo vs not, prefix diffs, local vs public ts tap vs core, testing, submission and bumping
