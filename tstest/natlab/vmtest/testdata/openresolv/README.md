# Vendored openresolv sources

These are two unmodified source files from upstream openresolv, the resolvconf
implementation behind `net/dns`'s "openresolv" backend. `DNSOpenresolv` installs
them into a guest so a vmtest can exercise that backend. See `../../openresolv.go`.

No cloud image ships openresolv, and a guest cannot download it, because vnet
has no route to the real internet. They are vendored rather than fetched at test
time so that running a vmtest locally needs no network access beyond the cloud
image it already downloads.

openresolv's build applies a handful of `sed` substitutions to these `.in` files
and compiles nothing, so `openresolv.go` can do the same substitutions in
process. That is why only the `.in` sources are here.

## Provenance

Both files come from commit
[`6489889ce5631364ad2f17d391e1a3ad969619f2`](https://github.com/NetworkConfiguration/openresolv/tree/6489889ce5631364ad2f17d391e1a3ad969619f2),
which is tagged `v3.17.4`. They are byte-identical to the same-named members of
the `v3.17.4` release tarball.

The SHA256 of each file is recorded in `openresolvInstall`, in
`../../openresolv.go`, next to the version. `buildOpenresolv` checks both files
against those hashes every time it runs, so a file that changes without its
recorded hash changing too fails the tests rather than reaching a guest. The
hashes say nothing about whether these files came from upstream, since none of
this reaches the network. They are what makes the version above a claim the
tests can hold the files to.

To update, copy the files from a new upstream revision:

```sh
ref=<new commit>
for f in resolvconf.in libc.in; do
  curl -fsSLo "$f" "https://raw.githubusercontent.com/NetworkConfiguration/openresolv/$ref/$f"
done
sha256sum resolvconf.in libc.in
```

Then replace the commit above, and in `../../openresolv.go` replace
`openresolvVersion` and both `srcSHA256` values. Run
`go test ./tstest/natlab/vmtest -run 'TestBuildOpenresolv|TestOpenresolvSHA256'`
afterwards. It fails if a hash was missed, or if the new revision adds a build
placeholder that `openresolvSubst` does not know about.

## Licensing

openresolv is BSD-2-Clause, copyright Roy Marples. Each file carries the full
license text in its header, and neither file is modified here.
