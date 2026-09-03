# Vendored openresolv sources

These are two unmodified source files from upstream openresolv, the resolvconf
implementation behind `net/dns`'s "openresolv" backend. `DNSOpenresolv` installs
them into a guest so a vmtest can exercise that backend. See `../../resolvconf.go`.

No cloud image ships openresolv, and a guest cannot download it, because vnet
has no route to the real internet. They are vendored rather than fetched at test
time so that running a vmtest locally needs no network access beyond the cloud
image it already downloads.

openresolv's build applies a handful of `sed` substitutions to these `.in` files
and compiles nothing, so `resolvconf.go` can do the same substitutions in
process. That is why only the `.in` sources are here.

## Provenance

Both files come from commit
[`6489889ce5631364ad2f17d391e1a3ad969619f2`](https://github.com/NetworkConfiguration/openresolv/tree/6489889ce5631364ad2f17d391e1a3ad969619f2),
which is tagged `v3.17.4`. They are byte-identical to the same-named members of
the `v3.17.4` release tarball.

| file | SHA256 |
| --- | --- |
| `resolvconf.in` | `c806bd4aa0d1c59736beae3af8a7e4c7cfd6a24664cfbc01be10b28af89f5b8c` |
| `libc.in` | `25b7ba247cb033130035a09751d78be40786ee449a93f31c61b93409dabd54ea` |

Nothing checks these hashes at build or test time. They are recorded so that a
reader can confirm the vendored files still match the upstream commit above,
by running `sha256sum resolvconf.in libc.in`.

To update, copy the files from a new upstream revision and replace the commit
and the hashes above:

```sh
ref=<new commit>
for f in resolvconf.in libc.in; do
  curl -fsSLo "$f" "https://raw.githubusercontent.com/NetworkConfiguration/openresolv/$ref/$f"
done
sha256sum resolvconf.in libc.in
```

Then run `go test ./tstest/natlab/vmtest -run TestBuildOpenresolv`. It fails if
the new revision adds a build placeholder that `openresolvSubst` does not know
about.

## Licensing

openresolv is BSD-2-Clause, copyright Roy Marples. Each file carries the full
license text in its header, and neither file is modified here.
