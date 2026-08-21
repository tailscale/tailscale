# Go major version bump checklist

Things to update every six months when we move to a new Go major
version (e.g. Go 1.NN to Go 1.MM). See the git history of this file
and past bump commits (e.g. "go.toolchain.branch: switch to Go 1.26",
"go.toolchain.branch: switch to Go 1.27") for worked examples.

## Prerequisites

- [ ] The `tailscale/go` fork has a `tailscale.goX.YY` branch with our
  patches rebased onto the new release, and its CI has published a
  toolchain tarball for that rev.
- [ ] During the rc period, test the new version via the "next"
  toolchain first: update `go.toolchain.next.branch` and run
  `TS_GO_NEXT=1 ./pull-toolchain.sh`, then let the optional
  `go-next` CI jobs find breakage before release day.

## Toolchain switch

- [ ] Update `go.toolchain.branch` to the new `tailscale.goX.YY` branch name.
- [ ] Run `./pull-toolchain.sh`. This updates:
  - `go.toolchain.rev` (and `go.toolchain.next.rev` if it fell behind)
  - `go.toolchain.version`
  - the `go` directive in `go.mod`
  - `flakehashes.json` (Nix SRI hashes, via `tool/updateflakes`)

## Version strings elsewhere

- [ ] `Dockerfile`: `FROM golang:1.NN-alpine` in the build stage.
- [ ] `README.md`: "We always require the latest Go release, currently Go 1.NN".
- [ ] `.github/workflows/`: grep for hardcoded Go versions. As of Go
  1.27 the workflows use `go-version-file: go.mod` and need no
  changes, but rc-period pins (e.g. `actions/setup-go` with an
  explicit rc version) must be reverted if any were added.

## Regenerate derived files

- [ ] `make updatedeps` to regenerate all `depaware.txt` files. The
  new stdlib usually reshuffles internal dependencies.
- [ ] Regenerate gzip assets if `compress/flate` output changed (it
  did in Go 1.27; the `go generate` steps embed compressed bytes and
  CI checks they are reproducible with the current toolchain):
  - `tempfork/spf13/cobra`: `go generate ./...`
  - `util/eventbus`: `go generate ./...`
  Use the new toolchain (`./tool/go`) on `PATH` when running these.

## Things that may need attention

- [ ] Lint tools: check that staticcheck and golangci-lint releases
  support the new Go version, and bump them in `go.mod` /
  `.github/workflows/golangci-lint.yml` if needed (Go 1.26 needed a
  staticcheck bump). The golangci-lint version pinned in the workflow
  must be a release *built with* the new Go version or it fails with
  "the Go language version (go1.NN) used to build golangci-lint is
  lower than the targeted Go version"; golangci-lint usually ships
  such a release within days of the Go release (v2.13.0 for Go 1.27).
  Verify with `golangci-lint version` and a local
  `golangci-lint run` against the repo config before pushing.
- [ ] `go.mod` / `go.sum`: run `./tool/go mod tidy` and eyeball the
  diff; a new Go version can reorganize the file format or module
  graph pruning.
- [ ] New-version breakage in our code or vendored deps: build and
  test everything (`./tool/go build ./... && ./tool/go test ./...`),
  including GOOS=darwin,windows,etc. cross-builds, before relying on CI.
- [ ] The corp repo, Android, iOS, and other downstream repos have
  their own bumps; this checklist covers only this repo.

## Behavior changes that have bitten us

Categories of Go release fallout seen in past bumps (mostly in corp,
but the categories generalize); grep for them before blaming the code:

- [ ] gofmt output can change; run `gofmt -l` across the tree (and
  corp) with the new toolchain and reformat (Go 1.27 reformatted two
  corp files).
- [ ] encoding/json error strings and UnmarshalTypeError.Field can
  change. Tests asserting exact error text break, and so can
  third-party libraries: Go 1.27 reports the full path to the
  offending value ("errors.deletes.0") where earlier versions
  reported just the top-level field, which broke dnsimple-go's
  error-recovery gate (their PR #271).
- [ ] Error identity from canceled streaming HTTP requests can change:
  Go 1.27's http2 surfaces the underlying "use of closed network
  connection" where Go 1.26 returned the context error. Prefer
  normalizing to ctx.Err() at the source (see sendMapRequest in
  control/controlclient) over teaching each test the new string.
- [ ] json.Decoder over a reader that gains data after reporting EOF
  is not guaranteed to see the later writes; Go 1.27 stopped
  re-polling. Interleaved write-then-decode test helpers should read
  complete lines instead (corp tslogtest).
- [ ] The race detector's cost profile can shift: Go 1.27's race mode
  made a reflection-heavy corp test several times slower, turning a
  slow-but-passing 70s test into a 10 minute timeout. Watch race job
  durations, not just pass/fail.

## After the switch

- [ ] Send the branch through full CI and fix what falls out; amend
  this checklist with anything new you discover.
- [ ] Once the release is proven, consider a follow-up "use Go 1.NN
  things" cleanup commit (gofix modernizers, new stdlib APIs), kept
  separate from the mechanical bump.
