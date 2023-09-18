// The client/web/build module provides the build artifacts (JS and CSS bundles) for the Tailscale web client.
// These artifacts are not checked into version control, but must be built locally before building the tailscale client.
//
// When the tailcale.com module is imported as a Go module (as it is in the Tailscale corp repo),
// the source is placed in the read-only Go module cache.
// Exposing client/web/build as a standalone module allows us to build the web client artifacts in a writable directory
// and then use go.mod to replace that module with the local copy.
//
// This could also be achieved by using `go mod vendor` to copy modules into a writable directory,
// but that copies far more than is really necessary.

module tailscale.com/client/web/build

go 1.21
