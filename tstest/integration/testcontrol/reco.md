# Experimental reco implementation

By default, this package uses the original in-memory test control server.
The `experiment.reco` build tag substitutes
[`github.com/bradfitz/reco/recotestcontrol`](https://pkg.go.dev/github.com/bradfitz/reco/recotestcontrol)
using type aliases, without changing callers.

Reco is an experimental research prototype, not a production control server or
a stable API. Its test server requires capability version 109 or later. The
protocol tests check both legacy behavior in the default server and rejection
of obsolete versions with the experiment enabled.

For example, from the module root:

```sh
GOWORK=off GOFLAGS=-tags=experiment.reco go test \
  ./tstest/integration/testcontrol ./control/tsp ./control/controlclient \
  ./tsnet ./tstest/integration
```

Use `GOFLAGS` so integration tests' child Go builds receive the tag too.
Omit it to exercise the default implementation.
