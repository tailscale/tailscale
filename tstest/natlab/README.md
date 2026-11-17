# natlab

Virtual network lab for integration tests. Tracking issue:
https://github.com/tailscale/tailscale/issues/13038

Use the `run-natlab-tests` GitHub label on PRs to run these tests.

## Prerequisites

- `qemu-system-x86_64` and `qemu-img`. On Debian/Ubuntu:
  `apt install qemu-system-x86 qemu-utils`
- A built gokrazy natlabapp image (auto-built on first run via
  `make -C gokrazy natlab`)

KVM is used automatically on Linux when `/dev/kvm` is readable+writable. Add
yourself to the `kvm` group to avoid QEMU falling back to software emulation.

## Running locally

```
go test ./tstest/natlab/vmtest/ --run-vm-tests -v -timeout=15
```

`go test`'s default timeout (10 min) is likely not enough to cover the whole
package. You may need to raise it further or disable the timeout entirely
(`-timeout=0`) when running the full suite.

Alternatively, select individual tests with the usual `-run`.

## Matrix testing (early stages)

Many tests can effectively be run across multiple variations. To wire up all
these tests programatically and not manually, a tool exists in
`./cmd/natlab-test-matrix` that will parse the test files in the folder
`./tstest/natlab/vmtest` and generate a full set of tests to run.

A `VariationMap` defines variations to be tested. Right now the only variation
used is OS image variation, but this can be expanded to NAT, portmapper and so
on.
