package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/hashicorp/raft"
	"tailscale.com/tsconsensus"
)

// fulfil the raft lib functional state machine interface
type fsm ipPool
type fsmSnapshot struct{}

func (f *fsm) Apply(l *raft.Log) interface{} {
	var c tsconsensus.Command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		panic(fmt.Sprintf("failed to unmarshal command: %s", err.Error()))
	}
	switch c.Name {
	case "checkoutAddr":
		return f.executeCheckoutAddr(c.Args)
	case "markLastUsed":
		return f.executeMarkLastUsed(c.Args)
	default:
		panic(fmt.Sprintf("unrecognized command: %s", c.Name))
	}
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	panic("Snapshot unexpectedly used")
	return nil, nil
}

func (f *fsm) Restore(rc io.ReadCloser) error {
	panic("Restore unexpectedly used")
	return nil
}

func (f *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	panic("Persist unexpectedly used")
	return nil
}

func (f *fsmSnapshot) Release() {
	panic("Release unexpectedly used")
}
