// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package workgraph

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"

	"tailscale.com/util/must"
	"tailscale.com/util/set"
)

func debugGraph(tb testing.TB, g *WorkGraph) {
	before := g.Graphviz()
	tb.Cleanup(func() {
		if !tb.Failed() {
			return
		}

		after := g.Graphviz()
		tb.Logf("graphviz at start of test:\n%s", before)
		tb.Logf("graphviz at end of test:\n%s", after)
	})
}

func makeTestGraph(tb testing.TB) *WorkGraph {
	logFunc := func(s string) func(context.Context) error {
		return func(_ context.Context) error {
			tb.Log(s)
			return nil
		}
	}
	makeNode := func(s string) Node {
		return NodeFunc(s, logFunc(s+" called"))
	}
	withDeps := func(ss ...string) *AddNodeOpts {
		return &AddNodeOpts{Dependencies: ss}
	}

	g := NewWorkGraph()

	// Ensure we have at least 2 concurrent goroutines
	g.Concurrency = runtime.GOMAXPROCS(-1)
	if g.Concurrency < 2 {
		g.Concurrency = 2
	}

	n1 := makeNode("one")
	n2 := makeNode("two")
	n3 := makeNode("three")
	n4 := makeNode("four")
	n5 := makeNode("five")
	n6 := makeNode("six")

	must.Do(g.AddNode(n1, nil)) // can execute first
	must.Do(g.AddNode(n2, nil)) // can execute first
	must.Do(g.AddNode(n3, withDeps("one")))
	must.Do(g.AddNode(n4, withDeps("one", "two")))
	must.Do(g.AddNode(n5, withDeps("one")))
	must.Do(g.AddNode(n6, withDeps("four", "five")))

	return g
}

func TestWorkGraph(t *testing.T) {
	g := makeTestGraph(t)
	debugGraph(t, g)

	if err := g.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestWorkGroup_Error(t *testing.T) {
	g := NewWorkGraph()

	terr := errors.New("test error")

	returnsErr := func(_ context.Context) error { return terr }
	notCalled := func(_ context.Context) error { panic("unused") }

	n1 := NodeFunc("one", returnsErr)
	n2 := NodeFunc("two", notCalled)
	n3 := NodeFunc("three", notCalled)

	must.Do(g.AddNode(n1, nil))
	must.Do(g.AddNode(n2, &AddNodeOpts{Dependencies: []string{"one"}}))
	must.Do(g.AddNode(n3, &AddNodeOpts{Dependencies: []string{"one", "two"}}))

	err := g.Run(context.Background())
	if err == nil {
		t.Fatal("wanted non-nil error")
	}
	if !errors.Is(err, terr) {
		t.Errorf("got %v, want %v", err, terr)
	}
}

func TestWorkGroup_HandlesPanic(t *testing.T) {
	g := NewWorkGraph()

	terr := errors.New("test error")
	n1 := NodeFunc("one", func(_ context.Context) error { panic(terr) })

	must.Do(g.AddNode(n1, nil))
	err := g.Run(context.Background())
	if err == nil {
		t.Fatal("wanted non-nil error")
	}
	if !errors.Is(err, terr) {
		t.Errorf("got %v, want %v", err, terr)
	}
}

func TestWorkGroup_Cancellation(t *testing.T) {
	g := NewWorkGraph()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var running atomic.Int64
	blocks := func(ctx context.Context) error {
		running.Add(1)
		<-ctx.Done()
		return ctx.Err()
	}

	n1 := NodeFunc("one", blocks)
	n2 := NodeFunc("two", blocks)
	n3 := NodeFunc("three", blocks)

	must.Do(g.AddNode(n1, nil))
	must.Do(g.AddNode(n2, nil))

	// Ensure that we have a node with dependencies that's also waiting
	// since we want to verify that the queue publisher also properly
	// handles context cancellation.
	must.Do(g.AddNode(n3, &AddNodeOpts{Dependencies: []string{"one", "two"}}))

	// call Run in a goroutine since it blocks
	errCh := make(chan error, 1)
	go func() {
		errCh <- g.Run(ctx)
	}()

	// after all goroutines are running, cancel the context to unblock
	for running.Load() != 2 {
		// wait
	}
	cancel()
	err := <-errCh

	if err == nil {
		t.Fatal("wanted non-nil error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want %v", err, context.Canceled)
	}
}

func TestTopoSortDFS(t *testing.T) {
	g := makeTestGraph(t)
	debugGraph(t, g)

	sorted, err := g.topoSortDFS()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("DFS topological sort: %v", sorted)

	validateTopologicalSortDFS(t, g, sorted)
}

func validateTopologicalSortDFS(tb testing.TB, g *WorkGraph, order []string) {
	// A valid ordering is any one where a node ID later in the list does
	// not depend on a node ID earlier in the list.
	for i, node := range order {
		for j := 0; j < i; j++ {
			if g.edges.Exists(node, order[j]) {
				tb.Errorf("invalid edge: %v [%d] -> %v [%d]", node, i, order[j], j)
			}
		}
	}
}

func TestTopoSortKahn(t *testing.T) {
	g := makeTestGraph(t)
	debugGraph(t, g)

	groups, err := g.topoSortKahn()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("grouped topological sort: %v", groups)

	validateTopologicalSortKahn(t, g, groups)
}

func validateTopologicalSortKahn(tb testing.TB, g *WorkGraph, groups []set.Set[string]) {
	// A valid ordering is any one where a node ID later in the list does
	// not depend on a node ID earlier in the list.
	prev := make(map[string]bool)
	for i, group := range groups {
		for node := range group {
			for m := range prev {
				if g.edges.Exists(node, m) {
					tb.Errorf("group[%d]: invalid edge: %v -> %v", i, node, m)
				}
			}
			prev[node] = true
		}
	}

	// Verify that our topologically sorted groups contain all nodes.
	for nid := range g.nodes {
		if !prev[nid] {
			tb.Errorf("topological sort missing node %v", nid)
		}
	}
}

func FuzzTopSortKahn(f *testing.F) {
	// We can't pass a map[string][]string (or similar) into a fuzz
	// function, so instead let's create test data by using a combination
	// of 'n' nodes and an adjacency matrix of edges from node to node.
	//
	// We then need to filter this adjacency matrix in the Fuzz function,
	// since the fuzzer doesn't distinguish between "invalid fuzz inputs
	// due to logic bugs", and "invalid fuzz data that causes a real
	// error".
	f.Add(
		10, // number of nodes
		[]byte{
			1, 0, // 1 depends on 0
			6, 2, // 6 depends on 2
			9, 8, // 9 depends on 8
		},
	)
	f.Fuzz(func(t *testing.T, numNodes int, edges []byte) {
		g := createGraphFromFuzzInput(t, numNodes, edges)
		if g == nil {
			return
		}

		// This should not error
		groups, err := g.topoSortKahn()
		if err != nil {
			t.Fatal(err)
		}
		validateTopologicalSortKahn(t, g, groups)
	})
}

func FuzzTopSortDFS(f *testing.F) {
	// We can't pass a map[string][]string (or similar) into a fuzz
	// function, so instead let's create test data by using a combination
	// of 'n' nodes and an adjacency matrix of edges from node to node.
	//
	// We then need to filter this adjacency matrix in the Fuzz function,
	// since the fuzzer doesn't distinguish between "invalid fuzz inputs
	// due to logic bugs", and "invalid fuzz data that causes a real
	// error".
	f.Add(
		10, // number of nodes
		[]byte{
			1, 0, // 1 depends on 0
			6, 2, // 6 depends on 2
			9, 8, // 9 depends on 8
		},
	)
	f.Fuzz(func(t *testing.T, numNodes int, edges []byte) {
		g := createGraphFromFuzzInput(t, numNodes, edges)
		if g == nil {
			return
		}

		// This should not error
		sorted, err := g.topoSortDFS()
		if err != nil {
			t.Fatal(err)
		}
		validateTopologicalSortDFS(t, g, sorted)
	})
}

func createGraphFromFuzzInput(tb testing.TB, numNodes int, edges []byte) *WorkGraph {
	nodeName := func(i int) string {
		return fmt.Sprintf("node-%d", i)
	}

	filterAdjacencyMatrix := func(numNodes int, edges []byte) map[string][]string {
		deps := make(map[string][]string)
		for i := 0; i < len(edges); i += 2 {
			node, dep := int(edges[i]), int(edges[i+1])
			if node >= numNodes || dep >= numNodes {
				// invalid node
				continue
			}
			if node == dep {
				// can't depend on self
				continue
			}

			// We add nodes in incrementing order (0, 1, 2, etc.),
			// so an edge can't point 'forward' or it'll fail to be
			// added.
			if dep > node {
				continue
			}

			nn := nodeName(node)
			deps[nn] = append(deps[nn], nodeName(dep))
		}
		return deps
	}

	// Constrain the number of nodes
	if numNodes <= 0 || numNodes > 1000 {
		return nil
	}
	// Must have pairs of edges (from, to)
	if len(edges)%2 != 0 {
		return nil
	}

	// Convert list of edges into list of dependencies
	deps := filterAdjacencyMatrix(numNodes, edges)
	if len(deps) == 0 {
		return nil
	}

	// Actually create graph.
	g := NewWorkGraph()
	doNothing := func(context.Context) error { return nil }
	for i := 0; i < numNodes; i++ {
		nn := nodeName(i)
		node := NodeFunc(nn, doNothing)
		if err := g.AddNode(node, &AddNodeOpts{
			Dependencies: deps[nn],
		}); err != nil {
			tb.Error(err) // shouldn't error after we filtered out bad edges above
		}
	}
	if tb.Failed() {
		return nil
	}
	return g
}
