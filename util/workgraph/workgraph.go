// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package workgraph contains a "workgraph"; a data structure that allows
// defining individual jobs, dependencies between them, and then executing all
// jobs to completion.
package workgraph

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"

	"tailscale.com/util/set"
)

// ErrCyclic is returned when there is a cycle in the graph.
var ErrCyclic = errors.New("graph is cyclic")

// Node is the interface that must be implemented by a node in a WorkGraph.
type Node interface {
	// ID should return a unique ID for this node. IDs for each Node in a
	// WorkGraph must be unique.
	ID() string

	// Run is called when this node in a WorkGraph is executed; it should
	// return an error if execution fails, which will cause all dependent
	// Nodes to fail to execute.
	Run(context.Context) error
}

type nodeFunc struct {
	id  string
	run func(context.Context) error
}

func (n *nodeFunc) ID() string                    { return n.id }
func (n *nodeFunc) Run(ctx context.Context) error { return n.run(ctx) }

// NodeFunc is a helper that returns a Node with the given ID that calls the
// given function when Node.Run is called.
func NodeFunc(id string, fn func(context.Context) error) Node {
	return &nodeFunc{id, fn}
}

// WorkGraph is a directed acyclic graph of individual jobs to be executed,
// each of which may have dependencies on other jobs. It supports adding a job
// as a Node–a combination of a unique ID and the function to execute that
// job–and then running all added Nodes while respecting dependencies.
type WorkGraph struct {
	nodes map[string]Node  // keyed by Node.ID
	edges edgeList[string] // keyed by Node.ID

	// Concurrency is the number of concurrent goroutines to use to process
	// jobs. If zero, runtime.GOMAXPROCS will be used.
	//
	// This field must not be modified after Run has been called.
	Concurrency int
}

// NewWorkGraph creates a new empty WorkGraph.
func NewWorkGraph() *WorkGraph {
	ret := &WorkGraph{
		nodes: make(map[string]Node),
		edges: newEdgeList[string](),
	}
	return ret
}

// AddNodeOpts contains options that can be passed to AddNode.
type AddNodeOpts struct {
	// Dependencies are any Node IDs that must be completed before this
	// Node is started.
	Dependencies []string
}

// AddNode adds a new Node to the WorkGraph with the provided options. It
// returns an error if the given Node.ID was already added to the WorkGraph, or
// if one of the options provided was invalid.
func (g *WorkGraph) AddNode(n Node, opts *AddNodeOpts) error {
	id := n.ID()
	if _, found := g.nodes[id]; found {
		return fmt.Errorf("node %q already exists", id)
	}
	g.nodes[id] = n

	if opts == nil {
		return nil
	}

	// Create an edge from each dependency pointing to this node, forcing
	// that node to be evaluated first.
	for _, dep := range opts.Dependencies {
		if _, found := g.nodes[dep]; !found {
			return fmt.Errorf("dependency %q not found", dep)
		}
		g.edges.Add(dep, id)
	}
	return nil
}

type queueEntry struct {
	id   string
	done chan struct{}
}

// Run will iterate through all Nodes in this WorkGraph, running them once all
// their dependencies have been satisfied, and returning any errors that occur.
func (g *WorkGraph) Run(ctx context.Context) error {
	groups, err := g.topoSortKahn()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create one goroutine that pushes jobs onto our queue...
	var wg sync.WaitGroup
	queue := make(chan queueEntry)
	publishCtx, publishCancel := context.WithCancel(ctx)
	defer publishCancel()

	wg.Add(1)
	go g.runPublisher(publishCtx, &wg, queue, groups)

	firstErr := make(chan error, 1)
	saveErr := func(err error) {
		if err == nil {
			return
		}

		// Tell the publisher to shut down
		publishCancel()

		select {
		case firstErr <- err:
		default:
		}
	}

	// ... and N goroutines that each work on an item from the queue.
	n := g.Concurrency
	if n == 0 {
		n = runtime.GOMAXPROCS(-1)
	}

	wg.Add(n)
	for i := 0; i < n; i++ {
		go g.runWorker(ctx, &wg, queue, saveErr)
	}

	wg.Wait()
	select {
	case err := <-firstErr:
		return err
	default:
	}
	return nil
}

func (g *WorkGraph) runPublisher(ctx context.Context, wg *sync.WaitGroup, queue chan queueEntry, groups []set.Set[string]) {
	defer wg.Done()
	defer close(queue)

	// For each parallel group...
	var dones []chan struct{}
	for _, group := range groups {
		dones = dones[:0] // re-use existing storage, if any

		// Push all items in this group onto our queue
		for curr := range group {
			done := make(chan struct{})
			dones = append(dones, done)

			select {
			case <-ctx.Done():
				return
			case queue <- queueEntry{curr, done}:
			}
		}

		// Now that we've started everything, wait for them all
		// to complete.
		for _, done := range dones {
			select {
			case <-ctx.Done():
				return
			case <-done:
			}
		}

		// Now that we've done this entire group, we can
		// continue with the next one.
	}
}

func (g *WorkGraph) runWorker(ctx context.Context, wg *sync.WaitGroup, queue chan queueEntry, saveErr func(error)) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ent, ok := <-queue:
			if !ok {
				return
			}
			if err := g.runEntry(ctx, ent); err != nil {
				saveErr(err)
				return
			}
		}
	}
}

func (g *WorkGraph) runEntry(ctx context.Context, ent queueEntry) (retErr error) {
	defer close(ent.done)
	defer func() {
		if r := recover(); r != nil {
			// Ensure that we wrap an existing error with %w so errors.Is works
			switch v := r.(type) {
			case error:
				retErr = fmt.Errorf("node %q: caught panic: %w", ent.id, v)
			default:
				retErr = fmt.Errorf("node %q: caught panic: %v", ent.id, v)
			}
		}
	}()

	node := g.nodes[ent.id]
	return node.Run(ctx)
}

// Depth-first toplogical sort; used in tests
//
// https://en.wikipedia.org/wiki/Topological_sorting#Depth-first_search
func (g *WorkGraph) topoSortDFS() (sorted []string, err error) {
	const (
		markTemporary = 1
		markPermanent = 2
	)
	marks := make(map[string]int) // map[node.ID]markType

	var visit func(string) error
	visit = func(n string) error {
		// "if n has a permanent mark then"
		if marks[n] == markPermanent {
			return nil
		}
		// "if n has a temporary mark then"
		if marks[n] == markTemporary {
			return ErrCyclic
		}

		// "mark n with a temporary mark"
		marks[n] = markTemporary

		// "for each node m with an edge from n to m do"
		for m := range g.edges.OutgoingNodes(n) {
			if err := visit(m); err != nil {
				return err
			}
		}

		// "remove temporary mark from n"
		// "mark n with a permanent mark"
		//
		// NOTE: this is safe because if this node had a temporary
		// mark, we'd have returned above, and the only thing that adds
		// a mark to a node is this function.
		marks[n] = markPermanent

		// "add n to head of L"; note that we append for performance
		// reasons and reverse later
		sorted = append(sorted, n)
		return nil
	}

	// For all nodes, visit them. From the algorithm description:
	//	while exists nodes without a permanent mark do
	//	    select an unmarked node n
	//	    visit(n)
	for nid := range g.nodes {
		if err := visit(nid); err != nil {
			return nil, err
		}
	}

	// We appended to the slice for performance reasons; reverse it to get
	// our final result.
	slices.Reverse(sorted)
	return sorted, nil
}

// topoSortKahn runs a variant of Kahn's algorithm for topological sorting,
// which not only returns a sort, but provides individual "groups" of nodes
// that can be executed concurrently.
//
// See:
//   - https://en.wikipedia.org/wiki/Topological_sorting#Kahn's_algorithm
//   - https://stackoverflow.com/a/67267597
func (g *WorkGraph) topoSortKahn() (sorted []set.Set[string], err error) {
	// We mutate the set of edges during this function, so copy it.
	edges := g.edges.Clone()

	// Create S_0, the set of nodes with no incoming edge
	s0 := make(set.Set[string])
	for nid := range g.nodes {
		if !edges.HasIncoming(nid) {
			s0.Add(nid)
		}
	}

	// Add this set to the returned set of nodes
	sorted = append(sorted, s0)

	// Repeatedly iterate, starting from the initial set, until we have no
	// more nodes. The inner loop is essentially Kahn's algorithm.
	sCurr := s0
	for {
		// Initialize the next set
		sNext := make(set.Set[string])

		// For each node 'n' in the current set...
		for n := range sCurr {
			// For each successor 'd' of the current node...
			for d := range edges.OutgoingNodes(n) {
				// Remove edge 'n -> d'
				edges.Remove(n, d)

				// If this node 'd' has no incoming edges, we
				// can add it to the current set since it can
				// be processed.
				if !edges.HasIncoming(d) {
					sNext.Add(d)
				}
			}
		}

		// If the current set is non-empty, then append it to the list
		// of returned sets, make it the current set, and continue.
		// Otherwise, we're done.
		if len(sNext) == 0 {
			break
		}

		sorted = append(sorted, sNext)
		sCurr = sNext
	}

	if edges.Len() > 0 {
		return nil, ErrCyclic
	}
	return sorted, nil
}

// Graphviz prints a basic Graphviz representation of the WorkGraph. This is
// primarily useful for debugging.
func (g *WorkGraph) Graphviz() string {
	var buf strings.Builder
	buf.WriteString("digraph workgraph {\n")
	for from, edges := range g.edges.outgoing {
		for to := range edges {
			fmt.Fprintf(&buf, "\t%s -> %s;\n", from, to)
		}
	}
	buf.WriteString("}")
	return buf.String()
}

// edgeList is a helper type that is used to maintain a set of edges, tracking
// both incoming and outgoing edges for a given node.
type edgeList[K comparable] struct {
	incoming map[K]set.Set[K] // for edge A -> B, keyed by B
	outgoing map[K]set.Set[K] // for edge A -> B, keyed by A
}

func newEdgeList[K comparable]() edgeList[K] {
	return edgeList[K]{
		incoming: make(map[K]set.Set[K]),
		outgoing: make(map[K]set.Set[K]),
	}
}

func (el *edgeList[K]) Clone() edgeList[K] {
	ret := edgeList[K]{
		incoming: make(map[K]set.Set[K], len(el.incoming)),
		outgoing: make(map[K]set.Set[K], len(el.outgoing)),
	}
	for k, v := range el.incoming {
		ret.incoming[k] = v.Clone()
	}
	for k, v := range el.outgoing {
		ret.outgoing[k] = v.Clone()
	}
	return ret
}

func (el *edgeList[K]) Len() int {
	i := 0
	for _, set := range el.incoming {
		i += set.Len()
	}
	return i
}

func (el *edgeList[K]) Add(from, to K) {
	if _, found := el.incoming[to]; !found {
		el.incoming[to] = make(set.Set[K])
	}
	if _, found := el.outgoing[from]; !found {
		el.outgoing[from] = make(set.Set[K])
	}

	el.incoming[to].Add(from)
	el.outgoing[from].Add(to)
}

func (el *edgeList[K]) Remove(from, to K) {
	if m, ok := el.incoming[to]; ok {
		delete(m, from)
	}
	if m, ok := el.outgoing[from]; ok {
		delete(m, to)
	}
}

func (el *edgeList[K]) HasIncoming(id K) bool {
	return el.incoming[id].Len() > 0
}

func (el *edgeList[K]) HasOutgoing(id K) bool {
	return el.outgoing[id].Len() > 0
}

func (el *edgeList[K]) Exists(from, to K) bool {
	return el.outgoing[from].Contains(to)
}

func (el *edgeList[K]) IncomingNodes(id K) set.Set[K] {
	return el.incoming[id]
}

func (el *edgeList[K]) OutgoingNodes(id K) set.Set[K] {
	return el.outgoing[id]
}
