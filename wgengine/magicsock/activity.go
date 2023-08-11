package magicsock

import (
	"sync"
	"tailscale.com/types/key"
)

// noter takes note of activity, identified by NodePublic key.  It forwards this to the provided noteRecvActivity
// function.  Noting activity is non-blocking, even if the call to noteRecvActivity blocks.
type noter struct {
	noteRecvActivity func(key.NodePublic)

	cond     *sync.Cond
	closed   bool
	activity map[key.NodePublic]bool
	running  map[key.NodePublic]bool
}

func newNoter(noteRecvActivity func(public key.NodePublic)) *noter {
	n := &noter{
		noteRecvActivity: noteRecvActivity,
		cond:             sync.NewCond(&sync.Mutex{}),
		activity:         make(map[key.NodePublic]bool),
		running:          make(map[key.NodePublic]bool),
	}
	go n.run()
	return n
}

func (n *noter) run() {
	n.cond.L.Lock()
	defer n.cond.L.Unlock()
	for {
		for !n.closed && n.nextWorkLocked() == nil {
			n.cond.Wait()
		}
		if n.closed {
			return
		}
		next := n.nextWorkLocked()
		delete(n.activity, *next)
		n.running[*next] = true
		go n.sendActivity(*next)
	}
}

func (n *noter) nextWorkLocked() *key.NodePublic {
	for k, _ := range n.activity {
		k := k
		if !n.running[k] {
			return &k
		}
	}
	return nil
}

func (n *noter) sendActivity(k key.NodePublic) {
	n.noteRecvActivity(k)
	n.cond.L.Lock()
	delete(n.running, k)
	n.cond.L.Unlock()
	n.cond.Broadcast()
}

func (n *noter) note(k key.NodePublic) {
	n.cond.L.Lock()
	defer n.cond.L.Unlock()
	n.activity[k] = true
	n.cond.Broadcast()
}

func (n *noter) close() {
	n.cond.L.Lock()
	defer n.cond.L.Unlock()
	n.closed = true
	n.cond.Broadcast()
}

func (n *noter) goroutinesRunning() bool {
	n.cond.L.Lock()
	defer n.cond.L.Unlock()
	return len(n.running) > 0
}
