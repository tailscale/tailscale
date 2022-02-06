package stack

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/refsvfs2"
)

// enableLogging indicates whether reference-related events should be logged (with
// stack traces). This is false by default and should only be set to true for
// debugging purposes, as it can generate an extremely large amount of output
// and drastically degrade performance.
const packetBufferenableLogging = false

// obj is used to customize logging. Note that we use a pointer to T so that
// we do not copy the entire object when passed as a format parameter.
var packetBufferobj *PacketBuffer

// Refs implements refs.RefCounter. It keeps a reference count using atomic
// operations and calls the destructor when the count reaches zero.
//
// NOTE: Do not introduce additional fields to the Refs struct. It is used by
// many filesystem objects, and we want to keep it as small as possible (i.e.,
// the same size as using an int64 directly) to avoid taking up extra cache
// space. In general, this template should not be extended at the cost of
// performance. If it does not offer enough flexibility for a particular object
// (example: b/187877947), we should implement the RefCounter/CheckedObject
// interfaces manually.
//
// +stateify savable
type packetBufferRefs struct {
	// refCount is composed of two fields:
	//
	//	[32-bit speculative references]:[32-bit real references]
	//
	// Speculative references are used for TryIncRef, to avoid a CompareAndSwap
	// loop. See IncRef, DecRef and TryIncRef for details of how these fields are
	// used.
	refCount int64
}

// InitRefs initializes r with one reference and, if enabled, activates leak
// checking.
func (r *packetBufferRefs) InitRefs() {
	atomic.StoreInt64(&r.refCount, 1)
	refsvfs2.Register(r)
}

// RefType implements refsvfs2.CheckedObject.RefType.
func (r *packetBufferRefs) RefType() string {
	return fmt.Sprintf("%T", packetBufferobj)[1:]
}

// LeakMessage implements refsvfs2.CheckedObject.LeakMessage.
func (r *packetBufferRefs) LeakMessage() string {
	return fmt.Sprintf("[%s %p] reference count of %d instead of 0", r.RefType(), r, r.ReadRefs())
}

// LogRefs implements refsvfs2.CheckedObject.LogRefs.
func (r *packetBufferRefs) LogRefs() bool {
	return packetBufferenableLogging
}

// ReadRefs returns the current number of references. The returned count is
// inherently racy and is unsafe to use without external synchronization.
func (r *packetBufferRefs) ReadRefs() int64 {
	return atomic.LoadInt64(&r.refCount)
}

// IncRef implements refs.RefCounter.IncRef.
//
//go:nosplit
func (r *packetBufferRefs) IncRef() {
	v := atomic.AddInt64(&r.refCount, 1)
	if packetBufferenableLogging {
		refsvfs2.LogIncRef(r, v)
	}
	if v <= 1 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %s", r, r.RefType()))
	}
}

// TryIncRef implements refs.TryRefCounter.TryIncRef.
//
// To do this safely without a loop, a speculative reference is first acquired
// on the object. This allows multiple concurrent TryIncRef calls to distinguish
// other TryIncRef calls from genuine references held.
//
//go:nosplit
func (r *packetBufferRefs) TryIncRef() bool {
	const speculativeRef = 1 << 32
	if v := atomic.AddInt64(&r.refCount, speculativeRef); int32(v) == 0 {

		atomic.AddInt64(&r.refCount, -speculativeRef)
		return false
	}

	v := atomic.AddInt64(&r.refCount, -speculativeRef+1)
	if packetBufferenableLogging {
		refsvfs2.LogTryIncRef(r, v)
	}
	return true
}

// DecRef implements refs.RefCounter.DecRef.
//
// Note that speculative references are counted here. Since they were added
// prior to real references reaching zero, they will successfully convert to
// real references. In other words, we see speculative references only in the
// following case:
//
//	A: TryIncRef [speculative increase => sees non-negative references]
//	B: DecRef [real decrease]
//	A: TryIncRef [transform speculative to real]
//
//go:nosplit
func (r *packetBufferRefs) DecRef(destroy func()) {
	v := atomic.AddInt64(&r.refCount, -1)
	if packetBufferenableLogging {
		refsvfs2.LogDecRef(r, v)
	}
	switch {
	case v < 0:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %s", r, r.RefType()))

	case v == 0:
		refsvfs2.Unregister(r)

		if destroy != nil {
			destroy()
		}
	}
}

func (r *packetBufferRefs) afterLoad() {
	if r.ReadRefs() > 0 {
		refsvfs2.Register(r)
	}
}
