package stack

// ElementMapper provides an identity mapping by default.
//
// This can be replaced to provide a struct that maps elements to linker
// objects, if they are not the same. An ElementMapper is not typically
// required if: Linker is left as is, Element is left as is, or Linker and
// Element are the same type.
type PacketBufferElementMapper struct{}

// linkerFor maps an Element to a Linker.
//
// This default implementation should be inlined.
//
//go:nosplit
func (PacketBufferElementMapper) linkerFor(elem *PacketBuffer) *PacketBuffer { return elem }

// List is an intrusive list. Entries can be added to or removed from the list
// in O(1) time and with no additional memory allocations.
//
// The zero value for List is an empty list ready to use.
//
// To iterate over a list (where l is a List):
//      for e := l.Front(); e != nil; e = e.Next() {
// 		// do something with e.
//      }
//
// +stateify savable
type PacketBufferList struct {
	head *PacketBuffer
	tail *PacketBuffer
}

// Reset resets list l to the empty state.
func (l *PacketBufferList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
//
//go:nosplit
func (l *PacketBufferList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
//
//go:nosplit
func (l *PacketBufferList) Front() *PacketBuffer {
	return l.head
}

// Back returns the last element of list l or nil.
//
//go:nosplit
func (l *PacketBufferList) Back() *PacketBuffer {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
//
//go:nosplit
func (l *PacketBufferList) Len() (count int) {
	for e := l.Front(); e != nil; e = (PacketBufferElementMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
//
//go:nosplit
func (l *PacketBufferList) PushFront(e *PacketBuffer) {
	linker := PacketBufferElementMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		PacketBufferElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
//
//go:nosplit
func (l *PacketBufferList) PushBack(e *PacketBuffer) {
	linker := PacketBufferElementMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		PacketBufferElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
//
//go:nosplit
func (l *PacketBufferList) PushBackList(m *PacketBufferList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		PacketBufferElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		PacketBufferElementMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
//
//go:nosplit
func (l *PacketBufferList) InsertAfter(b, e *PacketBuffer) {
	bLinker := PacketBufferElementMapper{}.linkerFor(b)
	eLinker := PacketBufferElementMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		PacketBufferElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
//
//go:nosplit
func (l *PacketBufferList) InsertBefore(a, e *PacketBuffer) {
	aLinker := PacketBufferElementMapper{}.linkerFor(a)
	eLinker := PacketBufferElementMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		PacketBufferElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
//
//go:nosplit
func (l *PacketBufferList) Remove(e *PacketBuffer) {
	linker := PacketBufferElementMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		PacketBufferElementMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		PacketBufferElementMapper{}.linkerFor(next).SetPrev(prev)
	} else if l.tail == e {
		l.tail = prev
	}

	linker.SetNext(nil)
	linker.SetPrev(nil)
}

// Entry is a default implementation of Linker. Users can add anonymous fields
// of this type to their structs to make them automatically implement the
// methods needed by List.
//
// +stateify savable
type PacketBufferEntry struct {
	next *PacketBuffer
	prev *PacketBuffer
}

// Next returns the entry that follows e in the list.
//
//go:nosplit
func (e *PacketBufferEntry) Next() *PacketBuffer {
	return e.next
}

// Prev returns the entry that precedes e in the list.
//
//go:nosplit
func (e *PacketBufferEntry) Prev() *PacketBuffer {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
//
//go:nosplit
func (e *PacketBufferEntry) SetNext(elem *PacketBuffer) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
//
//go:nosplit
func (e *PacketBufferEntry) SetPrev(elem *PacketBuffer) {
	e.prev = elem
}
