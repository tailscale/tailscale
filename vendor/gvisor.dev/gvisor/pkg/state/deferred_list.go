package state

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
type deferredList struct {
	head *objectEncodeState
	tail *objectEncodeState
}

// Reset resets list l to the empty state.
func (l *deferredList) Reset() {
	l.head = nil
	l.tail = nil
}

// Empty returns true iff the list is empty.
//
//go:nosplit
func (l *deferredList) Empty() bool {
	return l.head == nil
}

// Front returns the first element of list l or nil.
//
//go:nosplit
func (l *deferredList) Front() *objectEncodeState {
	return l.head
}

// Back returns the last element of list l or nil.
//
//go:nosplit
func (l *deferredList) Back() *objectEncodeState {
	return l.tail
}

// Len returns the number of elements in the list.
//
// NOTE: This is an O(n) operation.
//
//go:nosplit
func (l *deferredList) Len() (count int) {
	for e := l.Front(); e != nil; e = (deferredMapper{}.linkerFor(e)).Next() {
		count++
	}
	return count
}

// PushFront inserts the element e at the front of list l.
//
//go:nosplit
func (l *deferredList) PushFront(e *objectEncodeState) {
	linker := deferredMapper{}.linkerFor(e)
	linker.SetNext(l.head)
	linker.SetPrev(nil)
	if l.head != nil {
		deferredMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}

	l.head = e
}

// PushBack inserts the element e at the back of list l.
//
//go:nosplit
func (l *deferredList) PushBack(e *objectEncodeState) {
	linker := deferredMapper{}.linkerFor(e)
	linker.SetNext(nil)
	linker.SetPrev(l.tail)
	if l.tail != nil {
		deferredMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}

	l.tail = e
}

// PushBackList inserts list m at the end of list l, emptying m.
//
//go:nosplit
func (l *deferredList) PushBackList(m *deferredList) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
		deferredMapper{}.linkerFor(l.tail).SetNext(m.head)
		deferredMapper{}.linkerFor(m.head).SetPrev(l.tail)

		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

// InsertAfter inserts e after b.
//
//go:nosplit
func (l *deferredList) InsertAfter(b, e *objectEncodeState) {
	bLinker := deferredMapper{}.linkerFor(b)
	eLinker := deferredMapper{}.linkerFor(e)

	a := bLinker.Next()

	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	bLinker.SetNext(e)

	if a != nil {
		deferredMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

// InsertBefore inserts e before a.
//
//go:nosplit
func (l *deferredList) InsertBefore(a, e *objectEncodeState) {
	aLinker := deferredMapper{}.linkerFor(a)
	eLinker := deferredMapper{}.linkerFor(e)

	b := aLinker.Prev()
	eLinker.SetNext(a)
	eLinker.SetPrev(b)
	aLinker.SetPrev(e)

	if b != nil {
		deferredMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

// Remove removes e from l.
//
//go:nosplit
func (l *deferredList) Remove(e *objectEncodeState) {
	linker := deferredMapper{}.linkerFor(e)
	prev := linker.Prev()
	next := linker.Next()

	if prev != nil {
		deferredMapper{}.linkerFor(prev).SetNext(next)
	} else if l.head == e {
		l.head = next
	}

	if next != nil {
		deferredMapper{}.linkerFor(next).SetPrev(prev)
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
type deferredEntry struct {
	next *objectEncodeState
	prev *objectEncodeState
}

// Next returns the entry that follows e in the list.
//
//go:nosplit
func (e *deferredEntry) Next() *objectEncodeState {
	return e.next
}

// Prev returns the entry that precedes e in the list.
//
//go:nosplit
func (e *deferredEntry) Prev() *objectEncodeState {
	return e.prev
}

// SetNext assigns 'entry' as the entry that follows e in the list.
//
//go:nosplit
func (e *deferredEntry) SetNext(elem *objectEncodeState) {
	e.next = elem
}

// SetPrev assigns 'entry' as the entry that precedes e in the list.
//
//go:nosplit
func (e *deferredEntry) SetPrev(elem *objectEncodeState) {
	e.prev = elem
}
