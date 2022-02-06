// Licensed under the MIT license, see LICENCE file for details.

package quicktest

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Check runs the given check using the provided t and continues execution in
// case of failure. For instance:
//
//     qt.Check(t, answer, qt.Equals, 42)
//     qt.Check(t, got, qt.IsNil, qt.Commentf("iteration %d", i))
//
// Additional args (not consumed by the checker), when provided, are included as
// comments in the failure output when the check fails.
func Check(t testing.TB, got interface{}, checker Checker, args ...interface{}) bool {
	t.Helper()
	return New(t).Check(got, checker, args...)
}

// Assert runs the given check using the provided t and stops execution in case
// of failure. For instance:
//
//     qt.Assert(t, got, qt.DeepEquals, []int{42, 47})
//     qt.Assert(t, got, qt.ErrorMatches, "bad wolf .*", qt.Commentf("a comment"))
//
// Additional args (not consumed by the checker), when provided, are included as
// comments in the failure output when the check fails.
func Assert(t testing.TB, got interface{}, checker Checker, args ...interface{}) bool {
	t.Helper()
	return New(t).Assert(got, checker, args...)
}

// New returns a new checker instance that uses t to fail the test when checks
// fail. It only ever calls the Fatal, Error and (when available) Run methods
// of t. For instance.
//
//     func TestFoo(t *testing.T) {
//         t.Run("A=42", func(t *testing.T) {
//             c := qt.New(t)
//             c.Assert(a, qt.Equals, 42)
//         })
//     }
//
// The library already provides some base checkers, and more can be added by
// implementing the Checker interface.
//
// If there is a likelihood that Defer will be called, then
// a call to Done should be deferred after calling New.
// For example:
//
//     func TestFoo(t *testing.T) {
//             c := qt.New(t)
//             defer c.Done()
//             c.Setenv("HOME", "/non-existent")
//             c.Assert(os.Getenv("HOME"), qt.Equals, "/non-existent")
//     })
//
// A value of C that's has a non-nil TB field but is otherwise zero is valid.
// So:
//
//	c := &qt.C{TB: t}
//
// is valid a way to create a C value; it's exactly the same as:
//
//	c := qt.New(t)
//
// Methods on C may be called concurrently, assuming the underlying
// `testing.TB` implementation also allows that.
func New(t testing.TB) *C {
	return &C{
		TB: t,
	}
}

// C is a quicktest checker. It embeds a testing.TB value and provides
// additional checking functionality. If an Assert or Check operation fails, it
// uses the wrapped TB value to fail the test appropriately.
type C struct {
	testing.TB

	mu         sync.Mutex
	doneNeeded bool
	deferred   func()
	format     formatFunc
}

// cleaner is implemented by testing.TB on Go 1.14 and later.
type cleaner interface {
	Cleanup(func())
}

// Defer registers a function to be called when c.Done is
// called. Deferred functions will be called in last added, first called
// order. If c.Done is not called by the end of the test, the test
// may panic. Note that if Cleanup is called, there is no
// need to call Done.
//
// Deprecated: in Go >= 1.14 use testing.TB.Cleanup instead.
func (c *C) Defer(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cleaner, ok := c.TB.(cleaner); ok {
		// Use TB.Cleanup when available, but add a check
		// that Done has been called so that we don't run
		// into unexpected Go version incompatibilities.
		if c.doneNeeded {
			// We've already installed the wrapper func that checks for Done
			// so we can avoid doing it again.
			cleaner.Cleanup(f)
			return
		}
		c.doneNeeded = true
		cleaner.Cleanup(func() {
			c.mu.Lock()
			doneNeeded := c.doneNeeded
			c.mu.Unlock()
			if doneNeeded {
				panic("Done not called after Defer")
			}
			f()
		})
		return
	}

	oldDeferred := c.deferred
	c.deferred = func() {
		if oldDeferred != nil {
			defer oldDeferred()
		}
		f()
	}
}

// Done calls all the functions registered by Defer in reverse
// registration order. After it's called, the functions are
// unregistered, so calling Done twice will only call them once.
//
// When a test function is called by Run, Done will be called
// automatically on the C value passed into it.
//
// Deprecated: in Go >= 1.14 this is no longer needed if using
// testing.TB.Cleanup.
func (c *C) Done() {
	c.mu.Lock()
	deferred := c.deferred
	c.deferred = nil
	c.doneNeeded = false
	c.mu.Unlock()

	if deferred != nil {
		deferred()
	}
}

// SetFormat sets the function used to print values in test failures.
// By default Format is used.
// Any subsequent subtests invoked with c.Run will also use this function by
// default.
func (c *C) SetFormat(format func(interface{}) string) {
	c.mu.Lock()
	c.format = format
	c.mu.Unlock()
}

// getFormat returns the format function
// safely acquired under lock.
func (c *C) getFormat() func(interface{}) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.format
}

// Check runs the given check and continues execution in case of failure.
// For instance:
//
//     c.Check(answer, qt.Equals, 42)
//     c.Check(got, qt.IsNil, qt.Commentf("iteration %d", i))
//
// Additional args (not consumed by the checker), when provided, are included
// as comments in the failure output when the check fails.
func (c *C) Check(got interface{}, checker Checker, args ...interface{}) bool {
	c.TB.Helper()
	return check(c, checkParams{
		fail:    c.TB.Error,
		checker: checker,
		got:     got,
		args:    args,
	})
}

// Assert runs the given check and stops execution in case of failure.
// For instance:
//
//     c.Assert(got, qt.DeepEquals, []int{42, 47})
//     c.Assert(got, qt.ErrorMatches, "bad wolf .*", qt.Commentf("a comment"))
//
// Additional args (not consumed by the checker), when provided, are included
// as comments in the failure output when the check fails.
func (c *C) Assert(got interface{}, checker Checker, args ...interface{}) bool {
	c.TB.Helper()
	return check(c, checkParams{
		fail:    c.TB.Fatal,
		checker: checker,
		got:     got,
		args:    args,
	})
}

var (
	stringType = reflect.TypeOf("")
	boolType   = reflect.TypeOf(true)
	tbType     = reflect.TypeOf(new(testing.TB)).Elem()
)

// Run runs f as a subtest of t called name. It's a wrapper around
// the Run method of c.TB that provides the quicktest checker to f. When
// the function completes, c.Done will be called to run any
// functions registered with c.Defer.
//
// c.TB must implement a Run method of the following form:
//
//	Run(string, func(T)) bool
//
// where T is any type that is assignable to testing.TB.
// Implementations include *testing.T, *testing.B and *C itself.
//
// The TB field in the subtest will hold the value passed
// by Run to its argument function.
//
//     func TestFoo(t *testing.T) {
//         c := qt.New(t)
//         c.Run("A=42", func(c *qt.C) {
//             // This assertion only stops the current subtest.
//             c.Assert(a, qt.Equals, 42)
//         })
//     }
//
// A panic is raised when Run is called and the embedded concrete type does not
// implement a Run method with a correct signature.
func (c *C) Run(name string, f func(c *C)) bool {
	badType := func(m string) {
		panic(fmt.Sprintf("cannot execute Run with underlying concrete type %T (%s)", c.TB, m))
	}
	m := reflect.ValueOf(c.TB).MethodByName("Run")
	if !m.IsValid() {
		// c.TB doesn't implement a Run method.
		badType("no Run method")
	}
	mt := m.Type()
	if mt.NumIn() != 2 ||
		mt.In(0) != stringType ||
		mt.NumOut() != 1 ||
		mt.Out(0) != boolType {
		// The Run method doesn't have the right argument counts and types.
		badType("wrong argument count for Run method")
	}
	farg := mt.In(1)
	if farg.Kind() != reflect.Func ||
		farg.NumIn() != 1 ||
		farg.NumOut() != 0 ||
		!farg.In(0).AssignableTo(tbType) {
		// The first argument to the Run function arg isn't right.
		badType("bad first argument type for Run method")
	}
	fv := reflect.MakeFunc(farg, func(args []reflect.Value) []reflect.Value {
		c2 := New(args[0].Interface().(testing.TB))
		defer c2.Done()
		c2.SetFormat(c.getFormat())
		f(c2)
		return nil
	})
	return m.Call([]reflect.Value{reflect.ValueOf(name), fv})[0].Interface().(bool)
}

// Parallel signals that this test is to be run in parallel with (and only with) other parallel tests.
// It's a wrapper around *testing.T.Parallel.
//
// A panic is raised when Parallel is called and the embedded concrete type does not
// implement Parallel, for instance if TB's concrete type is a benchmark.
func (c *C) Parallel() {
	p, ok := c.TB.(interface {
		Parallel()
	})
	if !ok {
		panic(fmt.Sprintf("cannot execute Parallel with underlying concrete type %T", c.TB))
	}
	p.Parallel()
}

// check performs the actual check with the provided params.
// In case of failure p.fail is called. In the fail report values are formatted
// using p.format.
func check(c *C, p checkParams) bool {
	c.TB.Helper()
	rp := reportParams{
		got:    p.got,
		args:   p.args,
		format: c.getFormat(),
	}
	if rp.format == nil {
		// No format set; use the default: Format.
		rp.format = Format
	}
	// Allow checkers to annotate messages.
	note := func(key string, value interface{}) {
		rp.notes = append(rp.notes, note{
			key:   key,
			value: value,
		})
	}
	// Ensure that we have a checker.
	if p.checker == nil {
		p.fail(report(BadCheckf("nil checker provided"), rp))
		return false
	}
	// Extract a comment if it has been provided.
	rp.argNames = p.checker.ArgNames()
	wantNumArgs := len(rp.argNames) - 1
	if len(p.args) > 0 {
		if comment, ok := p.args[len(p.args)-1].(Comment); ok {
			rp.comment = comment
			rp.args = p.args[:len(p.args)-1]
		}
	}
	// Validate that we have the correct number of arguments.
	if gotNumArgs := len(rp.args); gotNumArgs != wantNumArgs {
		if gotNumArgs > 0 {
			note("got args", rp.args)
		}
		if wantNumArgs > 0 {
			note("want args", Unquoted(strings.Join(rp.argNames[1:], ", ")))
		}
		var prefix string
		if gotNumArgs > wantNumArgs {
			prefix = "too many arguments provided to checker"
		} else {
			prefix = "not enough arguments provided to checker"
		}
		p.fail(report(BadCheckf("%s: got %d, want %d", prefix, gotNumArgs, wantNumArgs), rp))
		return false
	}

	// Execute the check and report the failure if necessary.
	if err := p.checker.Check(p.got, p.args, note); err != nil {
		p.fail(report(err, rp))
		return false
	}
	return true
}

// checkParams holds parameters for executing a check.
type checkParams struct {
	fail    func(...interface{})
	checker Checker
	got     interface{}
	args    []interface{}
}
