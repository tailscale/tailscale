[![GoDoc](https://godoc.org/github.com/frankban/quicktest?status.svg)](https://godoc.org/github.com/frankban/quicktest)
[![Build Status](https://github.com/frankban/quicktest/actions/workflows/ci.yaml/badge.svg)](https://github.com/frankban/quicktest/actions/workflows/ci.yaml)

[//]: # (Generated with: godocdown -template=.godocdown.template -o README.md)

# quicktest

`go get github.com/frankban/quicktest`

Package quicktest provides a collection of Go helpers for writing tests.

Quicktest helpers can be easily integrated inside regular Go tests, for
instance:

    import qt "github.com/frankban/quicktest"

    func TestFoo(t *testing.T) {
        t.Run("numbers", func(t *testing.T) {
            c := qt.New(t)
            numbers, err := somepackage.Numbers()
            c.Assert(numbers, qt.DeepEquals, []int{42, 47})
            c.Assert(err, qt.ErrorMatches, "bad wolf")
        })
        t.Run("nil", func(t *testing.T) {
            c := qt.New(t)
            got := somepackage.MaybeNil()
            c.Assert(got, qt.IsNil, qt.Commentf("value: %v", somepackage.Value))
        })
    }


### Assertions

An assertion looks like this, where qt.Equals could be replaced by any available
checker. If the assertion fails, the underlying Fatal method is called to
describe the error and abort the test.

    c := qt.New(t)
    c.Assert(someValue, qt.Equals, wantValue)

If you don’t want to abort on failure, use Check instead, which calls Error
instead of Fatal:

    c.Check(someValue, qt.Equals, wantValue)

For really short tests, the extra line for instantiating *qt.C can be avoided:

    qt.Assert(t, someValue, qt.Equals, wantValue)
    qt.Check(t, someValue, qt.Equals, wantValue)

The library provides some base checkers like Equals, DeepEquals, Matches,
ErrorMatches, IsNil and others. More can be added by implementing the Checker
interface. Below, we list the checkers implemented by the package in
alphabetical order.


### All

All returns a Checker that uses the given checker to check elements of slice or
array or the values of a map. It succeeds if all elements pass the check. On
failure it prints the error from the first index that failed.

For example:

    c.Assert([]int{3, 5, 8}, qt.All(qt.Not(qt.Equals)), 0)
    c.Assert([][]string{{"a", "b"}, {"a", "b"}}, qt.All(qt.DeepEquals), []string{"c", "d"})

See also Any and Contains.


### Any

Any returns a Checker that uses the given checker to check elements of a slice
or array or the values from a map. It succeeds if any element passes the check.

For example:

    c.Assert([]int{3,5,7,99}, qt.Any(qt.Equals), 7)
    c.Assert([][]string{{"a", "b"}, {"c", "d"}}, qt.Any(qt.DeepEquals), []string{"c", "d"})

See also All and Contains.


### CmpEquals

CmpEquals checks equality of two arbitrary values according to the provided
compare options. DeepEquals is more commonly used when no compare options are
required.

Example calls:

    c.Assert(list, qt.CmpEquals(cmpopts.SortSlices), []int{42, 47})
    c.Assert(got, qt.CmpEquals(), []int{42, 47}) // Same as qt.DeepEquals.


### CodecEquals

CodecEquals returns a checker that checks for codec value equivalence.

    func CodecEquals(
        marshal func(interface{}) ([]byte, error),
        unmarshal func([]byte, interface{}) error,
        opts ...cmp.Option,
    ) Checker

It expects two arguments: a byte slice or a string containing some
codec-marshaled data, and a Go value.

It uses unmarshal to unmarshal the data into an interface{} value. It marshals
the Go value using marshal, then unmarshals the result into an interface{}
value.

It then checks that the two interface{} values are deep-equal to one another,
using CmpEquals(opts) to perform the check.

See JSONEquals for an example of this in use.


### Contains

Contains checks that a map, slice, array or string contains a value. It's the
same as using Any(Equals), except that it has a special case for strings - if
the first argument is a string, the second argument must also be a string and
strings.Contains will be used.

For example:

    c.Assert("hello world", qt.Contains, "world")
    c.Assert([]int{3,5,7,99}, qt.Contains, 7)


### ContentEquals

ContentEquals is is like DeepEquals but any slices in the compared values will
be sorted before being compared.

For example:

    c.Assert([]string{"c", "a", "b"}, qt.ContentEquals, []string{"a", "b", "c"})


### DeepEquals

DeepEquals checks that two arbitrary values are deeply equal. The comparison is
done using the github.com/google/go-cmp/cmp package. When comparing structs, by
default no exported fields are allowed. If a more sophisticated comparison is
required, use CmpEquals (see below).

Example call:

    c.Assert(got, qt.DeepEquals, []int{42, 47})


### Equals

Equals checks that two values are equal, as compared with Go's == operator.

For instance:

    c.Assert(answer, qt.Equals, 42)

Note that the following will fail:

    c.Assert((*sometype)(nil), qt.Equals, nil)

Use the IsNil checker below for this kind of nil check.


### ErrorAs

ErrorAs checks that the error is or wraps a specific error type. If so, it
assigns it to the provided pointer. This is analogous to calling errors.As.

For instance:

    // Checking for a specific error type
    c.Assert(err, qt.ErrorAs, new(*os.PathError))

    // Checking fields on a specific error type
    var pathError *os.PathError
    if c.Check(err, qt.ErrorAs, &pathError) {
        c.Assert(pathError.Path, Equals, "some_path")
    }


### ErrorIs

ErrorIs checks that the error is or wraps a specific error value. This is
analogous to calling errors.Is.

For instance:

    c.Assert(err, qt.ErrorIs, os.ErrNotExist)


### ErrorMatches

ErrorMatches checks that the provided value is an error whose message matches
the provided regular expression.

For instance:

    c.Assert(err, qt.ErrorMatches, `bad wolf .*`)


### HasLen

HasLen checks that the provided value has the given length.

For instance:

    c.Assert([]int{42, 47}, qt.HasLen, 2)
    c.Assert(myMap, qt.HasLen, 42)


### Implements

Implements checks that the provided value implements an interface. The interface
is specified with a pointer to an interface variable.

For instance:

    var rc io.ReadCloser
    c.Assert(myReader, qt.Implements, &rc)


### IsFalse

IsFalse checks that the provided value is false. The value must have a boolean
underlying type.

For instance:

    c.Assert(false, qt.IsFalse)
    c.Assert(IsValid(), qt.IsFalse)


### IsNil

IsNil checks that the provided value is nil.

For instance:

    c.Assert(got, qt.IsNil)

As a special case, if the value is nil but implements the error interface, it is
still considered to be non-nil. This means that IsNil will fail on an error
value that happens to have an underlying nil value, because that's invariably a
mistake. See https://golang.org/doc/faq#nil_error.

So it's just fine to check an error like this:

    c.Assert(err, qt.IsNil)


### IsNotNil

IsNotNil is a Checker checking that the provided value is not nil. IsNotNil is
the equivalent of qt.Not(qt.IsNil)

For instance:

    c.Assert(got, qt.IsNotNil)


### IsTrue

IsTrue checks that the provided value is true. The value must have a boolean
underlying type.

For instance:

    c.Assert(true, qt.IsTrue)
    c.Assert(myBoolean(false), qt.IsTrue)


### JSONEquals

JSONEquals checks whether a byte slice or string is JSON-equivalent to a Go
value. See CodecEquals for more information.

It uses DeepEquals to do the comparison. If a more sophisticated comparison is
required, use CodecEquals directly.

For instance:

    c.Assert(`{"First": 47.11}`, qt.JSONEquals, &MyStruct{First: 47.11})


### Matches

Matches checks that a string or result of calling the String method (if the
value implements fmt.Stringer) matches the provided regular expression.

For instance:

    c.Assert("these are the voyages", qt.Matches, `these are .*`)
    c.Assert(net.ParseIP("1.2.3.4"), qt.Matches, `1.*`)


### Not

Not returns a Checker negating the given Checker.

For instance:

    c.Assert(got, qt.Not(qt.IsNil))
    c.Assert(answer, qt.Not(qt.Equals), 42)


### PanicMatches

PanicMatches checks that the provided function panics with a message matching
the provided regular expression.

For instance:

    c.Assert(func() {panic("bad wolf ...")}, qt.PanicMatches, `bad wolf .*`)


### Satisfies

Satisfies checks that the provided value, when used as argument of the provided
predicate function, causes the function to return true. The function must be of
type func(T) bool, having got assignable to T.

For instance:

    // Check that an error from os.Open satisfies os.IsNotExist.
    c.Assert(err, qt.Satisfies, os.IsNotExist)

    // Check that a floating point number is a not-a-number.
    c.Assert(f, qt.Satisfies, math.IsNaN)


### Deferred Execution

The testing.TB.Cleanup helper provides the ability to defer the execution of
functions that will be run when the test completes. This is often useful for
creating OS-level resources such as temporary directories (see c.Mkdir).

When targeting Go versions that don't have Cleanup (< 1.14), the same can be
achieved using c.Defer. In this case, to trigger the deferred behavior, calling
c.Done is required. For instance, if you create a *C instance at the top level,
you’ll have to add a defer to trigger the cleanups at the end of the test:

    defer c.Done()

However, if you use quicktest to create a subtest, Done will be called
automatically at the end of that subtest. For example:

    func TestFoo(t *testing.T) {
        c := qt.New(t)
        c.Run("subtest", func(c *qt.C) {
            c.Setenv("HOME", c.Mkdir())
            // Here $HOME is set the path to a newly created directory.
            // At the end of the test the directory will be removed
            // and HOME set back to its original value.
        })
    }

The c.Patch, c.Setenv, c.Unsetenv and c.Mkdir helpers use t.Cleanup for cleaning
up resources when available, and fall back to Defer otherwise.

For a complete API reference, see the
[package documentation](https://pkg.go.dev/github.com/frankban/quicktest).
