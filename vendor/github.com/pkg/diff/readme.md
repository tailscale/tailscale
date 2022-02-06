# diff [![GoDoc](https://godoc.org/github.com/pkg/diff?status.svg)](http://godoc.org/github.com/pkg/diff)

Module github.com/pkg/diff can be used to create, modify, and print diffs.

The top level package, `diff`, contains convenience functions for the most common uses.

The subpackages provide very fine-grained control over every aspect:

* `myers` creates diffs using the Myers diff algorithm.
* `edit` contains the core diff data types.
* `ctxt` provides tools to reduce the amount of context in a diff.
* `write` provides routines to write diffs in standard formats.

License: BSD 3-Clause.

### Contributing

Contributions are welcome. However, I am not always fast to respond.
I apologize for any sadness or frustration that that causes.

Useful background reading about diffs:

* [Neil Fraser's website](https://neil.fraser.name/writing/diff)
* [Myers diff paper](http://www.xmailserver.org/diff2.pdf)
* [Guido Van Rossum's reverse engineering of the unified diff format](https://www.artima.com/weblogs/viewpost.jsp?thread=164293)
* [The If Works](https://blog.jcoglan.com/) blog entries about diff algorithms and implementations

This module has not yet reached v1.0;
the API is not yet settled (issue #18).
