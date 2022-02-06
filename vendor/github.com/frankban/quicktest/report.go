// Licensed under the MIT license, see LICENCE file for details.

package quicktest

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"reflect"
	"runtime"
	"strings"
)

// reportParams holds parameters for reporting a test error.
type reportParams struct {
	// argNames holds the names for the arguments passed to the checker.
	argNames []string
	// got holds the value that was checked.
	got interface{}
	// args holds all other arguments (if any) provided to the checker.
	args []interface{}
	// comment optionally holds the comment passed when performing the check.
	comment Comment
	// notes holds notes added while doing the check.
	notes []note
	// format holds the format function that must be used when outputting
	// values.
	format formatFunc
}

// Unquoted indicates that the string must not be pretty printed in the failure
// output. This is useful when a checker calls note and does not want the
// provided value to be quoted.
type Unquoted string

// report generates a failure report for the given error, optionally including
// in the output the checker arguments, comment and notes included in the
// provided report parameters.
func report(err error, p reportParams) string {
	var buf bytes.Buffer
	buf.WriteByte('\n')
	writeError(&buf, err, p)
	writeStack(&buf)
	return buf.String()
}

// writeError writes a pretty formatted output of the given error using the
// provided report parameters.
func writeError(w io.Writer, err error, p reportParams) {
	values := make(map[string]string)
	printPair := func(key string, value interface{}) {
		fmt.Fprintln(w, key+":")
		var v string
		if u, ok := value.(Unquoted); ok {
			v = string(u)
		} else {
			v = p.format(value)
		}
		if k := values[v]; k != "" {
			fmt.Fprint(w, prefixf(prefix, "<same as %q>", k))
			return
		}
		values[v] = key
		fmt.Fprint(w, prefixf(prefix, "%s", v))
	}

	// Write the checker error.
	if err != ErrSilent {
		printPair("error", Unquoted(err.Error()))
	}

	// Write the comment if provided.
	if comment := p.comment.String(); comment != "" {
		printPair("comment", Unquoted(comment))
	}

	// Write notes if present.
	for _, n := range p.notes {
		printPair(n.key, n.value)
	}
	if IsBadCheck(err) || err == ErrSilent {
		// For errors in the checker invocation or for silent errors, do not
		// show output from args.
		return
	}

	// Write provided args.
	for i, arg := range append([]interface{}{p.got}, p.args...) {
		printPair(p.argNames[i], arg)
	}
}

// writeStack writes the traceback information for the current failure into the
// provided writer.
func writeStack(w io.Writer) {
	fmt.Fprintln(w, "stack:")
	pc := make([]uintptr, 8)
	sg := &stmtGetter{
		fset:  token.NewFileSet(),
		files: make(map[string]*ast.File, 8),
		config: &printer.Config{
			Mode:     printer.UseSpaces,
			Tabwidth: 4,
		},
	}
	runtime.Callers(5, pc)
	frames := runtime.CallersFrames(pc)
	thisPackage := reflect.TypeOf(C{}).PkgPath() + "."
	for {
		frame, more := frames.Next()
		if strings.HasPrefix(frame.Function, "testing.") {
			// Stop before getting back to stdlib test runner calls.
			break
		}
		if fname := strings.TrimPrefix(frame.Function, thisPackage); fname != frame.Function {
			if ast.IsExported(fname) {
				// Continue without printing frames for quicktest exported API.
				continue
			}
			// Stop when entering quicktest internal calls.
			// This is useful for instance when using qtsuite.
			break
		}
		fmt.Fprint(w, prefixf(prefix, "%s:%d", frame.File, frame.Line))
		if strings.HasSuffix(frame.File, ".go") {
			stmt, err := sg.Get(frame.File, frame.Line)
			if err != nil {
				fmt.Fprint(w, prefixf(prefix+prefix, "<%s>", err))
			} else {
				fmt.Fprint(w, prefixf(prefix+prefix, "%s", stmt))
			}
		}
		if !more {
			// There are no more callers.
			break
		}
	}
}

type stmtGetter struct {
	fset   *token.FileSet
	files  map[string]*ast.File
	config *printer.Config
}

// Get returns the lines of code of the statement at the given file and line.
func (sg *stmtGetter) Get(file string, line int) (string, error) {
	f := sg.files[file]
	if f == nil {
		var err error
		f, err = parser.ParseFile(sg.fset, file, nil, parser.ParseComments)
		if err != nil {
			return "", fmt.Errorf("cannot parse source file: %s", err)
		}
		sg.files[file] = f
	}
	var stmt string
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil || stmt != "" {
			return false
		}
		pos := sg.fset.Position(n.Pos()).Line
		end := sg.fset.Position(n.End()).Line
		// Go < v1.9 reports the line where the statements ends, not the line
		// where it begins.
		if line == pos || line == end {
			var buf bytes.Buffer
			// TODO: include possible comment after the statement.
			sg.config.Fprint(&buf, sg.fset, &printer.CommentedNode{
				Node:     n,
				Comments: f.Comments,
			})
			stmt = buf.String()
			return false
		}
		return pos < line && line <= end
	})
	return stmt, nil
}

// prefixf formats the given string with the given args. It also inserts the
// final newline if needed and indentation with the given prefix.
func prefixf(prefix, format string, args ...interface{}) string {
	var buf []byte
	s := strings.TrimSuffix(fmt.Sprintf(format, args...), "\n")
	for _, line := range strings.Split(s, "\n") {
		buf = append(buf, prefix...)
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return string(buf)
}

// note holds a key/value annotation.
type note struct {
	key   string
	value interface{}
}

// prefix is the string used to indent blocks of output.
const prefix = "  "
