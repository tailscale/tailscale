package write

import (
	"bufio"
	"fmt"
	"io"

	"github.com/pkg/diff/edit"
)

// A Pair supports writing a unified diff, element by element.
// A is the initial state; B is the final state.
type Pair interface {
	// WriteATo writes the element a[aᵢ] to w.
	WriteATo(w io.Writer, ai int) (int, error)
	// WriteBTo writes the element b[bᵢ] to w.
	WriteBTo(w io.Writer, bi int) (int, error)
}

// Unified writes e to w using unified diff format.
// ab writes the individual elements. Opts are optional write arguments.
// Unified returns the number of bytes written and the first error (if any) encountered.
// Before writing, edit scripts usually have their context reduced,
// such as by a call to ctxt.Size.
func Unified(e edit.Script, w io.Writer, ab Pair, opts ...Option) error {
	// read opts
	nameA := "a"
	nameB := "b"
	color := false
	for _, opt := range opts {
		switch opt := opt.(type) {
		case names:
			nameA = opt.a
			nameB = opt.b
		case colorOpt:
			color = true
		// TODO: add date/time/timezone WriteOpts
		default:
			panic(fmt.Sprintf("unrecognized WriteOpt type %T", opt))
		}
	}

	bw := bufio.NewWriter(w)

	needsColorReset := false

	// per-file header
	if color {
		bw.WriteString(ansiBold)
		needsColorReset = true
	}
	fmt.Fprintf(bw, "--- %s\n", nameA)
	fmt.Fprintf(bw, "+++ %s\n", nameB)

	for i := 0; i < len(e.Ranges); {
		// Peek into the future to learn the line ranges for this chunk of output.
		// A chunk of output ends when there's a discontiguity in the edit script.
		var ar, br lineRange
		var started [2]bool
		var j int
		for j = i; j < len(e.Ranges); j++ {
			curr := e.Ranges[j]
			if !curr.IsInsert() {
				if !started[0] {
					ar.first = curr.LowA
					started[0] = true
				}
				ar.last = curr.HighA
			}
			if !curr.IsDelete() {
				if !started[1] {
					br.first = curr.LowB
					started[1] = true
				}
				br.last = curr.HighB
			}
			if j+1 >= len(e.Ranges) {
				// end of script
				break
			}
			if next := e.Ranges[j+1]; curr.HighA != next.LowA || curr.HighB != next.LowB {
				// discontiguous edit script
				break
			}
		}

		// Print chunk header.
		// TODO: add per-chunk context, like what function we're in
		// But how do we get this? need to add PairWriter methods?
		// Maybe it should be stored in the EditScript,
		// and we can have EditScript methods to populate it somehow?
		if color {
			if needsColorReset {
				bw.WriteString(ansiReset)
			}
			bw.WriteString(ansiFgBlue)
			needsColorReset = true
		}
		fmt.Fprintf(bw, "@@ -%s +%s @@\n", ar, br)

		// Print prefixed lines.
		for k := i; k <= j; k++ {
			seg := e.Ranges[k]
			switch seg.Op() {
			case edit.Eq:
				if needsColorReset {
					bw.WriteString(ansiReset)
				}
				for m := seg.LowA; m < seg.HighA; m++ {
					// " a[m]\n"
					bw.WriteByte(' ')
					ab.WriteATo(bw, m)
					bw.WriteByte('\n')
				}
			case edit.Del:
				if color {
					bw.WriteString(ansiFgRed)
					needsColorReset = true
				}
				for m := seg.LowA; m < seg.HighA; m++ {
					// "-a[m]\n"
					bw.WriteByte('-')
					ab.WriteATo(bw, m)
					bw.WriteByte('\n')
				}
			case edit.Ins:
				if color {
					bw.WriteString(ansiFgGreen)
					needsColorReset = true
				}
				for m := seg.LowB; m < seg.HighB; m++ {
					// "+b[m]\n"
					bw.WriteByte('+')
					ab.WriteBTo(bw, m)
					bw.WriteByte('\n')
				}
			}
		}

		// Advance to next chunk.
		i = j + 1

		// TODO: break if error detected?
	}

	// Always finish the output with no color, to prevent "leaking" the
	// color into any output that follows a diff.
	if needsColorReset {
		bw.WriteString(ansiReset)
	}

	// TODO:
	// If the last line of a file doesn't end in a newline character,
	// it is displayed with a newline character,
	// and the following line in the chunk has the literal text (starting in the first column):
	// '\ No newline at end of file'

	return bw.Flush()
}

type lineRange struct {
	first, last int
}

func (r lineRange) String() string {
	len := r.last - r.first
	r.first++ // 1-based index, safe to modify r directly because it is a value
	if len <= 0 {
		r.first-- // for no obvious reason, empty ranges are "before" the range
	}
	return fmt.Sprintf("%d,%d", r.first, len)
}

func (r lineRange) GoString() string {
	return fmt.Sprintf("(%d, %d)", r.first, r.last)
}
