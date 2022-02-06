// +build gofuzz

package diff

import (
	"bytes"
	"context"
	"io"
	"io/ioutil"

	"github.com/pkg/diff/ctxt"
	"github.com/pkg/diff/myers"
	"github.com/pkg/diff/write"
)

func Fuzz(data []byte) int {
	if len(data) < 2 {
		return -1
	}
	sz := int(data[0])
	data = data[1:]

	nul := bytes.IndexByte(data, 0)
	if nul == -1 {
		nul = len(data) - 1
	}
	a := data[:nul]
	b := data[nul:]
	ab := &IndividualBytes{a: a, b: b}
	s := myers.Diff(context.Background(), ab)
	s = ctxt.Size(s, sz)
	err := write.Unified(s, ioutil.Discard, ab)
	if err != nil {
		panic(err)
	}
	return 0
}

type IndividualBytes struct {
	a, b []byte
}

func (ab *IndividualBytes) LenA() int                                { return len(ab.a) }
func (ab *IndividualBytes) LenB() int                                { return len(ab.b) }
func (ab *IndividualBytes) Equal(ai, bi int) bool                    { return ab.a[ai] == ab.b[bi] }
func (ab *IndividualBytes) WriteATo(w io.Writer, i int) (int, error) { return w.Write([]byte{ab.a[i]}) }
func (ab *IndividualBytes) WriteBTo(w io.Writer, i int) (int, error) { return w.Write([]byte{ab.b[i]}) }
