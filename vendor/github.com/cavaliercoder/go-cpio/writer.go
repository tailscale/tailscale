package cpio

import (
	"errors"
	"fmt"
	"io"
)

var (
	ErrWriteTooLong    = errors.New("cpio: write too long")
	ErrWriteAfterClose = errors.New("cpio: write after close")
)

var trailer = &Header{
	Name:  string(headerEOF),
	Links: 1,
}

var zeroBlock [4]byte

// A Writer provides sequential writing of a CPIO archive. A CPIO archive
// consists of a sequence of files. Call WriteHeader to begin a new file, and
// then call Write to supply that file's data, writing at most hdr.Size bytes in
// total.
type Writer struct {
	w      io.Writer
	nb     int64 // number of unwritten bytes for current file entry
	pad    int64 // amount of padding to write after current file entry
	inode  int64
	err    error
	closed bool
}

// NewWriter creates a new Writer writing to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Flush finishes writing the current file (optional).
func (w *Writer) Flush() error {
	if w.nb > 0 {
		w.err = fmt.Errorf("cpio: missed writing %d bytes", w.nb)
		return w.err
	}
	_, w.err = w.w.Write(zeroBlock[:w.pad])
	if w.err != nil {
		return w.err
	}
	w.nb = 0
	w.pad = 0
	return w.err
}

// WriteHeader writes hdr and prepares to accept the file's contents.
// WriteHeader calls Flush if it is not the first header. Calling after a Close
// will return ErrWriteAfterClose.
func (w *Writer) WriteHeader(hdr *Header) (err error) {
	if w.closed {
		return ErrWriteAfterClose
	}
	if w.err == nil {
		w.Flush()
	}
	if w.err != nil {
		return w.err
	}

	if hdr.Name != headerEOF {
		// TODO: should we be mutating hdr here?
		// ensure all inodes are unique
		w.inode++
		if hdr.Inode == 0 {
			hdr.Inode = w.inode
		}

		// ensure file type is set
		if hdr.Mode&^ModePerm == 0 {
			hdr.Mode |= ModeRegular
		}

		// ensure regular files have at least 1 inbound link
		if hdr.Links < 1 && hdr.Mode.IsRegular() {
			hdr.Links = 1
		}
	}

	w.nb = hdr.Size
	w.pad, w.err = writeSVR4Header(w.w, hdr)
	return
}

// Write writes to the current entry in the CPIO archive. Write returns the
// error ErrWriteTooLong if more than hdr.Size bytes are written after
// WriteHeader.
func (w *Writer) Write(p []byte) (n int, err error) {
	if w.closed {
		err = ErrWriteAfterClose
		return
	}
	overwrite := false
	if int64(len(p)) > w.nb {
		p = p[0:w.nb]
		overwrite = true
	}
	n, err = w.w.Write(p)
	w.nb -= int64(n)
	if err == nil && overwrite {
		err = ErrWriteTooLong
		return
	}
	w.err = err
	return
}

// Close closes the CPIO archive, flushing any unwritten data to the underlying
// writer.
func (w *Writer) Close() error {
	if w.err != nil || w.closed {
		return w.err
	}
	w.err = w.WriteHeader(trailer)
	if w.err != nil {
		return w.err
	}
	w.Flush()
	w.closed = true
	return w.err
}
