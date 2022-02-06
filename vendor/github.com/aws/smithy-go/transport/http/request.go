package http

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	iointernal "github.com/aws/smithy-go/transport/http/internal/io"
)

// Request provides the HTTP specific request structure for HTTP specific
// middleware steps to use to serialize input, and send an operation's request.
type Request struct {
	*http.Request
	stream           io.Reader
	isStreamSeekable bool
	streamStartPos   int64
}

// NewStackRequest returns an initialized request ready to populated with the
// HTTP request details. Returns empty interface so the function can be used as
// a parameter to the Smithy middleware Stack constructor.
func NewStackRequest() interface{} {
	return &Request{
		Request: &http.Request{
			URL:           &url.URL{},
			Header:        http.Header{},
			ContentLength: -1, // default to unknown length
		},
	}
}

// Clone returns a deep copy of the Request for the new context. A reference to
// the Stream is copied, but the underlying stream is not copied.
func (r *Request) Clone() *Request {
	rc := *r
	rc.Request = rc.Request.Clone(context.TODO())
	return &rc
}

// StreamLength returns the number of bytes of the serialized stream attached
// to the request and ok set. If the length cannot be determined, an error will
// be returned.
func (r *Request) StreamLength() (size int64, ok bool, err error) {
	if r.stream == nil {
		return 0, true, nil
	}

	if l, ok := r.stream.(interface{ Len() int }); ok {
		return int64(l.Len()), true, nil
	}

	if !r.isStreamSeekable {
		return 0, false, nil
	}

	s := r.stream.(io.Seeker)
	endOffset, err := s.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, false, err
	}

	// The reason to seek to streamStartPos instead of 0 is to ensure that the
	// SDK only sends the stream from the starting position the user's
	// application provided it to the SDK at. For example application opens a
	// file, and wants to skip the first N bytes uploading the rest. The
	// application would move the file's offset N bytes, then hand it off to
	// the SDK to send the remaining. The SDK should respect that initial offset.
	_, err = s.Seek(r.streamStartPos, io.SeekStart)
	if err != nil {
		return 0, false, err
	}

	return endOffset - r.streamStartPos, true, nil
}

// RewindStream will rewind the io.Reader to the relative start position if it
// is an io.Seeker.
func (r *Request) RewindStream() error {
	// If there is no stream there is nothing to rewind.
	if r.stream == nil {
		return nil
	}

	if !r.isStreamSeekable {
		return fmt.Errorf("request stream is not seekable")
	}
	_, err := r.stream.(io.Seeker).Seek(r.streamStartPos, io.SeekStart)
	return err
}

// GetStream returns the request stream io.Reader if a stream is set. If no
// stream is present nil will be returned.
func (r *Request) GetStream() io.Reader {
	return r.stream
}

// IsStreamSeekable returns if the stream is seekable.
func (r *Request) IsStreamSeekable() bool {
	return r.isStreamSeekable
}

// SetStream returns a clone of the request with the stream set to the provided reader.
// May return an error if the provided reader is seekable but returns an error.
func (r *Request) SetStream(reader io.Reader) (rc *Request, err error) {
	rc = r.Clone()

	switch v := reader.(type) {
	case io.Seeker:
		n, err := v.Seek(0, io.SeekCurrent)
		if err != nil {
			return r, err
		}
		rc.isStreamSeekable = true
		rc.streamStartPos = n
	default:
		rc.isStreamSeekable = false
	}
	rc.stream = reader

	return rc, err
}

// Build returns a build standard HTTP request value from the Smithy request.
// The request's stream is wrapped in a safe container that allows it to be
// reused for subsequent attempts.
func (r *Request) Build(ctx context.Context) *http.Request {
	req := r.Request.Clone(ctx)

	if r.stream == nil && req.ContentLength == -1 {
		req.ContentLength = 0
	}

	switch stream := r.stream.(type) {
	case *io.PipeReader:
		req.Body = ioutil.NopCloser(stream)
		req.ContentLength = -1
	default:
		if r.stream != nil {
			req.Body = iointernal.NewSafeReadCloser(ioutil.NopCloser(stream))
		}
	}

	return req
}

// RequestCloner is a function that can take an input request type and clone the request
// for use in a subsequent retry attempt
func RequestCloner(v interface{}) interface{} {
	return v.(*Request).Clone()
}
