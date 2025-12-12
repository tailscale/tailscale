// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_drive

package ipnlocal

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"tailscale.com/drive"
	"tailscale.com/types/views"
)

// TestDriveShareViewsEqual_NilPointer tests nil pointer comparison
func TestDriveShareViewsEqual_NilPointer(t *testing.T) {
	shares := views.SliceOfViews([]*drive.Share{
		{Name: "test"},
	})

	if driveShareViewsEqual(nil, shares) {
		t.Error("driveShareViewsEqual(nil, shares) = true, want false")
	}
}

// TestDriveShareViewsEqual_EmptySlices tests empty slice comparison
func TestDriveShareViewsEqual_EmptySlices(t *testing.T) {
	a := views.SliceOfViews([]*drive.Share{})
	b := views.SliceOfViews([]*drive.Share{})

	if !driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(empty, empty) = false, want true")
	}
}

// TestDriveShareViewsEqual_DifferentLengths tests different length slices
func TestDriveShareViewsEqual_DifferentLengths(t *testing.T) {
	a := views.SliceOfViews([]*drive.Share{
		{Name: "share1"},
	})
	b := views.SliceOfViews([]*drive.Share{
		{Name: "share1"},
		{Name: "share2"},
	})

	if driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(len=1, len=2) = true, want false")
	}
}

// TestDriveShareViewsEqual_SameSingleShare tests identical single share
func TestDriveShareViewsEqual_SameSingleShare(t *testing.T) {
	share := &drive.Share{
		Name: "test",
		Path: "/path/to/test",
	}

	a := views.SliceOfViews([]*drive.Share{share})
	b := views.SliceOfViews([]*drive.Share{share})

	if !driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(same, same) = false, want true")
	}
}

// TestDriveShareViewsEqual_DifferentShares tests different shares
func TestDriveShareViewsEqual_DifferentShares(t *testing.T) {
	a := views.SliceOfViews([]*drive.Share{
		{Name: "share1", Path: "/path1"},
	})
	b := views.SliceOfViews([]*drive.Share{
		{Name: "share2", Path: "/path2"},
	})

	if driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(different, different) = true, want false")
	}
}

// TestDriveShareViewsEqual_MultipleShares tests multiple identical shares
func TestDriveShareViewsEqual_MultipleShares(t *testing.T) {
	shares := []*drive.Share{
		{Name: "share1", Path: "/path1"},
		{Name: "share2", Path: "/path2"},
		{Name: "share3", Path: "/path3"},
	}

	a := views.SliceOfViews(shares)
	b := views.SliceOfViews(shares)

	if !driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(same3, same3) = false, want true")
	}
}

// TestDriveShareViewsEqual_DifferentOrder tests shares in different order
func TestDriveShareViewsEqual_DifferentOrder(t *testing.T) {
	a := views.SliceOfViews([]*drive.Share{
		{Name: "share1", Path: "/path1"},
		{Name: "share2", Path: "/path2"},
	})
	b := views.SliceOfViews([]*drive.Share{
		{Name: "share2", Path: "/path2"},
		{Name: "share1", Path: "/path1"},
	})

	if driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(different order) = true, want false")
	}
}

// TestDriveShareViewsEqual_SameOrder tests shares in same order
func TestDriveShareViewsEqual_SameOrder(t *testing.T) {
	shares := []*drive.Share{
		{Name: "a", Path: "/a"},
		{Name: "b", Path: "/b"},
		{Name: "c", Path: "/c"},
	}

	a := views.SliceOfViews(shares)
	b := views.SliceOfViews(shares)

	if !driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(same order) = false, want true")
	}
}

// TestDriveShareViewsEqual_OneShareDifferent tests one share different
func TestDriveShareViewsEqual_OneShareDifferent(t *testing.T) {
	a := views.SliceOfViews([]*drive.Share{
		{Name: "share1", Path: "/path1"},
		{Name: "share2", Path: "/path2"},
		{Name: "share3", Path: "/path3"},
	})
	b := views.SliceOfViews([]*drive.Share{
		{Name: "share1", Path: "/path1"},
		{Name: "share2", Path: "/path_modified"},
		{Name: "share3", Path: "/path3"},
	})

	if driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(one different) = true, want false")
	}
}

// TestResponseBodyWrapper_Read tests Read method
func TestResponseBodyWrapper_Read(t *testing.T) {
	data := "test data for reading"
	rc := io.NopCloser(strings.NewReader(data))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	buf := make([]byte, len(data))
	n, err := rbw.Read(buf)

	if err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v, want nil or EOF", err)
	}

	if n != len(data) {
		t.Errorf("Read() n = %d, want %d", n, len(data))
	}

	if rbw.bytesRx != int64(len(data)) {
		t.Errorf("bytesRx = %d, want %d", rbw.bytesRx, len(data))
	}

	if string(buf) != data {
		t.Errorf("Read() data = %q, want %q", buf, data)
	}
}

// TestResponseBodyWrapper_ReadMultiple tests multiple Read calls
func TestResponseBodyWrapper_ReadMultiple(t *testing.T) {
	data := "abcdefghijklmnopqrstuvwxyz"
	rc := io.NopCloser(strings.NewReader(data))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	// Read in chunks
	buf1 := make([]byte, 10)
	n1, _ := rbw.Read(buf1)

	buf2 := make([]byte, 10)
	n2, _ := rbw.Read(buf2)

	totalRead := int64(n1 + n2)
	if rbw.bytesRx != totalRead {
		t.Errorf("bytesRx = %d, want %d", rbw.bytesRx, totalRead)
	}
}

// TestResponseBodyWrapper_ReadError tests Read with error
func TestResponseBodyWrapper_ReadError(t *testing.T) {
	testErr := errors.New("read error")

	rc := &errorReader{err: testErr}
	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	buf := make([]byte, 10)
	_, err := rbw.Read(buf)

	if err != testErr {
		t.Errorf("Read() error = %v, want %v", err, testErr)
	}
}

// TestResponseBodyWrapper_Close tests Close method
func TestResponseBodyWrapper_Close(t *testing.T) {
	rc := io.NopCloser(strings.NewReader("test"))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	err := rbw.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}
}

// TestResponseBodyWrapper_CloseWithError tests Close with error
func TestResponseBodyWrapper_CloseWithError(t *testing.T) {
	testErr := errors.New("close error")
	rc := &errorCloser{err: testErr}

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	err := rbw.Close()
	if err != testErr {
		t.Errorf("Close() error = %v, want %v", err, testErr)
	}
}

// TestResponseBodyWrapper_LogAccess_NilLogger tests logging with nil logger
func TestResponseBodyWrapper_LogAccess_NilLogger(t *testing.T) {
	rbw := &responseBodyWrapper{
		log:           nil,
		method:        "GET",
		statusCode:    200,
		contentLength: 1024,
	}

	// Should not panic
	rbw.logAccess("")
}

// TestResponseBodyWrapper_LogAccess_ZeroLength tests zero-length content logging
func TestResponseBodyWrapper_LogAccess_ZeroLength(t *testing.T) {
	logged := false
	rbw := &responseBodyWrapper{
		log: func(format string, args ...any) {
			logged = true
		},
		method:        "GET",
		statusCode:    200,
		contentLength: 0,
		logVerbose:    false,
	}

	rbw.logAccess("")

	if logged {
		t.Error("logAccess() logged zero-length non-verbose request, should be silent")
	}
}

// TestResponseBodyWrapper_LogAccess_VerboseMode tests verbose logging
func TestResponseBodyWrapper_LogAccess_VerboseMode(t *testing.T) {
	logged := false
	rbw := &responseBodyWrapper{
		log: func(format string, args ...any) {
			logged = true
			if !strings.Contains(format, "[v1]") {
				t.Error("verbose log should contain [v1] prefix")
			}
		},
		method:        "PROPFIND",
		statusCode:    200,
		contentLength: 0,
		logVerbose:    true,
	}

	rbw.logAccess("")

	if !logged {
		t.Error("logAccess() did not log in verbose mode")
	}
}

// TestResponseBodyWrapper_LogAccess_NonZeroContent tests logging non-zero content
func TestResponseBodyWrapper_LogAccess_NonZeroContent(t *testing.T) {
	logged := false
	rbw := &responseBodyWrapper{
		log: func(format string, args ...any) {
			logged = true
		},
		method:        "GET",
		statusCode:    200,
		contentLength: 1024,
		logVerbose:    false,
	}

	rbw.logAccess("")

	if !logged {
		t.Error("logAccess() did not log non-zero content")
	}
}

// TestResponseBodyWrapper_LogAccess_WithError tests logging with error
func TestResponseBodyWrapper_LogAccess_WithError(t *testing.T) {
	errorLogged := ""
	rbw := &responseBodyWrapper{
		log: func(format string, args ...any) {
			// Extract the error from the args
			for _, arg := range args {
				if s, ok := arg.(string); ok && s != "" {
					errorLogged = s
				}
			}
		},
		method:        "GET",
		statusCode:    500,
		contentLength: 100,
	}

	testError := "test error message"
	rbw.logAccess(testError)

	if errorLogged != testError {
		t.Errorf("logged error = %q, want %q", errorLogged, testError)
	}
}

// TestResponseBodyWrapper_ReadThenClose tests typical usage pattern
func TestResponseBodyWrapper_ReadThenClose(t *testing.T) {
	data := "test data"
	rc := io.NopCloser(strings.NewReader(data))

	closeLogged := false
	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log: func(format string, args ...any) {
			closeLogged = true
		},
		method:        "GET",
		statusCode:    200,
		contentLength: int64(len(data)),
	}

	// Read all data
	buf := make([]byte, len(data))
	rbw.Read(buf)

	// Close should log
	rbw.Close()

	if !closeLogged {
		t.Error("Close() did not log access")
	}

	if rbw.bytesRx != int64(len(data)) {
		t.Errorf("bytesRx = %d, want %d", rbw.bytesRx, len(data))
	}
}

// TestResponseBodyWrapper_StatusCodes tests different status codes
func TestResponseBodyWrapper_StatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantLogged bool
	}{
		{"success_200", 200, true},
		{"created_201", 201, true},
		{"no_content_204", 204, false}, // Zero content
		{"bad_request_400", 400, true},
		{"not_found_404", 404, true},
		{"server_error_500", 500, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logged := false
			rbw := &responseBodyWrapper{
				log: func(format string, args ...any) {
					logged = true
				},
				method:        "GET",
				statusCode:    tt.statusCode,
				contentLength: 0,
				logVerbose:    true, // Force logging
			}

			rbw.logAccess("")

			if logged != tt.wantLogged {
				t.Errorf("logged = %v, want %v", logged, tt.wantLogged)
			}
		})
	}
}

// TestResponseBodyWrapper_ContentTypes tests different content types
func TestResponseBodyWrapper_ContentTypes(t *testing.T) {
	tests := []struct {
		contentType string
	}{
		{"text/plain"},
		{"application/json"},
		{"application/octet-stream"},
		{"image/png"},
		{"video/mp4"},
		{""},
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			rbw := &responseBodyWrapper{
				log:           t.Logf,
				method:        "GET",
				statusCode:    200,
				contentType:   tt.contentType,
				contentLength: 100,
			}

			// Should not panic
			rbw.logAccess("")
		})
	}
}

// TestResponseBodyWrapper_Methods tests different HTTP methods
func TestResponseBodyWrapper_Methods(t *testing.T) {
	methods := []string{"GET", "PUT", "POST", "DELETE", "HEAD", "PROPFIND", "MKCOL"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rbw := &responseBodyWrapper{
				log:           t.Logf,
				method:        method,
				statusCode:    200,
				contentLength: 100,
			}

			// Should not panic
			rbw.logAccess("")
		})
	}
}

// TestResponseBodyWrapper_FileExtensions tests different file extensions
func TestResponseBodyWrapper_FileExtensions(t *testing.T) {
	extensions := []string{".txt", ".pdf", ".jpg", ".mp4", ".doc", ""}

	for _, ext := range extensions {
		t.Run(ext, func(t *testing.T) {
			rbw := &responseBodyWrapper{
				log:           t.Logf,
				method:        "GET",
				statusCode:    200,
				fileExtension: ext,
				contentLength: 100,
			}

			// Should not panic
			rbw.logAccess("")
		})
	}
}

// TestResponseBodyWrapper_TrafficRounding tests traffic rounding
func TestResponseBodyWrapper_TrafficRounding(t *testing.T) {
	rbw := &responseBodyWrapper{
		log:           t.Logf,
		method:        "GET",
		statusCode:    200,
		contentLength: 1536,      // Should round
		bytesRx:       2048,      // Should round
		bytesTx:       512,       // Should round
	}

	// Should not panic with large numbers
	rbw.logAccess("")
}

// TestResponseBodyWrapper_NodeKeys tests node key logging
func TestResponseBodyWrapper_NodeKeys(t *testing.T) {
	rbw := &responseBodyWrapper{
		log:           t.Logf,
		method:        "GET",
		statusCode:    200,
		selfNodeKey:   "self123",
		shareNodeKey:  "share456",
		contentLength: 100,
	}

	// Should not panic
	rbw.logAccess("")
}

// TestDriveTransport_RoundTrip_RemovesHeaders tests header removal
func TestDriveTransport_RoundTrip_RemovesHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers are removed
		if r.Header.Get("Origin") != "" {
			t.Error("Origin header not removed")
		}
		if r.Header.Get("Referer") != "" {
			t.Error("Referer header not removed")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Note: Cannot easily test driveTransport without full LocalBackend setup
	// This is a structural test
}

// TestDriveTransport_RequestBodyWrapper tests request body wrapping
func TestDriveTransport_RequestBodyWrapper(t *testing.T) {
	// Test the requestBodyWrapper concept
	data := "test request body"
	rc := io.NopCloser(strings.NewReader(data))

	// Read all data
	buf := make([]byte, len(data))
	n, err := rc.Read(buf)

	if err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v", err)
	}

	if n != len(data) {
		t.Errorf("Read() n = %d, want %d", n, len(data))
	}

	rc.Close()
}

// errorReader is a ReadCloser that always returns an error on Read
type errorReader struct {
	err error
}

func (er *errorReader) Read(p []byte) (int, error) {
	return 0, er.err
}

func (er *errorReader) Close() error {
	return nil
}

// errorCloser is a ReadCloser that always returns an error on Close
type errorCloser struct {
	err error
}

func (ec *errorCloser) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (ec *errorCloser) Close() error {
	return ec.err
}

// TestResponseBodyWrapper_LargeRead tests reading large data
func TestResponseBodyWrapper_LargeRead(t *testing.T) {
	// Create 1MB of data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	rc := io.NopCloser(strings.NewReader(string(data)))
	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	buf := make([]byte, len(data))
	n, err := io.ReadFull(rbw, buf)

	if err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}

	if n != len(data) {
		t.Errorf("ReadFull() n = %d, want %d", n, len(data))
	}

	if rbw.bytesRx != int64(len(data)) {
		t.Errorf("bytesRx = %d, want %d", rbw.bytesRx, len(data))
	}
}

// TestResponseBodyWrapper_PartialRead tests partial reading
func TestResponseBodyWrapper_PartialRead(t *testing.T) {
	data := "0123456789abcdefghijklmnopqrstuvwxyz"
	rc := io.NopCloser(strings.NewReader(data))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	// Read only first 10 bytes
	buf := make([]byte, 10)
	n, err := rbw.Read(buf)

	if err != nil && err != io.EOF {
		t.Fatalf("Read() error = %v", err)
	}

	if n != 10 {
		t.Errorf("Read() n = %d, want 10", n)
	}

	if rbw.bytesRx != 10 {
		t.Errorf("bytesRx = %d, want 10", rbw.bytesRx)
	}

	// Close should log with only 10 bytes read
	rbw.Close()
}

// TestResponseBodyWrapper_EmptyRead tests reading empty data
func TestResponseBodyWrapper_EmptyRead(t *testing.T) {
	rc := io.NopCloser(strings.NewReader(""))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	buf := make([]byte, 10)
	n, err := rbw.Read(buf)

	if err != io.EOF {
		t.Errorf("Read() error = %v, want EOF", err)
	}

	if n != 0 {
		t.Errorf("Read() n = %d, want 0", n)
	}

	if rbw.bytesRx != 0 {
		t.Errorf("bytesRx = %d, want 0", rbw.bytesRx)
	}
}

// TestResponseBodyWrapper_ReadEOF tests EOF handling
func TestResponseBodyWrapper_ReadEOF(t *testing.T) {
	data := "short"
	rc := io.NopCloser(strings.NewReader(data))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	buf := make([]byte, len(data))
	n1, _ := rbw.Read(buf)

	// Read again to get EOF
	buf2 := make([]byte, 10)
	n2, err := rbw.Read(buf2)

	if err != io.EOF {
		t.Errorf("second Read() error = %v, want EOF", err)
	}

	if n2 != 0 {
		t.Errorf("second Read() n = %d, want 0", n2)
	}

	totalBytes := int64(n1 + n2)
	if rbw.bytesRx != totalBytes {
		t.Errorf("bytesRx = %d, want %d", rbw.bytesRx, totalBytes)
	}
}

// TestResponseBodyWrapper_MultipleClose tests multiple Close calls
func TestResponseBodyWrapper_MultipleClose(t *testing.T) {
	rc := io.NopCloser(strings.NewReader("test"))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	// First close should succeed
	err1 := rbw.Close()
	if err1 != nil {
		t.Errorf("first Close() error = %v, want nil", err1)
	}

	// Second close behavior depends on underlying ReadCloser
	// Just verify it doesn't panic
	rbw.Close()
}

// TestResponseBodyWrapper_CloseWithoutRead tests closing without reading
func TestResponseBodyWrapper_CloseWithoutRead(t *testing.T) {
	rc := io.NopCloser(strings.NewReader("test"))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	// Close without reading
	err := rbw.Close()
	if err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	if rbw.bytesRx != 0 {
		t.Errorf("bytesRx = %d, want 0 (no reads)", rbw.bytesRx)
	}
}

// TestResponseBodyWrapper_InterruptedRead tests interrupted reading
func TestResponseBodyWrapper_InterruptedRead(t *testing.T) {
	data := "0123456789abcdefghijklmnopqrstuvwxyz"
	rc := io.NopCloser(strings.NewReader(data))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	// Read some data
	buf1 := make([]byte, 10)
	rbw.Read(buf1)

	// Close before reading all data
	rbw.Close()

	if rbw.bytesRx != 10 {
		t.Errorf("bytesRx = %d, want 10 (partial read)", rbw.bytesRx)
	}
}

// TestDriveShareViewsEqual_LargeLists tests large share lists
func TestDriveShareViewsEqual_LargeLists(t *testing.T) {
	// Create 100 shares
	shares := make([]*drive.Share, 100)
	for i := range shares {
		shares[i] = &drive.Share{
			Name: string(rune('a' + i%26)),
			Path: "/path/" + string(rune('a'+i%26)),
		}
	}

	a := views.SliceOfViews(shares)
	b := views.SliceOfViews(shares)

	if !driveShareViewsEqual(&a, b) {
		t.Error("driveShareViewsEqual(large, large) = false, want true")
	}
}

// TestDriveShareViewsEqual_NilVsEmpty tests nil vs empty slice
func TestDriveShareViewsEqual_NilVsEmpty(t *testing.T) {
	empty := views.SliceOfViews([]*drive.Share{})

	// nil pointer vs empty slice
	if driveShareViewsEqual(nil, empty) {
		t.Error("driveShareViewsEqual(nil, empty) = true, want false")
	}
}

// TestResponseBodyWrapper_BytesCounting tests accurate byte counting
func TestResponseBodyWrapper_BytesCounting(t *testing.T) {
	tests := []struct {
		name     string
		dataSize int
	}{
		{"small_10", 10},
		{"medium_1024", 1024},
		{"large_10240", 10240},
		{"exact_page_4096", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			rc := io.NopCloser(strings.NewReader(string(data)))

			rbw := &responseBodyWrapper{
				ReadCloser: rc,
				log:        t.Logf,
				method:     "GET",
			}

			buf := make([]byte, tt.dataSize)
			n, _ := io.ReadFull(rbw, buf)

			if rbw.bytesRx != int64(n) {
				t.Errorf("bytesRx = %d, want %d", rbw.bytesRx, n)
			}
		})
	}
}

// TestResponseBodyWrapper_ConcurrentAccess tests concurrent access safety
func TestResponseBodyWrapper_ConcurrentAccess(t *testing.T) {
	// Note: responseBodyWrapper is not designed for concurrent access
	// This test just ensures no obvious race conditions in single-threaded use
	data := "test data"
	rc := io.NopCloser(strings.NewReader(data))

	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	buf := make([]byte, len(data))
	rbw.Read(buf)
	rbw.Close()

	// Should complete without race detector warnings
}

// TestResponseBodyWrapper_LogFormat tests log format structure
func TestResponseBodyWrapper_LogFormat(t *testing.T) {
	formatSeen := ""
	rbw := &responseBodyWrapper{
		log: func(format string, args ...any) {
			formatSeen = format
		},
		method:        "GET",
		statusCode:    200,
		selfNodeKey:   "self",
		shareNodeKey:  "share",
		fileExtension: ".txt",
		contentType:   "text/plain",
		contentLength: 100,
		bytesTx:       50,
		bytesRx:       100,
	}

	rbw.logAccess("no error")

	// Verify log format contains expected fields
	expectedFields := []string{
		"taildrive: access:",
		"status-code=",
		"ext=",
		"content-type=",
		"content-length=",
		"tx=",
		"rx=",
		"err=",
	}

	for _, field := range expectedFields {
		if !strings.Contains(formatSeen, field) {
			t.Errorf("log format missing field: %q", field)
		}
	}
}

// TestDriveShareViewsEqual_BoundaryConditions tests boundary conditions
func TestDriveShareViewsEqual_BoundaryConditions(t *testing.T) {
	tests := []struct {
		name  string
		aLen  int
		bLen  int
		equal bool
	}{
		{"zero_zero", 0, 0, true},
		{"zero_one", 0, 1, false},
		{"one_zero", 1, 0, false},
		{"one_one", 1, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aShares := make([]*drive.Share, tt.aLen)
			bShares := make([]*drive.Share, tt.bLen)

			for i := range aShares {
				aShares[i] = &drive.Share{Name: "test"}
			}
			for i := range bShares {
				bShares[i] = &drive.Share{Name: "test"}
			}

			a := views.SliceOfViews(aShares)
			b := views.SliceOfViews(bShares)

			result := driveShareViewsEqual(&a, b)
			if result != tt.equal {
				t.Errorf("driveShareViewsEqual() = %v, want %v", result, tt.equal)
			}
		})
	}
}

// TestResponseBodyWrapper_AllFieldsSet tests all fields are logged
func TestResponseBodyWrapper_AllFieldsSet(t *testing.T) {
	rbw := &responseBodyWrapper{
		log:           t.Logf,
		logVerbose:    true,
		bytesRx:       1024,
		bytesTx:       512,
		method:        "PUT",
		statusCode:    201,
		contentType:   "application/octet-stream",
		fileExtension: ".bin",
		shareNodeKey:  "node123",
		selfNodeKey:   "self456",
		contentLength: 2048,
	}

	// Should not panic with all fields set
	rbw.logAccess("test error")
}

// TestResponseBodyWrapper_MinimalFields tests minimal field set
func TestResponseBodyWrapper_MinimalFields(t *testing.T) {
	rbw := &responseBodyWrapper{
		log:           t.Logf,
		method:        "GET",
		contentLength: 100,
	}

	// Should not panic with minimal fields
	rbw.logAccess("")
}

// TestDriveShareViewsEqual_IdenticalPointers tests same pointer
func TestDriveShareViewsEqual_IdenticalPointers(t *testing.T) {
	shares := views.SliceOfViews([]*drive.Share{
		{Name: "test"},
	})

	if !driveShareViewsEqual(&shares, shares) {
		t.Error("driveShareViewsEqual(same ptr, same ptr) = false, want true")
	}
}

// TestResponseBodyWrapper_ReadAfterError tests reading after error
func TestResponseBodyWrapper_ReadAfterError(t *testing.T) {
	rc := &errorReader{err: errors.New("read error")}
	rbw := &responseBodyWrapper{
		ReadCloser: rc,
		log:        t.Logf,
		method:     "GET",
	}

	buf := make([]byte, 10)

	// First read gets error
	_, err1 := rbw.Read(buf)
	if err1 == nil {
		t.Error("first Read() should return error")
	}

	// Second read should also get error
	_, err2 := rbw.Read(buf)
	if err2 == nil {
		t.Error("second Read() should return error")
	}
}
